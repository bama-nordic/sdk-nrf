# Copyright (c) 2026 Nordic Semiconductor ASA
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
"""Senior-care dashboard backend.

Subscribes to the MQTT care topic tree, maintains per-room state, persists
events and fall alerts to SQLite, and pushes realtime updates to dashboard
browsers over a WebSocket. Also serves the static dashboard and a small REST
API (including fall-alert acknowledgement, which is sent back to the device
as a command).
"""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

import paho.mqtt.client as mqtt
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse

MQTT_HOST = os.getenv("MQTT_HOST", "localhost")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
MQTT_TOPIC = os.getenv("MQTT_TOPIC", "care/#")
MQTT_TLS = os.getenv("MQTT_TLS", "0").lower() in ("1", "true", "yes")
MQTT_CA_CERT = os.getenv("MQTT_CA_CERT", "")
MQTT_USERNAME = os.getenv("MQTT_USERNAME", "")
MQTT_PASSWORD = os.getenv("MQTT_PASSWORD", "")
DB_PATH = os.getenv("DB_PATH", "/data/care.db")
# Docker mounts the dashboard at /app/web; locally it lives at ../web.
WEB_DIR = next(
    (p for p in (Path(__file__).parent / "web", Path(__file__).parent.parent / "web")
     if (p / "index.html").exists()),
    Path(__file__).parent / "web",
)
OFFLINE_AFTER_S = 30

# room_id -> room state dict
rooms: dict[str, dict] = {}
state_lock = threading.Lock()
ws_clients: set[WebSocket] = set()
main_loop: asyncio.AbstractEventLoop | None = None

mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)


# --------------------------------------------------------------------------- #
# Storage
# --------------------------------------------------------------------------- #
def db_connect() -> sqlite3.Connection:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.execute(
        "CREATE TABLE IF NOT EXISTS event ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, room TEXT, "
        "type TEXT, payload TEXT)"
    )
    con.execute(
        "CREATE TABLE IF NOT EXISTS fall_alert ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, room TEXT, "
        "confidence REAL, acked INTEGER DEFAULT 0, acked_ts REAL)"
    )
    con.commit()
    return con


db = db_connect()
db_lock = threading.Lock()


def db_event(room: str, etype: str, payload: dict) -> None:
    with db_lock:
        db.execute(
            "INSERT INTO event (ts, room, type, payload) VALUES (?, ?, ?, ?)",
            (time.time(), room, etype, json.dumps(payload)),
        )
        db.commit()


def db_fall_alert(room: str, confidence: float) -> None:
    with db_lock:
        db.execute(
            "INSERT INTO fall_alert (ts, room, confidence) VALUES (?, ?, ?)",
            (time.time(), room, confidence),
        )
        db.commit()


# --------------------------------------------------------------------------- #
# WebSocket broadcast
# --------------------------------------------------------------------------- #
async def _broadcast(message: dict) -> None:
    dead = []
    for ws in list(ws_clients):
        try:
            await ws.send_json(message)
        except Exception:
            dead.append(ws)
    for ws in dead:
        ws_clients.discard(ws)


def broadcast(message: dict) -> None:
    """Thread-safe broadcast usable from the MQTT (paho) thread."""
    if main_loop is not None:
        asyncio.run_coroutine_threadsafe(_broadcast(message), main_loop)


# --------------------------------------------------------------------------- #
# MQTT ingestion
# --------------------------------------------------------------------------- #
def get_room(site: str, room_id: str) -> dict:
    room = rooms.get(room_id)
    if room is None:
        room = {
            "room_id": room_id,
            "site": site,
            "online": False,
            "last_seen": 0.0,
            "presence": None,
            "breathing": None,
            "fall": {"state": "none"},
            "wave": [],
        }
        rooms[room_id] = room
    return room


def handle_message(topic: str, payload: dict) -> None:
    parts = topic.split("/")
    if len(parts) < 4 or parts[0] != "care":
        return
    site, room_id = parts[1], parts[2]
    sub = "/".join(parts[3:])

    with state_lock:
        room = get_room(site, room_id)
        room["last_seen"] = time.time()

        if sub == "status":
            room["online"] = bool(payload.get("online", True))
        elif sub == "presence":
            room["presence"] = payload
        elif sub == "breathing":
            room["breathing"] = payload
        elif sub == "breathing/wave":
            room["wave"] = payload.get("samples", [])
        elif sub == "fall":
            room["fall"] = payload
            if payload.get("state") == "confirmed":
                db_fall_alert(room_id, float(payload.get("confidence", 0.0)))

        snapshot = dict(room)

    db_event(room_id, sub, payload)
    broadcast({"type": "update", "room": snapshot})


def on_connect(client, userdata, flags, reason_code, properties=None):
    print(f"[mqtt] connected rc={reason_code}; subscribing {MQTT_TOPIC}")
    client.subscribe(MQTT_TOPIC)


def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return
    handle_message(msg.topic, payload)


def mqtt_start() -> None:
    mqtt_client.on_connect = on_connect
    mqtt_client.on_message = on_message
    if MQTT_USERNAME:
        mqtt_client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
    if MQTT_TLS:
        # ca_certs=None uses the system trust store; set MQTT_CA_CERT for a
        # private/self-signed broker CA. Hostname is verified against the cert.
        mqtt_client.tls_set(ca_certs=MQTT_CA_CERT or None)
        print(f"[mqtt] TLS enabled (ca={MQTT_CA_CERT or 'system'})")
    while True:
        try:
            mqtt_client.connect(MQTT_HOST, MQTT_PORT, keepalive=30)
            break
        except OSError as exc:
            print(f"[mqtt] connect failed ({exc}); retrying in 3s")
            time.sleep(3)
    mqtt_client.loop_start()


async def offline_watchdog() -> None:
    """Mark rooms offline if no message arrives within the timeout."""
    while True:
        await asyncio.sleep(5)
        now = time.time()
        changed = []
        with state_lock:
            for room in rooms.values():
                stale = (now - room["last_seen"]) > OFFLINE_AFTER_S
                if stale and room["online"]:
                    room["online"] = False
                    changed.append(dict(room))
        for snap in changed:
            broadcast({"type": "update", "room": snap})


# --------------------------------------------------------------------------- #
# FastAPI
# --------------------------------------------------------------------------- #
@asynccontextmanager
async def lifespan(app: FastAPI):
    global main_loop
    main_loop = asyncio.get_running_loop()
    mqtt_start()
    watchdog = asyncio.create_task(offline_watchdog())
    yield
    watchdog.cancel()
    mqtt_client.loop_stop()


app = FastAPI(title="Senior-care dashboard", lifespan=lifespan)


@app.get("/")
async def index():
    return FileResponse(WEB_DIR / "index.html")


@app.get("/api/rooms")
async def api_rooms():
    with state_lock:
        return JSONResponse(list(rooms.values()))


@app.get("/api/rooms/{room_id}/history")
async def api_history(room_id: str, limit: int = 200):
    with db_lock:
        cur = db.execute(
            "SELECT ts, type, payload FROM event WHERE room = ? "
            "ORDER BY id DESC LIMIT ?",
            (room_id, limit),
        )
        rows = [{"ts": r[0], "type": r[1], "payload": json.loads(r[2])} for r in cur]
    return JSONResponse(rows)


@app.post("/api/rooms/{room_id}/ack")
async def api_ack(room_id: str):
    with state_lock:
        room = rooms.get(room_id)
        site = room["site"] if room else os.getenv("SITE_ID", "site1")
        if room:
            room["fall"] = {"state": "none"}
    # Tell the device to clear its latched fall state.
    mqtt_client.publish(f"care/{site}/{room_id}/cmd", json.dumps({"ack_fall": True}), qos=1)
    with db_lock:
        db.execute(
            "UPDATE fall_alert SET acked = 1, acked_ts = ? "
            "WHERE room = ? AND acked = 0",
            (time.time(), room_id),
        )
        db.commit()
    broadcast({"type": "update", "room": dict(rooms.get(room_id, {"room_id": room_id}))})
    return {"ok": True}


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    ws_clients.add(ws)
    with state_lock:
        snapshot = list(rooms.values())
    await ws.send_json({"type": "snapshot", "rooms": snapshot})
    try:
        while True:
            await ws.receive_text()  # keepalive / ignore client messages
    except WebSocketDisconnect:
        pass
    finally:
        ws_clients.discard(ws)
