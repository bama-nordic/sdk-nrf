# Senior-Care Dashboard (Linux server)

Real-time care dashboard for the [radar_senior_care](../README.md) device(s):
an MQTT broker, a FastAPI ingestion service (MQTT -> SQLite + WebSocket), and a
self-contained web dashboard.

```
device(s) --MQTT--> Mosquitto --> FastAPI (ingest + alerting) --WebSocket--> browser
                                       |
                                       +--> SQLite (events, fall alerts)
```

## Quick start (Docker)

```bash
cd server
docker compose up --build
```

Then open <http://localhost:8000>.

Point the device at this host's IP as the MQTT broker
(`CONFIG_RADAR_CARE_BROKER_HOSTNAME`, port 1883). With no devices yet, you can
simulate one:

```bash
mosquitto_pub -h localhost -t care/site1/room_demo/status   -m '{"online":true}' -r
mosquitto_pub -h localhost -t care/site1/room_demo/presence -m '{"present":true,"score":3.1,"distance_m":1.8}'
mosquitto_pub -h localhost -t care/site1/room_demo/breathing -m '{"valid":true,"rate_bpm":14,"confidence":0.8}'
mosquitto_pub -h localhost -t care/site1/room_demo/fall -m '{"state":"confirmed","confidence":0.8,"distance_m":0.4}' -q 1
```

The device firmware in **synthetic mode** generates this traffic automatically.

## Run without Docker (dev)

```bash
# Broker (any MQTT broker works)
mosquitto -p 1883

cd server/app
pip install -r requirements.txt
MQTT_HOST=localhost uvicorn main:app --host 0.0.0.0 --port 8000
```

## Secure MQTT (TLS + auth)

The default broker is anonymous plaintext (port 1883) for quick bring-up. To run
the broker with TLS and username/password authentication (port 8883):

```bash
# 1. Generate a demo CA + broker cert + password file (lab use only)
cd server/broker
./gen_certs.sh room-device 'your-password'      # writes certs/ and passwd

# 2. Bring up the TLS broker + dashboard (app connects over TLS+auth)
cd ..
docker compose -f docker-compose.yml -f docker-compose.tls.yml up --build
```

`gen_certs.sh` issues a server certificate valid for `care-broker`, `localhost`,
`mosquitto`, and `127.0.0.1`. Paste `broker/certs/ca.crt` into the firmware's
`src/certs/ca_cert.h`, set the device's `overlay-tls.conf` username/password to
match the password file, and point it at port 8883.

The app reads these environment variables (set by `docker-compose.tls.yml`):

| Variable | Purpose |
|----------|---------|
| `MQTT_TLS` | `1` to connect over TLS |
| `MQTT_CA_CERT` | Path to the broker CA certificate (PEM) |
| `MQTT_USERNAME` / `MQTT_PASSWORD` | Broker credentials |
| `MQTT_PORT` | `8883` for TLS |

Verify the secured broker with the CLI:

```bash
mosquitto_pub -h 127.0.0.1 -p 8883 --cafile broker/certs/ca.crt \
  -u room-device -P 'your-password' -t care/site1/room1/status -m '{"online":true}' -r
```

Generated certificates and the password file are git-ignored — never commit them.

## Components

| Path | Description |
|------|-------------|
| `docker-compose.yml` | Mosquitto + dashboard app (plaintext) |
| `docker-compose.tls.yml` | Overlay: TLS + auth broker (port 8883) |
| `broker/mosquitto.conf` | Broker config (anonymous LAN) |
| `broker/mosquitto-tls.conf` | TLS + password-auth broker config |
| `broker/gen_certs.sh` | Generates demo CA/server certs + password file |
| `app/main.py` | MQTT ingest (TLS/auth aware), SQLite, REST + WebSocket |
| `web/index.html` | Dashboard (presence, breathing, fall alerts) |

## REST API

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/rooms` | Current state of all rooms |
| GET | `/api/rooms/{room}/history?limit=N` | Recent events |
| POST | `/api/rooms/{room}/ack` | Acknowledge a fall (sends `cmd` to device) |
| WS | `/ws` | Realtime snapshot + updates |

## Production notes

This scaffold targets a trusted LAN. Before any real deployment, enable MQTT
**TLS** + per-device ACLs, authenticate the dashboard, and review data
retention — see [`../DESIGN.md`](../DESIGN.md) §7.5 and §13. Fall detection is
experimental and is **not** a certified medical alarm.
