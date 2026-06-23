# Senior-Care Radar Monitoring System — Design

Status: **Design approved — decisions D1–D5 confirmed; implementation starting at Phase 0.**

### Confirmed decisions
| # | Decision | Resolution |
|---|----------|------------|
| D1 | Acconeer SDK access | **Available**: A121 SDK **v1.13.0** (GCC, Cortex-M33) at `~/work/cortex_m33_gcc`. Used as an external, separately licensed dependency (not committed to this repo). See Appendix A. |
| D2 | A121 pin map | **Use defaults** (see §4.2 / board overlay). |
| D3 | Sensor mounting | **Confirmed**: wall ~1.4 m, tilted slightly down, covering the bed/chair zone. |
| D4 | Wireless protocol | **MQTT.** |
| D5 | Dashboard stack | **Custom FastAPI + React.** |

This document designs an end-to-end system that uses an **Acconeer A121** 60 GHz
pulsed-coherent radar connected to an **nRF54LM20 DK** (with an **nRF7002 EB-II**
Wi-Fi companion) to perform **room presence sensing**, **respiration (breathing)
tracking**, and **fall detection** for a senior citizen confined to a room. The
device streams results over Wi-Fi to a **Linux server** that runs a professional,
real-time **care dashboard**.

The Zephyr/NCS sample will live at `samples/wifi/radar_senior_care/`, i.e. at the
same level as `samples/wifi/shell/`.

---

## 1. Goals and scope

### 1.1 Functional goals
- **Room presence**: is the resident in the monitored room/zone, and roughly where.
- **Breathing tracking**: respiration rate (breaths/min) and a breathing waveform
  while the resident is stationary (resting, sleeping, sitting).
- **Fall detection**: detect a fall event and raise a high-priority alert.
- **Wireless telemetry**: push live state + events to a Linux server over Wi-Fi.
- **Professional dashboard**: real-time web dashboard with per-resident status,
  live breathing, presence, fall alerts with acknowledgement, and history.

### 1.2 Non-goals (initial version)
- Multi-person tracking / disambiguating multiple people in one room.
- Medical-grade certification (this is an assistive/monitoring aid, not a
  certified medical device).
- Cloud deployment, user accounts/RBAC, mobile apps (LAN/self-hosted first).
- Through-wall sensing; one sensor monitors one room/zone.

### 1.3 Success criteria
- Presence latency < ~1 s; breathing rate within a few breaths/min of ground
  truth for a stationary subject; fall alert within a few seconds with a low
  false-negative rate (false positives tolerated more than missed falls).
- Dashboard reflects state changes in < 1 s end-to-end on a LAN.

---

## 2. Critical feasibility notes (read first)

These shape the whole project and need confirmation before implementation.

1. **Acconeer software is proprietary.** The A121 is driven by Acconeer's
   **RSS (Radar System Software)**, delivered as a prebuilt **static library per
   CPU architecture** plus C source for HAL integration and reference
   applications, under the **Acconeer Software License Agreement**. None of this
   is present in this NCS workspace (`modules/`, `nrf/`, `zephyr/`). We must:
   - Obtain the **A121 SDK** (a.k.a. `acconeer_a121` / Exploration embedded SDK)
     including the RSS lib built for **ARM Cortex-M33** (the nRF54LM20 core).
   - Vendor it into the build as an out-of-tree blob/module (see §7.6). Its
     license is **not** compatible with upstreaming to sdk-nrf, so the sample
     will reference it as an external dependency rather than bundling it.
2. **Presence and breathing have official Acconeer reference algorithms**; we
   adapt them. **Fall detection does *not* have an official Acconeer reference
   application** — it must be **custom** and should be treated as experimental
   (see §6.5).
3. **A121 vs. modules.** Acconeer ships the bare A121 sensor on EVKs (e.g.
   XE121/XC120) and also pre-integrated modules (XM125 with an on-board
   nRF5340, XM126 with nRF5340). This project explicitly targets the **bare
   A121 sensor wired to the nRF54LM20 DK over SPI**, so we use the **A121 SDK +
   our own HAL**, not the module firmware.

> **Decision needed (D1):** Confirm access to the Acconeer A121 embedded SDK +
> RSS library for Cortex-M33, and acceptance that it is an external, separately
> licensed dependency.

---

## 3. High-level architecture

```
 ┌─────────────────────────────────────────────┐        Wi-Fi (2.4/5 GHz)
 │                Room device                    │        TCP/TLS
 │                                               │
 │  Acconeer A121  ──SPI + ENABLE + IRQ──►  nRF54LM20 DK ───────────────┐
 │  (60 GHz radar)                          (Cortex-M33 app)            │
 │                                          + nRF7002 EB-II (Wi-Fi)     │
 └─────────────────────────────────────────────┘                       │
                                                                        ▼
                                              ┌──────────────────────────────────┐
                                              │           Linux server            │
                                              │                                    │
                                              │  MQTT broker (Mosquitto)           │
                                              │      │ subscribe                   │
                                              │      ▼                             │
                                              │  Ingestion service (FastAPI)       │
                                              │      │           │                 │
                                              │      ▼           ▼                 │
                                              │  Time-series DB   WebSocket push   │
                                              │  (SQLite/TSDB)        │            │
                                              └───────────────────────┼───────────┘
                                                                       ▼
                                                            ┌────────────────────┐
                                                            │  Web dashboard      │
                                                            │ (browser, realtime) │
                                                            └────────────────────┘
```

The device is a **publisher of structured events**; the server **ingests,
stores, and fans out** to dashboards. MQTT decouples device(s) from the
dashboard and scales to many rooms/devices.

---

## 4. Hardware design

### 4.1 Components
| Item | Role |
|------|------|
| nRF54LM20 DK (`nrf54lm20dk/nrf54lm20a/cpuapp`) | Host MCU, app logic, connectivity |
| nRF7002 EB-II (`SHIELD=nrf7002eb2`) | Wi-Fi companion (host has no on-chip Wi-Fi) |
| Acconeer A121 EVK (XE121 + satellite, or XC120 connector board) | Radar sensor |

### 4.2 Bus / pin allocation (the key constraint)
From the board and shield definitions:
- **nRF7002 EB-II uses `nordic_expansion_spi` = `spi22`** plus the expansion
  header GPIOs, and **moves the console to UART30** (UART20 conflicts with the
  shield).
- Therefore the **A121 must use a different SPI instance.** Plan:
  - **A121 SPI:** use the high-speed **`spi00`** instance (its on-board flash
    `mx25r64` is `disabled` by default, freeing the bus), or another free
    SERIAL instance, routed to free header pins. A121 supports SPI up to
    ~50 MHz; the high-speed instance is preferred for frame throughput.
  - **A121 control GPIOs:** `ENABLE` (output) and `INTERRUPT`/`READY` (input,
    edge IRQ via a free GPIOTE) on free header pins.
  - **A121 SS/CS:** a GPIO CS owned by the SPI node.
- A **sample-specific board overlay** (`boards/nrf54lm20dk_nrf54lm20a_cpuapp.overlay`)
  will declare the A121 SPI device node, CS, ENABLE and IRQ GPIOs, and pinctrl,
  chosen so they do **not** overlap the EB-II expansion header pins.

> **Decision needed (D2):** Final pin map for A121 (SPI instance + SCLK/MOSI/
> MISO/CS, ENABLE, IRQ). Depends on the exact A121 EVK adapter and which DK
> header pins remain free with the EB-II mounted. To be finalized against the
> board pinout.

### 4.3 Power
- Bench/USB powered for the prototype. The A121 has its own enable/clock and
  low-power modes; Wi-Fi power-save (listen interval, as in `arp_mqtt`) reduces
  idle current. Battery operation is a later optimization (§13).

---

## 5. Firmware architecture (device)

### 5.1 Layered view
```
┌──────────────────────────────────────────────────────────────┐
│ Application / care logic                                        │
│  presence FSM │ breathing estimator │ fall detector (custom)    │
│  resident-state aggregator → telemetry events                   │
├──────────────────────────────────────────────────────────────┤
│ Sensing manager (scheduler, mode switching, calibration)        │
├──────────────────────────────────────────────────────────────┤
│ Acconeer detectors / ref apps                                   │
│  acc_detector_presence │ acc_ref_app_breathing │ sparse-IQ svc  │
├──────────────────────────────────────────────────────────────┤
│ Acconeer RSS (prebuilt static lib, Cortex-M33)                  │
├──────────────────────────────────────────────────────────────┤
│ Acconeer HAL integration (we write this, on Zephyr APIs)        │
│  SPI transfer │ GPIO enable │ IRQ wait │ time/us │ log │ mem     │
├──────────────────────────────────────────────────────────────┤
│ Connectivity & services (Zephyr/NCS)                            │
│  conn_mgr + Wi-Fi (nRF7002) │ MQTT client │ TLS │ shell │ NVS    │
└──────────────────────────────────────────────────────────────┘
```

### 5.2 HAL integration (the bridge we own)
Acconeer RSS calls a small set of integration functions; we implement them on
Zephyr:
- SPI full-duplex transfer → Zephyr `spi_transceive` (DMA-backed SPIM).
- Sensor `ENABLE` line → `gpio_pin_set_dt`.
- Sensor interrupt → GPIOTE interrupt + `k_sem`; RSS "wait for interrupt" blocks
  on the semaphore.
- Microsecond time → `k_cycle`/`k_uptime` and busy-wait helpers.
- Logging → `LOG_*`; heap → Zephyr heap or a dedicated `k_heap`.

### 5.3 Threading model
- **Radar thread** (high priority): owns the A121, runs the active detector,
  produces results into a message queue. Drives sensor timing.
- **Care-logic thread**: consumes radar results, runs the presence FSM,
  breathing estimator, and fall detector; emits telemetry events.
- **Connectivity/telemetry**: `conn_mgr` brings up Wi-Fi; an MQTT publish path
  (reusing patterns proven in `samples/wifi/arp_mqtt`) sends events. A
  heartbeat/status thread publishes liveness + RSSI + sensor health.
- **Shell** (UART30): runtime commands for calibration, mode, thresholds,
  and diagnostics.
- Communication between threads via `k_msgq`/`k_fifo`; shared state guarded by
  mutex. Bounded queues drop oldest non-critical data under backpressure; fall
  alerts use a reliable path (QoS 1).

### 5.4 Sensing strategy / mode switching
The three features have different ideal radar configs, so the sensing manager
**time-multiplexes modes**:
- **Presence mode** (default, always on): wide range gate covering the room/zone,
  moderate update rate; low power. Detects presence + coarse distance.
- **Breathing mode**: entered when presence is *stationary* for a few seconds;
  narrower range gate around the subject, higher coherent sensitivity, slower
  frame rate tuned for respiration (~0.1–0.5 Hz band).
- **Fall watch**: a fast-sampling path (sparse-IQ/velocity) that runs alongside
  presence to catch rapid motion transients (see §6.5). May share frames with
  presence mode rather than being a separate exclusive mode.

State machine (simplified):
```
        no presence
   ┌───────────────────────── EMPTY ◄───────────────┐
   │                            │ presence            │ no presence (timeout)
   ▼                            ▼                     │
 (alert: room empty?)        PRESENT ───stationary──► RESTING ──breathing──► (rate)
                               │  ▲                     │
                          motion│  │motion resumes      │ abnormal/none
                               ▼  │                     ▼
                            ACTIVE                 (breathing-anomaly flag)
                               │
                         fall signature
                               ▼
                             FALLEN ──► FALL ALERT (latched until ack)
```

### 5.5 On-device data/event model
Internal result → telemetry mapping:
- `presence`: {detected: bool, score, distance_m, zone}
- `breathing`: {valid: bool, rate_bpm, confidence, waveform_chunk[]}
- `motion`: {level, fast_motion: bool}
- `fall`: {state: none|suspected|confirmed, confidence, ts}
- `device`: {uptime, wifi_rssi, sensor_ok, fw_version, mode}

---

## 6. Algorithms

### 6.1 Room presence — Acconeer Presence Detector
Use `acc_detector_presence`. It separates **inter-frame** (slow, e.g. breathing/
torso) and **intra-frame** (fast, limbs) motion to robustly detect a stationary
or moving person across a configurable range. Output: presence bool + score +
distance. Configuration: range start/length to cover the zone, profile, sweeps/
frame, frame rate, detection thresholds. Supports a low-power "wake-up + track"
two-stage operation.

### 6.2 Breathing — Acconeer Breathing reference application
Use `acc_ref_app_breathing` (built on the presence detector + sparse IQ). It
gates on a present, **stationary** subject, isolates the chest-wall micro-motion,
and estimates **respiration rate** plus a waveform. We surface rate (bpm),
confidence, and a downsampled waveform for the dashboard. "No breathing
detected while present and stationary" is itself an important alert condition.

### 6.3 Mode coordination
Presence is the gate for breathing: only run/trust breathing while the presence
detector reports a stationary subject within the configured range. This avoids
spurious rates when the room is empty or the subject is moving.

### 6.4 Calibration & environment
- Sensor calibration at startup and on temperature drift (RSS provides hooks).
- A short **room-learning** step to set background/thresholds for the empty room,
  triggered from shell or first boot, stored in NVS.

### 6.5 Fall detection — CUSTOM (experimental)
No official Acconeer ref app exists. Proposed approach using A121 sparse-IQ /
distance-velocity data:

**Signal features**
- **Rapid range/energy change**: a sudden, large downward displacement of the
  dominant target plus a spike in fast (intra-frame) motion = candidate "impact".
- **Post-event stillness at low height**: after the transient, the subject
  becomes near-motionless and the dominant reflection sits **low** (close to
  floor) relative to the learned standing/sitting baseline.
- **Breathing-only signature**: post-fall, only respiration micro-motion remains
  (person on the floor, conscious) — or *no* motion (unconscious) → escalate.

**Decision logic (heuristic, tunable)**
```
if fast_motion_spike AND downward_range_jump within T_impact:
    candidate = suspected
if suspected AND (stillness for T_settle) AND (target_low for T_settle):
    fall = confirmed → latched alert (requires ack or recovery)
if movement returns to standing baseline before T_settle:
    cancel (got up) 
```
Parameters (`T_impact`, `T_settle`, thresholds, low-height band) are Kconfig +
shell-tunable. The detector reports **confidence**; the dashboard distinguishes
*suspected* vs *confirmed*.

**Honesty about limitations**: single-sensor radar fall detection is hard;
expect tuning per room geometry/mounting height. v1 targets "good recall with
acceptable false positives + easy dashboard acknowledgement", and is explicitly
**not** a certified medical alarm. A later version can add a small ML classifier
(features → tiny model) trained on labeled recordings.

**As implemented** (`src/sensing_a121.c`, `fall_step()`): the heuristic reuses
the presence result produced each frame by the breathing reference app, so no
separate sparse-IQ path is needed. `intra_presence_score` (fast motion) drives
impact detection (`FALL_IMPACT_INTRA`); `presence_distance` provides the
corroborating downward/sudden step (`FALL_DISTANCE_STEP_M`); sustained low
`intra` while still present over `CONFIG_RADAR_CARE_FALL_SETTLE_MS` confirms.
The confirmed state is latched until the subject is active again
(`FALL_RECOVER_INTRA`) or leaves. The absolute "low-height band" of the original
sketch is approximated by the distance-step signal because mapping range→height
needs per-mounting calibration; that refinement is left for Phase 5.

> **Decision needed (D3):** Sensor mounting (ceiling vs wall, height, tilt).
> This strongly affects the fall heuristic and the range configuration. Default
> assumption: **wall-mounted ~1.4 m, tilted slightly down, covering the bed/
> chair zone.**

---

## 7. Connectivity & protocol design

### 7.1 Transport
- Wi-Fi via nRF7002 EB-II + Zephyr Connection Manager (same building blocks as
  `samples/wifi/arp_mqtt`: `conn_mgr_all_if_up/connect`, credentials, dual-stack
  handling, the broker-family connectivity gate).
- **MQTT** to a broker on the Linux server. MQTT is the right fit: lightweight,
  pub/sub, retained state, Last-Will-and-Testament for offline detection, scales
  to many rooms, and decouples device from dashboard.

### 7.2 Topic structure
Per-device namespace keyed by a stable device/room id (derived from MAC, like
`arp_mqtt`’s client id, or configured room id):

```
care/<site>/<room_id>/status        (retained, LWT)   device online/offline + health
care/<site>/<room_id>/presence      presence state + distance/zone
care/<site>/<room_id>/breathing     rate + confidence (periodic)
care/<site>/<room_id>/breathing/wave  downsampled waveform chunks (higher rate)
care/<site>/<room_id>/motion        motion level / activity
care/<site>/<room_id>/fall          fall alerts (QoS 1)
care/<site>/<room_id>/cmd           (subscribe) server→device commands
```

- **Retained** `status` so a newly opened dashboard immediately sees each room.
- **LWT** on `status` marks a device offline if it drops (caregiver-visible).
- **QoS 0** for high-rate telemetry (presence/breathing/wave), **QoS 1** for
  `fall` and command/ack.

### 7.3 Payloads (JSON)
Human-readable JSON for the prototype (CBOR is a later size optimization).
Examples:
```json
// presence
{"ts": 1719200000, "present": true, "score": 3.4, "distance_m": 1.8, "zone": "bed"}
// breathing
{"ts": 1719200000, "valid": true, "rate_bpm": 14.2, "confidence": 0.81}
// breathing/wave  (downsampled, for the live chart)
{"ts": 1719200000, "fs": 10, "samples": [/* normalized floats */]}
// fall
{"ts": 1719200000, "state": "confirmed", "confidence": 0.7, "distance_m": 0.4}
// status (retained + LWT)
{"online": true, "fw": "1.0.0", "rssi": -57, "sensor_ok": true, "mode": "presence"}
```

### 7.4 Commands (server → device)
`care/.../cmd` (JSON): set thresholds, switch/force mode, trigger room-learning/
recalibration, acknowledge/clear a latched fall, request status. Device replies
on a `cmd/resp` topic or via updated `status`.

### 7.5 Security
- **Prototype/lab**: plain TCP MQTT on a trusted LAN (mirrors `arp_mqtt`).
- **Production**: **MQTT over TLS** (server cert verified by device + broker
  username/password auth), Wi-Fi WPA2/WPA3, broker ACLs per device. Health data
  is sensitive — TLS is required for any real deployment.
- **Implemented**: `CONFIG_RADAR_CARE_MQTT_TLS` switches the device between
  plain and TLS. With `overlay-tls.conf` the device connects on 8883, verifies
  the broker against an embedded CA (`src/certs/ca_cert.h`, peer-verify required,
  SNI/CN check) and authenticates with
  `CONFIG_RADAR_CARE_MQTT_USERNAME`/`_PASSWORD`. The crypto backend mirrors
  `samples/net/mqtt/tls-nrf54l-nrf70.conf` (nRF Security / mbed TLS). Server side:
  `server/broker/mosquitto-tls.conf` + `gen_certs.sh` (CA, server cert, password
  file) and `docker-compose.tls.yml`; the FastAPI app connects over TLS+auth via
  `MQTT_TLS`/`MQTT_CA_CERT`/`MQTT_USERNAME`/`MQTT_PASSWORD`. Mutual-TLS (client
  certs) and per-device ACLs remain future work.

> **Decision needed (D4):** Protocol confirmation. **Recommendation: MQTT**
> (reuses your proven `arp_mqtt` stack). Alternative considered: a direct
> **WebSocket**/TCP-JSON link to the server — simpler server, but loses broker
> decoupling, retained state, LWT, and multi-room scaling. MQTT recommended.

---

## 8. Server & dashboard design (Linux)

### 8.1 Recommended stack
A self-contained, self-hosted stack:
- **Broker**: Mosquitto.
- **Ingestion + API**: **Python FastAPI** service that subscribes to MQTT
  (`paho-mqtt`/`asyncio-mqtt`), validates/normalizes messages, persists them,
  applies alerting rules (e.g. fall, breathing-absent, device-offline), and
  **pushes updates to browsers over WebSocket**.
- **Storage**: start with **SQLite** (events + rolling history); upgrade path to
  TimescaleDB/InfluxDB for long-term, high-rate waveform history.
- **Frontend**: a modern single-page **dashboard** (React + a charting lib such
  as Recharts/Chart.js; or Svelte). Realtime via the WebSocket feed. Served by
  the same FastAPI app for simplicity.
- Packaged with **docker-compose** (broker + app + db) for one-command bring-up.

Rationale: Python keeps ingestion/alerting logic approachable and matches the
existing `proto/*_pb2.py` tooling already in this repo; FastAPI gives both REST
+ WebSocket; docker-compose makes it reproducible.

**Alternative (faster to stand up, less custom):** Mosquitto → Telegraf →
**InfluxDB → Grafana** dashboards, with Grafana alerting. Very "professional"
out of the box, but less tailored UX for fall acknowledgement and per-resident
cards. Offered as an option.

> **Decision needed (D5):** Dashboard stack — **FastAPI + React custom**
> (recommended, tailored care UX) vs **Grafana + InfluxDB** (quick, generic).

### 8.2 Dashboard UX (custom option)
- **Overview wall**: one card per room/resident — online/offline, present/away,
  current breathing rate, activity, and a prominent **fall banner** when active.
- **Resident detail**: live breathing waveform + rate trend, presence/zone
  timeline, activity over the day, event log.
- **Fall alert flow**: full-screen/red alert, audible cue, **acknowledge**
  button (sends `cmd` ack to device to clear the latch), escalation if not
  acknowledged within N seconds.
- **History & reports**: presence hours, breathing trends, fall history,
  exportable.
- **Admin**: register rooms/residents, set per-room thresholds, trigger
  recalibration.

### 8.3 Server data model
```
device(room_id PK, site, fw, last_seen, online, rssi, sensor_ok)
resident(id PK, name, room_id FK, notes)
event(id, room_id, ts, type[presence|breathing|motion|fall|status], payload JSON)
breathing_sample(room_id, ts, rate_bpm, confidence)
fall_alert(id, room_id, ts, state, confidence, acked_by, acked_ts)
```

### 8.4 Alerting
Server-side rules (configurable):
- **Fall confirmed** → immediate alert + escalation.
- **Breathing absent** while present + stationary for > T → alert.
- **Device offline** (LWT/last_seen) → maintenance alert.
- Optional integrations later: email/SMS/push/Home Assistant webhook.

---

## 9. Proposed sample layout

```
samples/wifi/radar_senior_care/
├── DESIGN.md                      # this document
├── README.md                      # build/run instructions (after design sign-off)
├── CMakeLists.txt
├── Kconfig                        # sample-specific options (thresholds, ids, modes)
├── Kconfig.sysbuild
├── sysbuild.conf                  # nRF7002 Wi-Fi via sysbuild
├── prj.conf                       # Wi-Fi + MQTT + sensor + shell config
├── sample.yaml
├── boards/
│   └── nrf54lm20dk_nrf54lm20a_cpuapp.overlay   # A121 SPI + ENABLE + IRQ pins
├── src/
│   ├── main.c                     # init, conn_mgr, thread bring-up
│   ├── radar/                     # HAL integration + sensing manager
│   ├── care/                      # presence/breathing/fall logic
│   └── net/                       # MQTT telemetry + commands
└── server/                        # Linux server + dashboard (separate from FW build)
    ├── docker-compose.yml
    ├── broker/                    # mosquitto config
    ├── app/                       # FastAPI ingestion + WebSocket + REST
    └── web/                       # dashboard frontend
```
(The Acconeer SDK/RSS is referenced as an **external module**, not vendored in
the tree — see §2 and §7.6.)

### 9.1 Build & flash (planned)
```bash
west build -p -b nrf54lm20dk/nrf54lm20a/cpuapp \
  -- -Dradar_senior_care_SHIELD="nrf7002eb2"
west flash
```
Wi-Fi/MQTT/string config via `prj.conf` or `EXTRA_CONF_FILE`, with the Kconfig
string-escaping caveat documented for `arp_mqtt` applying here too.

---

## 10. Configuration (Kconfig sketch)
- Identity: `RADAR_CARE_SITE_ID`, `RADAR_CARE_ROOM_ID` (default derived from MAC).
- Broker: hostname/port, TLS on/off (mirrors `arp_mqtt`).
- Presence: range start/length, sensitivity/threshold, frame rate.
- Breathing: range window, enable, publish period, waveform rate.
- Fall: enable, impact/settle timing, low-height band, confidence threshold.
- Telemetry: publish intervals, QoS, waveform streaming on/off.
- Power: Wi-Fi listen interval (reuse the `arp_mqtt` pattern), radar low-power.

---

## 11. Testing & validation
- **HAL bring-up**: SPI loopback / A121 version read; IRQ + ENABLE toggling.
- **Presence**: walk-in/walk-out, sit still, empty room — score/threshold tuning.
- **Breathing**: compare rate vs. a manual count / reference belt for a seated
  and supine subject; verify gating when moving/empty.
- **Fall**: scripted fall scenarios vs. sit-down/lie-down (must not false-alarm
  on controlled lie-down where possible); measure recall and false-positive rate;
  tune per mounting.
- **Connectivity**: reconnect, broker down, Wi-Fi drop → LWT offline; fall alert
  delivery under QoS 1.
- **End-to-end latency**: sensor event → dashboard render.
- **Soak**: 24–72 h stability, memory, RPU recovery, sensor recalibration drift.

---

## 12. Phased implementation roadmap
1. **Phase 0 — Foundations** ✅: sample skeleton, board overlay, Wi-Fi + MQTT
   telemetry with *synthetic* data (no sensor) → proves the pipe + dashboard.
2. **Phase 1 — Sensor bring-up** ✅: Acconeer HAL on Zephyr, RSS init,
   calibration + measurement loop.
3. **Phase 2 — Presence** ✅: presence detector → live presence/distance on dash.
4. **Phase 3 — Breathing** ✅: breathing reference app → rate on dash. (The ref
   app's public result does not expose a raw waveform, so `breathing/wave` is
   only emitted by the synthetic backend.)
5. **Phase 4 — Fall (custom)** ✅ (implemented, needs tuning): impact-spike →
   sustained-stillness heuristic on the presence scores/distance; suspected →
   confirmed → cleared, with alert + ack flow. Thresholds need per-room
   calibration; not medical-grade.
6. **Phase 5 — Hardening** (in progress): server→device **fall-ack handling**
   is done (`care/<site>/<room>/cmd` → `{"ack_fall":true}` clears the latch via
   `sensing_ack_fall()`); multi-room works via the per-room topic tree.
   **MQTT TLS + broker auth** are done (`overlay-tls.conf`, embedded CA,
   username/password; broker `mosquitto-tls.conf` + `gen_certs.sh`; see §7.5).
   Remaining: Wi-Fi power-save, calibration persistence, per-device ACLs/mTLS.

---

## 13. Risks & open decisions
| # | Risk / decision | Default / recommendation |
|---|------------------|--------------------------|
| D1 | Acconeer RSS/SDK access + licensing | Required external dependency; confirm availability for Cortex-M33 |
| D2 | A121 pin map vs. EB-II header usage | Use free SPI (e.g. `spi00`) + 2 GPIOs; finalize against pinout |
| D3 | Sensor mounting geometry | Wall ~1.4 m, tilted down, covers bed/chair |
| D4 | Wireless protocol | **MQTT** (reuse arp_mqtt) |
| D5 | Dashboard stack | **FastAPI + React** custom (alt: Grafana+InfluxDB) |
| — | Fall detection accuracy | Experimental; tune per room; not medical-grade |
| — | Single-person assumption | One resident per room in v1 |
| — | Privacy/security of health data | TLS + ACLs for any non-lab use |

---

## 14. References (to confirm/obtain)
- Acconeer A121 SDK, RSS user guide, Presence Detector & Breathing reference
  application docs, and HAL integration guide (Acconeer developer site).
- NCS `samples/wifi/arp_mqtt` (Wi-Fi + MQTT building blocks, reused here).
- NCS `samples/wifi/shell` (Wi-Fi bring-up patterns; sibling sample).
- Zephyr SPI, GPIO/GPIOTE, Connection Manager, MQTT, TLS credentials APIs.
- nRF54LM20 DK board files; nRF7002 EB-II shield overlay.

---

### Summary of decisions needed from you
- **D1** Acconeer SDK/RSS access (blocker for sensor phases).
- **D2** A121 pin assignment (can default and refine on hardware).
- **D3** Sensor mounting assumption (affects fall + ranges).
- **D4** Protocol = MQTT? (recommended)
- **D5** Dashboard = custom FastAPI+React vs Grafana+InfluxDB?

All decisions are confirmed; implementation proceeds per the roadmap starting at
**Phase 0** (sample skeleton + board overlay + Wi-Fi/MQTT pipe + dashboard shell
using synthetic data), then the sensor is layered in per Appendix A.

---

## Appendix A — Acconeer A121 SDK integration (concrete)

SDK located at **`~/work/cortex_m33_gcc`**, version **`a121-v1.13.0`**, GCC /
Cortex-M33. It is proprietary (Acconeer Software License) and **must not be
committed** into sdk-nrf; it is referenced from its external location at build
time.

### A.1 What we link vs. compile
- **Link (prebuilt static libs, `rss/lib/`):**
  - `libacconeer_a121.a` — core RSS (sensor control, processing service).
  - `libacc_detector_presence_a121.a` — presence detector.
  - `libacc_detector_distance_a121.a` — distance detector (optional, useful for
    the fall heuristic’s range tracking).
- **Compile from source (shipped as `.c`):**
  - `algorithms/acc_algorithm.c` — DSP helpers used by reference apps.
  - `use_cases/reference_apps/ref_app_breathing.c` — breathing estimator
    (built on the presence detector). *(There is no breathing static lib.)*
  - Optionally `ref_app_smart_presence.c` for low-power presence.
- **Include dirs:** `rss/include/`, `integration/`, `algorithms/`,
  `use_cases/reference_apps/`.

### A.2 HAL we implement on Zephyr (the only sensor glue we own)
Mirror the STM32 reference (`integration/acc_hal_integration_stm32cube_xe121_single_sensor.c`,
`acc_integration_stm32.c`, `acc_integration_log.c`) onto Zephyr:

- `acc_hal_rss_integration_get_implementation()` → returns `acc_hal_a121_t`:
  - `max_spi_transfer_size`, `mem_alloc`/`mem_free` (Zephyr heap),
  - `transfer` (8-bit SPI full-duplex via `spi_transceive`) and/or
    `optimization.transfer16` (preferred, 16-bit DMA SPI),
  - `log` → Zephyr `LOG`.
- `acc_hal_integration_sensor_supply_on/off(id)` → supply/enable GPIO (if wired).
- `acc_hal_integration_sensor_enable/disable(id)` → A121 `ENABLE` GPIO; clear any
  pending interrupt on enable.
- `acc_hal_integration_wait_for_sensor_interrupt(id, timeout_ms)` → block on a
  `k_sem` given by the A121 interrupt GPIOTE ISR; return false on timeout.
- `acc_hal_integration_sensor_count()` → `1`.
- `acc_integration_sleep_us/ms`, `mem_alloc/calloc/free`, `get_time()` (free-
  running ms, wrapping at 2^32), `acc_integration_log(...)`.

SPI requirement: `ACC_HAL_SPI_TRANSFER_SIZE_REQUIRED` = 16 bytes minimum; A121
buffers are ≥4-byte aligned — fits Zephyr SPIM with DMA.

### A.3 Build wiring (CMake)
- A CMake cache var **`ACCONEER_A121_SDK_DIR`** (default `$ENV{HOME}/cortex_m33_gcc`)
  locates the SDK. A Kconfig **`RADAR_CARE_HAVE_ACCONEER_SDK`** selects between:
  - **Sensor mode** (SDK present): add include dirs, `target_link_libraries` the
    three `.a` files, compile `acc_algorithm.c` + `ref_app_breathing.c` + our HAL
    port + real sensing manager.
  - **Synthetic mode** (Phase 0 / SDK absent): compile a stub sensing manager
    that emits simulated presence/breathing/fall events so the Wi-Fi→MQTT→
    dashboard pipeline can be built and tested without hardware.
- The presence/distance libs are float; ensure the app is built with the FPU
  (Cortex-M33 hard-float, already the nRF54L default) and matching ABI.

### A.4 Reference reading in the SDK (for implementers)
- `examples/getting_started/` — minimal RSS init + processing loop.
- `examples/processing/` — sparse IQ / processing service (basis for fall).
- `use_cases/reference_apps/ref_app_breathing_main.c` — how breathing is driven.
- `rss/include/acc_detector_presence.h`, `acc_sensor.h`, `acc_processing.h`,
  `acc_rss_a121.h`, `acc_hal_definitions_a121.h`.
