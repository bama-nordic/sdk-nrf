# Senior-Care Radar Monitor (Acconeer A121 + Wi-Fi)

Monitors a senior citizen in a single room using an **Acconeer A121** 60 GHz
radar on an **nRF54LM20 DK** (with an **nRF7002 EB-II** Wi-Fi companion). It
performs **room presence**, **breathing tracking**, and **fall detection**, and
streams results over **Wi-Fi/MQTT** to a Linux **care dashboard**.

See [`DESIGN.md`](DESIGN.md) for the full system design and Appendix A for the
Acconeer SDK integration. The Linux server + dashboard live in
[`server/`](server/).

> Status: Synthetic data path and the full Wi-Fi/MQTT/dashboard pipeline are
> complete. The A121 backend implements **presence**, **breathing** (via the
> Acconeer breathing reference app) and a custom **fall** heuristic — see
> `src/sensing_a121.c`. Fall thresholds are tunable and need on-device
> calibration for the chosen mounting (DESIGN.md §6.5).

## Build modes

The sensor backend is selected at build time (`CONFIG_RADAR_CARE_SENSOR_*`):

- **Synthetic (default):** simulated presence/breathing/fall — no sensor or
  Acconeer SDK needed. Use this to bring up the pipeline and the dashboard.
- **A121:** drives a real sensor via the Acconeer RSS libraries. Requires the
  external SDK (see below).

## Hardware

| Item | Notes |
|------|-------|
| nRF54LM20 DK (`nrf54lm20dk/nrf54lm20a/cpuapp`) | Host MCU |
| nRF7002 EB-II (`SHIELD=nrf7002eb2`) | Wi-Fi companion |
| Acconeer A121 EVK | Radar sensor on `spi00` + ENABLE/INTERRUPT GPIOs |

A121 wiring is in `boards/nrf54lm20dk_nrf54lm20a_cpuapp.overlay` (default pins;
verify against the DK header pinout — see DESIGN.md §4.2).

## Build and flash

Synthetic (no sensor, no SDK):

```bash
west build -p -b nrf54lm20dk/nrf54lm20a/cpuapp \
  -- -Dradar_senior_care_SHIELD="nrf7002eb2"
west flash
```

Real A121 sensor (requires the external SDK). Point `ACCONEER_A121_SDK_DIR` at
your extracted Cortex-M33 SDK; an environment variable is used because it
propagates to every sysbuild image (a plain `-DACCONEER_A121_SDK_DIR=...` is
*not* forwarded to the application image under sysbuild):

```bash
export ACCONEER_A121_SDK_DIR="$HOME/cortex_m33_gcc"   # adjust to your path
west build -p -b nrf54lm20dk/nrf54lm20a/cpuapp \
  -- -Dradar_senior_care_SHIELD="nrf7002eb2" \
     -DCONFIG_RADAR_CARE_SENSOR_A121=y
west flash
```

The A121 backend uses the Acconeer breathing reference app as a single radar
pipeline (presence + breathing) and layers a custom fall heuristic on top; it
links `libacconeer_a121.a` plus the presence/distance detector libraries.

Set Wi-Fi credentials and the broker in `prj.conf` (or an `EXTRA_CONF_FILE`):

```conf
CONFIG_WIFI_CREDENTIALS_STATIC_SSID="your_ssid"
CONFIG_WIFI_CREDENTIALS_STATIC_PASSWORD="your_password"
CONFIG_RADAR_CARE_BROKER_HOSTNAME="192.168.1.100"
```

> The Kconfig string-escaping caveat from `samples/wifi/arp_mqtt` applies to
> string options set on the command line.

## Secure MQTT (TLS + auth)

Plain MQTT (port 1883, anonymous) is the default for quick bring-up. For a
production-style secured connection, build with the `overlay-tls.conf` overlay,
which enables TLS, broker authentication, and the nRF Security / mbed TLS
backend (mirrors `samples/net/mqtt/tls-nrf54l-nrf70.conf`):

1. Generate the broker CA + server cert (and password file) on the server:

```bash
cd server/broker && ./gen_certs.sh room-device 'your-password'
```

2. Paste the contents of `server/broker/certs/ca.crt` into
   [`src/certs/ca_cert.h`](src/certs/ca_cert.h) (replacing the placeholder).

3. Build with the overlay (set the username/password/hostname to match your
   broker in `overlay-tls.conf`):

```bash
west build -p -b nrf54lm20dk/nrf54lm20a/cpuapp \
  -- -Dradar_senior_care_SHIELD="nrf7002eb2" \
     -DEXTRA_CONF_FILE="overlay-tls.conf"
```

The device then connects to `CONFIG_RADAR_CARE_BROKER_PORT` (8883) over TLS,
verifies the broker certificate against the embedded CA (peer-verify required),
sends `CONFIG_RADAR_CARE_MQTT_TLS_HOSTNAME` for SNI/CN matching, and
authenticates with `CONFIG_RADAR_CARE_MQTT_USERNAME`/`_PASSWORD`. The TLS
hostname must match a CN/SAN in the broker certificate.

> Username/password auth can also be set without TLS, but credentials would be
> sent in cleartext — the firmware logs a warning in that case. Always pair auth
> with TLS in production.

Start the matching secured broker + dashboard with
`docker compose -f docker-compose.yml -f docker-compose.tls.yml up --build`
(see [`server/README.md`](server/README.md)).

## MQTT topics

Published under `care/<site>/<room>/...` (room id defaults to `room_<MAC4>`):

| Topic | QoS | Notes |
|-------|-----|-------|
| `status` | 1 | Retained online/offline; LWT marks the device offline |
| `presence` | 0 | `{present, score, distance_m}` |
| `breathing` | 0 | `{valid, rate_bpm, confidence}` |
| `breathing/wave` | 0 | Downsampled waveform chunk |
| `fall` | 1 | `{state, confidence, distance_m}` |
| `cmd` (subscribe) | 1 | Server -> device commands; `{"ack_fall":true}` clears a latched fall |

## Configuration

Sample options under **Senior-care radar monitor** (`menuconfig`): site/room id,
sensor backend, broker, publish periods, waveform streaming, fall detection.

## Running the dashboard

See [`server/README.md`](server/README.md):

```bash
cd server && docker compose up --build
# open http://localhost:8000
```

## Source layout

| Path | Description |
|------|-------------|
| `src/main.c` | Wi-Fi bring-up, sensing -> MQTT wiring, connect/heartbeat loop |
| `src/sensing_synthetic.c` | Simulated sensor (Phase 0) |
| `src/sensing_a121.c` | A121 backend: presence + breathing (ref app) + fall heuristic |
| `src/acconeer_hal/` | Zephyr port of the Acconeer HAL (SPI/GPIO/IRQ/log/mem) |
| `src/net_mqtt.c` | MQTT telemetry (LWT, retained status, commands, TLS+auth) |
| `src/care_json.c` | Event JSON serialization |
| `src/certs/ca_cert.h` | Broker CA certificate for TLS (replace placeholder) |
| `overlay-tls.conf` | Enables MQTT-over-TLS + auth + crypto backend |
| `boards/` | A121 board overlay |
| `dts/bindings/` | `acconeer,a121` devicetree binding |
| `server/` | Linux MQTT broker (+TLS) + FastAPI ingestion + web dashboard |
