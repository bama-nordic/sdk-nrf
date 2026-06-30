# ARP MQTT (Wi-Fi)

Wi-Fi MQTT client sample for Nordic nRF70 Series development kits. The device connects to a Wi-Fi access point, establishes a plain-TCP MQTT session with a broker over IPv4 or IPv6, subscribes to incoming topics, and publishes messages on demand through the Zephyr shell.

## Overview

This sample demonstrates end-to-end connectivity from an nRF7002-based board to an MQTT broker over Wi-Fi:

1. **Wi-Fi** — Static credentials are compiled in; the Connection Manager brings the interface up. IPv4 uses DHCP; IPv6 uses Router Advertisements (SLAAC) when the access point advertises it.
2. **MQTT** — A non-TLS MQTT 3.1.1 client connects to the configured broker (IPv4, IPv6, or DNS hostname), subscribes to a topic filter, and maintains the session with automatic reconnect.
3. **Shell** — The `mqtt_pub` command publishes a user-supplied payload to a configurable topic (empty prefix by default, so the topic is the shell argument as-is).
4. **Periodic RTT report** — A background thread periodically pings the broker (ICMP echo) and publishes the measured round-trip delays to the `sensor` topic.
5. **Wi-Fi power save (optional)** — When enabled, the sample programs a configurable listen interval and switches the station to listen-interval based power-save wakeup before associating. Disabled by default.

Incoming messages on the subscribe filter are logged with topic and payload. Every outgoing publish has the device MAC address prepended to the payload (for example `aa:bb:cc:dd:ee:ff <payload>`) and is logged as `MQTT TX topic=<topic> payload=<...>`.

## Supported hardware

| Board | Target |
|-------|--------|
| [nRF7002 DK](https://www.nordicsemi.com/Products/Development-hardware/nRF7002-DK) | `nrf7002dk/nrf5340/cpuapp` |

Other nRF70 Wi-Fi boards may work with appropriate `prj.conf` tuning; this sample is validated on the nRF7002 DK.

## Requirements

- [nRF Connect SDK](https://developer.nordicsemi.com/nRF_Connect_SDK/doc/latest/nrf/index.html) (NCS) installed and `west` available in your environment
- nRF7002 DK (application core programmed; network core image is built via sysbuild)
- Wi-Fi access point (2.4 GHz or 5 GHz, depending on AP and regulatory settings) with **IPv4 DHCP** and, for IPv6 broker use, **IPv6 Router Advertisements** enabled
- MQTT broker reachable from the Wi-Fi network (for example [Eclipse Mosquitto](https://mosquitto.org/)) on plain TCP port **1883**
- Serial terminal for the application core UART (115200 8N1 typical)

The broker and the DK must be on the same IP network (or routable). The sample does not use TLS; use only on trusted lab networks.

## How it works

```
┌─────────────┐   Wi-Fi (DHCPv4 + IPv6 RA)   ┌──────────────┐   TCP :1883    ┌─────────────┐
│  nRF7002 DK │ ───────────────────────────► │ Access point │ ─────────────► │ MQTT broker │
│  (this app) │                              │              │  IPv4 / IPv6   │ (Mosquitto) │
└─────────────┘                              └──────────────┘                └─────────────┘
       │                                                                            ▲
       │  Subscribe: actuator                                                      │
       │  Publish (shell): <topic>  (payload has device MAC prepended)                                          │
       │  Publish (periodic RTT): sensor  e.g. "aa:bb:cc:dd:ee:ff 5ms,102ms,4ms"                      │
       └────────────────────────────────────────────────────────────────────────────┘
```

### Startup sequence

1. `main()` first waits a random 1–50 s (`random_sleep()`, to stagger multiple devices), then brings all interfaces up through the Connection Manager. Autonomous threads (the periodic RTT publisher) block on an `app_ready` semaphore until this point, so they stay idle during the delay instead of logging "MQTT not connected".
2. If `CONFIG_ARP_MQTT_WIFI_LISTEN_INTERVAL=y`, `wifi_set_listen_interval()` programs the Wi-Fi power-save listen interval and switches the wakeup mode to listen interval **before** the connection is initiated (see [Wi-Fi power-save listen interval](#wi-fi-power-save-listen-interval)).
3. `main()` requests the connection, and `wait_for_network()` blocks until L4 connectivity is available (from `net_sample_common`).
4. `try_mqtt_connect()` resolves the broker, waits until the broker's IP family has L4 connectivity (see note below), opens a TCP socket, sends `CONNECT`, and waits for `CONNACK`.

> Note: with dual-stack enabled, `NET_EVENT_L4_CONNECTED` fires as soon as *either* family is up — IPv6 (link-local/RA) is usually ready well before IPv4 DHCP completes. Connecting to an IPv4 broker in that window fails with `-EINVAL` because no IPv4 source address exists yet. The sample tracks the per-family conn_mgr events (`NET_EVENT_L4_IPV4_CONNECTED` / `NET_EVENT_L4_IPV6_CONNECTED`) and only attempts the broker connect once the broker's family is actually up, avoiding those transient failures.
5. On success, the client subscribes to the configured topic filter (default `actuator`).
6. The main loop calls `mqtt_process()` to handle keepalive, incoming publishes, and disconnects. On failure, the client disconnects, waits, and reconnects.
7. A separate background thread (`rtt_report_thread`) wakes every `CONFIG_ARP_MQTT_RTT_PERIOD_SECONDS` and, while the MQTT session is up, pings the broker and publishes the result to `sensor` (see [Periodic RTT report](#periodic-rtt-report)).

### IPv4 and IPv6

The sample builds with **dual-stack** networking enabled (`CONFIG_NET_IPV4` and `CONFIG_NET_IPV6`).

| Layer | IPv4 | IPv6 |
|-------|------|------|
| Wi-Fi interface | DHCPv4 from AP | SLAAC via Router Advertisements (when AP provides IPv6) |
| Broker address | Literal `192.168.x.x` or DNS A record | Literal `2001:db8::1` or DNS AAAA record |
| MQTT transport | TCP over IPv4 | TCP over IPv6 |

Broker resolution in `broker_addr_setup()`:

1. If `CONFIG_ARP_MQTT_BROKER_HOSTNAME` is a literal IPv4 or IPv6 address, that address is used directly.
2. Otherwise DNS (`getaddrinfo`) is used. With both families enabled, **IPv4 is preferred** unless `CONFIG_ARP_MQTT_BROKER_PREFER_IPV6=y`.

The connect log shows the resolved address, for example:

```text
[inf] arp_mqtt: MQTT session up (broker [192.168.29.133]:1883, subscribe actuator)
[inf] arp_mqtt: MQTT session up (broker [2001:db8::1]:1883, subscribe actuator)
```

### MQTT topics

| Direction | Topic | Default | Notes |
|-----------|-------|---------|--------|
| Subscribe | `actuator` | `CONFIG_ARP_MQTT_SUB_TOPIC` | Exact topic by default; append `/#` for a multi-level wildcard. Only present when `CONFIG_ARP_MQTT_ENABLE_SUB=y` (default) |
| Publish | `<topic>` | `CONFIG_ARP_MQTT_PUB_TOPIC_PREFIX` (empty) + shell argument | `<topic>` must not contain `/` |
| Publish | `sensor` | Fixed (`RTT_TOPIC`) | Periodic broker round-trip delays |

Every published payload is prefixed with the device MAC address, for example `aa:bb:cc:dd:ee:ff 5ms,102ms,4ms`.

MQTT wildcards use `#` (multi-level) and `+` (single-level), not `*`.

### Shell command

```text
mqtt_pub <topic> <value>
```

Example:

```text
uart:~$ mqtt_pub test 102.75
```

With the default empty prefix this publishes to topic `test`, and the payload is sent with the device MAC prepended, e.g. `aa:bb:cc:dd:ee:ff 102.75`. The DK logs it as `MQTT TX topic=test payload=aa:bb:cc:dd:ee:ff 102.75`; errors are printed to the shell.

Maximum payload length is `CONFIG_ARP_MQTT_APP_BUFFER_SIZE - 1` (default 1023 bytes).

### Periodic RTT report

A dedicated background thread (`rtt_report_thread`) periodically measures the network round-trip time to the MQTT broker and publishes the result to the `sensor` topic. This autonomous publishing is controlled by `CONFIG_ARP_MQTT_PERIODIC_PUB` (**enabled by default**); set it to `n` to compile out the thread entirely, leaving only the shell `mqtt_pub` command for publishing.

### Publish-only build (disabling subscriptions)

The subscribe/receive path is controlled by `CONFIG_ARP_MQTT_ENABLE_SUB` (**enabled by default**). Set it to `n` for a publish-only build:

```conf
CONFIG_ARP_MQTT_ENABLE_SUB=n
```

When disabled:

- The sample never subscribes, and `CONFIG_ARP_MQTT_SUB_TOPIC` is unavailable. The session log reads `publish-only` instead of `subscribe <topic>`.
- The client connects with a **clean session**, so the broker discards any subscription left over from a previous (persistent) session under the same client ID. As a result the broker delivers nothing to this device: it does not respond to any publisher.
- Should an in-flight or retained message still arrive, its payload is drained from the socket and discarded (the device does not act on it), so the connection is not dropped.

Publishing is unaffected: the shell `mqtt_pub` command and, if `CONFIG_ARP_MQTT_PERIODIC_PUB=y`, the periodic RTT thread keep working.

Each cycle:

1. The thread sleeps for `CONFIG_ARP_MQTT_RTT_PERIOD_SECONDS` (default **60**).
2. If the MQTT session is **not** connected, the cycle is skipped and a warning is logged.
3. Otherwise it sends **3 ICMP echo requests** (pings) to the resolved broker address (IPv4 or IPv6), one per second, each with a 1-second timeout.
4. The per-ping round-trip delays are concatenated into a comma-separated string and published to `sensor` with QoS 0 (with the device MAC prepended, as for all publishes).

Payload format:

- Successful pings are reported as integer milliseconds with an `ms` suffix, for example `5ms,102ms,4ms`.
- A ping that fails or times out is reported as `Nan` in its position, for example `5ms,Nan,4ms`.
- If ICMP cannot be initialized at all, every entry is `Nan` (`Nan,Nan,Nan`).

On the DK UART, each published report is logged by the publish path:

```text
[inf] arp_mqtt: MQTT TX topic=sensor payload=aa:bb:cc:dd:ee:ff 5ms,102ms,4ms
```

> Note: round-trip times below 1 ms are reported as `0ms` because the delay is measured at millisecond resolution.

### Wi-Fi power-save listen interval

This optional feature lets the station sleep longer between wake-ups to save power. It is **disabled by default**.

When `CONFIG_ARP_MQTT_WIFI_LISTEN_INTERVAL=y`, after the Wi-Fi interface is brought up but **before** the connection is initiated, the sample calls `wifi_set_listen_interval()`, which issues two `net_mgmt(NET_REQUEST_WIFI_PS, ...)` requests on the Wi-Fi station interface:

1. `WIFI_PS_PARAM_LISTEN_INTERVAL` — sets the listen interval to `CONFIG_ARP_MQTT_WIFI_LISTEN_INTERVAL_VALUE` (default **10**).
2. `WIFI_PS_PARAM_WAKEUP_MODE` — sets the power-save wakeup mode to `WIFI_PS_WAKEUP_MODE_LISTEN_INTERVAL`.

On success the DK logs:

```text
[inf] arp_mqtt: Wi-Fi power save: listen interval wakeup, 10 beacon intervals
```

> Important: the listen interval is advertised to the AP in the association request, so the Wi-Fi stack only accepts `WIFI_PS_PARAM_LISTEN_INTERVAL` while the station is **not** associated. Setting it after the connection is established fails with `-ENOTSUP` and `fail_reason = WIFI_PS_PARAM_FAIL_DEVICE_CONNECTED`. That is why the sample configures it before connecting.

> Note: the listen interval value is expressed in **beacon intervals**, not seconds. The wall-clock sleep time depends on the AP beacon interval (a typical 100 TU beacon is ~102.4 ms, so a value of 10 is roughly 1 s). A larger listen interval saves more power but increases downlink latency, because buffered frames at the AP are only delivered when the station wakes.

## Configuration

All sample-specific options are in **`prj.conf`**. Optional MQTT settings can also be changed under **ARP MQTT Wi-Fi client** in `menuconfig`.

### Wi-Fi credentials

Set your access point SSID and password in `prj.conf`:

```conf
CONFIG_WIFI_CREDENTIALS_STATIC_SSID="your_wifi_ssid"
CONFIG_WIFI_CREDENTIALS_STATIC_PASSWORD="your_wifi_password"
```

| Variable | Description |
|----------|-------------|
| `CONFIG_WIFI_CREDENTIALS_STATIC_SSID` | Wi-Fi network name (SSID) |
| `CONFIG_WIFI_CREDENTIALS_STATIC_PASSWORD` | Wi-Fi passphrase (WPA2/WPA3 as supported by the stack) |

Wi-Fi credentials are stored in flash as part of the firmware image. Do not commit production passwords to version control.

### MQTT broker

**IPv4 broker (default):**

```conf
CONFIG_ARP_MQTT_BROKER_HOSTNAME="192.168.1.100"
CONFIG_ARP_MQTT_BROKER_PORT=1883
```

**IPv6 broker:**

```conf
CONFIG_ARP_MQTT_BROKER_HOSTNAME="2001:db8::100"
CONFIG_ARP_MQTT_BROKER_PORT=1883
```

**Hostname with DNS (dual-stack):**

```conf
CONFIG_ARP_MQTT_BROKER_HOSTNAME="mqtt.example.com"
# Optional: prefer AAAA record when both A and AAAA exist
# CONFIG_ARP_MQTT_BROKER_PREFER_IPV6=y
```

| Variable | Description |
|----------|-------------|
| `CONFIG_ARP_MQTT_BROKER_HOSTNAME` | Broker IPv4 address, IPv6 address, or hostname |
| `CONFIG_ARP_MQTT_BROKER_PORT` | Broker TCP port (default **1883**) |
| `CONFIG_ARP_MQTT_BROKER_PREFER_IPV6` | Prefer IPv6 when DNS returns both A and AAAA records |

IPv6 literals in `prj.conf` use standard notation **without** square brackets (for example `fe80::1`, not `[fe80::1]`).

### Networking (IPv4 / IPv6)

These options are set in `prj.conf` for dual-stack operation:

```conf
CONFIG_NET_IPV4=y
CONFIG_NET_IPV6=y
CONFIG_NET_IPV6_ND=y
CONFIG_NET_DHCPV4=y
CONFIG_NET_IF_UNICAST_IPV6_ADDR_COUNT=2
CONFIG_NET_IF_MCAST_IPV6_ADDR_COUNT=5
```

| Variable | Description |
|----------|-------------|
| `CONFIG_NET_IPV4` | Enable IPv4 |
| `CONFIG_NET_IPV6` | Enable IPv6 |
| `CONFIG_NET_IPV6_ND` | IPv6 Neighbor Discovery (required for IPv6 on Wi-Fi) |
| `CONFIG_NET_DHCPV4` | Obtain IPv4 address from the AP |
| `CONFIG_NET_IF_UNICAST_IPV6_ADDR_COUNT` | Number of IPv6 unicast addresses on the interface |

To disable IPv6 and use IPv4 only, set `CONFIG_NET_IPV6=n` in `prj.conf`.

### MQTT client and topics (optional in `prj.conf`)

Defaults are defined in `Kconfig`; override in `prj.conf` if needed:

```conf
CONFIG_ARP_MQTT_ENABLE_SUB=y
CONFIG_ARP_MQTT_SUB_TOPIC="actuator"
CONFIG_ARP_MQTT_PUB_TOPIC_PREFIX=""
CONFIG_ARP_MQTT_APP_BUFFER_SIZE=1024
CONFIG_ARP_MQTT_PERIODIC_PUB=y
CONFIG_ARP_MQTT_RTT_PERIOD_SECONDS=60
```

Each device derives its MQTT client ID at connect time as `nrf_` plus the four least significant hex digits of the Wi-Fi MAC (for example `nrf_E5F6`). The same firmware hex can be flashed to every DUT; IDs remain unique per board. The assigned ID is logged once at connect (`MQTT client ID nrf_XXXX`).

| Variable | Description |
|----------|-------------|
| `CONFIG_HW_ID_LIBRARY` / `CONFIG_HW_ID_LIBRARY_SOURCE_NET_MAC` | Required for MAC-based client ID (enabled in `prj.conf`) |
| `CONFIG_ARP_MQTT_ENABLE_SUB` | Compile in the MQTT subscribe/receive path (default **y**); set to `n` for a publish-only build that does not respond to any publisher |
| `CONFIG_ARP_MQTT_SUB_TOPIC` | Topic filter for subscriptions (only available when `CONFIG_ARP_MQTT_ENABLE_SUB=y`) |
| `CONFIG_ARP_MQTT_PUB_TOPIC_PREFIX` | Prefix for shell publish topics |
| `CONFIG_ARP_MQTT_APP_BUFFER_SIZE` | MQTT RX/TX and payload buffer size (bytes) |
| `CONFIG_ARP_MQTT_PERIODIC_PUB` | Enable the autonomous periodic RTT publish thread (default **y**) |
| `CONFIG_ARP_MQTT_RTT_PERIOD_SECONDS` | Interval, in seconds, between periodic broker RTT reports published to `sensor` (default 60, range 1–86400; requires `CONFIG_ARP_MQTT_PERIODIC_PUB`) |

#### Changing the subscribe topic (`CONFIG_ARP_MQTT_SUB_TOPIC`)

`CONFIG_ARP_MQTT_SUB_TOPIC` is a Kconfig **string**, so its value must include literal double quotes. There are three ways to set it; the simplest is to edit `prj.conf`.

**Option 1 — `prj.conf` (recommended):**

```conf
CONFIG_ARP_MQTT_SUB_TOPIC="nrf/device1/#"
```

**Option 2 — a per-device Kconfig fragment.** Useful when flashing several DUTs with different topics from the same source tree. Create `device1.conf`:

```conf
CONFIG_ARP_MQTT_SUB_TOPIC="nrf/device1/#"
```

Then build with:

```bash
west build -p -b nrf54lm20dk/nrf54lm20a/cpuapp -- \
  -Darp_mqtt_SHIELD="nrf7002eb2" \
  -DEXTRA_CONF_FILE="device1.conf"
```

**Option 3 — a one-off command-line override.** The double quotes must survive both the shell and CMake, so they have to be escaped; otherwise Kconfig receives an unquoted value and reports `malformed string literal in assignment to ARP_MQTT_SUB_TOPIC ... Assignment ignored`:

```bash
west build -p -b nrf54lm20dk/nrf54lm20a/cpuapp -- \
  -Darp_mqtt_SHIELD="nrf7002eb2" \
  "-DCONFIG_ARP_MQTT_SUB_TOPIC=\"nrf/device1/#\""
```

Equivalently, single-quote the whole argument so the inner double quotes stay literal:

```bash
'-DCONFIG_ARP_MQTT_SUB_TOPIC="nrf/device1/#"'
```

> Note: this escaping is only needed for Kconfig **string** symbols. Non-string symbols such as `-Darp_mqtt_SHIELD=...` (a CMake variable) or boolean/integer Kconfig options are not quoted and do not need escaping.

Verify the value was applied after building:

```bash
grep ARP_MQTT_SUB_TOPIC build/arp_mqtt/zephyr/.config
# CONFIG_ARP_MQTT_SUB_TOPIC="nrf/device1/#"
```

### Wi-Fi power-save listen interval (optional)

Disabled by default. To enable listen-interval based power-save wakeup, add to `prj.conf`:

```conf
CONFIG_ARP_MQTT_WIFI_LISTEN_INTERVAL=y
CONFIG_ARP_MQTT_WIFI_LISTEN_INTERVAL_VALUE=10
```

| Variable | Description |
|----------|-------------|
| `CONFIG_ARP_MQTT_WIFI_LISTEN_INTERVAL` | Enable configuring the Wi-Fi power-save listen interval and listen-interval wakeup mode after the network is up (default **n**) |
| `CONFIG_ARP_MQTT_WIFI_LISTEN_INTERVAL_VALUE` | Listen interval in beacon intervals (default **10**, range 0–65535) |

See [Wi-Fi power-save listen interval](#wi-fi-power-save-listen-interval) for behavior details.

### Configuration checklist

Before building, confirm:

- [ ] Wi-Fi SSID and password match your AP
- [ ] AP provides IPv4 DHCP (required for initial `wait_for_network()`)
- [ ] For IPv6 broker: AP advertises IPv6; broker has a global or LAN IPv6 address
- [ ] Broker hostname/IP and port are correct and reachable from the Wi-Fi subnet
- [ ] Broker listens on the target address family (`0.0.0.0` and/or `::` for Mosquitto)
- [ ] No firewall blocks TCP port **1883** from the DK to the broker
- [ ] Mosquitto (or other broker) allows anonymous connect, or configure auth separately (this sample does not send username/password to MQTT)

## Build and flash

From the NCS workspace root (or any directory with `west` configured):

```bash
cd nrf/samples/wifi/arp_mqtt
west build -b nrf7002dk/nrf5340/cpuapp
west flash
```

To perform a pristine build:

```bash
west build -b nrf7002dk/nrf5340/cpuapp -p always
```

Connect to the serial console (for example `minicom`, `picocom`, or the nRF Connect Serial Terminal). After Wi-Fi association and DHCP, you should see logs similar to:

```text
[inf] arp_mqtt: ARP MQTT (Wi-Fi) client starting
[inf] arp_mqtt: MQTT session up (broker [192.168.x.x]:1883, subscribe actuator)
[inf] arp_mqtt: MQTT subscribed to actuator
```

## Testing with Mosquitto

On a host on the same network as the broker:

**Subscribe to device publishes (IPv4):**

```bash
mosquitto_sub -h <broker_ipv4> -p 1883 -t '#' -v
```

**Subscribe using IPv6:**

```bash
mosquitto_sub -h <broker_ipv6> -p 1883 -t '#' -v
```

**Watch the periodic RTT reports:**

```bash
mosquitto_sub -h <broker_ip> -p 1883 -t 'sensor' -v
```

Approximately every `CONFIG_ARP_MQTT_RTT_PERIOD_SECONDS` (default 60), a line appears with the broker ping delays:

```text
sensor aa:bb:cc:dd:ee:ff 5ms,102ms,4ms
sensor aa:bb:cc:dd:ee:ff 6ms,Nan,5ms
```

**Publish to the device from another MQTT client:**

When another host publishes to the subscribed topic `actuator`, the nRF7002 DK prints the topic and payload on the serial console. Examples:

```bash
mosquitto_pub -h <broker_ip> -p 1883 -t 'actuator' -m '1122.90'
mosquitto_pub -h <broker_ip> -p 1883 -t 'actuator' -m '145ms'
```

On the DK UART you will see log lines like:

```text
[00:02:47.010,192] <inf> arp_mqtt: MQTT RX topic=actuator payload=1122.90
[00:03:07.782,073] <inf> arp_mqtt: MQTT RX topic=actuator payload=145ms
```

The timestamp prefix comes from the Zephyr logging subsystem; the message format is `MQTT RX topic=<topic> payload=<payload>`.

**Trigger a publish from the DK shell:**

```text
uart:~$ mqtt_pub test 102.75
```

The host running `mosquitto_sub` should show (note the MAC-prefixed payload):

```text
test aa:bb:cc:dd:ee:ff 102.75
```

### Mosquitto dual-stack notes

Ensure the broker accepts connections on the address family you use. In `mosquitto.conf`, for example:

```conf
listener 1883 0.0.0.0
listener 1883 ::
allow_anonymous true
```

Restart Mosquitto after configuration changes.

## Using menuconfig

For interactive editing of Kconfig options:

```bash
west build -t menuconfig
```

Relevant menus:

- **Wi-Fi credentials** — static SSID/password (if not only in `prj.conf`)
- **ARP MQTT Wi-Fi client** — broker, topics, buffer size, IPv6 preference, RTT report period, Wi-Fi listen interval
- **Networking** — IPv4/IPv6 options

Save and exit, then rebuild.

## Troubleshooting

| Symptom | Things to check |
|---------|------------------|
| Wi-Fi does not connect | SSID/password; AP band (2.4 vs 5 GHz); signal; `wifi status` in shell if available |
| No IPv4 address | DHCP on AP; `CONFIG_NET_DHCPV4=y`; wait after associate |
| IPv6 broker unreachable | AP IPv6 enabled; DK has IPv6 address (`net iface` / shell); broker listening on `::` |
| `Broker connect failed` | Broker IP/port; ping broker from another host; correct address family (v4 vs v6) |
| DNS resolves wrong family | Set literal IP in `CONFIG_ARP_MQTT_BROKER_HOSTNAME` or use `CONFIG_ARP_MQTT_BROKER_PREFER_IPV6` |
| `mqtt_pub`: `MQTT not connected` | Wait for CONNACK log; broker must accept the client ID |
| Subscribe works, publish does not | Topic spelling; `mosquitto_sub` on `#` (publishes have no prefix) |
| Payload truncated | Increase `CONFIG_ARP_MQTT_APP_BUFFER_SIZE` |
| `sensor` shows `Nan` | Broker/host blocks ICMP echo; check that the broker host replies to `ping`; verify the broker is reachable on the resolved address family |
| No `sensor` messages | MQTT not connected when the timer fires (look for "RTT report skipped" warning); confirm `CONFIG_ARP_MQTT_RTT_PERIOD_SECONDS` |

Enable more logging if needed:

```conf
CONFIG_LOG_DEFAULT_LEVEL=4
```

## Project structure

| Path | Description |
|------|-------------|
| `src/main.c` | Wi-Fi bring-up, MQTT client (IPv4/IPv6), shell `mqtt_pub`, periodic broker ping/RTT publish |
| `prj.conf` | Application and sample configuration |
| `Kconfig` | Sample-specific Kconfig symbols |
| `CMakeLists.txt` | Build definition |
| `sysbuild.conf` | Enables nRF70 Wi-Fi in sysbuild |

## Limitations

- Plain TCP only (no TLS, no WebSocket)
- No MQTT username/password in the current application code
- `wait_for_network()` waits for IPv4 L4 connectivity; IPv6-only networks without DHCPv4 are not supported
- Publish topic cannot contain `/` (single path segment only)

## License

SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
