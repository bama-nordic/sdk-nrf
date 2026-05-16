# ARP MQTT (Wi-Fi)

Wi-Fi MQTT client sample for Nordic nRF70 Series development kits. The device connects to a Wi-Fi access point, establishes a plain-TCP MQTT session with a broker over IPv4 or IPv6, subscribes to incoming topics, and publishes messages on demand through the Zephyr shell.

## Overview

This sample demonstrates end-to-end connectivity from an nRF7002-based board to an MQTT broker over Wi-Fi:

1. **Wi-Fi** — Static credentials are compiled in; the Connection Manager brings the interface up. IPv4 uses DHCP; IPv6 uses Router Advertisements (SLAAC) when the access point advertises it.
2. **MQTT** — A non-TLS MQTT 3.1.1 client connects to the configured broker (IPv4, IPv6, or DNS hostname), subscribes to a topic filter, and maintains the session with automatic reconnect.
3. **Shell** — The `mqtt_pub` command publishes a user-supplied payload to a topic under `nrf/pub/`.

Incoming messages on the subscribe filter are logged with topic and payload. Publish operations from the shell are silent on success (no log or shell output).

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
       │  Subscribe: nrf/sub/#                                                      │
       │  Publish (shell): nrf/pub/<topic>                                          │
       └────────────────────────────────────────────────────────────────────────────┘
```

### Startup sequence

1. `main()` enables all interfaces and requests connection through the Connection Manager.
2. `wait_for_network()` blocks until L4 connectivity is available (IPv4 DHCP bound; from `net_sample_common`).
3. `try_mqtt_connect()` resolves the broker to IPv4 or IPv6, opens a TCP socket, sends `CONNECT`, and waits for `CONNACK`.
4. On success, the client subscribes to the configured topic filter (default `nrf/sub/#`).
5. The main loop calls `mqtt_process()` to handle keepalive, incoming publishes, and disconnects. On failure, the client disconnects, waits, and reconnects.

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
[inf] arp_mqtt: MQTT session up (broker [192.168.29.133]:1883, subscribe nrf/sub/#)
[inf] arp_mqtt: MQTT session up (broker [2001:db8::1]:1883, subscribe nrf/sub/#)
```

### MQTT topics

| Direction | Topic pattern | Default | Notes |
|-----------|---------------|---------|--------|
| Subscribe | `nrf/sub/#` | `CONFIG_ARP_MQTT_SUB_TOPIC` | Multi-level wildcard; receives all topics under `nrf/sub/` |
| Publish | `nrf/pub/<topic>` | `CONFIG_ARP_MQTT_PUB_TOPIC_PREFIX` + shell argument | `<topic>` must not contain `/` |

MQTT wildcards use `#` (multi-level) and `+` (single-level), not `*`.

### Shell command

```text
mqtt_pub <topic> <value>
```

Example:

```text
uart:~$ mqtt_pub test 102.75
```

This publishes the string `102.75` to topic `nrf/pub/test`. The command returns silently on success; errors are printed to the shell.

Maximum payload length is `CONFIG_ARP_MQTT_APP_BUFFER_SIZE - 1` (default 1023 bytes).

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
CONFIG_ARP_MQTT_SUB_TOPIC="nrf/sub/#"
CONFIG_ARP_MQTT_PUB_TOPIC_PREFIX="nrf/pub/"
CONFIG_ARP_MQTT_APP_BUFFER_SIZE=1024
```

Each device derives its MQTT client ID at connect time as `nrf_` plus the four least significant hex digits of the Wi-Fi MAC (for example `nrf_E5F6`). The same firmware hex can be flashed to every DUT; IDs remain unique per board. The assigned ID is logged once at connect (`MQTT client ID nrf_XXXX`).

| Variable | Description |
|----------|-------------|
| `CONFIG_HW_ID_LIBRARY` / `CONFIG_HW_ID_LIBRARY_SOURCE_NET_MAC` | Required for MAC-based client ID (enabled in `prj.conf`) |
| `CONFIG_ARP_MQTT_SUB_TOPIC` | Topic filter for subscriptions |
| `CONFIG_ARP_MQTT_PUB_TOPIC_PREFIX` | Prefix for shell publish topics |
| `CONFIG_ARP_MQTT_APP_BUFFER_SIZE` | MQTT RX/TX and payload buffer size (bytes) |

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
[inf] arp_mqtt: MQTT session up (broker [192.168.x.x]:1883, subscribe nrf/sub/#)
[inf] arp_mqtt: MQTT subscribed to nrf/sub/#
```

## Testing with Mosquitto

On a host on the same network as the broker:

**Subscribe to device publishes (IPv4):**

```bash
mosquitto_sub -h <broker_ipv4> -p 1883 -t 'nrf/pub/#' -v
```

**Subscribe using IPv6:**

```bash
mosquitto_sub -h <broker_ipv6> -p 1883 -t 'nrf/pub/#' -v
```

**Publish to the device from another MQTT client:**

When another host publishes to a topic under `nrf/sub/`, the nRF7002 DK prints the topic and payload on the serial console. Examples:

```bash
mosquitto_pub -h <broker_ip> -p 1883 -t 'nrf/sub/Delay' -m '1122.90'
mosquitto_pub -h <broker_ip> -p 1883 -t 'nrf/sub/RTT' -m '145ms'
```

On the DK UART you will see log lines like:

```text
[00:02:47.010,192] <inf> arp_mqtt: MQTT RX topic=nrf/sub/Delay payload=1122.90
[00:03:07.782,073] <inf> arp_mqtt: MQTT RX topic=nrf/sub/RTT payload=145ms
```

The timestamp prefix comes from the Zephyr logging subsystem; the message format is `MQTT RX topic=<topic> payload=<payload>`.

**Trigger a publish from the DK shell:**

```text
uart:~$ mqtt_pub test 102.75
```

The host running `mosquitto_sub` should show:

```text
nrf/pub/test 102.75
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
- **ARP MQTT Wi-Fi client** — broker, topics, client ID, buffer size, IPv6 preference
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
| Subscribe works, publish does not | Topic spelling; `mosquitto_sub` on `nrf/pub/#` |
| Payload truncated | Increase `CONFIG_ARP_MQTT_APP_BUFFER_SIZE` |

Enable more logging if needed:

```conf
CONFIG_LOG_DEFAULT_LEVEL=4
```

## Project structure

| Path | Description |
|------|-------------|
| `src/main.c` | Wi-Fi bring-up, MQTT client (IPv4/IPv6), shell `mqtt_pub` |
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
