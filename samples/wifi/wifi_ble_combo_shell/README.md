# Wi-Fi and Bluetooth LE combo shell

This sample combines the **Wi-Fi shell** and the **Bluetooth LE shell** in a
single application. It is based on the `samples/wifi/shell` sample, with the
Zephyr/NCS Bluetooth subsystem and the BLE shell layered on top so that both
Wi-Fi and BLE can be exercised at runtime from the same serial console.

It is intended for coexistence bring-up and testing on Nordic platforms that
have both a Wi-Fi solution and a Bluetooth LE controller:

- **nRF54LM20 DK** — uses the external **nRF7002 EB-II** shield for Wi-Fi.
- **nRF7120 DK** — has **integrated Wi-Fi**, so no shield is required.

## Features

- Full Wi-Fi shell (`wifi ...`, `net ...`) from the base sample.
- Bluetooth LE shell (`bt ...`, `gatt ...`, `l2cap ...`) with central + peripheral
  roles, privacy, SMP/pairing, EATT, extended/periodic advertising and sync,
  coded PHY, the HRS service, and LLPM.

The Bluetooth configuration added on top of the Wi-Fi shell is in `prj.conf`
under the *"Bluetooth LE (combo with Wi-Fi)"* section.

## Requirements

| Board                         | Wi-Fi hardware            | Notes                          |
| ----------------------------- | ------------------------- | ------------------------------ |
| `nrf54lm20dk/nrf54lm20a/cpuapp` | nRF7002 EB-II shield      | Shield is mounted on the DK    |
| `nrf7120dk/nrf7120/cpuapp`      | Integrated (nRF71 Wi-Fi)  | No shield needed               |

You also need a serial terminal (115200 8N1) connected to the DK's console UART.

## Building

Run the commands from the sample directory:

```bash
cd nrf/samples/wifi/wifi_ble_combo_shell
```

### nRF54LM20 DK (with nRF7002 EB-II shield)

The external nRF7002 EB-II shield provides the Wi-Fi device, so it must be
passed to the build with `SHIELD`:

```bash
west build -p -b nrf54lm20dk/nrf54lm20a/cpuapp --sysbuild -- -DSHIELD=nrf7002eb2
```

### nRF7120 DK (integrated Wi-Fi)

The nRF7120 has Wi-Fi on-chip, so no shield is used. The standalone nRF70 host
image is disabled in sysbuild:

```bash
west build -p -b nrf7120dk/nrf7120/cpuapp --sysbuild -- -DSB_CONFIG_WIFI_NRF70=n
```

### Flashing

```bash
west flash
```

## Running

1. Connect a serial terminal to the DK console UART at **115200 8N1**.
2. Reset the board. You should get a shell prompt (`uart:~$`).

### Bluetooth LE

The Bluetooth stack is started from the shell:

```text
uart:~$ bt init
uart:~$ bt advertise on
uart:~$ bt scan on
uart:~$ gatt ...
```

The default device name is `Nordic-host` (configurable, see
`CONFIG_BT_DEVICE_NAME` / `CONFIG_BT_DEVICE_NAME_DYNAMIC`).

### Wi-Fi

```text
uart:~$ wifi scan
uart:~$ wifi connect -s <SSID> -k <key_mgmt> -p <password>
uart:~$ wifi status
uart:~$ net iface
```

Because both subsystems share one console, you can run Wi-Fi and BLE commands
interleaved to test coexistence behaviour.

## Continuous integration

`sample.yaml` defines build-only test cases for both targets:

- `sample.54lm20dk.nrf7002eb2.wifi_ble_combo_shell` — nRF54LM20 DK + nRF7002 EB-II.
- `sample.nrf7120.wifi_ble_combo_shell` — nRF7120 DK (integrated Wi-Fi).

Both are marked `build_only`.
