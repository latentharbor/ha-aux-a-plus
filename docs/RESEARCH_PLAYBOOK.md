# AUX A+ Investigation Playbook

Last updated: 2026-07-11

This document records the confirmed findings and repeatable investigation
steps for the AUX A+ Home Assistant integration. It intentionally excludes
account passwords, bearer tokens, cookies, device IDs, MAC addresses, local IP
addresses, and packet-capture contents.

## 1. Current Architecture

The integration uses three transports, in this order:

1. Local AUXLink LAN connection for state, temperature, and control.
2. AUX cloud MQTT for live state and control when LAN is unavailable.
3. AUX HTTP API for authentication, device metadata, energy data, and final
   control fallback.

Important behavior:

- LAN and MQTT connections are persistent rather than one-shot requests.
- Local state updates notify Home Assistant immediately.
- Repeated identical commands are suppressed to avoid multiple beeps.
- A short optimistic-state grace period prevents stale cloud updates from
  reverting a command that the air conditioner has already accepted.
- HTTP polling is not the primary live-state source.

Relevant files:

- `custom_components/aux_a_plus/api.py`: transport priority, authentication,
  fallback, caching, and state reconciliation.
- `custom_components/aux_a_plus/lan.py`: persistent local AUXLink protocol.
- `custom_components/aux_a_plus/mqtt.py`: persistent cloud MQTT/AUXLink
  protocol and packet encoding.
- `custom_components/aux_a_plus/climate.py`: Home Assistant climate mapping.
- `custom_components/aux_a_plus/sensor.py`: temperature and energy sensors.
- `tools/aux_lan_probe.py`: read-only local protocol probe.
- `tests/test_lan_protocol.py`: frame, encryption, and CRC tests.

## 2. Cloud Authentication

### Confirmed endpoints

- `GET /app/auth/getPubkey`
- `POST /app/auth/login/pwd`
- `GET /app/device_bindings?configId=...&getStatus=1`
- `POST /app/device/v2/control` for power commands
- `POST /app/device/control` for other controls
- `GET /app/daily/electricity?deviceId=...`

Base host:

```text
https://smarthome.aux-home.com
```

### Public-key rule

Fetch a new RSA public key immediately before password login. Reusing a saved
key can return:

```text
code: 64033
message: 公钥已过期
```

The password is RSA PKCS#1 v1.5 encrypted with the returned public key. Do not
hard-code a captured public key as the normal login path.

### Authentication troubleshooting

Check in this order:

1. System time and request timestamp.
2. Current app version and request headers.
3. A fresh public key was fetched for this login attempt.
4. Password login works in the official app, not only SMS login.
5. The bearer token was refreshed after an authentication failure.

Never commit a real password, token, cookie, phone number, or captured login
request.

## 3. Local AUXLink Protocol

### Network ports

```text
UDP 12414  discovery request
UDP 2415   discovery reply
TCP 12416  authenticated AUXLink session
```

The integration can use a configured local IP or discover the device by its
device ID/MAC. A DHCP reservation is strongly recommended.

### Session outline

1. Discover or connect to the module.
2. Obtain/configure the MAC and local passcode from cloud device metadata.
3. Authenticate the TCP session.
4. Derive the encrypted session key.
5. Keep the socket open.
6. Send heartbeat frames every few seconds.
7. Query small status for operating state.
8. Query large status for temperature data.
9. Send control frames and wait for acknowledgement.

The protocol uses encrypted framed packets with length and checksum/CRC
validation. Reuse the implementation in `lan.py`; do not rebuild packets with
ad hoc string manipulation.

### Power cycling

Power cycling was useful during reverse engineering because it forced fresh
discovery and authentication traffic. It is not required for normal Home
Assistant operation. The persistent client reconnects automatically after a
network interruption or device restart.

### Read-only probe

Use the bundled probe before modifying integration behavior:

```bash
python3 tools/aux_lan_probe.py \
  --host <AIR_CONDITIONER_IP> \
  --device-id <DEVICE_ID> \
  --passcode <LOCAL_PASSCODE>
```

Do not publish the passcode or full command output.

## 4. State and Control Findings

### Fan modes exposed by Home Assistant

```text
silent
low
medium
high
turbo
```

The raw AUX values are protocol-specific. Use the mapping tables in `mqtt.py`
as the source of truth; previous assumptions that a raw value represented
`auto` caused incorrect fan-mode behavior.

### Swing modes

```text
off
vertical
horizontal
both
```

Both vertical and horizontal swing are carried by the device protocol. Apple
Home may expose fewer controls than Home Assistant because Matter thermostat
and fan representations differ from the AUX feature model.

### Preventing state rollback

Symptoms previously observed:

- A 21.5 C setpoint briefly returned to 22 C.
- Off changed back to on.
- Controls caused several beeps.
- State oscillated between cloud and local values.

The working strategy is:

- Prefer acknowledged LAN state.
- Fall back to MQTT, then HTTP.
- Deduplicate identical commands sent close together.
- Preserve requested values during the reconciliation grace period.
- Clear optimistic values only after live state confirms them or the grace
  period expires.

When this regresses, inspect transport timestamps and pending-control state
before changing climate entity logic.

## 5. Temperature Findings

`environmentData.outdoorTemperature` and
`environmentData.outdoorHumidity` are outdoor/weather values. They are not the
air conditioner's indoor sensor readings and should not be exposed as indoor
temperature or humidity.

The confirmed indoor temperature comes from the large AUXLink status packet
received through LAN or MQTT. The climate entity and the independent
temperature sensor use that value.

Current entities:

```text
climate.aux
sensor.aux_indoor_temperature
```

No confirmed indoor humidity field has been found in the AUXLink data. Do not
create an indoor humidity entity until a packet field is validated against a
known reference measurement under changing conditions.

Validation rule for unknown fields:

1. Record official-app value and an independent thermometer/hygrometer.
2. Change room conditions enough to produce a visible delta.
3. Capture several packets before and after the change.
4. Confirm scale, offset, signedness, and update timing.
5. Reject fields that instead track outdoor weather or cached location data.

## 6. Energy Findings

Confirmed response shape:

```json
{
  "todayUseTime": "0.0",
  "todayElectricityConsumption": "0.00",
  "supportElectricCurve": false
}
```

The API provides daily runtime and daily energy, but no confirmed real-time
power value in watts.

Current entities:

```text
sensor.aux_today_runtime
sensor.aux_today_energy
sensor.aux_total_energy
```

`sensor.aux_total_energy` persists a cumulative total across midnight and Home
Assistant restarts. It accumulates positive changes from the daily-resetting
counter and is the correct entity for Home Assistant Energy and Matter energy
reporting.

Limitations:

- The cumulative total starts from the daily value present when the entity is
  first installed; older history cannot be reconstructed.
- Energy used while Home Assistant is offline across a daily reset may be
  partially unavailable because the AUX endpoint only returns the current day.
- Do not invent a real-time power sensor from sparse 0.01 kWh changes; it would
  be delayed and misleading.

## 7. Matter Hub and Apple Home

As investigated in July 2026:

- iOS 27 beta adds a device-level Power/Energy category in Apple Home.
- This is separate from Apple's utility-account electricity feature, which is
  limited to participating providers and regions.
- Matter energy uses `ElectricalPowerMeasurement` and
  `ElectricalEnergyMeasurement` clusters.
- Home Assistant Matter Hub v2.0.48 supports standalone HA energy sensors.
- Matter Hub does not currently attach electrical measurement clusters directly
  to its climate/thermostat endpoint.
- A standalone HA energy sensor is represented as a Matter electrical/solar
  power endpoint, so Apple Home displays it separately rather than inside the
  air-conditioner card.

Recommended test setup:

1. Confirm `sensor.aux_total_energy` is numeric, available, in kWh, has
   `device_class: energy`, and has `state_class: total_increasing`.
2. Create a separate Matter Hub bridge containing only
   `sensor.aux_total_energy`.
3. Pair that bridge to Apple Home.
4. Ensure both the iPhone and active Apple home hub run OS 27.
5. Run the air conditioner until the energy value changes.
6. Look for the Power/Energy category on the Home app's main screen, not in the
   thermostat details.

Controllers cache Matter endpoint descriptors during commissioning. If an
energy endpoint is added after the bridge was paired, force-sync first. If it
still does not appear, a separate newly commissioned test bridge is safer than
removing the main climate bridge and losing room assignments.

iOS 27 behavior was beta behavior at the time of investigation and may change
before or after the final release.

## 8. Packet Capture Playbooks

### HTTP/HTTPS capture

Stream-style proxy tools are sufficient for:

- Login and public-key requests.
- REST device metadata and control calls.
- Daily electricity requests.

They are insufficient for understanding raw MQTT, custom TCP, UDP discovery,
or local encrypted AUXLink traffic.

Export HAR files with response bodies. Before sharing or committing them,
remove:

- `Authorization`
- Cookies
- Phone/account identifiers
- Device IDs when not needed
- Tokens and MQTT credentials

### iPhone Remote Virtual Interface

Prerequisites:

- Xcode command-line tools selected.
- MobileDevice packages installed.
- iPhone trusted and connected by USB.
- `com.apple.rpmuxd` available.

Create the interface:

```bash
sudo rvictl -s <IPHONE_UDID>
```

Do not assume the interface is named `rvi0`. Find the actual name:

```bash
ifconfig -l | tr ' ' '\n' | rg '^rvi'
```

Capture local AUXLink traffic:

```bash
sudo tcpdump -i <RVI_INTERFACE> -B 4096 -s 0 -n \
  'host <AIR_CONDITIONER_IP> and tcp port 12416' \
  -w ~/Downloads/aux-lan.pcap
```

Remove the interface afterward:

```bash
sudo rvictl -x <IPHONE_UDID>
```

If `rvictl` reports success but `tcpdump` cannot find `rvi0`, inspect the
actual interface list before reinstalling Xcode components.

### Android APK investigation

Static analysis order:

1. Decode/decompile with JADX.
2. Search for hosts, ports, endpoint paths, MQTT topics, frame magic, AES/RSA,
   CRC functions, and `12414`/`12416`.
3. Trace callers from socket creation to authentication and packet encoding.
4. Compare constants and packet layouts with captures.
5. Use dynamic instrumentation only where obfuscation prevents validation.

Useful searches:

```bash
rg -n '12414|12416|smarthome|mqtt|AES|RSA|CRC|device_bindings|getPubkey' \
  <DECOMPILED_APK_DIRECTORY>
```

Static APK findings are hypotheses until confirmed against live packets or
device behavior.

## 9. Fast Diagnostic Checklist

### Login fails

1. Fetch a fresh public key.
2. Check timestamp and app headers.
3. Verify official-app password login.
4. Inspect response code without logging credentials.

### Control is slow

1. Confirm the configured local IP is reachable.
2. Check that TCP 12416 is open.
3. Confirm LAN authentication and heartbeat remain active.
4. Check whether logs show LAN -> MQTT -> HTTP fallback.
5. Reserve the device IP in DHCP.

### State flips back

1. Identify which transport supplied each update.
2. Check command deduplication.
3. Check pending-control reconciliation timing.
4. Verify acknowledgements before increasing polling frequency.

### Temperature is wrong or unavailable

1. Confirm a large AUXLink status packet is received.
2. Compare climate and standalone temperature entities.
3. Do not substitute `environmentData` weather values.
4. Check LAN first, then MQTT TLS/connectivity.

### Apple Home has no energy category

1. Confirm iPhone and active home hub are on OS 27.
2. Confirm Matter Hub version and endpoint inclusion.
3. Confirm the cumulative energy entity is numeric and changes.
4. Pair a new energy-only bridge to avoid cached endpoint descriptors.
5. Treat remaining failure as Apple beta/controller compatibility until the
   Matter endpoint is verified in Matter Hub diagnostics.

## 10. Verification Commands

Run protocol tests:

```bash
python3 -m unittest discover -s tests -v
```

Run syntax checks without generating repository cache files:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m py_compile \
  custom_components/aux_a_plus/*.py
```

Check repository cleanliness:

```bash
git status --short --ignored
```

Before publishing, verify that no captures, credentials, APK output, temporary
decompilation trees, or `__pycache__` directories are staged.
