# AUX A+ for Home Assistant

Home Assistant custom integration for AUX / 奥克斯 A+ air conditioners using the newer AUX Smart Home API (`smarthome.aux-home.com`).

This integration was built for newer AUX A+ modules that use:

- `POST /app/auth/login/pwd` for account login
- `GET /app/device_bindings?configId=...&getStatus=1` for device status
- `POST /app/device/v2/control` for power on/off
- `POST /app/device/control` for mode, target temperature, fan speed, and swing controls

## Features

- UI configuration flow: no YAML required
- Power on/off
- HVAC modes: Auto, Cool, Dry, Heat, Fan only
- Target temperature
- Real indoor temperature from the air conditioner's AUXLink status packet
- Separate Home Assistant indoor temperature sensor entity
- Daily runtime, daily energy, and persistent cumulative energy sensors
- Fan modes: quiet, low, medium, high, turbo
- Up/down and left/right swing modes
- Direct encrypted AUXLink LAN state and control
- Automatic cloud MQTT and HTTP fallback when LAN is unavailable
- Optimistic state reconciliation to prevent stale cloud status rollbacks
- Persistent LAN or MQTT state connection for immediate updates
- HTTP polling only for authentication, metadata, and energy data

The cumulative energy sensor is suitable for Home Assistant's Energy dashboard
and Matter energy reporting because it does not reset when the daily AUX counter
returns to zero at midnight.

## Installation with HACS custom repository

1. Upload this repository to GitHub.
2. In Home Assistant, open **HACS**.
3. Open the menu in the top-right corner and choose **Custom repositories**.
4. Add your GitHub repository URL.
5. Select category **Integration**.
6. Install **AUX A+** from HACS.
7. Restart Home Assistant.
8. Go to **Settings → Devices & services → Add integration**.
9. Search for **AUX A+** and log in with your AUX A+ phone number and password.
10. Open the integration's **Configure** dialog and enter the air conditioner's
    local IP address to enable reliable LAN control. Reserve this address in
    your router's DHCP settings.

## Repository layout

```text
custom_components/
  aux_a_plus/
    __init__.py
    api.py
    climate.py
    config_flow.py
    const.py
    lan.py
    manifest.json
    mqtt.py
    strings.json
    translations/
      zh-Hans.json
hacs.json
README.md
```

## Notes

- This is not the older BroadLink/AC Freedom MQTT integration.
- This is not the older `old_device_control` AUX component.
- If login fails, verify that you can log into the AUX A+ app with a password, not only SMS verification.
- The integration matches the device by MAC when the Linux ARP cache contains a
  newer DHCP address. A DHCP reservation is still recommended for predictable
  LAN startup after Home Assistant restarts.
- Do not commit your phone number, password, token, cookies, or packet-capture files to GitHub.

## Debug logging

Add this to `configuration.yaml` if you need debug logs:

```yaml
logger:
  default: warning
  logs:
    custom_components.aux_a_plus: debug
```
