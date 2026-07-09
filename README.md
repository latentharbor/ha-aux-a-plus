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
- Fan modes: low, medium, high, quiet, auto, turbo, medium low, medium high
- Up/down swing modes
- Cloud polling through the AUX A+ API

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

## Repository layout

```text
custom_components/
  aux_a_plus/
    __init__.py
    api.py
    climate.py
    config_flow.py
    const.py
    manifest.json
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
- Do not commit your phone number, password, token, cookies, or packet-capture files to GitHub.

## Debug logging

Add this to `configuration.yaml` if you need debug logs:

```yaml
logger:
  default: warning
  logs:
    custom_components.aux_a_plus: debug
```
