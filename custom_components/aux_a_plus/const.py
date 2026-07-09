"""Constants for AUX A+ Air Conditioner."""

DOMAIN = "aux_a_plus"
BASE_URL = "https://smarthome.aux-home.com"
APP_VERSION = "7.2.4"
USER_AGENT = "AUXSmartHome/7.2.4 (iPhone; iOS 27.0; Scale/3.00)"
OS_VERSION = "iOS 27.0"

CONF_CONFIG_ID = "config_id"
CONF_DEVICE_ID = "device_id"
CONF_PUBLIC_KEY = "public_key_base64"

DEFAULT_NAME = "AUX A+ AC"
DEFAULT_CONFIG_ID = "B7E65BB2-F02E-4EAD-B7BA-1C50FCE62882"

# Public key observed in AUX Smart Home/A+ 7.2.4 password-login traffic.
DEFAULT_PUBLIC_KEY_BASE64 = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUeg5SIayXPwxsIVaPoIcP4oFXs"
    "M5x4ktc6WE/thIf/IrZj1V7mYAiEIDWO/vDgfaNny6bfJk67y+IGO3y6igJoK5i"
    "SZlZzBNXbYXsdvztdpRbI4g9L0k2E8sjqsrMGyzvM7BEMehu8uEKo8UILIaDSx22"
    "V8Xg5hk8IjqJlofl5wIDAQAB"
)
