import os

from dotenv import load_dotenv

load_dotenv()

CROWDSEC_LAPI_URL = os.environ.get("CROWDSEC_LAPI_URL", "http://127.0.0.1:8078")
CROWDSEC_API_KEY = os.environ.get("CROWDSEC_API_KEY", "")
CROWDSEC_MACHINE_ID = os.environ.get("CROWDSEC_MACHINE_ID", "")
CROWDSEC_MACHINE_PASSWORD = os.environ.get("CROWDSEC_MACHINE_PASSWORD", "")
CROWDSEC_CONF_DIR = os.environ.get("CROWDSEC_CONF_DIR", "/opt/crowdsec/conf")
NPMPLUS_LOG_DIR = os.environ.get("NPMPLUS_LOG_DIR", "/opt/npmplus/nginx/logs")
