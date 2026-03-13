import os

from dotenv import load_dotenv

load_dotenv()

CROWDSEC_LAPI_URL = os.environ.get("CROWDSEC_LAPI_URL", "http://127.0.0.1:8078")
CROWDSEC_API_KEY = os.environ.get("CROWDSEC_API_KEY", "")
CROWDSEC_MACHINE_ID = os.environ.get("CROWDSEC_MACHINE_ID", "")
CROWDSEC_MACHINE_PASSWORD = os.environ.get("CROWDSEC_MACHINE_PASSWORD", "")
CROWDSEC_CONF_DIR = os.environ.get("CROWDSEC_CONF_DIR", "/opt/crowdsec/conf")
NPMPLUS_LOG_DIR = os.environ.get("NPMPLUS_LOG_DIR", "/opt/npmplus/nginx/logs")

# AI Provider settings (optional — set AI_PROVIDER to enable AI log analysis)
AI_PROVIDER = os.environ.get("AI_PROVIDER", "")        # "anthropic" or "openai"
AI_API_KEY = os.environ.get("AI_API_KEY", "")
AI_API_URL = os.environ.get("AI_API_URL", "")           # Override for Ollama etc.
AI_MODEL = os.environ.get("AI_MODEL", "")

# Trusted IPs — excluded from AI analysis to prevent self-banning
# Auto-detection of public IP is also done at analysis time
_raw_trusted = os.environ.get("TRUSTED_IPS", "")
TRUSTED_IPS = {ip.strip() for ip in _raw_trusted.split(",") if ip.strip()}
