import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


DATABASE_URL = _env(
    "AEGIS_DATABASE_URL",
    "sqlite:///" + str(BASE_DIR / "aegis.db"),
)
SECRET_KEY = _env("AEGIS_SECRET_KEY", "aegis-dev-secret-change-in-production")
EAT_KEY = _env("AEGIS_EAT_KEY", "aegis-dev-eat-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(_env("AEGIS_TOKEN_TTL_MINUTES", str(60 * 12)))
AGENT_TOKEN_PREFIX = "aegis_"
CORS_ORIGINS = [
    origin.strip()
    for origin in _env(
        "AEGIS_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if origin.strip()
]

AEGIS_ROLE = _env("AEGIS_ROLE", "all")
BROKER_URL = _env("AEGIS_BROKER_URL", "")
TOOL_URL = _env("AEGIS_TOOL_URL", "")
INTERNAL_GATEWAY_TOKEN = _env("AEGIS_INTERNAL_GATEWAY_TOKEN", "")
INTERNAL_TOOL_TOKEN = _env("AEGIS_INTERNAL_TOOL_TOKEN", "")
CRM_SECRET = _env("AEGIS_CRM_SECRET", "aegis-internal-crm-secret-do-not-export")
EAT_TTL_SECONDS = int(_env("AEGIS_EAT_TTL_SECONDS", "10"))
REMOTE_TIMEOUT_SECONDS = float(_env("AEGIS_REMOTE_TIMEOUT_SECONDS", "3"))
