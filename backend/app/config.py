from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_URL = "sqlite:///" + str(BASE_DIR / "aegis.db")
SECRET_KEY = "aegis-dev-secret-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 12
AGENT_TOKEN_PREFIX = "aegis_"
CORS_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]
