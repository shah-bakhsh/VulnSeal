"""
VulnSeal Core Configuration
Manages environment variables, security boundaries, and service settings.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from project root
ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
env_path = ROOT_DIR / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)
else:
    load_dotenv()

class Settings:
    APP_NAME: str = "VulnSeal"
    APP_VERSION: str = "1.0.0"
    APP_TAGLINE: str = "Find. Fix. Prove."
    APP_ENV: str = os.getenv("APP_ENV", "development")
    DEBUG: bool = APP_ENV.lower() == "development"

    # Server Ports
    PORT: int = int(os.getenv("PORT", 8000))
    FRONTEND_PORT: int = int(os.getenv("FRONTEND_PORT", 3000))

    # Host & URLs
    BACKEND_URL: str = os.getenv("BACKEND_URL", f"http://localhost:{PORT}")
    FRONTEND_URL: str = os.getenv("FRONTEND_URL", f"http://localhost:{FRONTEND_PORT}")

    # Database URL: default SQLite file in project root
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{ROOT_DIR / 'vulnseal.db'}")

    # AI Model Providers
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")

    # Strict Demo Lab Exception Settings
    DEMO_TARGET_HOSTS: tuple = ("localhost", "127.0.0.1")
    DEMO_TARGET_PORTS: tuple = (3000, 8000, 5173)
    DEMO_TARGET_PATH_PREFIX: str = "/demo-target"

    # CORS Allowed Origins
    CORS_ORIGINS: list = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]

settings = Settings()
