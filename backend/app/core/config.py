"""Application configuration loaded from environment variables."""

from pydantic_settings import BaseSettings
from pathlib import Path


class Settings(BaseSettings):
    """Global application settings."""

    # Project paths
    PROJECT_ROOT: Path = Path(__file__).resolve().parents[3]
    DATA_DIR: Path = PROJECT_ROOT / "data"

    # Database
    DATABASE_URL: str = "sqlite:///./data/protocol_analysis.db"

    # LLM
    OPENAI_API_KEY: str = ""
    OPENAI_BASE_URL: str = "https://api.openai.com/v1"
    OPENAI_MODEL: str = "gpt-4o"
    OPENAI_TIMEOUT_SECONDS: float = 240.0
    OPENAI_STREAM: bool = True
    OPENAI_TEMPERATURE: float = 0.0
    OPENAI_TOP_P: float = 1.0
    OPENAI_MAX_TOKENS: int = 3072
    OPENAI_MAX_RETRIES: int = 2

    # Server
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000

    # Probe
    FTP_PROBE_HOST: str = "127.0.0.1"
    FTP_PROBE_PORT: int = 2121
    SMTP_PROBE_HOST: str = "127.0.0.1"
    SMTP_PROBE_PORT: int = 2525
    HTTP_PROBE_HOST: str = "127.0.0.1"
    HTTP_PROBE_PORT: int = 8080
    RTSP_PROBE_HOST: str = "127.0.0.1"
    RTSP_PROBE_PORT: int = 8554

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
