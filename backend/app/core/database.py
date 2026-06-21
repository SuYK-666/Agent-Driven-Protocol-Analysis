"""Database engine and session management."""

from pathlib import Path
from sqlmodel import SQLModel, Session, create_engine
from .config import settings

# Resolve absolute DB path from project root
_db_path = settings.DATA_DIR / "protocol_analysis.db"
_db_path.parent.mkdir(parents=True, exist_ok=True)
_db_url = f"sqlite:///{_db_path}"

# Use check_same_thread=False for SQLite to allow FastAPI async access
connect_args = {"check_same_thread": False, "timeout": 120}
engine = create_engine(
    _db_url,
    echo=False,
    connect_args=connect_args,
    pool_size=30,
    max_overflow=30,
    pool_timeout=120,
)


def create_db_and_tables():
    """Create all tables defined by SQLModel metadata."""
    SQLModel.metadata.create_all(engine)


def get_session():
    """Yield a database session for dependency injection."""
    with Session(engine) as session:
        yield session
