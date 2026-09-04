from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import DATABASE_URL

connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


if DATABASE_URL.startswith("sqlite"):

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def ensure_schema() -> None:
    Base.metadata.create_all(bind=engine)
    if not DATABASE_URL.startswith("sqlite"):
        return
    with engine.begin() as conn:
        rows = conn.execute(text("PRAGMA table_info(events)")).fetchall()
        cols = {row[1] for row in rows}
        if "execution_id" not in cols:
            conn.execute(text("ALTER TABLE events ADD COLUMN execution_id VARCHAR"))
        if "seq" not in cols:
            conn.execute(
                text("ALTER TABLE events ADD COLUMN seq INTEGER DEFAULT 0 NOT NULL")
            )


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
