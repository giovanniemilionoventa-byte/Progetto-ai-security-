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
        if "evidence_hash" not in cols:
            conn.execute(text("ALTER TABLE events ADD COLUMN evidence_hash VARCHAR"))
        if "previous_evidence_hash" not in cols:
            conn.execute(
                text("ALTER TABLE events ADD COLUMN previous_evidence_hash VARCHAR")
            )
        approval_rows = conn.execute(text("PRAGMA table_info(approvals)")).fetchall()
        approval_cols = {row[1] for row in approval_rows}
        for column, ddl in (
            ("execution_id", "ALTER TABLE approvals ADD COLUMN execution_id VARCHAR"),
            ("request_id", "ALTER TABLE approvals ADD COLUMN request_id VARCHAR"),
            ("contract_id", "ALTER TABLE approvals ADD COLUMN contract_id VARCHAR"),
            (
                "contract_version",
                "ALTER TABLE approvals ADD COLUMN contract_version INTEGER",
            ),
            ("param_hash", "ALTER TABLE approvals ADD COLUMN param_hash VARCHAR"),
            ("expires_at", "ALTER TABLE approvals ADD COLUMN expires_at DATETIME"),
            ("consumed_at", "ALTER TABLE approvals ADD COLUMN consumed_at DATETIME"),
            (
                "consumed_event_id",
                "ALTER TABLE approvals ADD COLUMN consumed_event_id VARCHAR",
            ),
        ):
            if column not in approval_cols and approval_rows:
                conn.execute(text(ddl))

        exec_rows = conn.execute(text("PRAGMA table_info(executions)")).fetchall()
        exec_cols = {row[1] for row in exec_rows}
        if "evidence_chain_tip" not in exec_cols:
            conn.execute(
                text("ALTER TABLE executions ADD COLUMN evidence_chain_tip VARCHAR")
            )
        tables = {
            row[0]
            for row in conn.execute(
                text("SELECT name FROM sqlite_master WHERE type='table'")
            ).fetchall()
        }
        if "runtime_contracts" in tables:
            indexes = {
                row[1]
                for row in conn.execute(
                    text("PRAGMA index_list(runtime_contracts)")
                ).fetchall()
            }
            if "uq_runtime_contract_one_active_per_agent" not in indexes:
                conn.execute(
                    text(
                        "CREATE UNIQUE INDEX IF NOT EXISTS "
                        "uq_runtime_contract_one_active_per_agent "
                        "ON runtime_contracts (organization_id, agent_id) "
                        "WHERE status = 'ACTIVE'"
                    )
                )


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
