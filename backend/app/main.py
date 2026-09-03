from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import CORS_ORIGINS
from .database import Base, SessionLocal, engine
from .routers import agents, approvals, auth, authorize, policies, resources
from .seed import seed_if_empty


@asynccontextmanager
async def lifespan(_app: FastAPI):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_if_empty(db)
    finally:
        db.close()
    yield


app = FastAPI(
    title="Aegis — AI Security Control Layer",
    description=(
        "Model-agnostic control plane that governs identity, permissions, "
        "policy, risk, audit and human approval for AI agents."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS + ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API = "/api"
app.include_router(auth.router, prefix=API)
app.include_router(agents.router, prefix=API)
app.include_router(policies.router, prefix=API)
app.include_router(resources.router, prefix=API)
app.include_router(authorize.router, prefix=API)
app.include_router(approvals.router, prefix=API)


@app.get("/api/health")
def health():
    return {"status": "ok", "product": "aegis", "layer": "control-plane"}
