from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import CORS_ORIGINS
from .database import SessionLocal, ensure_schema
from fastapi.responses import JSONResponse

from .routers import (
    agents,
    approvals,
    auth,
    authorize,
    behavior_patterns,
    gateway,
    policies,
    resources,
)
from .seed import seed_builtin_patterns, seed_if_empty


@asynccontextmanager
async def lifespan(_app: FastAPI):
    ensure_schema()
    db = SessionLocal()
    try:
        seed_if_empty(db)
        seed_builtin_patterns(db)
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
app.include_router(behavior_patterns.router, prefix=API)
app.include_router(gateway.router, prefix=API)

_ENFORCEMENT_PREFIXES = ("/api/authorize", "/api/gateway")


@app.middleware("http")
async def reject_agent_tokens_on_control_plane(request, call_next):
    path = request.url.path
    if any(path.startswith(prefix) for prefix in _ENFORCEMENT_PREFIXES):
        return await call_next(request)
    if not path.startswith("/api/"):
        return await call_next(request)
    agent_header = request.headers.get("x-agent-token")
    authorization = request.headers.get("authorization") or ""
    uses_agent = bool(agent_header) or authorization.lower().startswith("bearer aegis_")
    if uses_agent:
        return JSONResponse(
            status_code=403,
            content={
                "detail": "Agent credentials cannot access the control plane"
            },
        )
    return await call_next(request)


@app.get("/api/health")
def health():
    return {"status": "ok", "product": "aegis", "layer": "control-plane"}
