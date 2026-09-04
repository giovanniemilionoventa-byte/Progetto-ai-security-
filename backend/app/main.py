from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import AEGIS_ROLE, CORS_ORIGINS
from .database import SessionLocal, ensure_schema
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
from .routers import broker as broker_router
from .routers import tool as tool_router
from .seed import seed_builtin_patterns, seed_if_empty

CONTROL_ROUTERS = (
    auth,
    agents,
    policies,
    resources,
    approvals,
    behavior_patterns,
)
ENFORCEMENT_ROUTERS = (authorize, gateway)
BROKER_ROUTERS = (broker_router,)
TOOL_ROUTERS = (tool_router,)

_ENFORCEMENT_PREFIXES = ("/api/authorize", "/api/gateway")


def _role_routers(role: str):
    if role == "control-plane":
        return CONTROL_ROUTERS
    if role == "enforcement-gateway":
        return ENFORCEMENT_ROUTERS
    if role == "credential-broker":
        return BROKER_ROUTERS
    if role == "protected-tool":
        return TOOL_ROUTERS
    return CONTROL_ROUTERS + ENFORCEMENT_ROUTERS


def _needs_database(role: str) -> bool:
    return role in {"all", "control-plane", "enforcement-gateway"}


def _needs_seed(role: str) -> bool:
    return role in {"all", "control-plane"}


def create_app(role: str | None = None) -> FastAPI:
    selected = (role or AEGIS_ROLE or "all").strip() or "all"

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        if _needs_database(selected):
            ensure_schema()
        if _needs_seed(selected):
            db = SessionLocal()
            try:
                seed_if_empty(db)
                seed_builtin_patterns(db)
            finally:
                db.close()
        yield

    health_layer = "control-plane" if selected in {"all", "control-plane"} else selected
    application = FastAPI(
        title="Aegis — AI Security Control Layer",
        description=(
            "Model-agnostic control plane that governs identity, permissions, "
            "policy, risk, audit and human approval for AI agents."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )
    application.state.aegis_role = selected

    application.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS + ["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    api = "/api"
    for router in _role_routers(selected):
        application.include_router(router.router, prefix=api)

    @application.middleware("http")
    async def reject_agent_tokens_on_control_plane(request, call_next):
        path = request.url.path
        if any(path.startswith(prefix) for prefix in _ENFORCEMENT_PREFIXES):
            return await call_next(request)
        if selected in {"credential-broker", "protected-tool"}:
            return await call_next(request)
        if not path.startswith("/api/"):
            return await call_next(request)
        if path.startswith("/api/health"):
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

    @application.get("/api/health")
    def health():
        return {"status": "ok", "product": "aegis", "layer": health_layer}

    return application


app = create_app()
