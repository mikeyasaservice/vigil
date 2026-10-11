"""Minimal tenant-local security service surface.

The application listener is bound to loopback behind an Envoy SPIFFE mTLS
listener. It intentionally mounts only claim and authorization routes.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException

from core.agents.managed_gateway_router import router as managed_gateway
from core.integrations.mcp.registry import MCPRegistry
from core.storage.connection import get_db_manager


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Own the security service's narrow durable-state dependency."""
    database = get_db_manager()
    database.initialize()
    if not database.health_check():
        database.close()
        raise RuntimeError("managed security database is unavailable")
    try:
        yield
    finally:
        database.close()


app = FastAPI(title="Vigil managed security service", version="1", lifespan=lifespan)
# Kept empty deliberately. It lets the nested-call normalizer reject a generic
# integration wrapper without importing the backend's executable tool catalog.
app.state.mcp_registry = MCPRegistry()
app.include_router(managed_gateway, prefix="/v1")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    if not get_db_manager().health_check():
        raise HTTPException(status_code=503, detail="managed security state is unavailable")
    return {"status": "ok"}
