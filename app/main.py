import logging
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app import deps
from app.routes import dashboard, decisions, alerts, config_editor, logs, scenarios, ai_analysis

logger = logging.getLogger("trapstack")


@asynccontextmanager
async def lifespan(app: FastAPI):
    deps.http_client = httpx.AsyncClient()
    yield
    await deps.http_client.aclose()


app = FastAPI(title="TrapStack", lifespan=lifespan)

# Static files (mount only if directory exists)
static_dir = Path(__file__).parent / "static"
if static_dir.is_dir():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Include routers
app.include_router(dashboard.router)
app.include_router(decisions.router)
app.include_router(alerts.router)
app.include_router(config_editor.router)
app.include_router(logs.router)
app.include_router(scenarios.router)
app.include_router(ai_analysis.router)
