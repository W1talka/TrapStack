"""Shared dependencies for FastAPI routes — avoids circular imports with app.main."""

from pathlib import Path

import httpx
from fastapi.templating import Jinja2Templates

# Templates
templates_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))

# HTTP client — set during app lifespan
http_client: httpx.AsyncClient | None = None


def get_http_client() -> httpx.AsyncClient:
    return http_client
