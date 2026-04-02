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


def _country_flag(code):
    """Convert ISO alpha-2 code to Unicode flag emoji."""
    if not code or len(code) != 2:
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code.upper())


templates.env.filters["country_flag"] = _country_flag
