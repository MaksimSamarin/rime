"""Compatibility URLs for the single Rime console and subscription icons."""
from pathlib import Path

from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app import app
from config import DASHBOARD_PATH

icons = Path(__file__).resolve().parents[1] / 'hy2bridge' / 'web' / 'icons'
app.mount('/statics/favicon', StaticFiles(directory=icons), name='subscription-icons')


def dashboard_redirect(path: str = ''):
    return RedirectResponse('/fleet#users', status_code=307)


legacy_path = DASHBOARD_PATH.rstrip('/') or '/dashboard'
app.add_api_route(legacy_path, dashboard_redirect, methods=['GET', 'HEAD'], include_in_schema=False)
app.add_api_route(legacy_path + '/{path:path}', dashboard_redirect, methods=['GET', 'HEAD'], include_in_schema=False)
