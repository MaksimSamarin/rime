"""Run explicitly with uvicorn panel_entry:app; upstream image stays unmodified."""
from app import app
from hy2bridge.panel import install

install(app)
