"""
VulnSeal FastAPI ASGI Entrypoint (Compatibility Forwarder)
Exposes the modular FastAPI application from backend.app.main.
"""
from .app.main import app, run_server

__all__ = ["app", "run_server"]

if __name__ == "__main__":
    import os
    port = int(os.getenv("PORT", 8000))
    run_server(port)
