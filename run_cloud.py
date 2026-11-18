"""DentaCore v6.2 Bulut Sunucu Başlatıcısı (Render / Railway / Fly.io / Docker VPS Uyumlu)."""
from __future__ import annotations

import os
from pathlib import Path
import uvicorn

# Kalıcı disk (/data) varsa veritabanını ve anahtarları orada tut
DATA_DIR = Path(os.environ.get("DC_DATA_DIR", "/data"))
if DATA_DIR.exists() and os.access(DATA_DIR, os.W_OK):
    os.environ.setdefault("DC_DB_PATH", str(DATA_DIR / "dentacore_local.db"))
    os.environ.setdefault("DC_SECRETS_PATH", str(DATA_DIR / ".local_secrets.json"))

import run_local  # noqa: E402

if os.environ.get("DC_DB_PATH"):
    run_local.DB_PATH = Path(os.environ["DC_DB_PATH"])
if os.environ.get("DC_SECRETS_PATH"):
    run_local.SECRETS_PATH = Path(os.environ["DC_SECRETS_PATH"])

app = run_local.app

if __name__ == "__main__":
    host = os.environ.get("DC_HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", os.environ.get("DC_PORT", "8000")))
    uvicorn.run(app, host=host, port=port, log_level="info", server_header=False)
