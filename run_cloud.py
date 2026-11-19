"""DentaCore v6.3 Bulut Sunucu Başlatıcısı (Render / Railway / Fly.io / Docker VPS Uyumlu).
- DATABASE_URL (PostgreSQL) tanımlıysa çoklu işçi (WEB_CONCURRENCY) ile api/app/main.py çalıştırır.
- DATABASE_URL yoksa kalıcı disk (/data) üzerinde SQLite WAL moduyla run_local.py çalıştırır.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
import uvicorn

ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DC_DATA_DIR", "/data"))
if DATA_DIR.exists() and os.access(DATA_DIR, os.W_OK):
    os.environ.setdefault("DC_DB_PATH", str(DATA_DIR / "dentacore_local.db"))
    os.environ.setdefault("DC_SECRETS_PATH", str(DATA_DIR / ".local_secrets.json"))
    os.environ.setdefault("DC_MEDIA_DIR", str(DATA_DIR / "patient_media"))

USE_PG = bool((os.environ.get("DATABASE_URL") or "").strip())

if USE_PG:
    sys.path.insert(0, str(ROOT / "api"))
    from app.main import app  # noqa: E402
else:
    import run_local  # noqa: E402

    if os.environ.get("DC_DB_PATH"):
        run_local.DB_PATH = Path(os.environ["DC_DB_PATH"])
    if os.environ.get("DC_SECRETS_PATH"):
        run_local.SECRETS_PATH = Path(os.environ["DC_SECRETS_PATH"])
    app = run_local.app

if __name__ == "__main__":
    host = os.environ.get("DC_HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", os.environ.get("DC_PORT", "8000")))
    workers = int(os.environ.get("WEB_CONCURRENCY", "2")) if USE_PG else 1
    target = "app.main:app" if USE_PG else app
    uvicorn.run(
        target,
        host=host,
        port=port,
        workers=workers,
        log_level="info",
        server_header=False,
        proxy_headers=True,
        forwarded_allow_ips=os.environ.get("FORWARDED_ALLOW_IPS", "*"),
    )
