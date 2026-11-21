"""İzole pytest test ortamı sarmalayıcısı.
Canlı `dentacore_local.db` veritabanına veya `.local_secrets.json` dosyasına dokunmadan
geçici bir dizinde izole bir `run_local.py` test sunucusu başlatır ve tüm test modüllerini
bu izole sunucuya yönlendirir.
"""
from __future__ import annotations

import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

import httpx
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Modül import anında DB_PATH ve DENTACORE_URL okuyan testler için erken geçici ortam kurulumu
_ISO_TMP_DIR = pathlib.Path(tempfile.mkdtemp(prefix="dentacore_pytest_iso_"))
_ISO_DB_PATH = _ISO_TMP_DIR / "isolated_test.db"
_ISO_SECRETS_PATH = _ISO_TMP_DIR / "isolated_secrets.json"

_sock = socket.socket()
_sock.bind(("127.0.0.1", 0))
_ISO_PORT = _sock.getsockname()[1]
_sock.close()
_ISO_URL = f"http://127.0.0.1:{_ISO_PORT}"

os.environ["DC_DB_PATH"] = str(_ISO_DB_PATH)
os.environ["DC_SECRETS_PATH"] = str(_ISO_SECRETS_PATH)
os.environ["DC_PORT"] = str(_ISO_PORT)
os.environ["DENTACORE_URL"] = _ISO_URL
os.environ["DC_ENV"] = "local"
os.environ["PYTHONUTF8"] = "1"
os.environ.setdefault("WA_APP_SECRET", "wa-secret-test")
os.environ.setdefault("IG_APP_SECRET", "ig-secret-test")


@pytest.fixture(scope="session", autouse=True)
def isolated_dentacore_server():
    env = os.environ.copy()
    log_file = open(_ISO_TMP_DIR / "isolated_server.log", "w", encoding="utf-8")
    proc = subprocess.Popen(  # noqa: S603 - sabit argüman listesi, kullanıcı girdisi yok
        [sys.executable, "-X", "utf8", str(ROOT / "run_local.py")],
        cwd=str(ROOT),
        env=env,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        text=True,
    )
    ready = False
    for _ in range(60):
        try:
            r = httpx.get(f"{_ISO_URL}/health", timeout=1.0)
            if r.status_code == 200:
                ready = True
                break
        except Exception:
            time.sleep(0.25)
    if not ready:
        proc.terminate()
        raise RuntimeError(f"İzole test sunucusu {_ISO_URL} adresinde başlatılamadı.")

    # Zaten import edilmiş test modüllerinin BASE ve DB_PATH değişkenlerini izole ortama bağla
    for mod_name, mod in list(sys.modules.items()):
        if mod and mod_name.startswith("test_"):
            if hasattr(mod, "BASE"):
                mod.BASE = _ISO_URL
            if hasattr(mod, "DB_PATH"):
                mod.DB_PATH = _ISO_DB_PATH

    yield _ISO_URL

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()
