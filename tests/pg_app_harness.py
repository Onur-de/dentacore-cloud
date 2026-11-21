"""Gerçek HTTP üzerinden PostgreSQL motorunu (api/app/main.py) sınayan test düzeneği.

- Her çağrı kendi geçici veritabanını yaratır (test_pg_reliability'nin `DROP SCHEMA`'sından etkilenmez) ve sonunda siler.
- Uygulama gerçek bir `uvicorn` alt süreci olarak, temiz bir ortamla çalışır (Windows'ta psycopg async için SelectorEventLoop).
- Oturum/CSRF/çerez akışı gerçek istemciyle (httpx) yürür; hiçbir uç nokta taklit edilmez.
- PG erişilemezse atlar; DC_REQUIRE_PG=1 ise atlamaz, başarısız olur.
"""
from __future__ import annotations

import contextlib
import io
import os
import pathlib
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field

import httpx
import pytest
from cryptography.fernet import Fernet

ROOT = pathlib.Path(__file__).resolve().parents[1]
API_DIR = ROOT / "api"
REQUIRE_PG = os.environ.get("DC_REQUIRE_PG") == "1"
PG_DSN = os.environ.get("DC_PG_TEST_DSN", "postgresql://dentacore:dctest_pw_local_only@127.0.0.1:55432/dentacore_test")

_LAUNCH = (
    "import asyncio, selectors, sys\n"
    f"sys.path.insert(0, {str(API_DIR)!r})\n"
    "import uvicorn\n"
    "from app.main import app\n"
    "port = int(sys.argv[1])\n"
    "cfg = uvicorn.Config(app, host='127.0.0.1', port=port, log_level='warning', server_header=False, workers=1)\n"
    "srv = uvicorn.Server(cfg)\n"
    "lf = (lambda: asyncio.SelectorEventLoop(selectors.SelectSelector())) if sys.platform == 'win32' else None\n"
    "asyncio.run(srv.serve(), loop_factory=lf)\n"
)
_KEEP = ("PATH", "SYSTEMROOT", "TEMP", "TMP", "COMSPEC", "PATHEXT", "WINDIR", "LOCALAPPDATA", "APPDATA", "USERPROFILE", "HOME")


def pg_admin():
    try:
        import psycopg
        return psycopg.connect(PG_DSN, autocommit=True, connect_timeout=3)
    except Exception as ex:  # noqa: BLE001
        if REQUIRE_PG:
            pytest.fail(f"DC_REQUIRE_PG=1 ama PG erişilemiyor: {ex}", pytrace=False)
        pytest.skip(f"Test PostgreSQL erişilemiyor: {ex}")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def make_jpeg(seed: int = 0, size: int = 800) -> bytes:
    """Gerçek, çözülebilir JPEG (rastgele gürültü: netlik denetiminden geçer)."""
    from PIL import Image
    rnd = secrets.token_bytes(size * size * 3) if seed == 0 else bytes((i * seed) % 256 for i in range(size * size * 3))
    img = Image.frombytes("RGB", (size, size), rnd)
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=85)
    return buf.getvalue()


@dataclass
class Session:
    base: str
    client: httpx.Client
    csrf: str
    email: str
    clinic_id: int

    def _h(self, extra: dict | None = None) -> dict:
        return {"x-csrf-token": self.csrf, **(extra or {})}

    def get(self, path: str, **kw) -> httpx.Response:
        return self.client.get(self.base + path, headers=self._h(), **kw)

    def post(self, path: str, **kw) -> httpx.Response:
        return self.client.post(self.base + path, headers=self._h(), **kw)

    def delete(self, path: str, **kw) -> httpx.Response:
        return self.client.delete(self.base + path, headers=self._h(), **kw)


@dataclass
class PgApp:
    base: str
    dsn: str
    dbname: str
    env: dict[str, str]
    media_dir: pathlib.Path
    proc: subprocess.Popen
    owner_email: str
    owner_password: str
    sessions: list = field(default_factory=list)

    def login(self, email: str, password: str, clinic_id: int = 1) -> Session:
        c = httpx.Client(timeout=30)
        r = c.post(self.base + "/auth/login", json={"email": email, "password": password})
        assert r.status_code == 200, f"giriş başarısız: {r.status_code} {r.text[:200]}"
        s = Session(self.base, c, r.json()["csrf"], email, clinic_id)
        self.sessions.append(s)
        return s

    def hq(self) -> Session:
        return self.login(self.owner_email, self.owner_password, 1)

    def new_clinic(self, hq: Session, name: str) -> Session:
        """HQ ile yeni klinik + o kliniğin (HQ olmayan) sahibi; sahibi olarak oturum açılmış Session döner."""
        email = f"sahip-{uuid.uuid4().hex[:8]}@klinik.example"
        pw = secrets.token_urlsafe(18) + 'aZ7q'
        r = hq.post("/app/api/clinics", json={
            "clinic_name": name, "owner_name": "Klinik Sahibi", "owner_email": email, "owner_password": pw})
        assert r.status_code == 200, r.text[:300]
        return self.login(email, pw, r.json()["clinic_id"])

    def new_patient(self, s: Session, name: str = "Test Hasta") -> int:
        phone = "+90532" + str(secrets.randbelow(9_000_000) + 1_000_000)
        r = s.post("/app/api/patients", json={"phone": phone, "name": name})
        assert r.status_code == 200, r.text[:300]
        return r.json()["id"]

    def upload(self, s: Session, pid: int, data: bytes, filename: str = "foto.jpg", category: str = "photo",
               stage: str = "general") -> httpx.Response:
        return s.post(f"/app/api/patients/{pid}/media", params={"filename": filename, "category": category, "stage": stage}, content=data)

    def stop(self) -> None:
        for s in self.sessions:
            with contextlib.suppress(Exception):
                s.client.close()
        with contextlib.suppress(Exception):
            self.proc.terminate()
            self.proc.wait(timeout=15)
        with contextlib.suppress(Exception):
            self.proc.kill()

    def restart(self) -> None:
        """Aynı veritabanı ve aynı medya klasörüyle süreci yeniden başlatır (kalıcılık testi). Oturumlar PG'de kalır."""
        self.stop()
        self.proc = _spawn(self.base, self.env)
        _wait_ready(self.base, self.proc)


def _spawn(base: str, env: dict[str, str]) -> subprocess.Popen:
    port = base.rsplit(":", 1)[1]
    return subprocess.Popen([sys.executable, "-X", "utf8", "-c", _LAUNCH, port], env=env, cwd=str(ROOT),  # noqa: S603
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8")


def _wait_ready(base: str, proc: subprocess.Popen, timeout: float = 90) -> None:
    t0 = time.time()
    while time.time() - t0 < timeout:
        if proc.poll() is not None:
            out = proc.stdout.read() if proc.stdout else ""
            raise RuntimeError(f"uygulama açılmadan kapandı (kod {proc.returncode}):\n{out[-1800:]}")
        try:
            if httpx.get(base + "/health", timeout=2).status_code == 200:
                return
        except Exception:  # noqa: BLE001
            time.sleep(0.4)
    raise RuntimeError("uygulama zamanında hazır olmadı")


@contextlib.contextmanager
def pg_app(extra_env: dict[str, str] | None = None):
    """Geçici DB + gerçek uygulama süreci. extra_env, medya/depolama ayarlarını geçersiz kılar."""
    admin = pg_admin()
    dbname = "dc_app_" + uuid.uuid4().hex[:10]
    admin.execute(f'CREATE DATABASE "{dbname}"')
    tmp = tempfile.TemporaryDirectory()
    proc = None
    app = None
    try:
        base_dsn, _, _ = PG_DSN.rpartition("/")
        media_dir = pathlib.Path(tmp.name) / "images"
        owner_pw = secrets.token_urlsafe(20) + 'aZ7q'
        env = {k: v for k, v in os.environ.items() if k in _KEEP}
        env.update({
            "PYTHONUTF8": "1", "PYTHONDONTWRITEBYTECODE": "1", "TZ": "Europe/Istanbul",
            "DC_ENV": "local", "DC_ALLOW_HTTP_LOCAL": "1",
            "DATABASE_URL": f"{base_dsn}/{dbname}",
            "ADMIN_TOKEN": secrets.token_hex(24), "PHONE_HMAC_KEY": secrets.token_hex(24),
            "DATA_ENCRYPTION_KEY": Fernet.generate_key().decode(),
            "OWNER_EMAIL": "merkez@klinik.example", "OWNER_PASSWORD": owner_pw,
            "IMAGE_DIR": str(media_dir), "PUBLIC_URL": "http://127.0.0.1:0",
        })
        env.update(extra_env or {})
        base = f"http://127.0.0.1:{free_port()}"
        proc = _spawn(base, env)
        _wait_ready(base, proc)
        app = PgApp(base, f"{base_dsn}/{dbname}", dbname, env, media_dir, proc, "merkez@klinik.example", owner_pw)
        yield app
    finally:
        if app:
            app.stop()
        elif proc:
            with contextlib.suppress(Exception):
                proc.kill()
        with contextlib.suppress(Exception):
            admin.execute(f'DROP DATABASE IF EXISTS "{dbname}" WITH (FORCE)')
        admin.close()
        with contextlib.suppress(Exception):
            tmp.cleanup()
