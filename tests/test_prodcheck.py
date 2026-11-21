"""Üretim başlangıç doğrulaması (api/app/prodcheck.py) testleri.

Katmanlar:
  1) Saf fonksiyon testleri: eksik/kısa anahtar, geçersiz Fernet, http/localhost PUBLIC_URL, Redis yokken çoklu işçi,
     kalıcı disk/S3 yokken yerel medya, DC_ALLOW_HTTP_LOCAL=1, örnek (placeholder) değerler. DC_ENV=local etkilenmemeli.
  2) Manifest uyumu: docker-compose.yml, render.yaml ve .env.example gerçekten prodcheck'ten geçecek ortamı kuruyor mu?
  3) Gerçek açılış: uygulamanın lifespan'ı temiz bir ortamla alt süreçte çalıştırılır. Hatalı yapılandırma açılışı reddetmeli
     (çıkış kodu + prodcheck'in kendi hata metni doğrulanır; yanlış nedenle geçmeyi önler). Geçerli yapılandırma, gerçek
     PostgreSQL'de açılmalı (PG yoksa atlanır; DC_REQUIRE_PG=1 ise atlanmaz, başarısız olur).
"""
from __future__ import annotations

import os
import pathlib
import re
import secrets
import subprocess
import sys
import tempfile
import uuid

import pytest
import yaml
from cryptography.fernet import Fernet

ROOT = pathlib.Path(__file__).resolve().parents[1]
API_DIR = ROOT / "api"
sys.path.insert(0, str(API_DIR))

from app.prodcheck import enforce_production_config, is_production, production_problems  # noqa: E402

REQUIRE_PG = os.environ.get("DC_REQUIRE_PG") == "1"
PG_DSN = os.environ.get("DC_PG_TEST_DSN", "postgresql://dentacore:dctest_pw_local_only@127.0.0.1:55432/dentacore_test")
BANNER = "Üretim yapılandırması geçersiz"


def valid_env() -> dict[str, str]:
    """production_problems() için boş liste döndürmesi gereken, rastgele değerli geçerli üretim ortamı."""
    return {
        "DC_ENV": "production",
        "ADMIN_TOKEN": secrets.token_hex(24),
        "PHONE_HMAC_KEY": secrets.token_hex(24),
        "DATA_ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "DATABASE_URL": "postgresql://u:p@db.internal:5432/dentacore",
        "PUBLIC_URL": "https://api.klinik.example",
        "REDIS_URL": "redis://:p@redis.internal:6379/0",
        "WEB_CONCURRENCY": "2",
        "MEDIA_BACKEND": "local",
        "DC_MEDIA_PERSISTENT": "1",
        "OWNER_PASSWORD": secrets.token_urlsafe(18),
        "POSTGRES_PASSWORD": secrets.token_hex(12),
        "REDIS_PASSWORD": secrets.token_hex(12),
        "N8N_ENCRYPTION_KEY": secrets.token_hex(16),
    }


def _without(key: str):
    def f(e: dict[str, str]) -> None:
        e.pop(key, None)
    return f


def _set(**kw: str):
    def f(e: dict[str, str]) -> None:
        e.update(kw)
    return f


# (ad, ortamı bozan fonksiyon, sorun listesinde aranacak metin)
NEGATIVE_CASES = [
    ("admin_token_eksik", _without("ADMIN_TOKEN"), "ADMIN_TOKEN tanımlı değil"),
    ("phone_hmac_eksik", _without("PHONE_HMAC_KEY"), "PHONE_HMAC_KEY tanımlı değil"),
    ("fernet_eksik", _without("DATA_ENCRYPTION_KEY"), "DATA_ENCRYPTION_KEY tanımlı değil"),
    ("admin_token_kisa", _set(ADMIN_TOKEN="a" * 31), "ADMIN_TOKEN en az 32"),
    ("phone_hmac_kisa", _set(PHONE_HMAC_KEY="kisa"), "PHONE_HMAC_KEY en az 32"),
    ("fernet_gecersiz", _set(DATA_ENCRYPTION_KEY="bu-bir-fernet-anahtari-degil"), "geçerli bir Fernet"),
    ("database_url_eksik", _without("DATABASE_URL"), "DATABASE_URL tanımlı değil"),
    ("public_url_eksik", _without("PUBLIC_URL"), "PUBLIC_URL tanımlı değil"),
    ("public_url_http", _set(PUBLIC_URL="http://api.klinik.example"), "https:// ile başlamalı"),
    ("public_url_localhost", _set(PUBLIC_URL="https://localhost"), "yerel bir adres"),
    ("public_url_loopback", _set(PUBLIC_URL="https://127.0.0.1:8000"), "yerel bir adres"),
    ("redis_yok_cok_isci", lambda e: (e.pop("REDIS_URL"), e.update(WEB_CONCURRENCY="2")), "REDIS_URL tanımlı değil"),
    ("redis_yok_izinli_ama_cok_isci",
     lambda e: (e.pop("REDIS_URL"), e.update(DC_ALLOW_NO_REDIS="1", WEB_CONCURRENCY="3")),
     "yalnızca WEB_CONCURRENCY=1"),
    ("web_concurrency_sayi_degil", _set(WEB_CONCURRENCY="iki"), "WEB_CONCURRENCY sayı olmalı"),
    ("medya_local_kalici_degil", _without("DC_MEDIA_PERSISTENT"), "kalıcı diske bağlanmalı"),
    ("medya_local_kalici_0", _set(DC_MEDIA_PERSISTENT="0"), "kalıcı diske bağlanmalı"),
    ("medya_s3_bucket_yok", _set(MEDIA_BACKEND="s3", S3_ACCESS_KEY_ID="k", S3_SECRET_ACCESS_KEY="s"), "S3_BUCKET zorunlu"),
    ("medya_s3_anahtar_yok", _set(MEDIA_BACKEND="s3", S3_BUCKET="b"), "S3_ACCESS_KEY_ID zorunlu"),
    ("medya_gecersiz_backend", _set(MEDIA_BACKEND="ftp"), "'local' ya da 's3' olmalı"),
    ("http_local_acik", _set(DC_ALLOW_HTTP_LOCAL="1"), "DC_ALLOW_HTTP_LOCAL üretimde kapalı"),
    ("ornek_admin_token", _set(ADMIN_TOKEN="degistir-uzun-rastgele" + "x" * 20), "ADMIN_TOKEN hâlâ .env.example"),
    ("ornek_owner_parola", _set(OWNER_PASSWORD="degistir-en-az-12-karakter"), "OWNER_PASSWORD hâlâ .env.example"),
    ("ornek_postgres_parola", _set(POSTGRES_PASSWORD="degistir-uzun-rastgele"), "POSTGRES_PASSWORD hâlâ .env.example"),
]


# ---------------------------------------------------------------- 1) saf fonksiyon testleri

def test_gecerli_uretim_ortami_sorunsuz():
    assert production_problems(valid_env()) == []


@pytest.mark.parametrize("ad,mutasyon,beklenen", NEGATIVE_CASES, ids=[c[0] for c in NEGATIVE_CASES])
def test_hatali_uretim_ortami_reddedilir(ad, mutasyon, beklenen):
    e = valid_env()
    mutasyon(e)
    sorunlar = production_problems(e)
    assert any(beklenen in s for s in sorunlar), f"{ad}: '{beklenen}' bekleniyordu, gelen: {sorunlar}"
    with pytest.raises(RuntimeError) as exc:
        enforce_production_config(e)
    assert BANNER in str(exc.value)
    assert beklenen in str(exc.value)


def test_s3_tam_yapilandirma_prodcheck_den_gecer():
    e = valid_env()
    e.pop("DC_MEDIA_PERSISTENT")
    e.update(MEDIA_BACKEND="s3", S3_BUCKET="b", S3_ACCESS_KEY_ID="k", S3_SECRET_ACCESS_KEY="s")
    assert production_problems(e) == []


def test_redis_yok_ama_bilerek_tek_isci_kabul_edilir():
    e = valid_env()
    e.pop("REDIS_URL")
    e.update(DC_ALLOW_NO_REDIS="1", WEB_CONCURRENCY="1")
    assert production_problems(e) == []


def test_tum_sorunlar_tek_hatada_listelenir():
    e = {"DC_ENV": "production"}
    with pytest.raises(RuntimeError) as exc:
        enforce_production_config(e)
    msg = str(exc.value)
    for parca in ("ADMIN_TOKEN", "PHONE_HMAC_KEY", "DATA_ENCRYPTION_KEY", "DATABASE_URL", "PUBLIC_URL", "REDIS_URL", "MEDIA"):
        assert parca in msg


@pytest.mark.parametrize("dc_env", ["prod", "production", "PRODUCTION", " Production "])
def test_uretim_degerleri_tanınır(dc_env):
    assert is_production({"DC_ENV": dc_env})
    with pytest.raises(RuntimeError):
        enforce_production_config({"DC_ENV": dc_env})


@pytest.mark.parametrize("env", [{}, {"DC_ENV": ""}, {"DC_ENV": "local"}, {"DC_ENV": "development"}])
def test_local_ortam_etkilenmez(env):
    """DC_ENV=local (ya da hiç verilmemiş): hiçbir zorunluluk yok, bozuk yapılandırma bile açılışı durdurmaz."""
    bozuk = {**env, "ADMIN_TOKEN": "x", "PUBLIC_URL": "http://localhost", "DC_ALLOW_HTTP_LOCAL": "1", "MEDIA_BACKEND": "ftp"}
    assert not is_production(bozuk)
    enforce_production_config(bozuk)  # istisna fırlatmamalı


# ---------------------------------------------------------------- 2) manifest uyumu

_VAR = re.compile(r"\$\{([A-Za-z0-9_]+)(?::-([^}]*))?\}")


def _parse_env_file(path: pathlib.Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def _interpolate(s: str, scope: dict[str, str]) -> str:
    return _VAR.sub(lambda m: scope.get(m.group(1)) or (m.group(2) if m.group(2) is not None else ""), s)


def _real_secrets_for_env_file() -> dict[str, str]:
    """.env dosyasını dolduran operatörü taklit eder: örnek değerlerin yerine gerçek rastgele sırlar."""
    v = valid_env()
    return {k: v[k] for k in ("ADMIN_TOKEN", "PHONE_HMAC_KEY", "DATA_ENCRYPTION_KEY", "OWNER_PASSWORD",
                              "POSTGRES_PASSWORD", "REDIS_PASSWORD", "N8N_ENCRYPTION_KEY")}


def test_compose_api_servisi_prodcheck_ten_gecer():
    dc = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    api = dc["services"]["api"]
    scope = {**_parse_env_file(ROOT / ".env.example"), **_real_secrets_for_env_file(), "DOMAIN": "klinik.example"}
    # Compose önceliği: environment, env_file'ı ezer. env_file = operatörün doldurduğu .env.
    efektif = {**scope, **{k: _interpolate(str(v), scope) for k, v in api["environment"].items()}}
    # Dockerfile ENV'leri (api/Dockerfile) de efektif ortama girer, ama Compose environment aynı değeri açıkça veriyor.
    assert production_problems(efektif) == [], production_problems(efektif)


def test_compose_medya_bildirimi_gercek_volume_ile_tutarli():
    """DC_MEDIA_PERSISTENT=1 yalnızca IMAGE_DIR gerçekten kalıcı bir volume içindeyse doğrudur."""
    dc = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    api = dc["services"]["api"]
    envs = api["environment"]
    assert str(envs["DC_MEDIA_PERSISTENT"]) == "1"
    image_dir = pathlib.PurePosixPath(envs["IMAGE_DIR"])
    mounts = {}
    for vol in api["volumes"]:
        src, dst = vol.split(":")[0], vol.split(":")[1]
        mounts[dst] = src
    kapsayan = [d for d in mounts if image_dir == pathlib.PurePosixPath(d) or pathlib.PurePosixPath(d) in image_dir.parents]
    assert kapsayan, f"IMAGE_DIR={image_dir} hiçbir volume içinde değil: {mounts}"
    adlandirilmis = mounts[kapsayan[0]]
    assert adlandirilmis in dc["volumes"], f"{adlandirilmis} üst düzey volumes içinde tanımlı değil (kalıcı değil)"


def test_compose_redis_ve_postgres_servisleri_api_ye_baglanir():
    dc = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    api = dc["services"]["api"]
    assert api["environment"]["REDIS_URL"].startswith("redis://")
    assert "redis" in api["depends_on"] and "postgres" in api["depends_on"]
    assert api["environment"]["PUBLIC_URL"].startswith("https://")


def test_api_dockerfile_varsayilan_olarak_uretim_modunda():
    """Fail-closed: DC_ENV verilmese bile imaj üretim doğrulamasına tabidir."""
    txt = (API_DIR / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r'DC_ENV="?production"?', txt)


def _render_web():
    r = yaml.safe_load((ROOT / "render.yaml").read_text(encoding="utf-8"))
    web = next(s for s in r["services"] if s["type"] == "web")
    return r, web


def test_render_manifest_prodcheck_ten_gecer():
    r, web = _render_web()
    gercek = valid_env()
    efektif: dict[str, str] = {}
    for item in web["envVars"]:
        k = item["key"]
        if "value" in item:
            efektif[k] = str(item["value"])
        elif "fromDatabase" in item:
            efektif[k] = "postgresql://u:p@dpg-internal:5432/dentacore"
        elif "fromService" in item:
            efektif[k] = "redis://red-internal:6379"
        elif item.get("sync") is False:
            efektif[k] = gercek.get(k, "https://api.klinik.example" if k == "PUBLIC_URL" else "operatorun-girdigi-gercek-deger")
        else:
            pytest.fail(f"{k}: değer kaynağı belirsiz")
    # Panelde elle girilecek ama prodcheck'in doğrudan istediği anahtarlar manifestte tanımlı olmalı.
    for k in ("ADMIN_TOKEN", "PHONE_HMAC_KEY", "DATA_ENCRYPTION_KEY", "PUBLIC_URL", "DATABASE_URL", "REDIS_URL"):
        assert k in efektif, f"render.yaml içinde {k} tanımlı değil"
    assert production_problems(efektif) == [], production_problems(efektif)


def test_render_disk_medya_dizinini_kapsar_ve_redis_servisi_var():
    r, web = _render_web()
    envs = {i["key"]: i for i in web["envVars"]}
    mount = pathlib.PurePosixPath(web["disk"]["mountPath"])
    image_dir = pathlib.PurePosixPath(envs["IMAGE_DIR"]["value"])
    assert image_dir == mount or mount in image_dir.parents
    assert str(envs["DC_MEDIA_PERSISTENT"]["value"]) == "1"
    ref = envs["REDIS_URL"]["fromService"]
    assert ref["type"] == "keyvalue"
    assert any(s.get("type") == "keyvalue" and s["name"] == ref["name"] for s in r["services"])
    assert any(d["name"] == envs["DATABASE_URL"]["fromDatabase"]["name"] for d in r["databases"])
    assert web["startCommand"] == "python run_cloud.py"


def test_env_example_oldugu_gibi_uretimde_kabul_edilmez():
    """Örnek dosya kopyalanıp doldurulmadan üretime çıkılırsa açılış reddedilmeli."""
    ex = _parse_env_file(ROOT / ".env.example")
    ortam = {**ex, "DC_ENV": "production", "PUBLIC_URL": "https://api.klinik.example", "REDIS_URL": "redis://r:6379",
             "DATABASE_URL": "postgresql://u:p@h/d", "DC_MEDIA_PERSISTENT": "1"}
    sorunlar = production_problems(ortam)
    assert any("DATA_ENCRYPTION_KEY" in s for s in sorunlar)
    assert any("hâlâ .env.example" in s for s in sorunlar)
    assert any("OWNER_PASSWORD" in s for s in sorunlar)


def test_env_example_uretim_anahtarlarini_belgeliyor():
    ex = _parse_env_file(ROOT / ".env.example")
    for k in ("MEDIA_BACKEND", "S3_BUCKET", "S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY", "DATA_ENCRYPTION_KEY",
              "PHONE_HMAC_KEY", "ADMIN_TOKEN", "OWNER_EMAIL", "OWNER_PASSWORD"):
        assert k in ex, f".env.example içinde {k} yok"
    # Örnek dosya güvensiz bayrakları açık bırakmamalı
    assert "DC_ALLOW_HTTP_LOCAL" not in ex
    assert "DC_ALLOW_NO_REDIS" not in ex


# ---------------------------------------------------------------- 3) gerçek açılış (alt süreç, temiz ortam)

_BOOT = (
    "import asyncio, sys\n"
    f"sys.path.insert(0, {str(API_DIR)!r})\n"
    "from app.main import app\n"
    "async def go():\n"
    "    async with app.router.lifespan_context(app):\n"
    "        print('LIFESPAN_OK')\n"
    "asyncio.run(go())\n"
)
_KEEP = ("PATH", "SYSTEMROOT", "TEMP", "TMP", "COMSPEC", "PATHEXT", "WINDIR", "LOCALAPPDATA", "APPDATA", "USERPROFILE", "HOME")


def _boot(env_extra: dict[str, str], timeout: int = 90) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if k in _KEEP}
    env.update({"PYTHONUTF8": "1", "PYTHONDONTWRITEBYTECODE": "1"})
    env.update(env_extra)
    return subprocess.run([sys.executable, "-X", "utf8", "-c", _BOOT], env=env, capture_output=True, text=True,
                          encoding="utf-8", timeout=timeout, cwd=str(ROOT))


def _boot_env() -> dict[str, str]:
    e = valid_env()
    e["DATABASE_URL"] = "postgresql://nouser:nopass@127.0.0.1:1/none"  # reddedilen vakalarda asla bağlanılmamalı
    e["TZ"] = "Europe/Istanbul"
    return e


BOOT_REFUSE_CASES = [c for c in NEGATIVE_CASES if c[0] in {
    "admin_token_kisa", "phone_hmac_kisa", "fernet_gecersiz", "public_url_http", "public_url_localhost",
    "redis_yok_cok_isci", "medya_local_kalici_degil", "http_local_acik", "medya_s3_bucket_yok", "ornek_admin_token",
}]


@pytest.mark.parametrize("ad,mutasyon,beklenen", BOOT_REFUSE_CASES, ids=[c[0] for c in BOOT_REFUSE_CASES])
def test_uygulama_hatali_uretim_yapilandirmasiyla_acilmaz(ad, mutasyon, beklenen):
    e = _boot_env()
    mutasyon(e)
    p = _boot(e)
    cikti = p.stdout + p.stderr
    assert p.returncode != 0, f"{ad}: uygulama açıldı! çıktı:\n{cikti[-800:]}"
    assert "LIFESPAN_OK" not in p.stdout
    assert BANNER in cikti, f"{ad}: red nedeni prodcheck değil:\n{cikti[-800:]}"
    assert beklenen in cikti


@pytest.mark.parametrize("eksik", ["ADMIN_TOKEN", "PHONE_HMAC_KEY", "DATA_ENCRYPTION_KEY", "DATABASE_URL"])
def test_uygulama_eksik_temel_anahtarla_acilmaz(eksik):
    e = _boot_env()
    e.pop(eksik)
    p = _boot(e)
    assert p.returncode != 0
    assert "LIFESPAN_OK" not in p.stdout
    assert f"{eksik} tanımlı değil" in (p.stdout + p.stderr)


def _pg_admin_dsn():
    try:
        import psycopg
        c = psycopg.connect(PG_DSN, autocommit=True, connect_timeout=3)
        return c
    except Exception as ex:  # noqa: BLE001
        if REQUIRE_PG:
            pytest.fail(f"DC_REQUIRE_PG=1 ama PG erişilemiyor: {ex}", pytrace=False)
        pytest.skip(f"Test PostgreSQL erişilemiyor: {ex}")


def test_gecerli_uretim_yapilandirmasi_gercek_postgresql_de_acilir():
    """Geçerli üretim ortamı + gerçek PG: prodcheck geçer, göç ve owner kurulumu çalışır, lifespan temiz kapanır."""
    admin = _pg_admin_dsn()
    dbname = "dc_prodcheck_" + uuid.uuid4().hex[:10]
    admin.execute(f'CREATE DATABASE "{dbname}"')
    try:
        base, _, _ = PG_DSN.rpartition("/")
        with tempfile.TemporaryDirectory() as tmp:
            e = valid_env()
            e.update(
                DATABASE_URL=f"{base}/{dbname}",
                DC_ALLOW_NO_REDIS="1", WEB_CONCURRENCY="1", IMAGE_DIR=str(pathlib.Path(tmp) / "images"),
                OWNER_EMAIL="yonetici@klinik.example", TZ="Europe/Istanbul",
            )
            e.pop("REDIS_URL")
            p = _boot(e, timeout=120)
        cikti = p.stdout + p.stderr
        assert p.returncode == 0, cikti[-1500:]
        assert "LIFESPAN_OK" in p.stdout
        assert BANNER not in cikti
    finally:
        admin.execute(f'DROP DATABASE IF EXISTS "{dbname}" WITH (FORCE)')
        admin.close()
