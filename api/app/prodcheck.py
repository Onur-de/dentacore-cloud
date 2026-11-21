"""Üretim (DC_ENV=production) başlangıç doğrulaması.

Amaç: Eksik ya da zayıf yapılandırmayla canlıya çıkmak yerine uygulamanın açılışta net bir hata vermesi.
Demo/yerel ortam (DC_ENV=local) etkilenmez. Saf fonksiyonlar: ortam sözlüğü verilir, sorun listesi döner (test edilebilir).
"""
from __future__ import annotations

import os
from collections.abc import Mapping
from urllib.parse import urlparse

PROD_VALUES = ("prod", "production")
MIN_SECRET_LEN = 32
# .env.example'daki örnek değerlerin ortak öneki ("degistir-uzun-rastgele", "degistir-en-az-12-karakter"). Üretimde kalmamalı.
PLACEHOLDER_PREFIX = "degistir"
PLACEHOLDER_CHECKED_KEYS = (
    "ADMIN_TOKEN", "PHONE_HMAC_KEY", "OWNER_PASSWORD", "POSTGRES_PASSWORD", "REDIS_PASSWORD", "N8N_ENCRYPTION_KEY",
)
LOCAL_HOSTS = ("localhost", "127.0.0.1", "0.0.0.0", "::1")  # nosec B104 - yalnızca karşılaştırma listesi


def is_production(environ: Mapping[str, str] | None = None) -> bool:
    e = environ if environ is not None else os.environ
    return (e.get("DC_ENV") or "local").strip().lower() in PROD_VALUES


def _flag(e: Mapping[str, str], key: str) -> bool:
    return (e.get(key) or "").strip() == "1"


def production_problems(environ: Mapping[str, str] | None = None) -> list[str]:
    """Üretim için engelleyici yapılandırma sorunlarını döndürür (boş liste = sorun yok)."""
    e = environ if environ is not None else os.environ
    out: list[str] = []

    # 1) Zorunlu gizli anahtarlar ve gücü
    for k in ("ADMIN_TOKEN", "PHONE_HMAC_KEY"):
        v = (e.get(k) or "").strip()
        if not v:
            out.append(f"{k} tanımlı değil")
        elif len(v) < MIN_SECRET_LEN:
            out.append(f"{k} en az {MIN_SECRET_LEN} karakter olmalı")
    dk = (e.get("DATA_ENCRYPTION_KEY") or "").strip()
    if not dk:
        out.append("DATA_ENCRYPTION_KEY tanımlı değil")
    else:
        try:
            from cryptography.fernet import Fernet
            Fernet(dk.encode())
        except Exception:
            out.append("DATA_ENCRYPTION_KEY geçerli bir Fernet anahtarı değil")

    # 2) Veritabanı
    if not (e.get("DATABASE_URL") or "").strip():
        out.append("DATABASE_URL tanımlı değil (üretimde PostgreSQL zorunlu)")

    # 2b) .env.example'daki örnek değerler üretimde kalmamalı (herkesin okuyabildiği bir parola/anahtar olur)
    for k in PLACEHOLDER_CHECKED_KEYS:
        v = (e.get(k) or "").strip().lower()
        if v.startswith(PLACEHOLDER_PREFIX):
            out.append(f"{k} hâlâ .env.example'daki örnek değer; gerçek, rastgele bir değerle değiştirin")

    # 3) Herkese açık adres: https ve yerel olmayan
    pu = (e.get("PUBLIC_URL") or "").strip()
    if not pu:
        out.append("PUBLIC_URL tanımlı değil")
    else:
        p = urlparse(pu)
        if p.scheme != "https":
            out.append("PUBLIC_URL https:// ile başlamalı")
        if (p.hostname or "") in LOCAL_HOSTS:
            out.append("PUBLIC_URL yerel bir adres olamaz")

    # 4) Hız sınırı durumu işçiler arasında paylaşılmalı
    try:
        workers = int((e.get("WEB_CONCURRENCY") or "2").strip() or "2")
    except ValueError:
        out.append("WEB_CONCURRENCY sayı olmalı")
        workers = 2
    if not (e.get("REDIS_URL") or "").strip() and not _flag(e, "DC_ALLOW_NO_REDIS"):
        out.append("REDIS_URL tanımlı değil: hız sınırı işçiler arasında paylaşılamaz "
                   f"(WEB_CONCURRENCY={workers}). Bilerek tek işçi ile çalışılacaksa DC_ALLOW_NO_REDIS=1 ve WEB_CONCURRENCY=1 verin")
    if not (e.get("REDIS_URL") or "").strip() and _flag(e, "DC_ALLOW_NO_REDIS") and workers > 1:
        out.append("DC_ALLOW_NO_REDIS=1 yalnızca WEB_CONCURRENCY=1 iken kabul edilir")

    # 5) Demo kapalı olmalı
    if _flag(e, "DC_ALLOW_HTTP_LOCAL"):
        out.append("DC_ALLOW_HTTP_LOCAL üretimde kapalı olmalı (çerezler Secure kalmalı)")

    # 6) Hasta görselleri kalıcı depoda olmalı
    backend = (e.get("MEDIA_BACKEND") or "local").strip().lower()
    if backend == "s3":
        for k in ("S3_BUCKET", "S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY"):
            if not (e.get(k) or "").strip():
                out.append(f"MEDIA_BACKEND=s3 iken {k} zorunlu")
    elif backend == "local":
        if not _flag(e, "DC_MEDIA_PERSISTENT"):
            out.append("MEDIA_BACKEND=local iken görsel klasörü kalıcı diske bağlanmalı; bağlandıysa DC_MEDIA_PERSISTENT=1 verin "
                       "(Render'da disk, Compose'ta volume). Alternatif: MEDIA_BACKEND=s3")
    else:
        out.append("MEDIA_BACKEND 'local' ya da 's3' olmalı")

    return out


def enforce_production_config(environ: Mapping[str, str] | None = None) -> None:
    """DC_ENV=production ise sorun varsa RuntimeError ile açılışı durdurur."""
    e = environ if environ is not None else os.environ
    if not is_production(e):
        return
    problems = production_problems(e)
    if problems:
        raise RuntimeError("Üretim yapılandırması geçersiz:\n - " + "\n - ".join(problems))
