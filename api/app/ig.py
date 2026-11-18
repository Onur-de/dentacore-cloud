"""Instagram DM kanalı (Instagram API with Instagram Login). Kimlik bilgisi yoksa gönderim yapılmaz, kuru çalıştırma kaydı döner."""
from __future__ import annotations

import hashlib
import hmac
import logging

import httpx

from .core import env

log = logging.getLogger("ig")
VER = env("IG_GRAPH_VERSION", "v21.0")
TOKEN = env("IG_ACCESS_TOKEN")
APP_SECRET = env("IG_APP_SECRET") or env("WA_APP_SECRET")
GRAPH = f"https://graph.instagram.com/{VER}"


def ready() -> bool:
    return bool(TOKEN)


def verify_signature(raw: bytes, header: str | None) -> bool:
    if not APP_SECRET or not header or not header.startswith("sha256="):
        return False
    good = hmac.new(APP_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(good, header[7:])


async def send_text(igsid: str, body: str) -> dict:
    if not ready():
        log.info("[ig kuru] metin")
        return {"dry_run": True}
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.post(f"{GRAPH}/me/messages", headers={"Authorization": f"Bearer {TOKEN}"},
                         json={"recipient": {"id": igsid}, "message": {"text": body[:1000]}})
        j = r.json()
        if r.status_code >= 400:
            log.warning("IG hata %s: %s", r.status_code, j)
            return {"error": j.get("error", {})}
        return j
