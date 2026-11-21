"""Resmi Meta WhatsApp Cloud API istemcisi. Kimlik bilgisi yoksa gönderim yapılmaz, kuru çalıştırma kaydı döner."""
from __future__ import annotations

import hashlib
import hmac
import logging

import httpx

from . import meta_graph
from .core import env

log = logging.getLogger("wa")
# Sürüm merkezîdir: WA_GRAPH_VERSION (özel) > META_GRAPH_VERSION (paylaşılan) > meta_graph.DEFAULT_VERSION. Biçim bozuksa varsayılan.
VER = meta_graph.resolve_version(env("WA_GRAPH_VERSION"), env("META_GRAPH_VERSION"), label="wa")
meta_graph.check_version(VER, "wa")
PHONE_ID = env("WA_PHONE_NUMBER_ID")
TOKEN = env("WA_ACCESS_TOKEN")
APP_SECRET = env("WA_APP_SECRET")
GRAPH = f"https://graph.facebook.com/{VER}"
TPL_LANG = env("WA_TPL_LANG", "tr")
OUTSIDE_WINDOW_CODES = {131047, 131026}
_CLIENT: httpx.AsyncClient | None = None


def get_client() -> httpx.AsyncClient:
    global _CLIENT
    if _CLIENT is None or _CLIENT.is_closed:
        _CLIENT = httpx.AsyncClient(
            timeout=20.0,
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=32, keepalive_expiry=30.0),
        )
    return _CLIENT


async def close_client() -> None:
    global _CLIENT
    if _CLIENT is not None and not _CLIENT.is_closed:
        await _CLIENT.aclose()
    _CLIENT = None


def ready() -> bool:
    return bool(PHONE_ID and TOKEN)


def verify_signature(raw: bytes, header: str | None) -> bool:
    if not APP_SECRET:
        return False
    if not header or not header.startswith("sha256="):
        return False
    good = hmac.new(APP_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(good, header[7:])


async def _post(payload: dict) -> dict:
    to = str(payload.get("to", ""))
    if to.startswith("ig:"):
        # Instagram hastası: yalnızca serbest metin gönderilebilir (şablon/ses yok)
        if payload.get("type") == "text":
            from . import ig
            return await ig.send_text(to[3:], payload["text"]["body"])
        log.info("[ig] %s türü Instagram'a gönderilemez, atlandı", payload.get("type"))
        return {"skipped": "ig"}
    if not ready():
        log.info("[wa kuru] %s", payload.get("type"))
        return {"dry_run": True}
    return await meta_graph.call(get_client(), "POST", f"{GRAPH}/{PHONE_ID}/messages", channel="wa",
                                 headers={"Authorization": f"Bearer {TOKEN}"},
                                 json={"messaging_product": "whatsapp", **payload})


async def send_text(to: str, body: str) -> dict:
    return await _post({"to": to, "type": "text", "text": {"preview_url": False, "body": body[:4000]}})


async def send_template(to: str, name: str, params: list[str] | None = None, lang: str | None = None,
                        quick_reply_payloads: list[str] | None = None) -> dict:
    comps = []
    if params:
        comps.append({"type": "body", "parameters": [{"type": "text", "text": str(p)[:1000]} for p in params]})
    for i, pl in enumerate(quick_reply_payloads or []):
        comps.append({"type": "button", "sub_type": "quick_reply", "index": str(i), "parameters": [{"type": "payload", "payload": pl}]})
    return await _post({"to": to, "type": "template",
                        "template": {"name": name, "language": {"code": lang or TPL_LANG}, "components": comps}})


async def send_text_or_template(to: str, text: str, tpl: str, params: list[str]) -> dict:
    r = await send_text(to, text)
    code = (r.get("error") or {}).get("code")
    if code in OUTSIDE_WINDOW_CODES and tpl:
        return await send_template(to, tpl, params)
    return r


async def upload_media(data: bytes, mime: str, filename: str) -> str | None:
    if not ready():
        return None
    res = await meta_graph.call(get_client(), "POST", f"{GRAPH}/{PHONE_ID}/media", channel="wa",
                                headers={"Authorization": f"Bearer {TOKEN}"},
                                data={"messaging_product": "whatsapp", "type": mime},
                                files={"file": (filename, data, mime)})
    mid = res.get("id")
    return str(mid) if mid and not res.get("error") else None


async def send_audio(to: str, media_id: str) -> dict:
    return await _post({"to": to, "type": "audio", "audio": {"id": media_id}})


async def download_media(media_id: str) -> tuple[bytes, str] | None:
    """Medya baytlarını indirir. Herhangi bir hatada (token, 5xx, ağ, bozuk gövde) istisna fırlatmaz, None döner."""
    c = get_client()
    auth = {"Authorization": f"Bearer {TOKEN}"}
    meta = await meta_graph.call(c, "GET", f"{GRAPH}/{media_id}", channel="wa", headers=auth)
    url = meta.get("url")
    if meta.get("error") or not isinstance(url, str) or not url:
        return None
    try:
        r = await c.get(url, headers=auth)
    except (httpx.HTTPError, httpx.InvalidURL) as ex:
        log.warning("[wa] medya indirilemedi: %s: %s", type(ex).__name__, str(ex)[:200])
        return None
    if r.status_code >= 400:
        log.warning("[wa] medya indirme HTTP %s", r.status_code)
        return None
    return r.content, str(meta.get("mime_type") or "application/octet-stream")
