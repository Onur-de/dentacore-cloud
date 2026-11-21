"""Meta Graph API: merkezî sürüm yapılandırması ve hata normalleştirme (WhatsApp Cloud API + Instagram DM).

Amaç: geçersiz/süresi dolmuş sürüm, süresi dolmuş token, Meta tarafında 5xx/HTML gövde ya da ağ hatası uygulamanın
geri kalanını veya webhook işçisini ÇÖKERTMESİN. Her çağrı dict döner; hata `{"error": {...}}` biçimindedir
(çağıranlar zaten `res.get("error")` ile bakar).
"""
from __future__ import annotations

import logging
import re
import time
from datetime import date

import httpx

log = logging.getLogger("meta_graph")

# Kaynak: https://developers.facebook.com/docs/graph-api/changelog/versions/ (2026-11-21'de okundu).
# v26.0 (29 Tem 2026) güncel sürümdür, sona erme tarihi yayımlanmamıştır. v25.0: 29 Tem 2028'e kadar.
# Bu tablo YALNIZCA uyarı içindir; Meta süresi dolan sürümü sessizce sonraki desteklenen sürüme yönlendirir.
DEFAULT_VERSION = "v25.0"
SUNSET: dict[str, date] = {
    "v20.0": date(2026, 9, 24),
    "v21.0": date(2027, 1, 21),
    "v22.0": date(2027, 5, 20),
    "v23.0": date(2027, 10, 8),
    "v24.0": date(2028, 2, 18),
    "v25.0": date(2028, 7, 29),
}
WARN_DAYS = 90
AUTH_CODES = {190, 102}  # 190: token geçersiz/süresi dolmuş; 102: oturum
_VER_RE = re.compile(r"^v\d{1,2}\.\d{1,2}$")
_AUTH_LOG_EVERY_S = 600
_last_auth_log: dict[str, float] = {}


def resolve_version(*candidates: str, label: str) -> str:
    """İlk dolu adayı (özel ortam değişkeni, sonra paylaşılan) alır; biçim bozuksa varsayılana döner ve loglar."""
    raw = next((c.strip() for c in candidates if c and c.strip()), "")
    if not raw:
        return DEFAULT_VERSION
    if re.fullmatch(r"\d{1,2}\.\d{1,2}", raw):
        raw = "v" + raw
    if not _VER_RE.match(raw):
        log.error("[%s] gecersiz Graph API surumu %r (vNN.N bekleniyor); %s kullaniliyor", label, raw, DEFAULT_VERSION)
        return DEFAULT_VERSION
    return raw


def version_warning(version: str, *, today: date | None = None) -> str | None:
    """Sürüm sona ermişse ya da WARN_DAYS içinde sona erecekse açıklayıcı mesaj döner; yoksa None."""
    end = SUNSET.get(version)
    if end is None:
        return None
    left = (end - (today or date.today())).days
    if left < 0:
        return f"Graph API {version} {end.isoformat()} tarihinde sona erdi; Meta cagrilari sessizce sonraki surume yonlendirir. META_GRAPH_VERSION'u guncelleyin."
    if left <= WARN_DAYS:
        return f"Graph API {version} {end.isoformat()} tarihinde sona erecek ({left} gun kaldi). META_GRAPH_VERSION'u guncelleyin."
    return None


def check_version(version: str, label: str) -> None:
    msg = version_warning(version)
    if msg:
        log.warning("[%s] %s", label, msg)


def safe_json(r: httpx.Response) -> dict:
    try:
        j = r.json()
    except ValueError:  # JSON olmayan gövde (HTML 502, boş yanıt vb.)
        return {}
    return j if isinstance(j, dict) else {}


def api_error(status: int, body: dict) -> dict:
    """Her zaman BOŞ OLMAYAN dict: çağıranlar `if res.get("error")` ile başarısızlığı anlar."""
    err = body.get("error")
    if isinstance(err, dict) and err:
        out = dict(err)
        out.setdefault("http_status", status)
        return out
    return {"message": f"HTTP {status}", "type": "http", "code": f"http_{status}", "http_status": status}


def transport_error(exc: Exception) -> dict:
    return {"message": f"{type(exc).__name__}: {exc}"[:300], "type": "transport", "code": "transport"}


def is_auth_error(err: dict) -> bool:
    return err.get("code") in AUTH_CODES or err.get("http_status") == 401


def _note_auth_failure(channel: str, err: dict) -> None:
    now = time.monotonic()
    if now - _last_auth_log.get(channel, -1e9) >= _AUTH_LOG_EVERY_S:
        _last_auth_log[channel] = now
        log.error("[%s] Meta erisim anahtari gecersiz/suresi dolmus (kod=%s): %s. Gonderimler basarisiz olacak; "
                  "token'i yenileyin. (Bu uyari %d sn'de bir tekrarlanir.)", channel, err.get("code"), err.get("message"), _AUTH_LOG_EVERY_S)


async def call(client: httpx.AsyncClient, method: str, url: str, *, channel: str, **kw) -> dict:
    """HTTP çağrısı; ASLA istisna fırlatmaz (görev iptali hariç). Hata -> {"error": {...}}, başarı -> yanıt gövdesi."""
    try:
        r = await client.request(method, url, **kw)
    except (httpx.HTTPError, httpx.InvalidURL) as ex:
        err = transport_error(ex)
        log.warning("[%s] Meta'ya ulasilamadi: %s", channel, err["message"])
        return {"error": err}
    body = safe_json(r)
    if r.status_code >= 400 or (isinstance(body.get("error"), dict) and body["error"]):
        err = api_error(r.status_code, body)
        if is_auth_error(err):
            _note_auth_failure(channel, err)
        else:
            log.warning("[%s] Meta hata %s: %s", channel, r.status_code, {k: err.get(k) for k in ("code", "type", "message")})
        return {"error": err}
    return body
