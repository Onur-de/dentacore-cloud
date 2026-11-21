"""Meta Graph API istemcisi (api/app/meta_graph.py) ve onu kullanan wa.py / ig.py testleri.

Hiçbir test gerçek Meta ucuna bağlanmaz ve gerçek WhatsApp/Instagram mesajı göndermez: tüm HTTP trafiği
`httpx.MockTransport` ile yakalanır. Kapsam: sürüm çözümleme, sona erme uyarısı, HTML 502 gövdesi, ağ/zaman aşımı,
süresi dolmuş token (kod 190/102) ve günlük kısıtlama, wa/ig çağrılarının istisna fırlatmaması, webhook akışının sürmesi.
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
import types
from datetime import date
from pathlib import Path

import httpx
import pytest
from cryptography.fernet import Fernet

# test_offline.py ile aynı kurulum: gerçek psycopg varsa kullan, yoksa bellekte stubla; ortam değişkenleri aynı değerler.
try:
    import psycopg  # noqa: F401
    import psycopg.rows  # noqa: F401
    import psycopg_pool  # noqa: F401
except ImportError:
    for _m in ("psycopg", "psycopg.rows", "psycopg_pool"):
        sys.modules.pop(_m, None)
    sys.modules["psycopg"] = types.ModuleType("psycopg")
    sys.modules["psycopg.rows"] = types.SimpleNamespace(dict_row=None)
    sys.modules["psycopg_pool"] = types.SimpleNamespace(AsyncConnectionPool=object)

os.environ["CLINIC_NAME"] = "Test Klinik"
os.environ["DATA_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ["PHONE_HMAC_KEY"] = "test-hmac-key-32-bytes-minimum-ok"
os.environ["ADMIN_TOKEN"] = "test-admin-token-32-bytes-minimum"
os.environ["WA_APP_SECRET"] = "wa-secret-test"
os.environ["IG_APP_SECRET"] = "ig-secret-test"

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
sys.path.insert(0, str(ROOT / "lead_hunter"))

from app import ig, main, meta_graph, wa  # noqa: E402

GRAPH_URL = "https://graph.test/v0.0/x"
TOKEN_ERR_BODY = {"error": {"message": "Error validating access token: Session has expired", "type": "OAuthException", "code": 190}}


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0)


def _patch_client(monkeypatch, module, handler) -> list[httpx.Request]:
    """module.get_client() yerine MockTransport'lu istemci koyar; görülen istekleri döner."""
    seen: list[httpx.Request] = []
    holder: dict = {}

    def wrapped(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return handler(req)

    def get_client() -> httpx.AsyncClient:
        if "c" not in holder:
            holder["c"] = _client(wrapped)
        return holder["c"]

    monkeypatch.setattr(module, "get_client", get_client)
    return seen


def _html_502(_req: httpx.Request) -> httpx.Response:
    return httpx.Response(502, text="<html><body><h1>502 Bad Gateway</h1></body></html>", headers={"content-type": "text/html"})


def _timeout(_req: httpx.Request) -> httpx.Response:
    raise httpx.ConnectTimeout("zaman asimi")


def _token_expired(_req: httpx.Request) -> httpx.Response:
    return httpx.Response(401, json=TOKEN_ERR_BODY)


@pytest.fixture(autouse=True)
def _reset_auth_throttle():
    meta_graph._last_auth_log.clear()
    yield
    meta_graph._last_auth_log.clear()


@pytest.fixture
def wa_ready(monkeypatch):
    monkeypatch.setattr(wa, "TOKEN", "test-token")
    monkeypatch.setattr(wa, "PHONE_ID", "111222333")


@pytest.fixture
def ig_ready(monkeypatch):
    monkeypatch.setattr(ig, "TOKEN", "test-ig-token")


# ---------------------------------------------------------------- sürüm çözümleme

@pytest.mark.parametrize("candidates, beklenen", [
    (("", ""), meta_graph.DEFAULT_VERSION),
    (("v22.0", ""), "v22.0"),
    (("", "v23.0"), "v23.0"),
    (("v22.0", "v25.0"), "v22.0"),   # kanala özel değer paylaşılanı geçer
    (("   ", "v24.0"), "v24.0"),     # yalnız boşluk boş sayılır
    (("25.0", ""), "v25.0"),         # baştaki v unutulmuşsa tamamlanır
    ((" v21.0 ", ""), "v21.0"),
])
def test_resolve_version_gecerli(candidates, beklenen):
    assert meta_graph.resolve_version(*candidates, label="t") == beklenen


@pytest.mark.parametrize("bozuk", ["abc", "v25", "v25.0.1", "latest", "v2x.0", "../v25.0", "v25.0/me"])
def test_resolve_version_bozuk_bicim_varsayilana_doner(bozuk, caplog):
    with caplog.at_level(logging.ERROR, logger="meta_graph"):
        assert meta_graph.resolve_version(bozuk, "", label="t") == meta_graph.DEFAULT_VERSION
    assert any("gecersiz" in r.getMessage() for r in caplog.records)


def test_wa_ve_ig_surumu_gecerli_bicimde():
    import re
    assert re.fullmatch(r"v\d{1,2}\.\d{1,2}", wa.VER) and re.fullmatch(r"v\d{1,2}\.\d{1,2}", ig.VER)
    assert wa.GRAPH == f"https://graph.facebook.com/{wa.VER}"
    assert ig.GRAPH == f"https://graph.instagram.com/{ig.VER}"


# ---------------------------------------------------------------- sona erme uyarısı

def test_version_warning_tablosu():
    bugun = date(2026, 11, 21)
    assert "sona erdi" in (meta_graph.version_warning("v20.0", today=bugun) or "")      # geçmiş
    uyari = meta_graph.version_warning("v21.0", today=bugun) or ""                       # 61 gün kaldı
    assert "sona erecek" in uyari and "61 gun" in uyari
    assert meta_graph.version_warning("v25.0", today=bugun) is None                      # temiz
    assert meta_graph.version_warning("v99.0", today=bugun) is None                      # tabloda yok


def test_version_warning_esik_siniri():
    son = meta_graph.SUNSET["v22.0"]
    assert meta_graph.version_warning("v22.0", today=date.fromordinal(son.toordinal() - meta_graph.WARN_DAYS))
    assert meta_graph.version_warning("v22.0", today=date.fromordinal(son.toordinal() - meta_graph.WARN_DAYS - 1)) is None
    assert "sona erdi" in meta_graph.version_warning("v22.0", today=date.fromordinal(son.toordinal() + 1))


def test_check_version_log_yazar(monkeypatch, caplog):
    class SabitTarih(date):
        @classmethod
        def today(cls):
            return cls(2026, 11, 21)

    monkeypatch.setattr(meta_graph, "date", SabitTarih)
    with caplog.at_level(logging.WARNING, logger="meta_graph"):
        meta_graph.check_version("v25.0", "wa")
        assert not caplog.records
        meta_graph.check_version("v21.0", "wa")
        meta_graph.check_version("v20.0", "ig")
    mesajlar = [r.getMessage() for r in caplog.records]
    assert len(mesajlar) == 2
    assert "sona erecek" in mesajlar[0] and "sona erdi" in mesajlar[1]
    assert all(r.levelno == logging.WARNING for r in caplog.records)


# ---------------------------------------------------------------- meta_graph.call: hata normalleştirme

def _call(handler, **kw) -> dict:
    async def go():
        async with _client(handler) as c:
            return await meta_graph.call(c, "POST", GRAPH_URL, channel="t", json={"a": 1}, **kw)
    return asyncio.run(go())


def test_call_basari_govdeyi_doner():
    assert _call(lambda r: httpx.Response(200, json={"messages": [{"id": "wamid.1"}]})) == {"messages": [{"id": "wamid.1"}]}


def test_call_html_502_istisna_firlatmaz():
    res = _call(_html_502)
    assert res["error"]["code"] == "http_502" and res["error"]["http_status"] == 502
    assert not meta_graph.is_auth_error(res["error"])


@pytest.mark.parametrize("istisna", [httpx.ConnectTimeout("t"), httpx.ReadTimeout("t"), httpx.ConnectError("ret"), httpx.RemoteProtocolError("kesildi")])
def test_call_ag_hatalari_donusur(istisna):
    def h(_r):
        raise istisna
    res = _call(h)
    assert res["error"]["type"] == "transport" and res["error"]["code"] == "transport"
    assert type(istisna).__name__ in res["error"]["message"]


def test_call_200_govdede_error_alani_hata_sayilir():
    res = _call(lambda r: httpx.Response(200, json={"error": {"message": "x", "type": "OAuthException", "code": 100}}))
    assert res["error"]["code"] == 100


def test_call_bos_5xx_govde_bos_olmayan_hata_dondurur():
    res = _call(lambda r: httpx.Response(500, content=b""))
    assert res["error"] and res["error"]["code"] == "http_500"


@pytest.mark.parametrize("kod, durum", [(190, 401), (190, 400), (102, 400)])
def test_call_token_suresi_doldu(kod, durum):
    res = _call(lambda r: httpx.Response(durum, json={"error": {"message": "oturum", "type": "OAuthException", "code": kod}}))
    assert res["error"]["code"] == kod and meta_graph.is_auth_error(res["error"])


def test_token_hatasi_log_kisitlanir(caplog):
    with caplog.at_level(logging.INFO, logger="meta_graph"):
        for _ in range(5):
            _call(_token_expired)
        errors = [r for r in caplog.records if r.levelno == logging.ERROR]
        assert len(errors) == 1 and "190" in errors[0].getMessage()
        meta_graph._last_auth_log["t"] = time.monotonic() - meta_graph._AUTH_LOG_EVERY_S - 1  # pencere doldu
        _call(_token_expired)
        assert len([r for r in caplog.records if r.levelno == logging.ERROR]) == 2


def test_token_logu_token_degerini_sizdirmaz(caplog):
    with caplog.at_level(logging.DEBUG, logger="meta_graph"):
        async def go():
            async with _client(_token_expired) as c:
                return await meta_graph.call(c, "POST", GRAPH_URL, channel="t", headers={"Authorization": "Bearer GIZLI-DEGER"})
        asyncio.run(go())
    assert "GIZLI-DEGER" not in caplog.text


# ---------------------------------------------------------------- wa.py

def test_wa_gonderim_basari_ve_istek_bicimi(monkeypatch, wa_ready):
    seen = _patch_client(monkeypatch, wa, lambda r: httpx.Response(200, json={"messages": [{"id": "wamid.9"}]}))
    res = asyncio.run(wa.send_text("905321112233", "Merhaba"))
    assert res == {"messages": [{"id": "wamid.9"}]}
    assert len(seen) == 1
    assert str(seen[0].url) == f"{wa.GRAPH}/111222333/messages"
    assert seen[0].headers["authorization"] == "Bearer test-token"


@pytest.mark.parametrize("handler", [_html_502, _timeout, _token_expired], ids=["html502", "zaman_asimi", "token190"])
def test_wa_send_text_hicbir_hatada_istisna_firlatmaz(monkeypatch, wa_ready, handler):
    _patch_client(monkeypatch, wa, handler)
    res = asyncio.run(wa.send_text("905321112233", "Merhaba"))
    assert isinstance(res, dict) and res["error"]


def test_wa_hazir_degilse_kuru_calisir(monkeypatch):
    monkeypatch.setattr(wa, "TOKEN", "")
    monkeypatch.setattr(wa, "PHONE_ID", "")
    assert asyncio.run(wa.send_text("905321112233", "x")) == {"dry_run": True}


def test_wa_pencere_disi_sablona_duser(monkeypatch, wa_ready):
    n = {"i": 0}

    def h(req):
        n["i"] += 1
        if n["i"] == 1:
            return httpx.Response(400, json={"error": {"message": "pencere disi", "type": "OAuthException", "code": 131047}})
        return httpx.Response(200, json={"messages": [{"id": "wamid.t"}]})
    seen = _patch_client(monkeypatch, wa, h)
    res = asyncio.run(wa.send_text_or_template("905321112233", "metin", "randevu_hatirlatma", ["a"]))
    assert res == {"messages": [{"id": "wamid.t"}]} and len(seen) == 2
    assert b'"template"' in seen[1].content


def test_wa_ig_hastasina_giderken_ig_hatasi_istisna_olmaz(monkeypatch, ig_ready):
    _patch_client(monkeypatch, ig, _timeout)
    res = asyncio.run(wa.send_text("ig:17841400000000000", "Merhaba"))
    assert res["error"]["type"] == "transport"


def test_wa_upload_media(monkeypatch, wa_ready):
    seen = _patch_client(monkeypatch, wa, lambda r: httpx.Response(200, json={"id": "MEDYA1"}))
    assert asyncio.run(wa.upload_media(b"OggS", "audio/ogg", "mesaj.ogg")) == "MEDYA1"
    assert str(seen[0].url).endswith("/111222333/media")


@pytest.mark.parametrize("handler", [_html_502, _timeout, _token_expired, lambda r: httpx.Response(200, json={})],
                         ids=["html502", "zaman_asimi", "token190", "id_yok"])
def test_wa_upload_media_hatada_none_doner(monkeypatch, wa_ready, handler):
    _patch_client(monkeypatch, wa, handler)
    assert asyncio.run(wa.upload_media(b"OggS", "audio/ogg", "mesaj.ogg")) is None


def test_wa_download_media_basari(monkeypatch, wa_ready):
    def h(req):
        if req.url.host == "graph.facebook.com":
            return httpx.Response(200, json={"url": "https://lookaside.test/m/1", "mime_type": "image/jpeg"})
        return httpx.Response(200, content=b"\xff\xd8\xffJPEG")
    seen = _patch_client(monkeypatch, wa, h)
    assert asyncio.run(wa.download_media("MEDYA1")) == (b"\xff\xd8\xffJPEG", "image/jpeg")
    assert all(r.headers["authorization"] == "Bearer test-token" for r in seen)


def _indirme_iki_asama(ilk, ikinci):
    def h(req):
        return ilk(req) if req.url.host == "graph.facebook.com" else ikinci(req)
    return h


@pytest.mark.parametrize("handler", [
    _indirme_iki_asama(_token_expired, _html_502),
    _indirme_iki_asama(_html_502, _html_502),
    _indirme_iki_asama(_timeout, _timeout),
    _indirme_iki_asama(lambda r: httpx.Response(200, json={}), _html_502),
    _indirme_iki_asama(lambda r: httpx.Response(200, json={"url": "https://l.test/m", "mime_type": "image/png"}), _html_502),
    _indirme_iki_asama(lambda r: httpx.Response(200, json={"url": "https://l.test/m"}), _timeout),
], ids=["token190", "html502", "ag_hatasi", "url_yok", "indirme_502", "indirme_zaman_asimi"])
def test_wa_download_media_hatada_none_doner(monkeypatch, wa_ready, handler):
    _patch_client(monkeypatch, wa, handler)
    assert asyncio.run(wa.download_media("MEDYA1")) is None


# ---------------------------------------------------------------- ig.py

def test_ig_gonderim_basari(monkeypatch, ig_ready):
    seen = _patch_client(monkeypatch, ig, lambda r: httpx.Response(200, json={"recipient_id": "1", "message_id": "m1"}))
    res = asyncio.run(ig.send_text("1784", "Merhaba"))
    assert res == {"recipient_id": "1", "message_id": "m1"}
    assert str(seen[0].url) == f"{ig.GRAPH}/me/messages"
    assert seen[0].headers["authorization"] == "Bearer test-ig-token"


@pytest.mark.parametrize("handler", [_html_502, _timeout, _token_expired], ids=["html502", "zaman_asimi", "token190"])
def test_ig_send_text_hicbir_hatada_istisna_firlatmaz(monkeypatch, ig_ready, handler):
    _patch_client(monkeypatch, ig, handler)
    res = asyncio.run(ig.send_text("1784", "Merhaba"))
    assert isinstance(res, dict) and res["error"]


def test_ig_hazir_degilse_kuru_calisir(monkeypatch):
    monkeypatch.setattr(ig, "TOKEN", "")
    assert asyncio.run(ig.send_text("1784", "x")) == {"dry_run": True}


# ---------------------------------------------------------------- webhook akışı

def test_gorsel_mesaji_meta_cokunce_webhook_isleyicisi_cokmez(monkeypatch, wa_ready):
    """Görsel indirme 502 + yanıt gönderimi token hatası: handle_message istisna fırlatmaz, giden kayıt 'failed' yazılır."""
    def h(req):
        if req.method == "GET":
            return _html_502(req)
        return _token_expired(req)
    seen = _patch_client(monkeypatch, wa, h)
    loglar: list[tuple] = []

    async def sahte_upsert(phone, lang=None, name=None, clinic_id=1):
        return 7

    async def sahte_log_msg(*a, **kw):
        loglar.append((a, kw))

    async def sahte_riza(*a, **kw):
        return True

    monkeypatch.setattr(main, "upsert_patient", sahte_upsert)
    monkeypatch.setattr(main, "log_msg", sahte_log_msg)
    monkeypatch.setattr(main, "has_consent", sahte_riza)
    monkeypatch.setitem(main.state, "router", object())

    mesaj = {"from": "905321112233", "id": "wamid.in1", "type": "image", "image": {"id": "MEDYA1", "mime_type": "image/jpeg"}}
    asyncio.run(main.handle_message(mesaj, "Ayşe", channel="wa", clinic_id=1))

    assert [r.method for r in seen] == ["GET", "POST"]
    giden = [kw for a, kw in loglar if len(a) > 1 and a[1] == "out"]
    assert len(giden) == 1 and giden[0]["delivery_status"] == "failed" and giden[0]["delivery_error"]
    assert "190" in giden[0]["delivery_error"]
    assert any(len(a) > 3 and a[3] == "gorsel_invalid" for a, _kw in loglar)
