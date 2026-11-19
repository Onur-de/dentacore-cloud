"""DentaCore v7 sertleştirme regresyon paketi (OWASP ASVS L2 / CheatSheetSeries / WSTG uyumlu).

Her test, `test_scale_100_and_cloud_demo.py` ile aynı izole kalıbı kullanır: geçici SQLite DB,
sıfırlanmış hız sınırlayıcı ve `rl.app` üzerine kurulu `TestClient`. Canlı `dentacore_local.db`
ve `.local_secrets.json` dosyalarına dokunulmaz.

Rate limit testleri dosyanın EN SONUNDADIR; her test kendi temiz sınırlayıcısıyla çalışır.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("WA_APP_SECRET", "hardening_v7_webhook_secret_key_2026")
os.environ.setdefault("IG_APP_SECRET", "hardening_v7_webhook_secret_key_2026")
os.environ.setdefault("DC_WEBHOOK_RATE_LIMIT", "5000")

import run_local as rl  # noqa: E402

HQ_CREDS = ("yonetici@dentacore.com", "DentaCore2026!")
SEC_CREDS = ("sekreter@dentacore.com", "DentaCore2026!")
BURSA_CREDS = ("klinik@bursadis.com", "BursaDis2026!")


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(rl, "DB_PATH", tmp_path / "hardening_v7.db")
    monkeypatch.setattr(rl, "_CONN", None)
    monkeypatch.setenv("DC_MEDIA_DIR", str(tmp_path / "media_v7"))
    monkeypatch.setenv("DC_WEBHOOK_RATE_LIMIT", "5000")
    monkeypatch.setenv("DC_ALLOW_HTTP_LOCAL", "1")
    monkeypatch.delenv("TRUSTED_PROXY", raising=False)
    monkeypatch.delenv("TRUSTED_PROXY_HOPS", raising=False)
    rl._SEEN_WEBHOOK_IDS = rl.sec.WebhookDedupCache(max_size=10_000, ttl_seconds=86_400)
    rl._LIMITER = rl.sec.RateLimiter()
    rl.init_and_seed()
    yield
    if rl._CONN is not None:
        rl._CONN.close()
        rl._CONN = None


def _fresh_limiter() -> None:
    rl._LIMITER = rl.sec.RateLimiter()


def _client() -> TestClient:
    return TestClient(rl.app, base_url="https://testserver", raise_server_exceptions=False)


def _login(email: str, password: str) -> tuple[TestClient, dict]:
    c = _client()
    r = c.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, f"Giriş başarısız ({email}): {r.status_code} {r.text}"
    return c, {"X-CSRF-Token": r.json()["csrf"]}


def _next_weekday(min_days: int, hour: int, minute: int) -> datetime:
    dt = (datetime.now(rl.TZ) + timedelta(days=min_days)).replace(hour=hour, minute=minute, second=0, microsecond=0)
    while dt.weekday() >= 5:
        dt += timedelta(days=1)
    return dt


def _next_sunday(min_days: int, hour: int = 12) -> datetime:
    dt = (datetime.now(rl.TZ) + timedelta(days=min_days)).replace(hour=hour, minute=0, second=0, microsecond=0)
    while dt.weekday() != 6:
        dt += timedelta(days=1)
    return dt


def _book_body(phone: str, starts: datetime, **extra) -> dict:
    body = {
        "name": "Hardening Test Hasta",
        "phone": phone,
        "starts_at": starts.isoformat(),
        "treatment": "İlk Muayene",
        "kvkk_consent": True,
    }
    body.update(extra)
    return body


def _create_patient(hq: TestClient, hdr: dict, phone: str, name: str = "V7 Test Hasta") -> int:
    r = hq.post("/app/api/patients", json={"name": name, "phone": phone, "first_source": "walk_in"}, headers=hdr)
    assert r.status_code == 200, r.text
    return int(r.json()["id"])


# ---------------------------------------------------------------------------
# 1) X-Forwarded-For: sağdan proxy hop
# ---------------------------------------------------------------------------
def test_xff_rightmost_hop_unit_and_lead_rate_limit_cannot_be_spoofed(env, monkeypatch):
    # Birim: TRUSTED_PROXY=1 iken liste SAĞDAN okunur, soldaki sahte IP'ler hesaba katılmaz
    monkeypatch.setenv("TRUSTED_PROXY", "1")
    assert rl.sec.client_ip_from("6.6.6.6, 198.51.100.7", "10.0.0.1") == "198.51.100.7"
    assert rl.sec.client_ip_from("1.1.1.1, 2.2.2.2, 198.51.100.7", "10.0.0.1") == "198.51.100.7"
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "2")
    assert rl.sec.client_ip_from("1.1.1.1, 2.2.2.2, 198.51.100.7", "10.0.0.1") == "2.2.2.2"
    monkeypatch.delenv("TRUSTED_PROXY_HOPS", raising=False)
    # Güvenilir proxy kapalıysa başlık tamamen yok sayılır
    monkeypatch.delenv("TRUSTED_PROXY", raising=False)
    assert rl.sec.client_ip_from("6.6.6.6", "10.0.0.1") == "10.0.0.1"

    lead = {"clinic": "XFF Hop Test", "contact": "05320001122", "kvkk_aydinlatma": True}

    # Davranış A: TRUSTED_PROXY=1, sağdaki hop sabit, soldaki sahte IP her istekte farklı -> yine 429
    monkeypatch.setenv("TRUSTED_PROXY", "1")
    _fresh_limiter()
    c = _client()
    statuses = [
        c.post("/lead", json=lead, headers={"X-Forwarded-For": f"203.0.113.{i + 1}, 198.51.100.7"}).status_code
        for i in range(14)
    ]
    assert 429 in statuses, f"Sola sahte IP eklemek /lead hız sınırını atlatmamalı: {statuses}"

    # Davranış B: TRUSTED_PROXY kapalı, tamamen sahte XFF değerleri -> yine 429
    monkeypatch.delenv("TRUSTED_PROXY", raising=False)
    _fresh_limiter()
    statuses_b = [
        c.post("/lead", json=lead, headers={"X-Forwarded-For": f"198.51.100.{i + 20}"}).status_code
        for i in range(14)
    ]
    assert 429 in statuses_b, f"Güvenilmeyen modda XFF sahteciliği 429'u atlatmamalı: {statuses_b}"


# ---------------------------------------------------------------------------
# 2) GET/POST /randevu/merkez
# ---------------------------------------------------------------------------
def test_randevu_merkez_real_html_form_and_post(env):
    c = _client()
    g = c.get("/randevu/merkez")
    assert g.status_code == 200
    assert "text/html" in g.headers.get("content-type", "")
    page = g.text
    low = page.lower()
    assert "<form" in low and "<input" in low
    assert 'name="kvkk_consent"' in page
    # Honeypot: görünmez, odaklanamaz, erişilebilirlik ağacından gizli
    assert 'name="website"' in page and 'tabindex="-1"' in page and 'aria-hidden="true"' in page
    # CSP script-src 'self': inline script veya olay işleyici bulunmamalı
    assert "<script" not in low
    assert not re.search(r"\son[a-z]+\s*=", low)

    start = _next_weekday(9, 10, 30)
    ok = c.post("/randevu/merkez", data={
        "name": "Form Hasta", "phone": "05325550101", "starts_at": start.strftime("%Y-%m-%dT%H:%M"),
        "treatment": "İlk Muayene", "kvkk_consent": "1", "website": "",
    })
    assert ok.status_code == 200, ok.text[:300]
    assert "Randevunuz Oluşturuldu" in ok.text

    # KVKK onayı olmadan randevu oluşmaz
    no_kvkk = c.post("/randevu/merkez", data={
        "name": "Form Hasta Iki", "phone": "05325550102", "starts_at": start.strftime("%Y-%m-%dT%H:%M"),
        "treatment": "İlk Muayene", "website": "",
    })
    assert no_kvkk.status_code == 400


# ---------------------------------------------------------------------------
# 3) POST /api/public/book/merkez
# ---------------------------------------------------------------------------
def test_public_book_past_sunday_after_hours_422(env):
    c = _client()
    past = (datetime.now(rl.TZ) - timedelta(days=2)).replace(hour=11, minute=0, second=0, microsecond=0)
    assert c.post("/api/public/book/merkez", json=_book_body("05326660001", past)).status_code == 422
    assert c.post("/api/public/book/merkez", json=_book_body("05326660002", _next_sunday(4))).status_code == 422
    night = _next_weekday(5, 3, 0)
    assert c.post("/api/public/book/merkez", json=_book_body("05326660003", night)).status_code == 422


def test_public_book_archived_patient_409_never_reactivated_and_no_patient_id_leak(env):
    hq, hdr = _login(*HQ_CREDS)
    phone = "+905321117788"
    pid = _create_patient(hq, hdr, phone, "Arşiv Hasta")
    rl.ex("UPDATE patients SET active=0 WHERE id=?", pid)

    anon = _client()
    start = _next_weekday(8, 11, 30)
    r = anon.post("/api/public/book/merkez", json=_book_body(phone, start))
    assert r.status_code == 409, r.text
    assert rl.q1("SELECT active FROM patients WHERE id=?", pid)["active"] == 0
    assert rl.q1("SELECT count(*) AS n FROM appointments WHERE patient_id=?", pid)["n"] == 0

    # Başarılı randevuda yanıt içinde patient_id sızmaz
    ok = anon.post("/api/public/book/merkez", json=_book_body("05327770011", _next_weekday(10, 14, 30)))
    assert ok.status_code == 200, ok.text
    body = ok.json()
    assert body["ok"] is True and body["appointment_id"]
    assert "patient_id" not in body and "patient_id" not in ok.text


def test_public_book_honeypot_creates_nothing(env):
    anon = _client()
    before_p = rl.q1("SELECT count(*) AS n FROM patients")["n"]
    before_a = rl.q1("SELECT count(*) AS n FROM appointments")["n"]
    r = anon.post(
        "/api/public/book/merkez",
        json=_book_body("05328880099", _next_weekday(12, 15, 0), website="http://spam.example"),
    )
    assert r.status_code == 200
    assert r.json().get("appointment_id") is None
    assert rl.q1("SELECT count(*) AS n FROM patients")["n"] == before_p
    assert rl.q1("SELECT count(*) AS n FROM appointments")["n"] == before_a


# ---------------------------------------------------------------------------
# 4) Yetki matrisi
# ---------------------------------------------------------------------------
def test_authorization_matrix_leads_drain_ecosystem(env):
    hq, hq_hdr = _login(*HQ_CREDS)
    sec_c, sec_hdr = _login(*SEC_CREDS)
    bursa, b_hdr = _login(*BURSA_CREDS)

    assert sec_c.get("/app/api/leads").status_code == 403
    assert bursa.get("/app/api/leads").status_code == 403
    assert hq.get("/app/api/leads").status_code == 200

    assert bursa.post("/app/api/admin/webhook-queue/drain", headers=b_hdr).status_code == 403
    assert hq.post("/app/api/admin/webhook-queue/drain", headers=hq_hdr).status_code == 200

    assert sec_c.get("/app/api/ecosystem-status").status_code == 403
    assert bursa.get("/app/api/ecosystem-status").status_code == 403
    assert hq.get("/app/api/ecosystem-status").status_code == 200


# ---------------------------------------------------------------------------
# 5) Takvim önbellek ve X-Request-ID
# ---------------------------------------------------------------------------
def test_calendar_ics_no_store_and_request_id_on_every_response(env):
    hq, _ = _login(*HQ_CREDS)
    links = hq.get("/app/api/calendar-links")
    assert links.status_code == 200
    assert links.headers.get("x-request-id")
    ics_path = "/" + links.json()["ics_url"].split("/", 3)[-1]

    anon = _client()
    feed = anon.get(ics_path)
    assert feed.status_code == 200
    assert "no-store" in feed.headers.get("cache-control", "").lower()
    assert feed.headers.get("x-request-id")

    # Başarılı, 404 ve yetkisiz yanıtların hepsinde X-Request-ID bulunur
    for resp in (anon.get("/health"), anon.get("/olmayan-yol-v7"), anon.get("/app/api/leads")):
        assert resp.headers.get("x-request-id"), f"X-Request-ID yok: {resp.status_code}"

    # İstemci güvenli bir kimlik gönderirse aynen döner; sahte karakterli kimlik yenilenir
    echo = anon.get("/health", headers={"X-Request-ID": "trace-abc_123"})
    assert echo.headers.get("x-request-id") == "trace-abc_123"
    bad = anon.get("/health", headers={"X-Request-ID": "bad id;<script>"})
    assert bad.headers.get("x-request-id") and bad.headers["x-request-id"] != "bad id;<script>"


# ---------------------------------------------------------------------------
# 6) /form/tedavi-onay/{token}: CSRF, imza uzunluğu, geçerli imza
# ---------------------------------------------------------------------------
def test_tedavi_onay_csrf_signer_length_and_valid_sign(env):
    hq, hdr = _login(*HQ_CREDS)
    pid = _create_patient(hq, hdr, "+905329990011", "Onam Hasta")
    cr = hq.post(
        f"/app/api/patients/{pid}/treatment-consents",
        json={"custom_items": [{"tooth_fdi": 11, "surface": "FULL", "procedure_name": "Dolgu", "amount": 1500}]},
        headers=hdr,
    )
    assert cr.status_code == 200, cr.text
    token = cr.json()["token"]
    form_path = f"/form/tedavi-onay/{token}"

    anon = _client()
    g = anon.get(form_path)
    assert g.status_code == 200
    assert "no-store" in g.headers.get("cache-control", "").lower()
    m = re.search(r'name="csrf_token" value="([^"]+)"', g.text)
    assert m, "Formda csrf_token gizli alanı bulunmalı"
    csrf = m.group(1)

    # CSRF eksik -> 403
    missing = anon.post(form_path, data={"accept_plan": "1", "signer_name": "Ayşe Yılmaz"})
    assert missing.status_code == 403
    # Geçersiz CSRF -> 403
    forged = anon.post(form_path, data={"csrf_token": "9999999999.deadbeef", "accept_plan": "1", "signer_name": "Ayşe Yılmaz"})
    assert forged.status_code == 403
    # signer_name 80 karakterden uzun -> 400
    too_long = anon.post(form_path, data={"csrf_token": csrf, "accept_plan": "1", "signer_name": "A" * 81})
    assert too_long.status_code == 400
    # Geçerli CSRF + geçerli imza -> 200
    ok = anon.post(form_path, data={"csrf_token": csrf, "accept_plan": "1", "signer_name": "Ayşe Yılmaz"})
    assert ok.status_code == 200
    assert rl.q1("SELECT status FROM treatment_consents WHERE token=?", token)["status"] == "signed"


# ---------------------------------------------------------------------------
# 7) /c/{code}: parametre enjeksiyonu Location başlığına sızmaz
# ---------------------------------------------------------------------------
def test_campaign_redirect_does_not_leak_injected_param(env):
    hq, hdr = _login(*HQ_CREDS)
    code = "v7-inj-test"
    r = hq.post(
        "/app/api/campaigns",
        json={"name": "V7 Enjeksiyon Kampanyası", "source": "instagram", "channel": "instagram", "code": code,
              "utm_source": "instagram", "utm_medium": "cpc", "utm_campaign": "v7_inj"},
        headers=hdr,
    )
    assert r.status_code == 200, r.text

    anon = _client()
    res = anon.get(f"/c/{code}?utm_source=ig%26inj=1", follow_redirects=False)
    assert res.status_code == 302, res.text
    loc = res.headers["location"]
    assert "&inj=1" not in loc, f"Ham enjeksiyon Location'a sızdı: {loc}"
    qs = parse_qs(urlparse(loc).query)
    assert "inj" not in qs
    assert qs["utm_source"] == ["ig&inj=1"]


# ---------------------------------------------------------------------------
# 8) İade idempotency
# ---------------------------------------------------------------------------
def test_refund_same_idempotency_key_is_idempotent_not_500(env):
    hq, hdr = _login(*HQ_CREDS)
    pid = _create_patient(hq, hdr, "+905329990022", "İade Hasta")
    pay_id = rl.ex(
        "INSERT INTO payments (clinic_id,patient_id,amount_kurus,method,created_at) VALUES (1,?,?,'nakit',?)",
        pid, 50000, rl.iso_now(),
    )
    body = {"amount": 100, "reason": "Hardening iade testi", "idempotency_key": "idem-v7-refund-001"}
    first = hq.post(f"/app/api/payments/{pay_id}/refund", json=body, headers=hdr)
    assert first.status_code == 200, first.text
    second = hq.post(f"/app/api/payments/{pay_id}/refund", json=body, headers=hdr)
    assert second.status_code == 200, second.text
    assert second.json().get("idempotent_replay") is True
    assert second.json()["refund_id"] == first.json()["refund_id"]
    n = rl.q1("SELECT count(*) AS n FROM payments WHERE refund_of_id=?", pay_id)["n"]
    assert n == 1, "Aynı anahtarla yalnız tek iade kaydı oluşmalı"


# ---------------------------------------------------------------------------
# 9) Rol değişiminde oturum iptali
# ---------------------------------------------------------------------------
def test_role_change_revokes_old_session_immediately(env):
    hq, hdr = _login(*HQ_CREDS)
    email = "rol.degisim.v7@dentacore.com"
    pw = "StrongRoleChange2026!"
    st = hq.post("/app/api/staff", json={"email": email, "full_name": "Rol Test", "role": "secretary", "password": pw}, headers=hdr)
    assert st.status_code == 200, st.text
    sid = rl.q1("SELECT id FROM staff_users WHERE email=?", email)["id"]

    victim, _ = _login(email, pw)
    assert victim.get("/auth/me").status_code == 200

    patch = hq.patch(f"/app/api/staff/{sid}/permissions", json={"role": "doctor"}, headers=hdr)
    assert patch.status_code == 200, patch.text
    assert victim.get("/auth/me").status_code == 401, "Rol değişince eski oturum anında geçersiz olmalı"


# ---------------------------------------------------------------------------
# 10) RATE LIMIT TESTLERİ (EN SONDA)
# ---------------------------------------------------------------------------
def test_zz_rate_limit_geri_bildirim_429(env):
    c = _client()
    statuses = [
        c.post("/form/geri-bildirim", data={"rating": "5", "comment": f"Test yorum {i}"}).status_code
        for i in range(60)
    ]
    assert 429 in statuses, f"/form/geri-bildirim hız sınırı 429 dönmeli: {set(statuses)}"


def test_zz_rate_limit_public_book_429(env):
    c = _client()
    start = _next_weekday(15, 11, 0)
    statuses = [
        c.post("/api/public/book/merkez", json=_book_body(f"0533{i:07d}", start)).status_code
        for i in range(1, 9)
    ]
    assert 429 in statuses, f"/api/public/book hız sınırı 429 dönmeli: {statuses}"


def test_zz_rate_limit_campaign_click_429(env):
    hq, hdr = _login(*HQ_CREDS)
    code = "v7-rate-click"
    r = hq.post(
        "/app/api/campaigns",
        json={"name": "V7 Rate Kampanyası", "source": "instagram", "channel": "instagram", "code": code,
              "utm_source": "instagram", "utm_medium": "cpc", "utm_campaign": "v7_rate"},
        headers=hdr,
    )
    assert r.status_code == 200, r.text
    _fresh_limiter()
    anon = _client()
    statuses = [anon.get(f"/c/{code}", follow_redirects=False).status_code for _ in range(30)]
    assert 429 in statuses, f"/c/{{code}} hız sınırı 429 dönmeli: {set(statuses)}"


def test_zz_rate_limit_campaign_track_429(env):
    c = _client()
    statuses = [
        c.post("/api/campaigns/track", json={"event_type": "click", "campaign_code": "yok-v7"}).status_code
        for _ in range(30)
    ]
    assert 429 in statuses, f"/api/campaigns/track hız sınırı 429 dönmeli: {set(statuses)}"
