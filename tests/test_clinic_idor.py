"""Adım 9: çoklu-klinik `clinic_id` izolasyonu ve IDOR negatif yetki paketi (gerçek HTTP yolları).

İki taze klinik (A, B) merkez yönetici (HQ) ile açılır; her birinin HQ olmayan kendi sahibi vardır.
Klinik A'da hasta, randevu, borç, tahsilat, mesaj, medya, odontogram, lab, taksit, stok, bekleme listesi,
banka anlaşması, tedarikçi, gider ve kampanya oluşturulur. Klinik B oturumu bunların tamamına okuma / yazma /
güncelleme / silme dener: her biri 403 veya 404 dönmeli, yanıt gövdesinde A'ya ait işaretçi bulunmamalı ve
sonunda A'nın verisi değişmeden kalmalı. Ayrıca B'nin KENDİ nesnelerini A'nın kimlikleriyle bağlamaya çalıştığı
yabancı-anahtar (FK) enjeksiyonları denenir; veritabanında B tarafında A'ya işaret eden satır kalmamalıdır.
"""
from __future__ import annotations

import io
import os
import secrets
import sqlite3
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import httpx
import pytest
from PIL import Image

TZ = ZoneInfo("Europe/Istanbul")
HQ_CREDS = ("yonetici@dentacore.com", "DentaCore2026!")
OWNER_PW = "IdorTest-2026-Guclu!"
DENIED = (403, 404)


def _base() -> str:
    return os.environ["DENTACORE_URL"].rstrip("/")


def _db() -> sqlite3.Connection:
    con = sqlite3.connect(f"file:{os.environ['DC_DB_PATH']}?mode=ro", uri=True, timeout=10)
    con.row_factory = sqlite3.Row
    return con


def _login(email: str, password: str) -> httpx.Client:
    c = httpx.Client(base_url=_base(), timeout=30.0)
    r = c.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, f"giriş başarısız {email}: {r.status_code} {r.text[:200]}"
    c.headers.update({"X-CSRF-Token": c.get("/auth/me").json()["csrf"]})
    return c


def _png() -> bytes:
    img = Image.new("RGB", (800, 800), (140, 140, 140))
    px = img.load()
    for x in range(0, 800, 8):
        for y in range(0, 800, 8):
            px[x, y] = (20, 20, 20) if ((x + y) // 8) % 2 == 0 else (235, 235, 235)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _ok(r: httpx.Response, what: str) -> dict:
    assert r.status_code == 200, f"{what}: {r.status_code} {r.text[:300]}"
    return r.json()


def _slot() -> str:
    d = datetime.now(TZ).date() + timedelta(days=3)
    while d.weekday() >= 5:
        d += timedelta(days=1)
    return datetime(d.year, d.month, d.day, 11, 0, tzinfo=TZ).isoformat()


def _slot2() -> str:
    d = datetime.now(TZ).date() + timedelta(days=4)
    while d.weekday() >= 5:
        d += timedelta(days=1)
    return datetime(d.year, d.month, d.day, 15, 0, tzinfo=TZ).isoformat()


def _seed_clinic(hq: httpx.Client, tag: str) -> dict:
    u = secrets.token_hex(3)
    email = f"idor.{tag.lower()}.{u}@example.com"
    made = _ok(hq.post("/app/api/clinics", json={
        "clinic_name": f"Idor Klinik {tag} {u}", "owner_name": f"Sahip {tag}", "owner_email": email,
        "owner_password": OWNER_PW}), f"klinik {tag} oluştur")
    return {"tag": tag, "u": u, "cid": made["clinic_id"], "email": email, "client": _login(email, OWNER_PW)}


def _seed_data(w: dict) -> None:
    c, u, tag = w["client"], w["u"], w["tag"]
    w["mark"] = f"IDORMARK{tag}{u}"
    w["phone"] = f"+9053{secrets.randbelow(10**8):08d}"
    p = _ok(c.post("/app/api/patients", json={"name": f"{w['mark']} Hasta", "phone": w["phone"]}), "hasta")
    w["pid"] = p["id"]
    st = _ok(c.post("/app/api/staff", json={
        "email": f"doc.{tag.lower()}.{u}@example.com", "full_name": f"Hekim {tag}", "role": "doctor",
        "job_title": "dentist", "password": OWNER_PW}), "personel")
    w["doc"] = st.get("id") or st.get("user_id")
    assert w["doc"], st
    a = _ok(c.post("/app/api/appointments", json={
        "patient_id": w["pid"], "starts_at": _slot(), "duration_min": 30, "treatment": f"{w['mark']} Kontrol",
        "chair": "1"}), "randevu")
    w["appt"] = a["id"]
    ch = _ok(c.post("/app/api/charges", json={
        "patient_id": w["pid"], "description": f"{w['mark']} Dolgu", "amount": "1000"}), "borç")
    w["charge"] = ch["id"]
    py = _ok(c.post("/app/api/payments", json={
        "patient_id": w["pid"], "amount": "300", "method": "nakit", "note": w["mark"]}), "tahsilat")
    w["payment"] = py["id"]
    _ok(c.post(f"/app/api/conversations/{w['pid']}/send", json={"text": f"{w['mark']} mesaj"}), "mesaj")
    w["msgs_before"] = len(_ok(c.get(f"/app/api/conversations/{w['pid']}/messages"), "mesaj listesi"))
    m = _ok(c.post(f"/app/api/patients/{w['pid']}/media?filename=rontgen.png&category=xray", content=_png(),
                   headers={"Content-Type": "application/octet-stream"}), "medya")
    w["media"] = m["media_id"]
    o = _ok(c.post(f"/app/api/patients/{w['pid']}/odontogram", json={
        "tooth_fdi": 16, "surface": "O", "status": "filling", "procedure_name": "Kompozit Dolgu", "amount": "3000"}), "odontogram")
    w["odo"] = o["id"]
    lab = _ok(c.post("/app/api/lab-orders", json={
        "patient_id": w["pid"], "lab_name": f"{w['mark']} Lab", "procedure_type": "Zirkonyum",
        "due_date": "2027-05-01", "cost": "2500"}), "lab")
    w["lab"] = lab["id"]
    inst = _ok(c.post(f"/app/api/patients/{w['pid']}/installments", json={
        "total_amount": "500", "installment_count": 2, "first_due_date": "2027-03-01", "charge_id": w["charge"]}), "taksit")
    w["inst"] = inst["installment_ids"][0]
    w["wait"] = _ok(c.post("/app/api/waitlist", json={"patient_id": w["pid"], "treatment": "kontrol"}), "bekleme")["id"]
    w["item"] = _ok(c.post("/app/api/inventory", json={"name": f"{w['mark']} Stok", "qty": "10"}), "stok")["id"]
    w["bank"] = _ok(c.post("/app/api/bank-agreements", json={
        "bank_name": f"{w['mark']} Banka", "discount_pct": "10"}), "banka anlaşması")["id"]
    w["supplier"] = _ok(c.post("/app/api/suppliers", json={"name": f"{w['mark']} Tedarikçi"}), "tedarikçi")["id"]
    _ok(c.post("/app/api/expenses", json={"description": f"{w['mark']} gider", "amount": "50"}), "gider")
    w["camp"] = _ok(c.post("/app/api/campaigns", json={"name": f"{w['mark']} Kampanya"}), "kampanya")["id"]


@pytest.fixture(scope="module")
def world():
    hq = _login(*HQ_CREDS)
    A, B = _seed_clinic(hq, "A"), _seed_clinic(hq, "B")
    hq.close()
    _seed_data(A)
    _seed_data(B)
    A["anon"] = httpx.Client(base_url=_base(), timeout=30.0)
    yield {"A": A, "B": B}
    for k in ("A", "B"):
        A_ = {"A": A, "B": B}[k]
        A_["client"].close()
    A["anon"].close()


# --------------------------------------------------------------------------------------------------
# 1) Doğrudan nesne erişimi: saldırgan X, kurban V'nin kimlikleriyle okur / yazar / günceller / siler
# --------------------------------------------------------------------------------------------------
_TEETH = {"16": {}}


def _probes():
    P = lambda *a: a  # noqa: E731
    return [
        # --- okuma ---
        P("get_patient", "GET", lambda v, x: f"/app/api/patients/{v['pid']}", None),
        P("export_patient", "GET", lambda v, x: f"/app/api/patients/{v['pid']}/export", None),
        P("get_odontogram", "GET", lambda v, x: f"/app/api/patients/{v['pid']}/odontogram", None),
        P("list_media", "GET", lambda v, x: f"/app/api/patients/{v['pid']}/media", None),
        P("get_media", "GET", lambda v, x: f"/app/api/patients/{v['pid']}/media/{v['media']}", None),
        P("list_installments", "GET", lambda v, x: f"/app/api/patients/{v['pid']}/installments", None),
        P("get_periodontal", "GET", lambda v, x: f"/app/api/patients/{v['pid']}/periodontal", None),
        P("get_treatment_consents", "GET", lambda v, x: f"/app/api/patients/{v['pid']}/treatment-consents", None),
        P("get_messages", "GET", lambda v, x: f"/app/api/conversations/{v['pid']}/messages", None),
        P("appt_ics", "GET", lambda v, x: f"/app/api/appointments/{v['appt']}/ics", None),
        P("item_moves", "GET", lambda v, x: f"/app/api/inventory/{v['item']}/moves", None),
        # --- hasta yazma ---
        P("patch_patient", "PATCH", lambda v, x: f"/app/api/patients/{v['pid']}", lambda v, x: {"name": "Hack Adı"}),
        P("archive_patient", "POST", lambda v, x: f"/app/api/patients/{v['pid']}/archive", lambda v, x: {}),
        P("unarchive_patient", "POST", lambda v, x: f"/app/api/patients/{v['pid']}/unarchive", lambda v, x: {}),
        P("send_anamnesis", "POST", lambda v, x: f"/app/api/patients/{v['pid']}/anamnesis", lambda v, x: {}),
        P("revoke_consent", "POST", lambda v, x: f"/app/api/patients/{v['pid']}/consents/revoke", lambda v, x: {"kind": "all"}),
        P("assign_group", "POST", lambda v, x: f"/app/api/patients/{v['pid']}/groups", lambda v, x: {"group_id": 1}),
        P("anonymize_patient", "POST", lambda v, x: f"/app/api/patients/{v['pid']}/anonymize", lambda v, x: {}),
        P("delete_patient", "DELETE", lambda v, x: f"/app/api/patients/{v['pid']}", None),
        # --- dişler, medya, lab ---
        P("add_odontogram", "POST", lambda v, x: f"/app/api/patients/{v['pid']}/odontogram",
          lambda v, x: {"tooth_fdi": 17, "surface": "O", "status": "planned", "procedure_name": "Saldırı kaydı", "amount": "100"}),
        P("patch_odontogram", "PATCH", lambda v, x: f"/app/api/patients/{v['pid']}/odontogram/{v['odo']}", lambda v, x: {"status": "treated"}),
        P("delete_odontogram", "DELETE", lambda v, x: f"/app/api/patients/{v['pid']}/odontogram/{v['odo']}", None),
        P("upload_media", "POST", lambda v, x: f"/app/api/patients/{v['pid']}/media?filename=x.png&category=xray", "PNG"),
        P("delete_media", "DELETE", lambda v, x: f"/app/api/patients/{v['pid']}/media/{v['media']}", None),
        P("patch_lab", "PATCH", lambda v, x: f"/app/api/lab-orders/{v['lab']}", lambda v, x: {"status": "delivered"}),
        P("add_periodontal", "POST", lambda v, x: f"/app/api/patients/{v['pid']}/periodontal", lambda v, x: {"teeth": _TEETH}),
        P("add_treatment_consent", "POST", lambda v, x: f"/app/api/patients/{v['pid']}/treatment-consents", lambda v, x: {}),
        # --- randevu / mesaj ---
        P("patch_appt", "PATCH", lambda v, x: f"/app/api/appointments/{v['appt']}", lambda v, x: {"treatment": "Hack"}),
        P("appt_cancel", "POST", lambda v, x: f"/app/api/appointments/{v['appt']}/status", lambda v, x: {"status": "cancelled"}),
        P("appt_done", "POST", lambda v, x: f"/app/api/appointments/{v['appt']}/done", lambda v, x: {}),
        P("send_message", "POST", lambda v, x: f"/app/api/conversations/{v['pid']}/send", lambda v, x: {"text": "saldırı mesajı"}),
        # --- finans ---
        P("refund_payment", "POST", lambda v, x: f"/app/api/payments/{v['payment']}/refund", lambda v, x: {"reason": "saldırı testi"}),
        P("void_payment", "POST", lambda v, x: f"/app/api/payments/{v['payment']}/void", lambda v, x: {"reason": "saldırı testi"}),
        P("void_charge", "POST", lambda v, x: f"/app/api/charges/{v['charge']}/void", lambda v, x: {"reason": "saldırı testi"}),
        P("add_installments", "POST", lambda v, x: f"/app/api/patients/{v['pid']}/installments",
          lambda v, x: {"total_amount": "100", "installment_count": 2, "first_due_date": "2027-04-01"}),
        P("pay_installment", "POST", lambda v, x: f"/app/api/installments/{v['inst']}/pay", lambda v, x: {"method": "nakit"}),
        P("settle_advance", "POST", lambda v, x: f"/app/api/patients/{v['pid']}/settle-advance", lambda v, x: {"charge_id": v["charge"]}),
        P("patch_bank_agreement", "PATCH", lambda v, x: f"/app/api/bank-agreements/{v['bank']}", lambda v, x: {"active": False}),
        # --- bekleme, stok, personel ---
        P("remove_waitlist", "POST", lambda v, x: f"/app/api/waitlist/{v['wait']}/remove", lambda v, x: {}),
        P("move_stock", "POST", lambda v, x: f"/app/api/inventory/{v['item']}/move", lambda v, x: {"delta": "-1", "reason": "saldırı testi"}),
        P("transfer_stock", "POST", lambda v, x: f"/app/api/inventory/{v['item']}/transfer",
          lambda v, x: {"target_clinic_id": x["cid"], "qty": "1"}),
        P("deactivate_staff", "POST", lambda v, x: f"/app/api/staff/{v['doc']}/active", lambda v, x: {"active": False}),
        P("staff_permissions", "PATCH", lambda v, x: f"/app/api/staff/{v['doc']}/permissions", lambda v, x: {"role": "owner"}),
        # --- klinik yönetimi ---
        P("switch_clinic", "POST", lambda v, x: f"/app/api/clinics/{v['cid']}/switch", lambda v, x: {}),
    ]


def _fire(client: httpx.Client, method: str, path: str, body):
    if body == "PNG":
        return client.request(method, path, content=_png(), headers={"Content-Type": "application/octet-stream"})
    if body is None:
        return client.request(method, path)
    return client.request(method, path, json=body)


def _no_leak(r: httpx.Response, v: dict, what: str) -> None:
    assert v["mark"] not in r.text, f"{what}: yanıtta kurban işaretçisi sızdı: {r.text[:300]}"
    assert v["phone"].replace("+", "") not in r.text.replace("+", ""), f"{what}: kurban telefonu sızdı"


@pytest.mark.parametrize("direction", ["B->A", "A->B"])
@pytest.mark.parametrize("probe", _probes(), ids=lambda p: p[0])
def test_cross_clinic_direct_object_access_denied(world, probe, direction):
    atk, vic = (world["B"], world["A"]) if direction == "B->A" else (world["A"], world["B"])
    label, method, path_fn, body_fn = probe
    body = body_fn(vic, atk) if callable(body_fn) else body_fn
    r = _fire(atk["client"], method, path_fn(vic, atk), body)
    assert r.status_code in DENIED, f"{direction} {label}: beklenen 403/404, gelen {r.status_code} {r.text[:300]}"
    _no_leak(r, vic, f"{direction} {label}")


# --------------------------------------------------------------------------------------------------
# 2) Liste uçları: saldırganın görünümünde kurban verisi bulunmaz
# --------------------------------------------------------------------------------------------------
_LISTS = [
    "/app/api/patients", "/app/api/appointments", "/app/api/kasa", "/app/api/conversations", "/app/api/waitlist",
    "/app/api/inventory", "/app/api/bank-agreements", "/app/api/lab-orders", "/app/api/staff", "/app/api/expenses",
    "/app/api/suppliers", "/app/api/campaigns/report", "/app/api/implants", "/app/api/patient-groups", "/app/api/alerts",
]


@pytest.mark.parametrize("direction", ["B->A", "A->B"])
@pytest.mark.parametrize("path", _LISTS)
def test_cross_clinic_lists_do_not_leak(world, path, direction):
    atk, vic = (world["B"], world["A"]) if direction == "B->A" else (world["A"], world["B"])
    r = atk["client"].get(path)
    assert r.status_code == 200, f"{direction} {path}: {r.status_code} {r.text[:200]}"
    _no_leak(r, vic, f"{direction} {path}")
    assert atk["mark"] in r.text or path in ("/app/api/alerts", "/app/api/implants", "/app/api/patient-groups",
                                            "/app/api/campaigns/report", "/app/api/appointments", "/app/api/kasa"), \
        f"{path}: kendi verisi bile görünmüyor (test körleşti)"


# --------------------------------------------------------------------------------------------------
# 3) Yabancı-anahtar enjeksiyonu: saldırgan KENDİ nesnesini kurbanın kimliğine bağlamaya çalışır
# --------------------------------------------------------------------------------------------------
def _fk_cases():
    c = lambda *a: a  # noqa: E731
    return [
        c("appt_foreign_patient", "POST", lambda v, x: "/app/api/appointments",
          lambda v, x: {"patient_id": v["pid"], "starts_at": _slot2(), "treatment": "Saldırı", "chair": "2"}),
        c("appt_foreign_doctor", "POST", lambda v, x: "/app/api/appointments",
          lambda v, x: {"patient_id": x["pid"], "doctor_id": v["doc"], "starts_at": _slot2(), "treatment": "Saldırı", "chair": "2"}),
        c("appt_patch_foreign_doctor", "PATCH", lambda v, x: f"/app/api/appointments/{x['appt']}", lambda v, x: {"doctor_id": v["doc"]}),
        c("charge_foreign_patient", "POST", lambda v, x: "/app/api/charges",
          lambda v, x: {"patient_id": v["pid"], "description": "Saldırı borcu", "amount": "10"}),
        c("charge_foreign_doctor", "POST", lambda v, x: "/app/api/charges",
          lambda v, x: {"patient_id": x["pid"], "doctor_id": v["doc"], "description": "Saldırı borcu 2", "amount": "11"}),
        c("payment_foreign_patient", "POST", lambda v, x: "/app/api/payments",
          lambda v, x: {"patient_id": v["pid"], "amount": "10", "method": "nakit"}),
        c("payment_foreign_charge", "POST", lambda v, x: "/app/api/payments",
          lambda v, x: {"patient_id": x["pid"], "amount": "10", "method": "nakit", "applied_charge_id": v["charge"]}),
        c("payment_foreign_doctor", "POST", lambda v, x: "/app/api/payments",
          lambda v, x: {"patient_id": x["pid"], "amount": "10", "method": "nakit", "doctor_id": v["doc"]}),
        c("waitlist_foreign_patient", "POST", lambda v, x: "/app/api/waitlist", lambda v, x: {"patient_id": v["pid"]}),
        c("lab_foreign_patient", "POST", lambda v, x: "/app/api/lab-orders",
          lambda v, x: {"patient_id": v["pid"], "lab_name": "Saldırı Lab", "procedure_type": "Kron", "due_date": "2027-06-01"}),
        c("lab_foreign_doctor", "POST", lambda v, x: "/app/api/lab-orders",
          lambda v, x: {"patient_id": x["pid"], "doctor_id": v["doc"], "lab_name": "Saldırı Lab", "procedure_type": "Kron", "due_date": "2027-06-01"}),
        c("installment_foreign_charge", "POST", lambda v, x: f"/app/api/patients/{x['pid']}/installments",
          lambda v, x: {"total_amount": "100", "installment_count": 2, "first_due_date": "2027-04-01", "charge_id": v["charge"]}),
        c("settle_foreign_charge", "POST", lambda v, x: f"/app/api/patients/{x['pid']}/settle-advance", lambda v, x: {"charge_id": v["charge"]}),
        c("expense_foreign_supplier", "POST", lambda v, x: "/app/api/expenses",
          lambda v, x: {"supplier_id": v["supplier"], "description": "Saldırı gideri", "amount": "5"}),
        c("patient_new_foreign_doctor", "POST", lambda v, x: "/app/api/patients",
          lambda v, x: {"name": "Saldırı Hasta", "phone": f"+9054{secrets.randbelow(10**8):08d}", "primary_doctor_id": v["doc"]}),
        c("patient_new_foreign_bank", "POST", lambda v, x: "/app/api/patients",
          lambda v, x: {"name": "Saldırı Hasta", "phone": f"+9054{secrets.randbelow(10**8):08d}", "bank_agreement_id": v["bank"]}),
        c("patient_new_foreign_campaign", "POST", lambda v, x: "/app/api/patients",
          lambda v, x: {"name": "Saldırı Hasta", "phone": f"+9054{secrets.randbelow(10**8):08d}", "campaign_id": v["camp"]}),
        c("patient_patch_foreign_doctor", "PATCH", lambda v, x: f"/app/api/patients/{x['pid']}", lambda v, x: {"primary_doctor_id": v["doc"]}),
        c("patient_patch_foreign_bank", "PATCH", lambda v, x: f"/app/api/patients/{x['pid']}", lambda v, x: {"bank_agreement_id": v["bank"]}),
        c("patient_patch_foreign_campaign", "PATCH", lambda v, x: f"/app/api/patients/{x['pid']}", lambda v, x: {"campaign_id": v["camp"]}),
        c("periodontal_foreign_doctor", "POST", lambda v, x: f"/app/api/patients/{x['pid']}/periodontal",
          lambda v, x: {"doctor_id": v["doc"], "teeth": _TEETH}),
        c("treatment_consent_foreign_doctor", "POST", lambda v, x: f"/app/api/patients/{x['pid']}/treatment-consents",
          lambda v, x: {"doctor_id": v["doc"]}),
    ]


@pytest.mark.parametrize("direction", ["B->A", "A->B"])
@pytest.mark.parametrize("case", _fk_cases(), ids=lambda c: c[0])
def test_foreign_key_injection_is_rejected(world, case, direction):
    atk, vic = (world["B"], world["A"]) if direction == "B->A" else (world["A"], world["B"])
    label, method, path_fn, body_fn = case
    r = _fire(atk["client"], method, path_fn(vic, atk), body_fn(vic, atk))
    assert r.status_code in DENIED, f"{direction} {label}: beklenen 403/404, gelen {r.status_code} {r.text[:300]}"
    _no_leak(r, vic, f"{direction} {label}")


# --------------------------------------------------------------------------------------------------
# 4) Oturum / kimlik sahteciliği
# --------------------------------------------------------------------------------------------------
def test_unauthenticated_requests_are_refused(world):
    A = world["A"]
    for path in (f"/app/api/patients/{A['pid']}", "/app/api/patients", "/app/api/kasa",
                 f"/app/api/conversations/{A['pid']}/messages", f"/app/api/patients/{A['pid']}/media/{A['media']}"):
        r = A["anon"].get(path)
        assert r.status_code in (401, 403), f"{path}: kimliksiz {r.status_code}"
        _no_leak(r, A, path)


def test_clinic_selector_spoofing_does_not_change_tenant(world):
    A, B = world["A"], world["B"]
    for kw in ({"headers": {"X-Clinic-Id": str(A["cid"])}}, {"params": {"clinic_id": A["cid"]}},
               {"headers": {"X-Clinic-Id": str(A["cid"])}, "params": {"clinic_id": A["cid"], "cid": A["cid"]}}):
        r = B["client"].get(f"/app/api/patients/{A['pid']}", **kw)
        assert r.status_code in DENIED, f"{kw}: {r.status_code}"
        _no_leak(r, A, str(kw))
        lst = B["client"].get("/app/api/patients", **kw)
        assert lst.status_code == 200
        _no_leak(lst, A, f"liste {kw}")


def test_non_hq_owner_cannot_open_or_enter_other_clinics(world):
    B, A = world["B"], world["A"]
    assert B["client"].post("/app/api/clinics", json={
        "clinic_name": "Saldırı Kliniği", "owner_name": "Saldırgan", "owner_email": f"x{secrets.token_hex(3)}@example.com",
        "owner_password": OWNER_PW}).status_code == 403
    assert B["client"].post(f"/app/api/clinics/{A['cid']}/switch").status_code == 403
    me = B["client"].get("/auth/me").json()
    assert me["user"]["clinic_id"] == B["cid"], me


# --------------------------------------------------------------------------------------------------
# 5) Kampanya FK sızıntısı: kurban kampanya adı saldırganın hasta detayında görünmemeli
# --------------------------------------------------------------------------------------------------
def test_foreign_campaign_name_never_surfaces_in_other_clinic(world):
    A, B = world["A"], world["B"]
    for atk, vic in ((B, A), (A, B)):
        r = atk["client"].patch(f"/app/api/patients/{atk['pid']}", json={"campaign_id": vic["camp"]})
        assert r.status_code in DENIED, f"yabancı kampanya bağlandı: {r.status_code} {r.text[:200]}"
        d = atk["client"].get(f"/app/api/patients/{atk['pid']}")
        assert d.status_code == 200
        assert vic["mark"] not in d.text, "kurban kampanya adı hasta detayında sızdı"
        assert (d.json().get("campaign_name") or "") != f"{vic['mark']} Kampanya"


# --------------------------------------------------------------------------------------------------
# 6) Son durum: A ve B verisi saldırılardan sonra değişmedi, karşı tarafa işaret eden satır yok
# --------------------------------------------------------------------------------------------------
def test_victim_data_unchanged_and_no_cross_clinic_rows(world):
    A, B = world["A"], world["B"]
    con = _db()
    try:
        for me, other in ((A, B), (B, A)):
            r = con.execute("SELECT display_name, active, clinic_id FROM patients WHERE id=?", (me["pid"],)).fetchone()
            assert r and r["clinic_id"] == me["cid"] and r["display_name"] == f"{me['mark']} Hasta" and int(r["active"] or 0) == 1, dict(r or {})
            ap = con.execute("SELECT status, treatment, doctor_id, clinic_id FROM appointments WHERE id=?", (me["appt"],)).fetchone()
            assert ap["clinic_id"] == me["cid"] and ap["status"] in ("booked", "confirmed") and ap["treatment"] == f"{me['mark']} Kontrol"
            assert ap["doctor_id"] in (None, me["doc"]), "randevuya yabancı hekim bağlandı"
            ch = con.execute("SELECT voided_at, clinic_id FROM charges WHERE id=?", (me["charge"],)).fetchone()
            assert ch["voided_at"] is None and ch["clinic_id"] == me["cid"]
            py = con.execute("SELECT voided_at, clinic_id FROM payments WHERE id=?", (me["payment"],)).fetchone()
            assert py["voided_at"] is None and py["clinic_id"] == me["cid"]
            assert con.execute("SELECT count(*) FROM payments WHERE refund_of_id=?", (me["payment"],)).fetchone()[0] == 0, "iade satırı oluştu"
            assert con.execute("SELECT status FROM lab_orders WHERE id=?", (me["lab"],)).fetchone()["status"] == "sent"
            assert float(con.execute("SELECT qty FROM inventory_items WHERE id=?", (me["item"],)).fetchone()["qty"]) == 10.0
            assert int(con.execute("SELECT active FROM waitlist WHERE id=?", (me["wait"],)).fetchone()["active"]) == 1
            assert int(con.execute("SELECT active FROM staff_users WHERE id=?", (me["doc"],)).fetchone()["active"]) == 1
            assert con.execute("SELECT role FROM staff_users WHERE id=?", (me["doc"],)).fetchone()["role"] == "doctor"
            assert int(con.execute("SELECT active FROM bank_agreements WHERE id=?", (me["bank"],)).fetchone()["active"]) == 1
            assert con.execute("SELECT status FROM tooth_records WHERE id=?", (me["odo"],)).fetchone()["status"] == "filling"
            # karşı tarafa işaret eden satır kalmamalı
            q = lambda sql, *a: con.execute(sql, a).fetchone()[0]  # noqa: E731
            assert q("SELECT count(*) FROM appointments WHERE clinic_id=? AND patient_id=?", other["cid"], me["pid"]) == 0
            assert q("SELECT count(*) FROM charges WHERE clinic_id=? AND patient_id=?", other["cid"], me["pid"]) == 0
            assert q("SELECT count(*) FROM payments WHERE clinic_id=? AND patient_id=?", other["cid"], me["pid"]) == 0
            assert q("SELECT count(*) FROM message_log WHERE clinic_id=? AND patient_id=?", other["cid"], me["pid"]) == 0
            assert q("SELECT count(*) FROM lab_orders WHERE clinic_id=? AND patient_id=?", other["cid"], me["pid"]) == 0
            assert q("SELECT count(*) FROM payment_installments WHERE clinic_id=? AND patient_id=?", other["cid"], me["pid"]) == 0
            assert q("SELECT count(*) FROM patients WHERE clinic_id=? AND (primary_doctor_id=? OR bank_agreement_id=? OR campaign_id=?)",
                     other["cid"], me["doc"], me["bank"], me["camp"]) == 0, "diğer klinik hastası bu kliniğin hekim/banka/kampanyasına bağlı"
            assert q("SELECT count(*) FROM expenses WHERE clinic_id=? AND supplier_id=?", other["cid"], me["supplier"]) == 0
            assert q("SELECT count(*) FROM waitlist w JOIN patients p ON p.id=w.patient_id WHERE p.clinic_id=? AND w.patient_id=?",
                     other["cid"], me["pid"]) == 0
    finally:
        con.close()
    for me in (A, B):
        r = me["client"].get(f"/app/api/patients/{me['pid']}/media")
        assert r.status_code == 200 and str(me["media"]) in r.text, "medya kayboldu"
        assert len(_ok(me["client"].get(f"/app/api/conversations/{me['pid']}/messages"), "mesajlar")) == me["msgs_before"], "mesaj sayısı değişti"
