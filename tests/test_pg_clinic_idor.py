"""Adım 9 (kapanış): PostgreSQL bulut yolu (`api/app/panel.py`) için klinik izolasyonu ve yabancı anahtar (FK) enjeksiyonu paketi.

`tests/test_clinic_idor.py` SQLite motorunu (`run_local.py`) sınar. Bu dosya aynı sözleşmeyi GERÇEK `uvicorn` süreci +
GERÇEK PostgreSQL üzerinde sınar (tests/pg_app_harness.py). Kapsanan iki gerçek açık:

1. `POST /app/api/inventory/{id}/transfer` yalnızca `CLINICAL` yetkisiyle çalışıyordu; HQ olmayan bir klinik sahibi başka bir
   kiracının envanterine kayıt yazabiliyordu. Artık yalnızca HQ sahibi (SQLite yolundaki kuralın aynısı).
2. `PATCH /app/api/patients/{pid}/odontogram/{rid}` gövdedeki `doctor_id` değerini klinik doğrulaması olmadan
   `tooth_records` ve otomatik `charges` satırına yazıyordu (oluşturma yolunda doğrulama vardı).

Ayrıca B kliniğinin A kliniğinin nesnelerine doğrudan erişemediği ve A'nın kendi nesnelerini B'nin personel kimliğiyle
bağlayamadığı doğrulanır. DC_REQUIRE_PG=1 iken PG yoksa test atlamaz, başarısız olur.
"""
from __future__ import annotations

import pathlib
import sys
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from pg_app_harness import pg_app  # noqa: E402

TZ = ZoneInfo("Europe/Istanbul")
DENIED = (403, 404)
A_MARK = "Alfa-Gizli-Hasta"


def _patch(s, path: str, body: dict):
    return s.client.patch(s.base + path, headers=s._h(), json=body)


def _rows(r) -> list:
    j = r.json()
    return j if isinstance(j, list) else (j.get("staff") or j.get("items") or j.get("rows") or [])


def _next_tuesday_11() -> str:
    d = datetime.now(TZ) + timedelta(days=8)
    while d.weekday() != 1:
        d += timedelta(days=1)
    return d.replace(hour=11, minute=0, second=0, microsecond=0).isoformat()


def _q(app, sql: str, *args):
    import psycopg
    with psycopg.connect(app.dsn, autocommit=True) as con:
        return con.execute(sql, args).fetchall()


@pytest.fixture(scope="module")
def world():
    with pg_app() as app:
        hq = app.hq()
        a = app.new_clinic(hq, "Klinik Alfa")
        b = app.new_clinic(hq, "Klinik Beta")
        a_pid = app.new_patient(a, A_MARK)

        b_staff = next(x for x in _rows(b.get("/app/api/staff")) if x.get("email") == b.email)["id"]

        r = a.post("/app/api/inventory", json={"name": "Eldiven-Alfa", "qty": "10"})
        assert r.status_code == 200, r.text[:300]
        a_item = r.json()["id"]

        r = a.post(f"/app/api/patients/{a_pid}/odontogram", json={
            "tooth_fdi": 11, "procedure_name": "Dolgu Alfa", "status": "planned", "amount": "0"})
        assert r.status_code == 200, r.text[:300]
        a_rec = r.json()["id"]

        r = a.post("/app/api/appointments", json={
            "patient_id": a_pid, "starts_at": _next_tuesday_11(), "duration_min": 30, "treatment": "Muayene", "chair": "1"})
        assert r.status_code == 200, r.text[:300]
        a_appt = r.json()["id"]

        yield {"app": app, "hq": hq, "a": a, "b": b, "a_pid": a_pid, "b_staff": b_staff,
               "a_item": a_item, "a_rec": a_rec, "a_appt": a_appt}


# ---------------------------------------------------------------- 1) stok transferi: yalnızca HQ

def test_non_hq_owner_cannot_transfer_stock_into_other_tenant(world):
    a, b, app = world["a"], world["b"], world["app"]
    r = a.post(f"/app/api/inventory/{world['a_item']}/transfer", json={"target_clinic_id": b.clinic_id, "qty": "1"})
    assert r.status_code == 403, f"HQ olmayan sahip başka kiracıya transfer yapabildi: {r.status_code} {r.text[:200]}"
    assert _q(app, "SELECT count(*) FROM inventory_items WHERE clinic_id=%s", b.clinic_id)[0][0] == 0
    assert float(_q(app, "SELECT qty FROM inventory_items WHERE id=%s", world["a_item"])[0][0]) == 10.0


def test_hq_owner_transfer_still_works(world):
    """Pozitif kontrol: meşru HQ transferi bozulmamalı."""
    hq, a, app = world["hq"], world["a"], world["app"]
    r = hq.post("/app/api/inventory", json={"name": "Maske-Merkez", "qty": "5"})
    assert r.status_code == 200, r.text[:300]
    item = r.json()["id"]
    r = hq.post(f"/app/api/inventory/{item}/transfer", json={"target_clinic_id": a.clinic_id, "qty": "2"})
    assert r.status_code == 200, r.text[:300]
    got = _q(app, "SELECT qty FROM inventory_items WHERE clinic_id=%s AND name=%s", a.clinic_id, "Maske-Merkez")
    assert got and float(got[0][0]) == 2.0


# ---------------------------------------------------------------- 2) doctor_id FK enjeksiyonu

def test_odontogram_update_rejects_foreign_doctor_id(world):
    a, app = world["a"], world["app"]
    before = _q(app, "SELECT doctor_id, status FROM tooth_records WHERE id=%s", world["a_rec"])[0]
    r = _patch(a, f"/app/api/patients/{world['a_pid']}/odontogram/{world['a_rec']}",
               {"doctor_id": world["b_staff"], "status": "treated", "amount": "100"})
    assert r.status_code == 404, f"yabancı doctor_id kabul edildi: {r.status_code} {r.text[:200]}"
    assert _q(app, "SELECT doctor_id, status FROM tooth_records WHERE id=%s", world["a_rec"])[0] == before
    assert _q(app, "SELECT count(*) FROM charges WHERE doctor_id=%s", world["b_staff"])[0][0] == 0


def test_charge_and_appointment_reject_foreign_doctor_id(world):
    a, app = world["a"], world["app"]
    r = a.post("/app/api/charges", json={"patient_id": world["a_pid"], "description": "Test işlem", "amount": "50",
                                         "doctor_id": world["b_staff"]})
    assert r.status_code == 404, f"{r.status_code} {r.text[:200]}"
    r = a.post("/app/api/appointments", json={
        "patient_id": world["a_pid"], "starts_at": _next_tuesday_11(), "duration_min": 30, "treatment": "Kontrol",
        "chair": "2", "doctor_id": world["b_staff"]})
    assert r.status_code == 404, f"{r.status_code} {r.text[:200]}"
    r = _patch(a, f"/app/api/appointments/{world['a_appt']}", {"doctor_id": world["b_staff"]})
    assert r.status_code == 404, f"{r.status_code} {r.text[:200]}"
    assert _q(app, "SELECT count(*) FROM appointments WHERE doctor_id=%s", world["b_staff"])[0][0] == 0
    assert _q(app, "SELECT count(*) FROM charges WHERE doctor_id=%s", world["b_staff"])[0][0] == 0


# ---------------------------------------------------------------- 3) çapraz klinik doğrudan erişim

def test_clinic_b_cannot_touch_clinic_a_objects(world):
    b, a_pid = world["b"], world["a_pid"]
    attempts = [
        ("GET", f"/app/api/patients/{a_pid}", None),
        ("POST", "/app/api/charges", {"patient_id": a_pid, "description": "Sızma", "amount": "10"}),
        ("POST", "/app/api/payments", {"patient_id": a_pid, "amount": "10", "method": "nakit", "allow_advance": True}),
        ("POST", "/app/api/waitlist", {"patient_id": a_pid, "treatment": "herhangi"}),
        ("POST", "/app/api/appointments", {"patient_id": a_pid, "starts_at": _next_tuesday_11(), "duration_min": 30,
                                           "treatment": "Sızma", "chair": "1"}),
        ("PATCH", f"/app/api/patients/{a_pid}/odontogram/{world['a_rec']}", {"status": "caries"}),
        ("PATCH", f"/app/api/appointments/{world['a_appt']}", {"treatment": "Sızma"}),
        ("POST", f"/app/api/inventory/{world['a_item']}/move", {"delta": "-1", "reason": "sızma denemesi"}),
    ]
    for method, path, body in attempts:
        if method == "GET":
            r = b.get(path)
        elif method == "POST":
            r = b.post(path, json=body)
        else:
            r = _patch(b, path, body)
        assert r.status_code in DENIED, f"{method} {path} -> {r.status_code} {r.text[:200]}"
        assert A_MARK not in r.text, f"{method} {path} yanıtında A kliniğinin verisi var"


def test_victim_data_unchanged_after_attacks(world):
    app, a = world["app"], world["a"]
    assert float(_q(app, "SELECT qty FROM inventory_items WHERE id=%s", world["a_item"])[0][0]) == 10.0
    assert _q(app, "SELECT status FROM tooth_records WHERE id=%s", world["a_rec"])[0][0] == "planned"
    assert _q(app, "SELECT treatment FROM appointments WHERE id=%s", world["a_appt"])[0][0] == "Muayene"
    assert _q(app, "SELECT count(*) FROM waitlist WHERE patient_id=%s", world["a_pid"])[0][0] == 0
    assert _q(app, "SELECT count(*) FROM charges WHERE patient_id=%s", world["a_pid"])[0][0] == 0
    assert _q(app, "SELECT count(*) FROM payments WHERE patient_id=%s", world["a_pid"])[0][0] == 0
    assert a.get(f"/app/api/patients/{world['a_pid']}").status_code == 200
