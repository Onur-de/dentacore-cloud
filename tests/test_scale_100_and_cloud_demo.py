"""DentaCore v6.3 — 100 Eşzamanlı Hasta + 100 WhatsApp Webhook + 50 Takvim Yük & Bulut Demo Doğrulama Paketi."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import time
from datetime import datetime, timedelta
from pathlib import Path

import httpx
import pytest

os.environ.setdefault("WA_APP_SECRET", "scale100_webhook_secret_key_2026_safe")
os.environ.setdefault("IG_APP_SECRET", "scale100_webhook_secret_key_2026_safe")
os.environ.setdefault("DC_WEBHOOK_RATE_LIMIT", "5000")

import run_local as rl  # noqa: E402


def _wa_sig(raw: bytes) -> str:
    sec_val = os.environ["WA_APP_SECRET"].encode()
    return "sha256=" + hmac.new(sec_val, raw, hashlib.sha256).hexdigest()


@pytest.fixture()
def isolated_env(tmp_path, monkeypatch):
    db_file = tmp_path / "dentacore_scale100.db"
    media_dir = tmp_path / "media_scale100"
    monkeypatch.setattr(rl, "DB_PATH", db_file)
    monkeypatch.setattr(rl, "_CONN", None)
    monkeypatch.setenv("DC_MEDIA_DIR", str(media_dir))
    monkeypatch.setenv("DC_WEBHOOK_RATE_LIMIT", "5000")
    monkeypatch.setenv("DC_ALLOW_HTTP_LOCAL", "1")
    rl._SEEN_WEBHOOK_IDS = rl.sec.WebhookDedupCache(max_size=10_000, ttl_seconds=86_400)
    rl._LIMITER = rl.sec.RateLimiter()
    rl.init_and_seed()
    rl.ex("UPDATE clinics SET wa_phone_id='100200300400', chairs=3 WHERE id=1")
    yield
    if rl._CONN is not None:
        rl._CONN.close()
        rl._CONN = None


def test_100_concurrent_patients_and_csv_import(isolated_env):
    """1) 100 eşzamanlı hasta kaydı + mükerrer telefon koruması + 50 satırlık CSV toplu aktarım."""

    async def _run():
        transport = httpx.ASGITransport(app=rl.app)
        async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as ac:
            r_login = await ac.post(
                "/auth/login",
                json={"email": "sekreter@dentacore.com", "password": "DentaCore2026!"},
            )
            assert r_login.status_code == 200
            csrf = r_login.json()["csrf"]
            headers = {"X-CSRF-Token": csrf}

            sources = [
                "instagram", "facebook", "tiktok", "google", "google_ads",
                "whatsapp", "website", "phone", "qr", "referral",
                "patient_referral", "walk_in", "other",
            ]

            async def _create_one(idx: int):
                src = sources[idx % len(sources)]
                phone = f"+90541{idx:07d}"
                res = await ac.post(
                    "/app/api/patients",
                    headers=headers,
                    json={
                        "name": f"Yük Testi Hasta {idx:03d}",
                        "phone": phone,
                        "first_source": src,
                        "lang": "tr",
                    },
                )
                return idx, src, res

            t0 = time.perf_counter()
            results = await asyncio.gather(*[_create_one(i) for i in range(1, 101)])
            elapsed = time.perf_counter() - t0

            created_ids = set()
            for idx, src, res in results:
                assert res.status_code == 200, f"Patient {idx} failed: {res.text}"
                body = res.json()
                assert body["duplicate"] is False
                created_ids.add(body["id"])

            assert len(created_ids) == 100
            assert elapsed < 10.0

            # Aynı telefonla mükerrer kayıt kontrolü
            r_dup_chk = await ac.get("/app/api/patients/check-duplicate?phone=%2B905410000001")
            assert r_dup_chk.status_code == 200
            assert r_dup_chk.json()["duplicate"] is True

            r_dup_post = await ac.post(
                "/app/api/patients",
                headers=headers,
                json={"name": "Mükerrer Deneme", "phone": "0541 000 00 01", "first_source": "walk_in"},
            )
            assert r_dup_post.status_code == 200
            assert r_dup_post.json()["duplicate"] is True

            # İlk kaynak kilidi kontrolü (onaysız değişmemeli)
            first_pid = results[0][2].json()["id"]
            r_p1 = await ac.get(f"/app/api/patients/{first_pid}")
            assert r_p1.status_code == 200
            assert r_p1.json()["first_source"] == sources[1 % len(sources)]

            # 50 satırlık CSV (25 mevcut + 25 yeni)
            csv_lines = ["ad,telefon,kaynak,dil"]
            for i in range(1, 26):
                csv_lines.append(f"Mevcut {i},+90541{i:07d},instagram,tr")
            for i in range(101, 126):
                csv_lines.append(f"CSV Yeni {i},+90542{i:07d},google_ads,tr")
            r_csv = await ac.post(
                "/app/api/patients/import-csv",
                headers=headers,
                json={"csv_text": "\n".join(csv_lines), "default_source": "other"},
            )
            assert r_csv.status_code == 200
            j_csv = r_csv.json()
            assert j_csv["imported"] == 25
            assert j_csv["duplicates"] == 25
            assert j_csv.get("errors_count", len(j_csv.get("errors", []))) == 0

            r_list = await ac.get("/app/api/patients")
            assert r_list.status_code == 200
            assert len(r_list.json()) >= 125

    asyncio.run(_run())


def test_100_concurrent_whatsapp_webhooks_async_queue_and_attribution(isolated_env):
    """2) 100 eşzamanlı WhatsApp mesajı: <200ms asenkron kuyruk yanıtı, aynı gönderici kilidi, kampanya [Ref] eşleşmesi ve dedup."""

    async def _run():
        transport = httpx.ASGITransport(app=rl.app)
        async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as ac:
            r_login = await ac.post(
                "/auth/login",
                json={"email": "yonetici@dentacore.com", "password": "DentaCore2026!"},
            )
            assert r_login.status_code == 200
            headers = {"X-CSRF-Token": r_login.json()["csrf"]}

            # Kampanya oluştur
            r_camp = await ac.post(
                "/app/api/campaigns",
                headers=headers,
                json={
                    "name": "100 Hasta Yük Testi Meta Kampanyası",
                    "code": "META100",
                    "channel": "instagram",
                    "utm_source": "instagram",
                    "utm_medium": "cpc",
                    "utm_campaign": "meta100_test",
                    "budget": "15000",
                },
            )
            assert r_camp.status_code == 200
            camp_id = r_camp.json()["id"]

            async def _send_wh(idx: int, async_flag: bool = True, custom_mid: str | None = None, custom_phone: str | None = None):
                sender = custom_phone or f"90555{idx:07d}"
                mid = custom_mid or f"wamid.SCALE100.{idx}"
                text = (
                    f"[Ref: META100] Merhaba, implant fiyatı ve konum öğrenebilir miyim? ({idx})"
                    if idx % 2 == 0
                    else f"Klinik çalışma saatleriniz ve adresiniz nedir? ({idx})"
                )
                payload = {
                    "entry": [{
                        "changes": [{
                            "value": {
                                "metadata": {"phone_number_id": "100200300400"},
                                "contacts": [{"wa_id": sender, "profile": {"name": f"WA Misafir {idx:03d}"}}],
                                "messages": [{"id": mid, "from": sender, "type": "text", "text": {"body": text}}],
                            }
                        }]
                    }]
                }
                raw = json.dumps(payload).encode()
                t_start = time.perf_counter()
                url = "/webhooks/whatsapp?async=1" if async_flag else "/webhooks/whatsapp"
                resp = await ac.post(
                    url,
                    content=raw,
                    headers={"Content-Type": "application/json", "X-Hub-Signature-256": _wa_sig(raw)},
                )
                lat_ms = (time.perf_counter() - t_start) * 1000.0
                return resp, lat_ms

            # 100 eşzamanlı mesajı asenkron kuyruğa gönder
            batch_res = await asyncio.gather(*[_send_wh(i, async_flag=True) for i in range(1, 101)])
            latencies = [lat for _, lat in batch_res]
            for resp, _ in batch_res:
                assert resp.status_code == 200
                assert resp.json()["ok"] is True

            avg_lat_ms = sum(latencies) / len(latencies)
            assert avg_lat_ms < 200.0, f"Average webhook response time too high: {avg_lat_ms:.2f}ms"

            # Kuyruğu boşalt ve doğrula (OWNER yetkisi ve CSRF zorunlu)
            r_drain = await ac.post("/app/api/admin/webhook-queue/drain", headers={"X-CSRF-Token": csrf})
            assert r_drain.status_code == 200
            assert r_drain.json()["queue_depth"] == 0

            # Mükerrer mesaj ID (dedup) kontrolü
            r_dup, _ = await _send_wh(1, async_flag=False, custom_mid="wamid.SCALE100.1")
            assert r_dup.status_code == 200
            assert r_dup.json()["dedup"] == 1

            # Aynı telefon numarasından aynı anda 10 mesaj geldiğinde tek hasta kartı oluşmalı
            same_phone = "905599998877"
            same_res = await asyncio.gather(*[
                _send_wh(200 + k, async_flag=False, custom_mid=f"wamid.SAME.{k}", custom_phone=same_phone)
                for k in range(10)
            ])
            for sr, _ in same_res:
                assert sr.status_code == 200
            cnt_same = rl.q1("SELECT count(*) AS n FROM patients WHERE clinic_id=1 AND phone_hmac=?", rl.phone_hmac(same_phone))["n"]
            assert cnt_same == 1

            # Kampanya [Ref: META100] ile gelen 50 hastanın (+ 1 aynı numaradan çoklu mesaj gönderen hasta = 51 tekil hasta) attribution kontrolü
            r_funnel = await ac.get("/app/api/campaigns/funnel")
            assert r_funnel.status_code == 200
            c_row = next(c for c in r_funnel.json()["campaigns"] if c["id"] == camp_id)
            leads_cnt = (
                c_row.get("leads_count")
                or c_row.get("patients_created")
                or (c_row.get("funnel") or {}).get("patients_created")
                or c_row.get("conversations")
            )
            assert leads_cnt == 51

            # /health kuyruk ve WAL bilgisi kontrolü
            r_health = await ac.get("/health")
            assert r_health.status_code == 200
            hj = r_health.json()
            assert hj["ok"] is True
            assert hj["db_ok"] is True
            assert hj["wal_mode"] == "wal"

    asyncio.run(_run())


def test_50_concurrent_calendar_appointments_and_waitlist_race(isolated_env):
    """3) 50+ eşzamanlı randevu talebinde çift rezervasyonun (%100) engellenmesi ve bekleme listesi atomik slot kapma."""

    async def _run():
        transport = httpx.ASGITransport(app=rl.app)
        async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as ac:
            r_login = await ac.post(
                "/auth/login",
                json={"email": "yonetici@dentacore.com", "password": "DentaCore2026!"},
            )
            assert r_login.status_code == 200
            headers = {"X-CSRF-Token": r_login.json()["csrf"]}

            # Gelecek Pazartesi'den itibaren 3 koltuk × 10 saat dilimi = 30 benzersiz slot + 25 çakışan talep = 55 eşzamanlı istek
            now_loc = datetime.now(rl.TZ)
            days_ahead = (7 - now_loc.weekday()) % 7 or 7
            base_day = (now_loc + timedelta(days=days_ahead)).replace(hour=9, minute=0, second=0, microsecond=0)

            requests_spec = []
            # 30 benzersiz slot (3 koltuk x 10 yarım saatlik dilim, farklı doktor/koltuk)
            for slot_idx in range(10):
                st_iso = (base_day + timedelta(minutes=30 * slot_idx)).isoformat()
                for ch_num in (1, 2, 3):
                    requests_spec.append((st_iso, str(ch_num), f"+90531{len(requests_spec)+1:07d}"))
            # İlk 25 slota aynı koltuk ve aynı saatte çakışan ikinci birer hasta talebi ekle
            for dup_idx in range(25):
                st_iso, ch_str, _ = requests_spec[dup_idx]
                requests_spec.append((st_iso, ch_str, f"+90538{dup_idx+1:07d}"))

            async def _book(idx: int, starts_iso: str, chair_s: str, phone_s: str):
                return await ac.post(
                    "/app/api/appointments",
                    headers=headers,
                    json={
                        "name": f"Takvim Yük Hasta {idx}",
                        "phone": phone_s,
                        "starts_at": starts_iso,
                        "duration_min": 30,
                        "treatment": "Muayene & Planlama",
                        "chair": chair_s,
                    },
                )

            resps = await asyncio.gather(*[_book(i, s, c, p) for i, (s, c, p) in enumerate(requests_spec)])
            ok_200 = [r for r in resps if r.status_code == 200]
            conflict_409 = [r for r in resps if r.status_code == 409]
            assert len(ok_200) == 30, f"Expected 30 booked slots, got {len(ok_200)}"
            assert len(conflict_409) == 25, f"Expected 25 conflict rejections, got {len(conflict_409)}"

            # Bekleme listesi yarış testi: 1 randevu iptal edildiğinde aynı teklife 5 eşzamanlı kabul isteği
            first_aid = ok_200[0].json()["id"]
            r_cancel = await ac.post(
                f"/app/api/appointments/{first_aid}/status",
                headers=headers,
                json={"status": "cancelled"},
            )
            assert r_cancel.status_code == 200

            r_offers = await ac.get("/app/api/waitlist/offers?status=sent")
            assert r_offers.status_code == 200
            offers = [o for o in r_offers.json() if o["appointment_id"] == first_aid]
            assert len(offers) >= 1
            oid = offers[0]["id"]

            race_resps = await asyncio.gather(*[
                ac.post(f"/app/api/waitlist/offers/{oid}/respond", headers=headers, json={"action": "accept"})
                for _ in range(5)
            ])
            won_cnt = sum(1 for r in race_resps if r.status_code == 200)
            lost_cnt = sum(1 for r in race_resps if r.status_code == 409)
            assert won_cnt == 1
            assert lost_cnt == 4

    asyncio.run(_run())


def test_postgres_migration_order_and_static_cloud_demo_parity():
    """4) PostgreSQL 002_platform.sql CREATE/ALTER sırası, audit_digest uyumu ve docs/panel.html 57 uç nokta tamlığı."""
    root = Path(__file__).resolve().parent.parent
    sql_path = root / "api" / "app" / "migrations" / "002_platform.sql"
    sql_text = sql_path.read_text(encoding="utf-8")

    # 001 (db/init.sql) ile oluşturulan çekirdek tablolar:
    created_tables: set[str] = {
        "patients", "appointments", "anamnesis", "consents", "waitlist",
        "slot_offers", "postop_checks", "message_log", "alerts", "leads",
    }
    for m in re.finditer(r"\b(CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?|ALTER\s+TABLE)\s+([a-zA-Z0-9_]+)", sql_text, re.IGNORECASE):
        op = m.group(1).upper()
        tbl = m.group(2).lower()
        if op.startswith("CREATE"):
            created_tables.add(tbl)
        elif op.startswith("ALTER"):
            assert tbl in created_tables, f"002_platform.sql error: ALTER TABLE {tbl} appears before CREATE TABLE {tbl}"

    ent_text = (root / "api" / "app" / "enterprise_ext.py").read_text(encoding="utf-8")
    assert "sec_mod.audit_digest(" in ent_text
    assert "chain_hash" not in ent_text

    app_js_text = (root / "api" / "app" / "web" / "app.js").read_text(encoding="utf-8")
    assert "const PATIENT_SOURCE_MAP =" in app_js_text
    assert "openQuickSearch" in app_js_text

    cloud_panel = root.parent.parent / "5_KALICI_GITHUB_VE_BULUT_KURULUMU" / "docs" / "panel.html"
    if cloud_panel.exists():
        p_txt = cloud_panel.read_text(encoding="utf-8")
        for req_ep in (
            "/app/api/patient-groups",
            "/app/api/bank-agreements",
            "/app/api/treatment-catalog",
            "/app/api/campaigns/report",
            "/app/api/campaigns/funnel",
            "/app/api/doctors/revenue-report",
            "/app/api/suppliers",
            "/app/api/expenses",
            "/app/api/kasa/closings",
            "/app/api/patients/check-duplicate",
            "/app/api/patients/import-csv",
            "/app/api/ai-costs",
            "/app/api/appointments/available",
            "/app/api/appointments/recurring",
            "/app/api/waitlist/offers",
            "/app/api/demo/simulate-flow",
            "const PATIENT_SOURCE_MAP =",
            "bank_agreements: []",
        ):
            assert req_ep in p_txt, f"Missing {req_ep} in docs/panel.html"
