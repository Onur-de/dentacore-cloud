"""DentaCore Kurumsal Genişletme Modülü (Bölüm 3–25 Tam Kapsam).
Mevcut `run_local.py` (SQLite) ve `api/app/panel.py` (PostgreSQL) altyapısını bozmadan:
- 13 Hasta Geliş Kanalı + İlk Kaynak (`first_source`, değiştirilemez) / Son Kaynak (`last_source`)
- Sorumlu Doktor (`primary_doctor_id`) ve Tedaviyi Yapan Doktor (`doctor_id`) Ayrımı
- Gerçek Kampanya Tıklama, Bot Filtresi, Tekilleştirme ve Kasa Tahsilat Dönüşüm Hunisi (`/c/{code}`)
- Banka / Kurum Anlaşmaları ve Otomatik İndirim Motoru (`bank_agreements`, Taslak Modu)
- Hasta Grupları ve Etik Özel İşaretleme (`patient_groups`, `patient_group_members`)
- 10 Kalemlik `Decimal` Finans Motoru, Avans Mahsuplaşması, İade, Taksit/Vade (`payment_installments`),
  Günlük Kasa Kapanışı (`cash_closings`), Tedarikçi (`suppliers`) ve Giderler (`expenses`)
- ISO 3950 FDI 52 Diş Anatomik Kataloğu, Tedavi Fiyat Kataloğu (`treatment_catalog`) ve Periodontal Çizelge (`periodontal_exams`)
- Dijital Tedavi Onamı (`treatment_consents`, 5070 E-İmza vs Elektronik Onay ayrımı), Laboratuvar (`lab_orders`) ve İmplant/Lot (`implant_records`)
- Güvenli Dosya/Röntgen/DICOM/Fotoğraf (Öncesi-Sonrası)/PDF Yükleme (`patient_media`)
- 14 Personel Mesleği ve 15 Granüler Yetki (RBAC) Denetimi
- Online Randevu (`/randevu/{slug}`), CSV Hasta İçe Aktarma ve CSV/Excel Rapor Dışa Aktarma
uçlarını sağlar.
"""
from __future__ import annotations

import csv
import hashlib
import hmac
import html
import io
import json
import os
import re
import secrets
import sqlite3
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Any, Callable, Literal
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from pydantic import BaseModel, Field

from . import cal, media, security as sec
from .dental_catalog import (
    DEFAULT_TREATMENT_CATALOG,
    FDI_TOOTH_CATALOG,
    ODO_ALL_STATUSES,
    ODO_BILLABLE_STATUSES,
    ODO_PLANNED_STATUSES,
    PATIENT_SOURCE_LABELS,
    PERMISSION_KEYS,
    PERMISSION_LABELS_TR,
    ROLE_DEFAULT_PERMISSIONS,
    STAFF_PROFESSIONS,
    VALID_FDI_NUMBERS,
    VALID_PATIENT_SOURCES,
    compute_ai_cost_report,
    compute_bank_discount,
    detect_acquisition_source,
    is_bot_traffic,
    normalize_source,
    resolve_permissions,
    validate_ethical_group_tag,
)

TZ = ZoneInfo("Europe/Istanbul")


def migrate_enterprise_sqlite(c: sqlite3.Connection, t0: str) -> None:
    """Mevcut SQLite veritabanını veri kaybı olmadan yeni kurumsal şemaya yükseltir."""
    def _cols(tbl: str) -> set[str]:
        return {r["name"] for r in c.execute(f"PRAGMA table_info({tbl})").fetchall()}

    # 1) patients tablosu genişletmeleri
    p_cols = _cols("patients")
    for col_def in (
        ("first_source", "TEXT NOT NULL DEFAULT 'whatsapp'"),
        ("last_source", "TEXT NOT NULL DEFAULT 'whatsapp'"),
        ("campaign_id", "INTEGER"),
        ("utm_source", "TEXT NOT NULL DEFAULT ''"),
        ("utm_medium", "TEXT NOT NULL DEFAULT ''"),
        ("utm_campaign", "TEXT NOT NULL DEFAULT ''"),
        ("click_id", "TEXT NOT NULL DEFAULT ''"),
        ("primary_doctor_id", "INTEGER"),
        ("bank_agreement_id", "INTEGER"),
        ("created_by", "INTEGER"),
        ("notes", "TEXT NOT NULL DEFAULT ''"),
        ("birth_date", "TEXT NOT NULL DEFAULT ''"),
    ):
        if col_def[0] not in p_cols:
            c.execute(f"ALTER TABLE patients ADD COLUMN {col_def[0]} {col_def[1]}")
    # Mevcut kayıtlarda channel='ig' ise first_source='instagram' olarak senkronla
    c.execute("UPDATE patients SET first_source='instagram', last_source='instagram' WHERE channel='ig' AND first_source='whatsapp'")

    # 2) tooth_records tablosu (yeni durumlar: filling, bridge, postponed, cancelled + brüt/indirim/banka)
    tr_sql_row = c.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='tooth_records'").fetchone()
    tr_sql = (tr_sql_row["sql"] or "") if tr_sql_row else ""
    if tr_sql and "'bridge'" not in tr_sql:
        c.execute("PRAGMA foreign_keys = OFF")
        c.executescript("""
            CREATE TABLE tooth_records_new (
              id                  INTEGER PRIMARY KEY AUTOINCREMENT,
              clinic_id           INTEGER NOT NULL DEFAULT 1,
              patient_id          INTEGER NOT NULL,
              tooth_fdi           INTEGER NOT NULL CHECK ((tooth_fdi BETWEEN 11 AND 48) OR (tooth_fdi BETWEEN 51 AND 85)),
              surface             TEXT NOT NULL DEFAULT 'FULL' CHECK (surface IN ('M','D','O','B','L','FULL')),
              status              TEXT NOT NULL DEFAULT 'planned' CHECK (status IN ('healthy','caries','planned','treated','filling','implant','crown','bridge','root_canal','missing','extraction','postponed','cancelled')),
              procedure_code      TEXT NOT NULL DEFAULT '',
              procedure_name      TEXT NOT NULL DEFAULT '',
              amount_kurus        INTEGER NOT NULL DEFAULT 0 CHECK (amount_kurus >= 0),
              gross_amount_kurus  INTEGER NOT NULL DEFAULT 0,
              discount_kurus      INTEGER NOT NULL DEFAULT 0,
              bank_agreement_id   INTEGER,
              discount_reason     TEXT NOT NULL DEFAULT '',
              doctor_id           INTEGER,
              created_by          INTEGER,
              note                TEXT NOT NULL DEFAULT '',
              created_at          TEXT NOT NULL
            );
            INSERT INTO tooth_records_new (id, clinic_id, patient_id, tooth_fdi, surface, status, procedure_code, procedure_name, amount_kurus, gross_amount_kurus, doctor_id, note, created_at)
            SELECT id, clinic_id, patient_id, tooth_fdi, surface, status, procedure_code, procedure_name, amount_kurus, amount_kurus, doctor_id, note, created_at FROM tooth_records;
            DROP TABLE tooth_records;
            ALTER TABLE tooth_records_new RENAME TO tooth_records;
            CREATE INDEX IF NOT EXISTS tooth_records_patient_idx ON tooth_records(clinic_id, patient_id, tooth_fdi);
        """)
        c.execute("PRAGMA foreign_keys = ON")
    else:
        tr_cols = _cols("tooth_records")
        for col_def in (
            ("gross_amount_kurus", "INTEGER NOT NULL DEFAULT 0"),
            ("discount_kurus", "INTEGER NOT NULL DEFAULT 0"),
            ("bank_agreement_id", "INTEGER"),
            ("discount_reason", "TEXT NOT NULL DEFAULT ''"),
            ("created_by", "INTEGER"),
        ):
            if col_def[0] not in tr_cols:
                c.execute(f"ALTER TABLE tooth_records ADD COLUMN {col_def[0]} {col_def[1]}")

    # 3) charges tablosu genişletmeleri
    ch_cols = _cols("charges")
    for col_def in (
        ("gross_amount_kurus", "INTEGER NOT NULL DEFAULT 0"),
        ("discount_kurus", "INTEGER NOT NULL DEFAULT 0"),
        ("bank_agreement_id", "INTEGER"),
        ("discount_reason", "TEXT NOT NULL DEFAULT ''"),
        ("tooth_record_id", "INTEGER"),
    ):
        if col_def[0] not in ch_cols:
            c.execute(f"ALTER TABLE charges ADD COLUMN {col_def[0]} {col_def[1]}")
    c.execute("UPDATE charges SET gross_amount_kurus = amount_kurus WHERE gross_amount_kurus = 0 AND amount_kurus > 0")

    # 4) payments tablosu genişletmeleri
    py_cols = _cols("payments")
    for col_def in (
        ("status", "TEXT NOT NULL DEFAULT 'completed'"),
        ("doctor_id", "INTEGER"),
        ("is_advance", "INTEGER NOT NULL DEFAULT 0"),
        ("applied_charge_id", "INTEGER"),
        ("refund_of_id", "INTEGER"),
        ("note", "TEXT NOT NULL DEFAULT ''"),
    ):
        if col_def[0] not in py_cols:
            c.execute(f"ALTER TABLE payments ADD COLUMN {col_def[0]} {col_def[1]}")

    # 5) appointments tablosu genişletmeleri
    ap_cols = _cols("appointments")
    for col_def in (
        ("confirmed_at", "TEXT"),
        ("cancelled_at", "TEXT"),
        ("cancel_reason", "TEXT NOT NULL DEFAULT ''"),
        ("satisfaction_sent_at", "TEXT"),
        ("satisfaction_reply", "TEXT"),
        ("satisfaction_replied_at", "TEXT"),
        ("satisfaction_status", "TEXT NOT NULL DEFAULT ''"),
        ("google_link_sent_at", "TEXT"),
        ("series_id", "TEXT"),
        ("sequence", "INTEGER NOT NULL DEFAULT 0"),
        ("updated_at", "TEXT"),
        ("campaign_id", "INTEGER"),
    ):
        if col_def[0] not in ap_cols:
            c.execute(f"ALTER TABLE appointments ADD COLUMN {col_def[0]} {col_def[1]}")

    # 6) clinics tablosu genişletmeleri
    cl_cols = _cols("clinics")
    for col_def in (
        ("ai_monthly_token_limit", "INTEGER NOT NULL DEFAULT 1500000"),
        ("ai_monthly_budget_try", "REAL NOT NULL DEFAULT 250.0"),
        ("ai_hard_stop", "INTEGER NOT NULL DEFAULT 1"),
        ("max_reminders", "INTEGER NOT NULL DEFAULT 1"),
        ("reminder_hours_before", "INTEGER NOT NULL DEFAULT 24"),
    ):
        if col_def[0] not in cl_cols:
            c.execute(f"ALTER TABLE clinics ADD COLUMN {col_def[0]} {col_def[1]}")

    # 7) inventory_items & stock_moves genişletmeleri (Bölüm 14: 13 alan)
    inv_cols = _cols("inventory_items")
    for col_def in (
        ("category", "TEXT NOT NULL DEFAULT 'Sarf Malzeme'"),
        ("supplier", "TEXT NOT NULL DEFAULT ''"),
        ("expiry_date", "TEXT NOT NULL DEFAULT ''"),
        ("lot_number", "TEXT NOT NULL DEFAULT ''"),
        ("warehouse", "TEXT NOT NULL DEFAULT 'Ana Depo'"),
    ):
        if col_def[0] not in inv_cols:
            c.execute(f"ALTER TABLE inventory_items ADD COLUMN {col_def[0]} {col_def[1]}")

    sm_cols = _cols("stock_moves")
    for col_def in (
        ("move_type", "TEXT NOT NULL DEFAULT 'in'"),
        ("lot_number", "TEXT NOT NULL DEFAULT ''"),
    ):
        if col_def[0] not in sm_cols:
            c.execute(f"ALTER TABLE stock_moves ADD COLUMN {col_def[0]} {col_def[1]}")

    # 8) staff_users genişletmeleri (Bölüm 17: 14 meslek & 15 yetki)
    st_cols = _cols("staff_users")
    for col_def in (
        ("job_title", "TEXT NOT NULL DEFAULT ''"),
        ("permissions_json", "TEXT NOT NULL DEFAULT '{}'"),
        ("working_schedule_json", "TEXT NOT NULL DEFAULT '{}'"),
    ):
        if col_def[0] not in st_cols:
            c.execute(f"ALTER TABLE staff_users ADD COLUMN {col_def[0]} {col_def[1]}")
    c.execute("UPDATE staff_users SET job_title='clinic_manager' WHERE job_title='' AND role='owner'")
    c.execute("UPDATE staff_users SET job_title='dentist' WHERE job_title='' AND role='doctor'")
    c.execute("UPDATE staff_users SET job_title='secretary' WHERE job_title='' AND role='secretary'")

    # 9) campaigns genişletmeleri
    cp_cols = _cols("campaigns")
    for col_def in (
        ("code", "TEXT NOT NULL DEFAULT ''"),
        ("channel", "TEXT NOT NULL DEFAULT 'instagram'"),
        ("utm_source", "TEXT NOT NULL DEFAULT 'instagram'"),
        ("utm_medium", "TEXT NOT NULL DEFAULT 'cpc'"),
        ("utm_campaign", "TEXT NOT NULL DEFAULT ''"),
        ("target_url", "TEXT NOT NULL DEFAULT '/'"),
        ("is_sample", "INTEGER NOT NULL DEFAULT 0"),
    ):
        if col_def[0] not in cp_cols:
            c.execute(f"ALTER TABLE campaigns ADD COLUMN {col_def[0]} {col_def[1]}")
    c.execute("UPDATE campaigns SET is_sample=1 WHERE name LIKE '%ÖRNEK VERİ%' OR (clicks=420 AND revenue_kurus=14800000)")
    c.execute("UPDATE campaigns SET code = 'kampanya-' || id WHERE code = ''")

    # 10) Yeni kurumsal tablolar
    c.executescript("""
        CREATE TABLE IF NOT EXISTS campaign_events (
          id                 INTEGER PRIMARY KEY AUTOINCREMENT,
          clinic_id          INTEGER NOT NULL DEFAULT 1,
          campaign_id        INTEGER,
          event_type         TEXT NOT NULL,
          source             TEXT NOT NULL DEFAULT 'website',
          utm_source         TEXT NOT NULL DEFAULT '',
          utm_medium         TEXT NOT NULL DEFAULT '',
          utm_campaign       TEXT NOT NULL DEFAULT '',
          click_id           TEXT NOT NULL DEFAULT '',
          visitor_hash       TEXT NOT NULL DEFAULT '',
          is_bot             INTEGER NOT NULL DEFAULT 0,
          is_unique          INTEGER NOT NULL DEFAULT 0,
          patient_id         INTEGER,
          appointment_id     INTEGER,
          idempotency_key    TEXT,
          user_agent_summary TEXT NOT NULL DEFAULT '',
          created_at         TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS campaign_events_cid_idx ON campaign_events(clinic_id, campaign_id, event_type);
        CREATE UNIQUE INDEX IF NOT EXISTS campaign_events_idem_uq ON campaign_events(clinic_id, idempotency_key) WHERE idempotency_key IS NOT NULL;

        CREATE TABLE IF NOT EXISTS bank_agreements (
          id                    INTEGER PRIMARY KEY AUTOINCREMENT,
          clinic_id             INTEGER NOT NULL DEFAULT 1,
          bank_name             TEXT NOT NULL,
          start_date            TEXT NOT NULL DEFAULT '',
          end_date              TEXT NOT NULL DEFAULT '',
          discount_pct          REAL NOT NULL DEFAULT 0,
          discount_type         TEXT NOT NULL DEFAULT 'percentage',
          fixed_discount_kurus  INTEGER NOT NULL DEFAULT 0,
          applicable_treatments TEXT NOT NULL DEFAULT 'all',
          max_discount_kurus    INTEGER NOT NULL DEFAULT 0,
          combinable            INTEGER NOT NULL DEFAULT 0,
          eligibility_notes     TEXT NOT NULL DEFAULT '',
          active                INTEGER NOT NULL DEFAULT 1,
          created_by            INTEGER,
          created_at            TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS patient_groups (
          id            INTEGER PRIMARY KEY AUTOINCREMENT,
          clinic_id     INTEGER NOT NULL DEFAULT 1,
          name          TEXT NOT NULL,
          color         TEXT NOT NULL DEFAULT 'teal',
          is_restricted INTEGER NOT NULL DEFAULT 0,
          description   TEXT NOT NULL DEFAULT '',
          created_by    INTEGER,
          created_at    TEXT NOT NULL,
          UNIQUE(clinic_id, name)
        );

        CREATE TABLE IF NOT EXISTS patient_group_members (
          id            INTEGER PRIMARY KEY AUTOINCREMENT,
          clinic_id     INTEGER NOT NULL DEFAULT 1,
          patient_id    INTEGER NOT NULL,
          group_id      INTEGER NOT NULL,
          reason        TEXT NOT NULL DEFAULT '',
          added_by      INTEGER,
          added_by_name TEXT NOT NULL DEFAULT '',
          added_at      TEXT NOT NULL,
          UNIQUE(patient_id, group_id)
        );

        CREATE TABLE IF NOT EXISTS payment_installments (
          id                 INTEGER PRIMARY KEY AUTOINCREMENT,
          clinic_id          INTEGER NOT NULL DEFAULT 1,
          patient_id         INTEGER NOT NULL,
          charge_id          INTEGER,
          installment_no     INTEGER NOT NULL DEFAULT 1,
          total_installments INTEGER NOT NULL DEFAULT 1,
          amount_kurus       INTEGER NOT NULL CHECK (amount_kurus > 0),
          paid_kurus         INTEGER NOT NULL DEFAULT 0,
          due_date           TEXT NOT NULL,
          status             TEXT NOT NULL DEFAULT 'pending',
          paid_payment_id    INTEGER,
          note               TEXT NOT NULL DEFAULT '',
          created_by         INTEGER,
          created_at         TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS periodontal_exams (
          id                INTEGER PRIMARY KEY AUTOINCREMENT,
          clinic_id         INTEGER NOT NULL DEFAULT 1,
          patient_id        INTEGER NOT NULL,
          doctor_id         INTEGER,
          exam_date         TEXT NOT NULL,
          measurements_json TEXT NOT NULL DEFAULT '{}',
          mean_pd           REAL NOT NULL DEFAULT 0,
          max_pd            INTEGER NOT NULL DEFAULT 0,
          bop_pct           REAL NOT NULL DEFAULT 0,
          plaque_pct        REAL NOT NULL DEFAULT 0,
          doctor_approved   INTEGER NOT NULL DEFAULT 1,
          doctor_note       TEXT NOT NULL DEFAULT '',
          created_by        INTEGER,
          created_at        TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS treatment_consents (
          id                 INTEGER PRIMARY KEY AUTOINCREMENT,
          clinic_id          INTEGER NOT NULL DEFAULT 1,
          patient_id         INTEGER NOT NULL,
          doctor_id          INTEGER,
          token              TEXT UNIQUE NOT NULL,
          plan_summary_json  TEXT NOT NULL DEFAULT '[]',
          total_amount_kurus INTEGER NOT NULL DEFAULT 0,
          document_version   TEXT NOT NULL DEFAULT '2026-11-v1',
          content_sha256     TEXT NOT NULL,
          signer_name        TEXT NOT NULL DEFAULT '',
          signature_svg_enc  TEXT NOT NULL DEFAULT '',
          consent_type       TEXT NOT NULL DEFAULT 'electronic_approval',
          status             TEXT NOT NULL DEFAULT 'pending',
          signed_at          TEXT,
          expires_at         TEXT NOT NULL,
          created_by         INTEGER,
          created_at         TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS lab_orders (
          id             INTEGER PRIMARY KEY AUTOINCREMENT,
          clinic_id      INTEGER NOT NULL DEFAULT 1,
          patient_id     INTEGER NOT NULL,
          doctor_id      INTEGER,
          tooth_fdi      INTEGER,
          lab_name       TEXT NOT NULL,
          procedure_type TEXT NOT NULL,
          shade_color    TEXT NOT NULL DEFAULT 'A2',
          sent_date      TEXT NOT NULL,
          due_date       TEXT NOT NULL,
          delivered_date TEXT,
          cost_kurus     INTEGER NOT NULL DEFAULT 0,
          status         TEXT NOT NULL DEFAULT 'sent',
          note           TEXT NOT NULL DEFAULT '',
          created_by     INTEGER,
          created_at     TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS implant_records (
          id                      INTEGER PRIMARY KEY AUTOINCREMENT,
          clinic_id               INTEGER NOT NULL DEFAULT 1,
          patient_id              INTEGER NOT NULL,
          doctor_id               INTEGER,
          tooth_fdi               INTEGER NOT NULL,
          brand                   TEXT NOT NULL,
          model                   TEXT NOT NULL,
          diameter_mm             REAL NOT NULL DEFAULT 4.1,
          length_mm               REAL NOT NULL DEFAULT 10.0,
          lot_number              TEXT NOT NULL,
          serial_number           TEXT NOT NULL DEFAULT '',
          expiry_date             TEXT NOT NULL DEFAULT '',
          used_at                 TEXT NOT NULL,
          supplier                TEXT NOT NULL DEFAULT '',
          document_ref            TEXT NOT NULL DEFAULT '',
          uts_barcode             TEXT NOT NULL DEFAULT '',
          uts_notification_status TEXT NOT NULL DEFAULT 'not_connected_prepared',
          note                    TEXT NOT NULL DEFAULT '',
          created_by              INTEGER,
          created_at              TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS patient_media (
          id                INTEGER PRIMARY KEY AUTOINCREMENT,
          clinic_id         INTEGER NOT NULL DEFAULT 1,
          patient_id        INTEGER NOT NULL,
          appointment_id    INTEGER,
          tooth_record_id   INTEGER,
          category          TEXT NOT NULL DEFAULT 'xray',
          stage             TEXT NOT NULL DEFAULT 'general',
          original_filename TEXT NOT NULL DEFAULT 'gorsel.jpg',
          mime_type         TEXT NOT NULL DEFAULT 'image/jpeg',
          file_size_bytes   INTEGER NOT NULL DEFAULT 0,
          sha256_hash       TEXT NOT NULL DEFAULT '',
          encrypted_path    TEXT NOT NULL,
          is_dicom          INTEGER NOT NULL DEFAULT 0,
          width             INTEGER NOT NULL DEFAULT 0,
          height            INTEGER NOT NULL DEFAULT 0,
          sharpness         REAL NOT NULL DEFAULT 0,
          brightness        REAL NOT NULL DEFAULT 0,
          qc_verdict        TEXT NOT NULL DEFAULT 'ok',
          note              TEXT NOT NULL DEFAULT '',
          uploaded_by       INTEGER,
          created_at        TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS suppliers (
          id            INTEGER PRIMARY KEY AUTOINCREMENT,
          clinic_id     INTEGER NOT NULL DEFAULT 1,
          name          TEXT NOT NULL,
          contact_name  TEXT NOT NULL DEFAULT '',
          phone         TEXT NOT NULL DEFAULT '',
          email         TEXT NOT NULL DEFAULT '',
          tax_no        TEXT NOT NULL DEFAULT '',
          balance_kurus INTEGER NOT NULL DEFAULT 0,
          note          TEXT NOT NULL DEFAULT '',
          created_at    TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS expenses (
          id           INTEGER PRIMARY KEY AUTOINCREMENT,
          clinic_id    INTEGER NOT NULL DEFAULT 1,
          supplier_id  INTEGER,
          category     TEXT NOT NULL DEFAULT 'malzeme',
          description  TEXT NOT NULL,
          amount_kurus INTEGER NOT NULL CHECK (amount_kurus > 0),
          method       TEXT NOT NULL DEFAULT 'havale',
          paid_at      TEXT NOT NULL,
          created_by   INTEGER,
          voided_at    TEXT,
          void_reason  TEXT
        );

        CREATE TABLE IF NOT EXISTS cash_closings (
          id                       INTEGER PRIMARY KEY AUTOINCREMENT,
          clinic_id                INTEGER NOT NULL DEFAULT 1,
          closing_date             TEXT NOT NULL,
          opening_balance_kurus    INTEGER NOT NULL DEFAULT 0,
          total_in_kurus           INTEGER NOT NULL DEFAULT 0,
          total_out_kurus          INTEGER NOT NULL DEFAULT 0,
          cash_in_kurus            INTEGER NOT NULL DEFAULT 0,
          card_in_kurus            INTEGER NOT NULL DEFAULT 0,
          bank_in_kurus            INTEGER NOT NULL DEFAULT 0,
          closing_balance_kurus    INTEGER NOT NULL DEFAULT 0,
          physical_counted_kurus   INTEGER NOT NULL DEFAULT 0,
          diff_kurus               INTEGER NOT NULL DEFAULT 0,
          note                     TEXT NOT NULL DEFAULT '',
          closed_by                INTEGER,
          closed_at                TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS treatment_catalog (
          id                  INTEGER PRIMARY KEY AUTOINCREMENT,
          clinic_id           INTEGER NOT NULL DEFAULT 1,
          code                TEXT NOT NULL,
          name                TEXT NOT NULL,
          category            TEXT NOT NULL DEFAULT 'Genel',
          default_price_kurus INTEGER NOT NULL DEFAULT 0,
          default_status      TEXT NOT NULL DEFAULT 'treated',
          active              INTEGER NOT NULL DEFAULT 1,
          created_at          TEXT NOT NULL
        );
    """)

    # Varsayılan hasta grupları ve tedavi kataloğu (yoksa ekle)
    default_groups = [
        ("VIP", "teal", 0, "Öncelikli VIP hasta grubu"),
        ("Özel takip", "blue", 0, "Hekim yakın takibindeki hastalar"),
        ("Ödeme takibi", "amber", 1, "Taksit veya bakiye takibi gereken hastalar"),
        ("Randevuya gelmeyen", "red", 1, "Habersiz randevuya gelmeme (no-show) geçmişi olanlar"),
        ("İleri tedavi bekleyen", "teal", 0, "İmplant üst yapı veya cerrahi aşama bekleyenler"),
        ("Kontrol zamanı gelen", "green", 0, "6 aylık periyodik kontrol zamanı gelenler"),
        ("İletişim tercihi özel olan", "gray", 0, "Belirli saat veya kanal tercihi bulunanlar"),
        ("Özel dikkat gerektiren", "red", 1, "Operasyonel özel dikkat ve randevu öncesi teyit gerektiren kayıtlar"),
    ]
    for g_name, g_col, g_rest, g_desc in default_groups:
        c.execute(
            "INSERT OR IGNORE INTO patient_groups (clinic_id, name, color, is_restricted, description, created_at) VALUES (1, ?, ?, ?, ?, ?)",
            (g_name, g_col, g_rest, g_desc, t0),
        )

    if not c.execute("SELECT 1 FROM treatment_catalog WHERE clinic_id=1 LIMIT 1").fetchone():
        for item in DEFAULT_TREATMENT_CATALOG:
            pk = int((Decimal(item["default_price_try"]) * 100).to_integral_value(rounding=ROUND_HALF_UP))
            c.execute(
                "INSERT INTO treatment_catalog (clinic_id, code, name, category, default_price_kurus, default_status, active, created_at) VALUES (1, ?, ?, ?, ?, ?, 1, ?)",
                (item["code"], item["name"], item["category"], pk, item["default_status"], t0),
            )
    c.commit()


# ==============================================================================
# KURUMSAL UÇ NOKTALAR VE YARDIMCILAR (register_enterprise_routes)
# ==============================================================================

def compute_patient_finance_summary(c: sqlite3.Connection, cid: int, pid: int, tl_fn: Callable[[int], float]) -> dict[str, Any]:
    """Hasta bazlı 10 kalemlik Decimal/kuruş finansal özet ve kaynak açıklaması."""
    odo_rows = c.execute(
        "SELECT status, amount_kurus, gross_amount_kurus, discount_kurus FROM tooth_records WHERE clinic_id=? AND patient_id=?",
        (cid, pid),
    ).fetchall()
    planned_k = sum(int(r["amount_kurus"] or 0) for r in odo_rows if r["status"] in ODO_PLANNED_STATUSES)

    ch_rows = c.execute(
        "SELECT id, amount_kurus, gross_amount_kurus, discount_kurus, voided_at FROM charges WHERE clinic_id=? AND patient_id=?",
        (cid, pid),
    ).fetchall()
    active_ch = [r for r in ch_rows if not r["voided_at"]]
    completed_net_k = sum(int(r["amount_kurus"] or 0) for r in active_ch)
    discount_k = sum(int(r["discount_kurus"] or 0) for r in active_ch)
    completed_gross_k = sum(
        int(r["gross_amount_kurus"] or (int(r["amount_kurus"] or 0) + int(r["discount_kurus"] or 0)))
        for r in active_ch
    )

    py_rows = c.execute(
        "SELECT id, amount_kurus, method, status, is_advance, voided_at FROM payments WHERE clinic_id=? AND patient_id=?",
        (cid, pid),
    ).fetchall()
    active_py = [r for r in py_rows if not r["voided_at"]]
    # Yalnız status='completed' olan ödemeler tahsilat sayılır; 'pending' ve 'failed' ASLA borçtan düşülmez!
    # 'avans_mahsup' iç mahsup hareketi olduğu için nakit girişine iki kez eklenmez.
    collected_k = sum(
        int(r["amount_kurus"] or 0)
        for r in active_py
        if (r["status"] or "completed") == "completed" and r["method"] != "avans_mahsup"
    )
    pending_k = sum(int(r["amount_kurus"] or 0) for r in active_py if r["status"] == "pending")
    failed_k = sum(int(r["amount_kurus"] or 0) for r in active_py if r["status"] == "failed")
    refunded_k = sum(int(r["amount_kurus"] or 0) for r in active_py if r["status"] == "refunded")

    net_paid_k = max(0, collected_k - refunded_k)
    net_remaining_debt_k = max(0, completed_net_k - net_paid_k)
    available_advance_k = max(0, net_paid_k - completed_net_k)

    inst_rows = c.execute(
        "SELECT amount_kurus, paid_kurus, status, due_date FROM payment_installments WHERE clinic_id=? AND patient_id=? AND status <> 'voided'",
        (cid, pid),
    ).fetchall()
    inst_total_k = sum(int(r["amount_kurus"] or 0) for r in inst_rows)
    inst_paid_k = sum(int(r["paid_kurus"] or 0) for r in inst_rows)
    inst_rem_k = max(0, inst_total_k - inst_paid_k)
    next_due = min((r["due_date"] for r in inst_rows if r["status"] in ("pending", "overdue") and r["due_date"]), default=None)

    return {
        "planned_total": tl_fn(planned_k),
        "completed_gross": tl_fn(completed_gross_k),
        "discount_total": tl_fn(discount_k),
        "completed_net_debt": tl_fn(completed_net_k),
        "collected_paid": tl_fn(collected_k),
        "pending_payment": tl_fn(pending_k),
        "failed_payment": tl_fn(failed_k),
        "refunded_total": tl_fn(refunded_k),
        "net_paid_after_refund": tl_fn(net_paid_k),
        "available_advance": tl_fn(available_advance_k),
        "net_remaining_debt": tl_fn(net_remaining_debt_k),
        "balance": tl_fn(completed_net_k - net_paid_k),
        "installments_total": tl_fn(inst_total_k),
        "installments_paid": tl_fn(inst_paid_k),
        "installments_remaining": tl_fn(inst_rem_k),
        "next_due_date": next_due,
        "sources_explanation": {
            "planned_total": "tooth_records tablosunda status IN ('planned','caries','extraction') olan kalemlerin toplamı (borç oluşturmaz).",
            "completed_gross": "charges tablosunda voided_at IS NULL olan gerçekleşmiş hizmetlerin indirim öncesi brüt toplamı.",
            "discount_total": "charges.discount_kurus (banka anlaşması + özel indirim) toplamı.",
            "completed_net_debt": "Gerçekleşen Brüt Hizmet - Toplam İndirim (charges.amount_kurus toplamı).",
            "collected_paid": "payments tablosunda status='completed' ve voided_at IS NULL olan başarılı tahsilatlar.",
            "pending_payment": "payments tablosunda status='pending' olan bekleyen ödemeler (kalan borçtan düşülmez).",
            "failed_payment": "payments tablosunda status='failed' olan başarısız ödemeler (kalan borçtan düşülmez).",
            "refunded_total": "payments tablosunda status='refunded' olan denetim kayıtlı iadeler.",
            "available_advance": "Net başarılı tahsilatın gerçekleşmiş net hizmet borcunu aşan avans kısmı.",
            "net_remaining_debt": "max(0, Gerçekleşen Net Hizmet Borcu - (Başarılı Tahsilat - İade)).",
        },
    }


# ==============================================================================
# MODÜL SEVİYESİ PYDANTIC ŞEMALARI (FastAPI from __future__ import annotations uyumu)
# ==============================================================================
LEGAL_CONSENT_NOTICE_TR = (
    "Hukuki Bilgilendirme: Bu dijital onay kaydı; tedavi planı, tahmini bütçe ve klinik bilgilendirme için "
    "zaman damgalı ve SHA-256 bütünlük özetli elektronik onay kanıtıdır. 5070 sayılı Elektronik İmza Kanunu "
    "kapsamındaki Nitelikli Elektronik İmza (NES) yerine geçmez; cerrahi müdahalelerde ıslak imzalı aydınlatılmış "
    "onam formunun tamamlayıcısı olarak saklanır."
)


class CsvImportIn(BaseModel):
    csv_text: str = Field(min_length=3, max_length=500_000)
    default_source: str = "other"


class TreatmentCatalogIn(BaseModel):
    code: str = Field(min_length=2, max_length=24)
    name: str = Field(min_length=2, max_length=120)
    category: str = Field("Genel", max_length=60)
    default_price: Decimal = Field(Decimal(0), ge=0, le=10_000_000)
    default_status: str = "treated"


class BankAgreementIn(BaseModel):
    bank_name: str = Field(min_length=2, max_length=80)
    start_date: str = Field("", max_length=20)
    end_date: str = Field("", max_length=20)
    discount_pct: Decimal = Field(Decimal(0), ge=0, le=100)
    discount_type: Literal["percentage", "fixed"] = "percentage"
    fixed_discount: Decimal = Field(Decimal(0), ge=0, le=10_000_000)
    applicable_treatments: str = Field("all", max_length=300)
    max_discount: Decimal = Field(Decimal(0), ge=0, le=10_000_000)
    combinable: bool = False
    eligibility_notes: str = Field("", max_length=300)
    active: bool = True


class BankAgreementPatchIn(BaseModel):
    active: bool | None = None
    discount_pct: Decimal | None = Field(default=None, ge=0, le=100)
    end_date: str | None = None
    max_discount: Decimal | None = Field(default=None, ge=0)


class BankCalcIn(BaseModel):
    gross_amount: Decimal = Field(gt=0, le=10_000_000)
    bank_agreement_id: int | None = None
    procedure_name: str = ""
    manual_discount: Decimal = Field(Decimal(0), ge=0, le=10_000_000)
    ref_date: str | None = None


class PatientGroupIn(BaseModel):
    name: str = Field(min_length=2, max_length=60)
    color: Literal["teal", "amber", "red", "green", "blue", "gray"] = "teal"
    is_restricted: bool = False
    description: str = Field("", max_length=200)


class AssignGroupIn(BaseModel):
    group_id: int
    reason: str = Field("", max_length=240)


class CampaignTrackIn(BaseModel):
    campaign_id: int | None = None
    campaign_code: str | None = None
    event_type: Literal["click", "form_start", "form_submit"] = "click"
    source: str | None = None
    utm_source: str = ""
    utm_medium: str = ""
    utm_campaign: str = ""
    gclid: str = ""
    fbclid: str = ""
    ttclid: str = ""
    click_id: str = ""
    idempotency_key: str | None = Field(default=None, max_length=80)


class RefundIn(BaseModel):
    amount: Decimal | None = Field(default=None, gt=0, le=10_000_000)
    reason: str = Field(min_length=3, max_length=200)
    idempotency_key: str | None = Field(default=None, max_length=80)


class AdvanceSettleIn(BaseModel):
    charge_id: int | None = None
    amount: Decimal | None = Field(default=None, gt=0, le=10_000_000)


class InstallmentPlanIn(BaseModel):
    total_amount: Decimal = Field(gt=0, le=10_000_000)
    installment_count: int = Field(ge=1, le=36)
    first_due_date: str = Field(min_length=10, max_length=10)
    charge_id: int | None = None
    note: str = Field("", max_length=160)


class InstallmentPayIn(BaseModel):
    method: Literal["nakit", "kart", "kredi_karti", "banka_karti", "havale", "diger"] = "kredi_karti"
    amount: Decimal | None = Field(default=None, gt=0, le=10_000_000)


class SupplierIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    contact_name: str = Field("", max_length=80)
    phone: str = Field("", max_length=30)
    email: str = Field("", max_length=120)
    tax_no: str = Field("", max_length=30)
    note: str = Field("", max_length=200)


class ExpenseIn(BaseModel):
    supplier_id: int | None = None
    category: Literal["malzeme", "laboratuvar", "kira", "maas", "fatura", "diger"] = "malzeme"
    description: str = Field(min_length=2, max_length=160)
    amount: Decimal = Field(gt=0, le=10_000_000)
    method: Literal["nakit", "kart", "kredi_karti", "banka_karti", "havale", "diger"] = "havale"


class CashClosingIn(BaseModel):
    closing_date: str | None = None
    opening_balance: Decimal = Field(Decimal(0), ge=0, le=100_000_000)
    physical_counted: Decimal = Field(Decimal(0), ge=0, le=100_000_000)
    note: str = Field("", max_length=240)


class PerioToothIn(BaseModel):
    pd: list[int] = Field(default_factory=lambda: [2, 2, 2, 2, 2, 2], min_length=6, max_length=6)
    gm: list[int] = Field(default_factory=lambda: [0, 0, 0, 0, 0, 0], min_length=6, max_length=6)
    bop: list[bool] = Field(default_factory=lambda: [False] * 6, min_length=6, max_length=6)
    plaque: list[bool] = Field(default_factory=lambda: [False] * 6, min_length=6, max_length=6)
    mobility: int = Field(0, ge=0, le=3)
    furcation: int = Field(0, ge=0, le=3)


class PerioExamIn(BaseModel):
    exam_date: str | None = None
    doctor_id: int | None = None
    teeth: dict[str, PerioToothIn]
    doctor_approved: bool = True
    doctor_note: str = Field("", max_length=400)


class TreatmentConsentCreateIn(BaseModel):
    doctor_id: int | None = None
    document_version: str = Field("2026-11-v1", max_length=30)
    custom_items: list[dict[str, Any]] | None = None
    signer_name: str | None = None
    signature_text: str | None = None


class LabOrderIn(BaseModel):
    patient_id: int
    doctor_id: int | None = None
    tooth_fdi: int | None = None
    lab_name: str = Field(min_length=2, max_length=100)
    procedure_type: str = Field(min_length=2, max_length=100)
    shade_color: str = Field("A2", max_length=20)
    sent_date: str | None = None
    due_date: str = Field(min_length=10, max_length=10)
    cost: Decimal = Field(Decimal(0), ge=0, le=10_000_000)
    status: Literal["sent", "rehearsal", "delivered", "cancelled"] = "sent"
    note: str = Field("", max_length=240)


class LabOrderPatchIn(BaseModel):
    status: Literal["sent", "rehearsal", "delivered", "cancelled"]
    delivered_date: str | None = None
    note: str | None = None


class ImplantRecordIn(BaseModel):
    patient_id: int
    doctor_id: int | None = None
    tooth_fdi: int
    brand: str = Field(min_length=2, max_length=80)
    model: str = Field(min_length=1, max_length=80)
    diameter_mm: float = Field(4.1, gt=1.0, le=10.0)
    length_mm: float = Field(10.0, gt=3.0, le=25.0)
    lot_number: str = Field(min_length=2, max_length=60)
    serial_number: str = Field("", max_length=60)
    expiry_date: str = Field("", max_length=20)
    used_at: str | None = None
    supplier: str = Field("", max_length=100)
    document_ref: str = Field("", max_length=120)
    uts_barcode: str = Field("", max_length=80)
    note: str = Field("", max_length=240)


class StaffPermissionsPatchIn(BaseModel):
    job_title: str | None = None
    role: Literal["owner", "doctor", "secretary", "accounting", "clinical_support", "lab_tech", "warehouse", "no_access"] | None = None
    share_pct: Decimal | None = Field(default=None, ge=0, le=100)
    permissions: dict[str, bool] | None = None
    working_schedule: dict[str, Any] | None = None


class AIQuotaIn(BaseModel):
    monthly_token_limit: int = Field(ge=10_000, le=50_000_000)
    monthly_budget_try: float = Field(ge=10.0, le=50_000.0)
    hard_stop: bool = True


class PublicBookIn(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    phone: str = Field(min_length=10, max_length=30)
    starts_at: datetime
    treatment: str = Field("İlk Muayene", min_length=2, max_length=100)
    source: str = "website"
    utm_source: str = ""
    utm_medium: str = ""
    utm_campaign: str = ""
    campaign_code: str = ""
    kvkk_consent: bool = False
    website: str = Field("", max_length=200)


class RecurringAppointmentIn(BaseModel):
    patient_id: int
    starts_at: datetime
    duration_min: int = Field(30, ge=5, le=480)
    treatment: str = Field(min_length=2, max_length=100)
    chair: str = Field("1", min_length=1, max_length=10)
    doctor_id: int | None = None
    frequency: Literal["weekly", "biweekly", "monthly"] = "weekly"
    occurrences: int = Field(2, ge=2, le=12)


def register_enterprise_routes(app: FastAPI, ctx: dict[str, Any]) -> None:
    q = ctx["q"]
    q1 = ctx["q1"]
    ex = ctx["ex"]
    db = ctx["db"]
    db_lock = ctx["db_lock"]
    current_user = ctx["current_user"]
    write_audit = ctx["write_audit"]
    enc = ctx["enc"]
    dec = ctx["dec"]
    norm_phone = ctx["norm_phone"]
    phone_hmac = ctx["phone_hmac"]
    mask_phone = ctx["mask_phone"]
    tl = ctx["tl"]
    kurus = ctx["kurus"]
    iso_now = ctx["iso_now"]
    now_utc = ctx["now_utc"]
    client_ip = ctx["client_ip"]
    root_dir: Path = ctx["root_dir"]
    fernet_obj = ctx.get("fernet")
    _fernet_factory = ctx.get("fernet_factory")
    _limiter_src = ctx.get("limiter") or sec.RateLimiter()
    _vh_raw = ctx.get("phone_hmac_key")
    # Ziyaretçi özet anahtarı: çalışma zamanı PHONE_HMAC_KEY; yoksa süreç başına rastgele (sabit metin yok, CWE-798)
    _visitor_key: bytes = (_vh_raw.encode() if isinstance(_vh_raw, str) else _vh_raw) or secrets.token_bytes(32)
    _csrf_key: bytes = hmac.new(_visitor_key, b"dc-form-csrf-v1", hashlib.sha256).digest()

    def _get_fernet():
        nonlocal fernet_obj
        if fernet_obj is None and _fernet_factory is not None:
            fernet_obj = _fernet_factory()
        if fernet_obj is None:
            raise HTTPException(503, "Şifreleme anahtarı yapılandırılmamış")
        return fernet_obj

    def _rate_limit(key: str, limit: int, window: int) -> None:
        lim = _limiter_src if isinstance(_limiter_src, sec.RateLimiter) else _limiter_src()
        if not lim.hit_sync(key, limit, window):
            raise HTTPException(429, "Çok fazla istek gönderildi; lütfen daha sonra tekrar deneyin")

    def hq_owner(u: dict = Depends(current_user)) -> dict:
        if not u.get("is_hq") or u.get("role") != "owner":
            raise HTTPException(403, "Bu işlem yalnızca Merkez (HQ) yöneticisi yetkisindedir")
        return u

    def _form_csrf(token: str, exp: int) -> str:
        sig = hmac.new(_csrf_key, f"tc:{token}:{exp}".encode(), hashlib.sha256).hexdigest()
        return f"{exp}.{sig}"

    def _verify_form_csrf(token: str, value: str) -> bool:
        try:
            exp_s, sig = str(value or "").split(".", 1)
            exp = int(exp_s)
        except ValueError:
            return False
        if exp < int(datetime.now(timezone.utc).timestamp()):
            return False
        return hmac.compare_digest(_form_csrf(token, exp), f"{exp}.{sig}")

    def _media_dir() -> Path:
        custom = os.environ.get("DC_MEDIA_DIR", "").strip()
        if custom:
            return Path(custom)
        db_p = os.environ.get("DC_DB_PATH", "").strip()
        if db_p:
            return Path(db_p).resolve().parent / "encrypted_media"
        return root_dir / "encrypted_media"

    def require_perm(*perm_keys: str):
        def dep(u: dict = Depends(current_user)) -> dict:
            perms = u.get("permissions") or resolve_permissions(u.get("role"), u.get("job_title"), u.get("permissions_json"))
            if not perms.get("view", False):
                raise HTTPException(403, "Sistem görüntüleme yetkiniz bulunmamaktadır")
            for pk in perm_keys:
                if not perms.get(pk, False):
                    lbl = PERMISSION_LABELS_TR.get(pk, pk)
                    raise HTTPException(403, f"Bu işlem için '{lbl}' ({pk}) yetkisi gereklidir")
            return u
        return dep

    # ------------------------------------------------------------------
    # 1) HASTA ÇİFT KAYIT KONTROLÜ & CSV İÇE AKTARMA (BÖLÜM 4 & 18)
    # ------------------------------------------------------------------
    @app.get("/app/api/patients/check-duplicate")
    def check_duplicate_patient(phone: str = "", exclude_id: int | None = None, u: dict = Depends(require_perm("patient_view"))):
        np = norm_phone(phone)
        if len(np) < 10:
            return {"duplicate": False, "normalized_phone": np, "patient": None}
        cid = u["clinic_id"]
        ph = phone_hmac(np)
        sql = "SELECT id, display_name, first_source, last_source, primary_doctor_id, active FROM patients WHERE clinic_id=? AND phone_hmac=?"
        args: list[Any] = [cid, ph]
        if exclude_id is not None:
            sql += " AND id<>?"
            args.append(exclude_id)
        row = q1(sql, *args)
        if not row:
            return {"duplicate": False, "normalized_phone": np, "patient": None}
        return {
            "duplicate": True,
            "normalized_phone": np,
            "patient": {
                "id": row["id"],
                "display_name": row["display_name"],
                "first_source": row.get("first_source") or "whatsapp",
                "active": bool(row.get("active", 1)),
            },
        }

    @app.post("/app/api/patients/import-csv")
    def import_patients_csv(b: CsvImportIn, u: dict = Depends(require_perm("patient_edit", "create"))):
        cid = u["clinic_id"]
        # Ayrıştırma ve doğrulama global kilidin DIŞINDA yapılır; satır sınırı DoS'u engeller (CWE-400)
        rows_in = list(csv.DictReader(io.StringIO(b.csv_text.strip())))
        if len(rows_in) > 500:
            raise HTTPException(422, "Tek seferde en fazla 500 hasta satırı içe aktarılabilir")
        imported = 0
        duplicates = 0
        invalid = 0
        t_now = iso_now()
        def_src = normalize_source(b.default_source, "other")
        prepared: list[tuple] = []
        for row in rows_in:
            norm_row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items() if isinstance(v, str) or v is None}
            name = norm_row.get("name") or norm_row.get("ad_soyad") or norm_row.get("ad") or ""
            phone = norm_row.get("phone") or norm_row.get("telefon") or ""
            src = normalize_source(norm_row.get("source") or norm_row.get("kaynak"), def_src)
            lang = (norm_row.get("lang") or norm_row.get("dil") or "tr").lower()
            if lang not in ("tr", "en", "de", "ar", "ru", "fr", "nl", "es", "it", "fa", "az", "uk", "bg", "ro", "el", "he"):
                lang = "tr"
            notes = (norm_row.get("notes") or norm_row.get("not") or "")[:400]
            np = norm_phone(phone)
            if len(name) < 2 or len(np) < 10:
                invalid += 1
                continue
            prepared.append((name, np, src, lang, notes))
        with db_lock, db() as c:
            for name, np, src, lang, notes in prepared:
                ph = phone_hmac(np)
                if c.execute("SELECT 1 FROM patients WHERE clinic_id=? AND phone_hmac=?", (cid, ph)).fetchone():
                    duplicates += 1
                    continue
                ch = "ig" if src == "instagram" else "wa"
                c.execute(
                    """INSERT INTO patients
                       (clinic_id,phone_hmac,phone_enc,display_name,lang,channel,first_source,last_source,created_by,notes,active,created_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,1,?)""",
                    (cid, ph, enc(np), name[:80], lang, ch, src, src, u["id"], notes, t_now),
                )
                imported += 1
            c.commit()
        write_audit(u["id"], u["email"], "patients.import_csv", f"clinic:{cid}", u["ip_h"],
                    {"imported": imported, "duplicates": duplicates, "invalid": invalid}, clinic_id=cid)
        return {"ok": True, "imported": imported, "duplicates": duplicates, "invalid": invalid}

    # ------------------------------------------------------------------
    # 2) FDI 52 DİŞ KATALOĞU & TEDAVİ FİYAT KATALOĞU (BÖLÜM 8 & 18)
    # ------------------------------------------------------------------
    @app.get("/app/api/fdi-catalog")
    def get_fdi_catalog(u: dict = Depends(require_perm("view"))):
        t_cat = q("SELECT * FROM treatment_catalog WHERE clinic_id=? AND active=1 ORDER BY code", u["clinic_id"])
        for t in t_cat:
            t["default_price"] = tl(t.pop("default_price_kurus"))
        return {
            "fdi_teeth": FDI_TOOTH_CATALOG,
            "statuses": ODO_ALL_STATUSES,
            "billable_statuses": sorted(ODO_BILLABLE_STATUSES),
            "planned_statuses": sorted(ODO_PLANNED_STATUSES),
            "treatment_catalog": t_cat,
            "patient_sources": PATIENT_SOURCE_LABELS,
        }

    @app.get("/app/api/treatment-catalog")
    def list_treatment_catalog(u: dict = Depends(require_perm("view"))):
        rows = q("SELECT * FROM treatment_catalog WHERE clinic_id=? AND active=1 ORDER BY code", u["clinic_id"])
        for r in rows:
            r["default_price"] = tl(r.pop("default_price_kurus"))
        return rows

    @app.post("/app/api/treatment-catalog")
    def add_treatment_catalog(b: TreatmentCatalogIn, u: dict = Depends(require_perm("finance_view", "finance_edit"))):
        cid = u["clinic_id"]
        code_up = b.code.strip().upper()
        if q1("SELECT id FROM treatment_catalog WHERE clinic_id=? AND code=? AND active=1", cid, code_up):
            raise HTTPException(409, f"Bu tedavi kodu ({code_up}) zaten katalogda mevcut")
        st = b.default_status if b.default_status in ODO_ALL_STATUSES else "treated"
        tid = ex(
            "INSERT INTO treatment_catalog (clinic_id,code,name,category,default_price_kurus,default_status,active,created_at) VALUES (?,?,?,?,?,?,1,?)",
            cid, code_up, b.name.strip(), b.category.strip(), kurus(b.default_price), st, iso_now(),
        )
        write_audit(u["id"], u["email"], "treatment_catalog.create", f"catalog:{tid}", u["ip_h"], {"code": code_up}, clinic_id=cid)
        return {"id": tid}

    # ------------------------------------------------------------------
    # 3) BANKA ANLAŞMALARI VE OTOMATİK İNDİRİM (BÖLÜM 9)
    # ------------------------------------------------------------------
    @app.get("/app/api/bank-agreements")
    def list_bank_agreements(u: dict = Depends(require_perm("view"))):
        rows = q("SELECT * FROM bank_agreements WHERE clinic_id=? ORDER BY id DESC", u["clinic_id"])
        for r in rows:
            r["fixed_discount"] = tl(r.pop("fixed_discount_kurus"))
            r["max_discount"] = tl(r.pop("max_discount_kurus"))
            r["combinable"] = bool(r["combinable"])
            r["active"] = bool(r["active"])
        return rows

    @app.post("/app/api/bank-agreements")
    def create_bank_agreement(b: BankAgreementIn, u: dict = Depends(require_perm("finance_view", "finance_edit"))):
        cid = u["clinic_id"]
        if b.start_date and b.end_date and b.start_date > b.end_date:
            raise HTTPException(400, "Anlaşma başlangıç tarihi bitiş tarihinden büyük olamaz")
        bid = ex(
            """INSERT INTO bank_agreements
               (clinic_id,bank_name,start_date,end_date,discount_pct,discount_type,fixed_discount_kurus,
                applicable_treatments,max_discount_kurus,combinable,eligibility_notes,active,created_by,created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            cid, b.bank_name.strip(), b.start_date.strip(), b.end_date.strip(), float(b.discount_pct),
            b.discount_type, kurus(b.fixed_discount), b.applicable_treatments.strip() or "all",
            kurus(b.max_discount), 1 if b.combinable else 0, b.eligibility_notes.strip(),
            1 if b.active else 0, u["id"], iso_now(),
        )
        write_audit(u["id"], u["email"], "bank_agreement.create", f"bank_agreement:{bid}", u["ip_h"],
                    {"bank": b.bank_name, "pct": float(b.discount_pct)}, clinic_id=cid)
        return {"id": bid}

    @app.patch("/app/api/bank-agreements/{bid}")
    def update_bank_agreement(bid: int, b: BankAgreementPatchIn, u: dict = Depends(require_perm("finance_view", "finance_edit"))):
        cid = u["clinic_id"]
        row = q1("SELECT * FROM bank_agreements WHERE id=? AND clinic_id=?", bid, cid)
        if not row:
            raise HTTPException(404, "banka anlaşması yok")
        act = (1 if b.active else 0) if b.active is not None else row["active"]
        pct = float(b.discount_pct) if b.discount_pct is not None else row["discount_pct"]
        end_d = b.end_date.strip() if b.end_date is not None else row["end_date"]
        max_k = kurus(b.max_discount) if b.max_discount is not None else row["max_discount_kurus"]
        ex("UPDATE bank_agreements SET active=?, discount_pct=?, end_date=?, max_discount_kurus=? WHERE id=? AND clinic_id=?",
           act, pct, end_d, max_k, bid, cid)
        write_audit(u["id"], u["email"], "bank_agreement.update", f"bank_agreement:{bid}", u["ip_h"], {"active": bool(act), "pct": pct}, clinic_id=cid)
        return {"ok": True}

    @app.post("/app/api/bank-agreements/calculate")
    def calculate_bank_discount_api(b: BankCalcIn, u: dict = Depends(require_perm("view"))):
        cid = u["clinic_id"]
        ag = q1("SELECT * FROM bank_agreements WHERE id=? AND clinic_id=?", b.bank_agreement_id, cid) if b.bank_agreement_id else None
        res = compute_bank_discount(kurus(b.gross_amount), ag, b.procedure_name, kurus(b.manual_discount), b.ref_date)
        return {
            **res,
            "gross_amount": tl(res["gross_kurus"]),
            "bank_discount": tl(res["bank_discount_kurus"]),
            "manual_discount": tl(res["manual_discount_kurus"]),
            "total_discount": tl(res["total_discount_kurus"]),
            "net_payable": tl(res["net_kurus"]),
        }

    # ------------------------------------------------------------------
    # 4) HASTA GRUPLARI VE ETİK ÖZEL İŞARETLEME (BÖLÜM 10)
    # ------------------------------------------------------------------
    @app.get("/app/api/patient-groups")
    def list_patient_groups(u: dict = Depends(require_perm("patient_view"))):
        cid = u["clinic_id"]
        rows = q(
            """SELECT g.*, (SELECT count(*) FROM patient_group_members m WHERE m.group_id=g.id AND m.clinic_id=g.clinic_id) AS member_count
               FROM patient_groups g WHERE g.clinic_id=? ORDER BY g.id""",
            cid,
        )
        for r in rows:
            r["is_restricted"] = bool(r["is_restricted"])
        return rows

    @app.post("/app/api/patient-groups")
    def create_patient_group(b: PatientGroupIn, u: dict = Depends(require_perm("patient_edit"))):
        ok, msg = validate_ethical_group_tag(b.name, b.description)
        if not ok:
            raise HTTPException(400, msg)
        cid = u["clinic_id"]
        try:
            gid = ex(
                "INSERT INTO patient_groups (clinic_id,name,color,is_restricted,description,created_by,created_at) VALUES (?,?,?,?,?,?,?)",
                cid, b.name.strip(), b.color, 1 if b.is_restricted else 0, b.description.strip(), u["id"], iso_now(),
            )
        except Exception as exc:
            if isinstance(exc, sqlite3.IntegrityError) or "integrity" in type(exc).__name__.lower() or "unique" in str(exc).lower():
                raise HTTPException(409, "Bu isimde bir hasta grubu zaten mevcut")
            raise
        write_audit(u["id"], u["email"], "patient_group.create", f"group:{gid}", u["ip_h"], {"name": b.name}, clinic_id=cid)
        return {"id": gid}

    @app.post("/app/api/patients/{pid}/groups")
    def assign_patient_group(pid: int, b: AssignGroupIn, u: dict = Depends(require_perm("patient_edit"))):
        cid = u["clinic_id"]
        _check_doc_own_patient(pid, u)
        if not q1("SELECT id FROM patients WHERE id=? AND clinic_id=?", pid, cid):
            raise HTTPException(404, "hasta yok")
        grp = q1("SELECT * FROM patient_groups WHERE id=? AND clinic_id=?", b.group_id, cid)
        if not grp:
            raise HTTPException(404, "hasta grubu yok")
        ok, msg = validate_ethical_group_tag(grp["name"], b.reason)
        if not ok:
            raise HTTPException(400, msg)
        if grp["is_restricted"] and len(b.reason.strip()) < 3:
            raise HTTPException(400, f"'{grp['name']}' etiketi için nesnel bir neden/açıklama (en az 3 karakter) girilmesi zorunludur")
        t_now = iso_now()
        with db_lock, db() as c:
            c.execute(
                """INSERT INTO patient_group_members (clinic_id,patient_id,group_id,reason,added_by,added_by_name,added_at)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(patient_id, group_id) DO UPDATE SET reason=excluded.reason, added_by=excluded.added_by,
                   added_by_name=excluded.added_by_name, added_at=excluded.added_at""",
                (cid, pid, b.group_id, b.reason.strip(), u["id"], u["full_name"], t_now),
            )
            c.commit()
        write_audit(u["id"], u["email"], "patient.group_assign", f"patient:{pid}:group:{b.group_id}", u["ip_h"],
                    {"group": grp["name"], "reason": b.reason.strip()}, clinic_id=cid)
        return {"ok": True, "group_id": b.group_id, "group_name": grp["name"]}

    @app.delete("/app/api/patients/{pid}/groups/{gid}")
    def remove_patient_group(pid: int, gid: int, u: dict = Depends(require_perm("patient_edit"))):
        cid = u["clinic_id"]
        _check_doc_own_patient(pid, u)
        ex("DELETE FROM patient_group_members WHERE clinic_id=? AND patient_id=? AND group_id=?", cid, pid, gid)
        write_audit(u["id"], u["email"], "patient.group_remove", f"patient:{pid}:group:{gid}", u["ip_h"], clinic_id=cid)
        return {"ok": True}

    # ------------------------------------------------------------------
    # 5) GERÇEK KAMPANYA TIKLAMA VE MÜŞTERİ DÖNÜŞÜM HUNİSİ (BÖLÜM 5)
    # ------------------------------------------------------------------
    def _visitor_hash(request: Request, campaign_id: int | None) -> str:
        ip = client_ip(request)
        ua = (request.headers.get("user-agent") or "")[:160]
        day_s = date.today().isoformat()
        secret = _visitor_key
        return hmac.new(secret, f"v:{campaign_id or 0}:{day_s}:{ip}:{ua}".encode(), hashlib.sha256).hexdigest()[:32]

    def _record_campaign_event(
        request: Request,
        clinic_id: int,
        campaign_id: int | None,
        event_type: str,
        source: str,
        utm_source: str = "",
        utm_medium: str = "",
        utm_campaign: str = "",
        click_id: str = "",
        patient_id: int | None = None,
        appointment_id: int | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        ua = request.headers.get("user-agent") or ""
        purpose = (request.headers.get("purpose") or request.headers.get("x-purpose") or request.headers.get("sec-purpose") or "").lower()
        is_prefetch = "preview" in purpose or "prefetch" in purpose
        bot = 1 if is_bot_traffic(ua, is_prefetch=is_prefetch) else 0
        v_hash = _visitor_hash(request, campaign_id)
        t_now = iso_now()

        with db_lock, db() as c:
            if idempotency_key:
                dup = c.execute(
                    "SELECT id FROM campaign_events WHERE clinic_id=? AND idempotency_key=?",
                    (clinic_id, idempotency_key),
                ).fetchone()
                if dup:
                    return {"ok": True, "dedup": True, "is_bot": bool(bot), "is_unique": False, "event_id": dup["id"]}

            prev_unique = c.execute(
                "SELECT 1 FROM campaign_events WHERE clinic_id=? AND COALESCE(campaign_id,0)=COALESCE(?,0) AND event_type=? AND visitor_hash=? AND is_bot=0 LIMIT 1",
                (clinic_id, campaign_id, event_type, v_hash),
            ).fetchone()
            is_uniq = 1 if (not bot and not prev_unique) else 0

            cur = c.execute(
                """INSERT INTO campaign_events
                   (clinic_id,campaign_id,event_type,source,utm_source,utm_medium,utm_campaign,click_id,
                    visitor_hash,is_bot,is_unique,patient_id,appointment_id,idempotency_key,user_agent_summary,created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    clinic_id, campaign_id, event_type, source, utm_source[:80], utm_medium[:80], utm_campaign[:120],
                    click_id[:120], v_hash, bot, is_uniq, patient_id, appointment_id, idempotency_key, ua[:120], t_now,
                ),
            )
            ev_id = cur.lastrowid
            if campaign_id and event_type == "click" and not bot:
                c.execute("UPDATE campaigns SET clicks = clicks + 1 WHERE id=? AND clinic_id=?", (campaign_id, clinic_id))
            c.commit()
        return {"ok": True, "dedup": False, "is_bot": bool(bot), "is_unique": bool(is_uniq), "event_id": ev_id}

    @app.get("/c/{code}")
    def campaign_tracking_redirect(
        code: str,
        request: Request,
        utm_source: str = "",
        utm_medium: str = "",
        utm_campaign: str = "",
        gclid: str = "",
        fbclid: str = "",
        ttclid: str = "",
        format: str = "",
    ):
        _rate_limit(f"camp_click:{client_ip(request)}", 20, 60)
        camp = q1("SELECT * FROM campaigns WHERE code=? ORDER BY id DESC LIMIT 1", code.strip())
        if not camp:
            raise HTTPException(404, "kampanya takip bağlantısı bulunamadı")
        cid = int(camp["clinic_id"] or 1)
        eff_us = utm_source or camp.get("utm_source") or camp.get("channel") or "instagram"
        eff_um = utm_medium or camp.get("utm_medium") or "cpc"
        eff_uc = utm_campaign or camp.get("utm_campaign") or camp["code"]
        click_id = gclid or fbclid or ttclid or ""
        det_src = detect_acquisition_source(
            explicit_source=camp.get("channel"),
            utm_source=eff_us,
            utm_medium=eff_um,
            referrer=request.headers.get("referer"),
            gclid=gclid,
            fbclid=fbclid,
            ttclid=ttclid,
        )
        ev = _record_campaign_event(
            request, cid, camp["id"], "click", det_src,
            utm_source=eff_us, utm_medium=eff_um, utm_campaign=eff_uc, click_id=click_id,
        )
        q_params = {
            "dc_cid": camp["id"], "dc_code": camp["code"], "utm_source": eff_us, "utm_medium": eff_um,
            "utm_campaign": eff_uc, "source": det_src,
        }
        if click_id:
            q_params["click_id"] = click_id
        # Tüm parametreler urlencode ile kodlanır: '&' / '=' enjeksiyonu Location başlığına sızamaz (CWE-74)
        target = "/?" + urlencode(q_params)
        if format == "json" or "application/json" in (request.headers.get("accept") or ""):
            return {
                "ok": True,
                "campaign_id": camp["id"],
                "code": camp["code"],
                "detected_source": det_src,
                "is_bot": ev["is_bot"],
                "is_unique": ev["is_unique"],
                "redirect_to": target,
            }
        return RedirectResponse(target, status_code=302)

    @app.post("/api/campaigns/track")
    def track_campaign_event_public(b: CampaignTrackIn, request: Request):
        _rate_limit(f"camp_track:{client_ip(request)}", 20, 60)
        camp = None
        if b.campaign_id:
            camp = q1("SELECT * FROM campaigns WHERE id=?", b.campaign_id)
        elif b.campaign_code:
            camp = q1("SELECT * FROM campaigns WHERE code=?", b.campaign_code.strip())
        elif b.utm_campaign:
            camp = q1("SELECT * FROM campaigns WHERE utm_campaign=? OR code=?", b.utm_campaign.strip(), b.utm_campaign.strip())
        cid = int(camp["clinic_id"]) if camp else 1
        camp_id = int(camp["id"]) if camp else None
        cid_tok = b.click_id or b.gclid or b.fbclid or b.ttclid or ""
        det_src = detect_acquisition_source(
            explicit_source=b.source or (camp and camp.get("channel")),
            utm_source=b.utm_source or (camp and camp.get("utm_source")),
            utm_medium=b.utm_medium or (camp and camp.get("utm_medium")),
            referrer=request.headers.get("referer"),
            gclid=b.gclid,
            fbclid=b.fbclid,
            ttclid=b.ttclid,
        )
        ev = _record_campaign_event(
            request, cid, camp_id, b.event_type, det_src,
            utm_source=b.utm_source, utm_medium=b.utm_medium, utm_campaign=b.utm_campaign,
            click_id=cid_tok, idempotency_key=b.idempotency_key,
        )
        return {**ev, "campaign_id": camp_id, "detected_source": det_src}

    @app.get("/app/api/campaigns/report")
    @app.get("/app/api/campaigns/funnel")
    def get_campaigns_funnel_report(request: Request, include_samples: bool = False, u: dict = Depends(require_perm("view"))):
        cid = u["clinic_id"]
        base_url = str(request.base_url).rstrip("/")
        sql = "SELECT * FROM campaigns WHERE clinic_id=?"
        if not include_samples:
            sql += " AND COALESCE(is_sample, 0) = 0"
        sql += " ORDER BY id DESC"
        camps = q(sql, cid)
        out = []
        for cp in camps:
            cp_id = cp["id"]
            evs = q("SELECT event_type, is_bot, is_unique FROM campaign_events WHERE clinic_id=? AND campaign_id=?", cid, cp_id)
            real_clicks = sum(1 for e in evs if e["event_type"] == "click" and not e["is_bot"])
            uniq_clicks = sum(1 for e in evs if e["event_type"] == "click" and not e["is_bot"] and e["is_unique"])
            bot_clicks = sum(1 for e in evs if e["event_type"] == "click" and e["is_bot"])
            form_starts = sum(1 for e in evs if e["event_type"] == "form_start" and not e["is_bot"])
            form_submits = sum(1 for e in evs if e["event_type"] == "form_submit" and not e["is_bot"])
            ev_pat_created = sum(1 for e in evs if e["event_type"] == "patient_created" and not e["is_bot"])

            uc_key = cp.get("utm_campaign") or cp.get("code") or "__none__"
            pats = q(
                """SELECT DISTINCT p.id FROM patients p
                   LEFT JOIN campaign_events ce ON ce.patient_id=p.id AND ce.campaign_id=?
                   WHERE p.clinic_id=? AND (p.campaign_id=? OR (p.utm_campaign<>'' AND p.utm_campaign=?) OR ce.id IS NOT NULL)""",
                cp_id, cid, cp_id, uc_key,
            )
            pids = [p["id"] for p in pats]
            pat_cnt = max(len(pids), ev_pat_created)
            appts_cnt = 0
            visits_done = 0
            collected_k = 0
            if pids or cp_id:
                ap_rows = q(
                    """SELECT DISTINCT a.id, a.status FROM appointments a
                       LEFT JOIN patients p ON p.id=a.patient_id
                       WHERE a.clinic_id=? AND a.status<>'cancelled'
                         AND (a.campaign_id=? OR p.campaign_id=? OR (p.utm_campaign<>'' AND p.utm_campaign=?)
                              OR EXISTS (SELECT 1 FROM campaign_events ce WHERE ce.patient_id=p.id AND ce.campaign_id=?))""",
                    cid, cp_id, cp_id, uc_key, cp_id,
                )
                appts_cnt = len(ap_rows)
                visits_done = sum(1 for a in ap_rows if a["status"] == "done")
                py_row = q1(
                    """SELECT COALESCE(sum(
                         CASE WHEN py.status='refunded' THEN -py.amount_kurus
                              WHEN COALESCE(py.status,'completed')='completed' AND py.method<>'avans_mahsup' THEN py.amount_kurus
                              ELSE 0 END
                       ),0) AS s FROM payments py
                       JOIN patients p ON p.id=py.patient_id
                       WHERE py.clinic_id=? AND p.clinic_id=?
                         AND (p.campaign_id=? OR (p.utm_campaign<>'' AND p.utm_campaign=?)
                              OR EXISTS (SELECT 1 FROM campaign_events ce WHERE ce.patient_id=p.id AND ce.campaign_id=?))
                         AND py.voided_at IS NULL""",
                    cid, cid, cp_id, uc_key, cp_id,
                )
                collected_k = max(0, int((py_row and py_row["s"]) or 0))

            code = cp.get("code") or f"kampanya-{cp_id}"
            us = cp.get("utm_source") or cp.get("channel") or "instagram"
            um = cp.get("utm_medium") or "cpc"
            uc = cp.get("utm_campaign") or code
            track_url = f"{base_url}/c/{code}?utm_source={us}&utm_medium={um}&utm_campaign={uc}"
            conv_patient_pct = round(100.0 * pat_cnt / uniq_clicks, 2) if uniq_clicks > 0 else 0.0
            conv_appt_pct = round(100.0 * appts_cnt / uniq_clicks, 2) if uniq_clicks > 0 else 0.0

            out.append({
                "id": cp_id,
                "name": cp["name"],
                "code": code,
                "channel": cp.get("channel") or cp.get("source") or "instagram",
                "utm_source": us,
                "utm_medium": um,
                "utm_campaign": uc,
                "tracking_url": track_url,
                "is_sample": bool(cp.get("is_sample", 0)),
                "raw_clicks": real_clicks + bot_clicks,
                "total_clicks": real_clicks,
                "unique_clicks": uniq_clicks,
                "bot_clicks": bot_clicks,
                "form_start": form_starts,
                "form_starts": form_starts,
                "form_submit": form_submits,
                "form_submits": form_submits,
                "patient_created": pat_cnt,
                "patients_created": pat_cnt,
                "appointments_booked": appts_cnt,
                "visits_done": visits_done,
                "visits_completed": visits_done,
                "collected_revenue_try": tl(collected_k),
                "declared_clicks": int(cp.get("clicks") or 0),
                "declared_revenue_try": tl(int(cp.get("revenue_kurus") or 0)),
                "conversion_patient_pct": conv_patient_pct,
                "conversion_appointment_pct": conv_appt_pct,
                "created_at": cp["created_at"],
            })

        # Kanal bazlı gerçek hasta dağılımı (first_source)
        src_rows = q(
            "SELECT first_source, count(*) AS patient_count FROM patients WHERE clinic_id=? AND active=1 GROUP BY first_source ORDER BY patient_count DESC",
            cid,
        )
        return {
            "measurement_honesty_notice_tr": (
                "Sunucu tarafı gerçek ölçüm aktiftir: Bot/önizleme tarayıcıları ayrıştırılır ve ham IP saklanmadan tekil ziyaretçi "
                "özetlemesi yapılır. iOS gizlilik kısıtlamaları, reklam engelleyiciler veya doğrudan telefon aramaları nedeniyle "
                "dijital reklam tıklamalarında %100 ölçüm garantisi verilemez."
            ),
            "campaigns": out,
            "patients_by_first_source": [
                {"source": r["first_source"], "label": PATIENT_SOURCE_LABELS.get(r["first_source"], r["first_source"]), "count": r["patient_count"]}
                for r in src_rows
            ],
        }

    # ------------------------------------------------------------------
    # 6) FİNANS: İADE, AVANS MAHSUP, TAKSİT, KASA KAPANIŞI, GİDER & DOKTOR GELİR (BÖLÜM 7, 11, 12)
    # ------------------------------------------------------------------
    @app.post("/app/api/payments/{pay_id}/refund")
    def refund_payment(pay_id: int, b: RefundIn, u: dict = Depends(require_perm("finance_view", "finance_edit"))):
        cid = u["clinic_id"]
        pre = q1("SELECT patient_id FROM payments WHERE id=? AND clinic_id=?", pay_id, cid)
        if pre and pre.get("patient_id"):
            _check_doc_own_patient(int(pre["patient_id"]), u)
        with db_lock, db() as c:
            if b.idempotency_key:
                dup = c.execute(
                    "SELECT id, amount_kurus, refund_of_id FROM payments WHERE clinic_id=? AND idempotency_key=?",
                    (cid, b.idempotency_key),
                ).fetchone()
                if dup:
                    if dup["refund_of_id"] != pay_id:
                        raise HTTPException(409, "Bu idempotency anahtarı başka bir işlem için kullanılmış")
                    return {"ok": True, "refund_id": dup["id"], "refunded_amount": tl(dup["amount_kurus"]),
                            "idempotent_replay": True}
            orig = c.execute(
                "SELECT * FROM payments WHERE id=? AND clinic_id=? AND voided_at IS NULL AND COALESCE(status,'completed')='completed' AND method<>'avans_mahsup'",
                (pay_id, cid),
            ).fetchone()
            if not orig:
                raise HTTPException(404, "İade edilecek geçerli tahsilat bulunamadı (iç avans mahsup hareketleri doğrudan iade edilemez)")
            already_ref = (c.execute(
                "SELECT COALESCE(sum(amount_kurus),0) AS s FROM payments WHERE clinic_id=? AND refund_of_id=? AND voided_at IS NULL AND status='refunded'",
                (cid, pay_id),
            ).fetchone() or {"s": 0})["s"]
            rem_refundable = int(orig["amount_kurus"]) - int(already_ref or 0)
            ref_k = kurus(b.amount) if b.amount is not None else rem_refundable
            if ref_k <= 0 or ref_k > rem_refundable:
                raise HTTPException(422, f"İade tutarı kalan iade edilebilir tutarı ({tl(rem_refundable):.2f} TL) aşamaz")
            t_now = iso_now()
            cur = c.execute(
                """INSERT INTO payments
                   (clinic_id,patient_id,amount_kurus,method,status,doctor_id,refund_of_id,note,created_by,created_at,idempotency_key)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (cid, orig["patient_id"], ref_k, orig["method"], "refunded", orig["doctor_id"], pay_id, f"İade (#{pay_id}): {b.reason}", u["id"], t_now, b.idempotency_key),
            )
            ref_id = cur.lastrowid
            fin = compute_patient_finance_summary(c, cid, orig["patient_id"], tl)
            c.commit()
        write_audit(u["id"], u["email"], "kasa.payment_refund", f"payment:{pay_id}->refund:{ref_id}", u["ip_h"],
                    {"refund_kurus": ref_k, "reason": b.reason}, clinic_id=cid)
        return {"ok": True, "refund_id": ref_id, "refunded_amount": tl(ref_k), "finance_summary": fin}

    @app.post("/app/api/patients/{pid}/settle-advance")
    def settle_patient_advance(pid: int, b: AdvanceSettleIn, u: dict = Depends(require_perm("finance_edit"))):
        cid = u["clinic_id"]
        _check_doc_own_patient(pid, u)
        with db_lock, db() as c:
            if b.charge_id is not None:
                ch = c.execute("SELECT * FROM charges WHERE id=? AND clinic_id=? AND patient_id=? AND voided_at IS NULL", (b.charge_id, cid, pid)).fetchone()
            else:
                ch = c.execute("SELECT * FROM charges WHERE clinic_id=? AND patient_id=? AND voided_at IS NULL ORDER BY id DESC LIMIT 1", (cid, pid)).fetchone()
            if not ch:
                raise HTTPException(404, "Mahsup edilecek hizmet borcu bulunamadı")
            target_cid = int(ch["id"])
            adv_rows = c.execute(
                "SELECT COALESCE(sum(amount_kurus),0) AS s FROM payments WHERE clinic_id=? AND patient_id=? AND voided_at IS NULL AND COALESCE(status,'completed')='completed' AND is_advance=1",
                (cid, pid),
            ).fetchone()
            adv_refunded_rows = c.execute(
                """SELECT COALESCE(sum(r.amount_kurus),0) AS s FROM payments r
                   JOIN payments orig ON orig.id=r.refund_of_id
                   WHERE r.clinic_id=? AND r.patient_id=? AND r.voided_at IS NULL AND r.status='refunded' AND orig.is_advance=1""",
                (cid, pid),
            ).fetchone()
            settled_rows = c.execute(
                "SELECT COALESCE(sum(amount_kurus),0) AS s FROM payments WHERE clinic_id=? AND patient_id=? AND voided_at IS NULL AND method='avans_mahsup'",
                (cid, pid),
            ).fetchone()
            avail_adv_k = max(
                0,
                int((adv_rows and adv_rows["s"]) or 0)
                - int((adv_refunded_rows and adv_refunded_rows["s"]) or 0)
                - int((settled_rows and settled_rows["s"]) or 0),
            )
            if avail_adv_k <= 0:
                raise HTTPException(422, "Hastanın mahsup edilebilir açık avansı bulunmuyor")
            already_on_charge_row = c.execute(
                "SELECT COALESCE(sum(amount_kurus),0) AS s FROM payments WHERE clinic_id=? AND patient_id=? AND applied_charge_id=? AND voided_at IS NULL AND COALESCE(status,'completed')='completed'",
                (cid, pid, target_cid),
            ).fetchone()
            rem_charge_k = max(0, int(ch["amount_kurus"]) - int((already_on_charge_row and already_on_charge_row["s"]) or 0))
            if rem_charge_k <= 0:
                raise HTTPException(422, "Seçilen hizmet borcu zaten tamamen mahsup edilmiş veya ödenmiştir")
            req_k = kurus(b.amount) if b.amount is not None else min(avail_adv_k, rem_charge_k)
            if req_k > rem_charge_k:
                raise HTTPException(422, f"Mahsup tutarı kalan hizmet borcunu ({tl(rem_charge_k):.2f} TL) aşamaz")
            settle_k = min(avail_adv_k, rem_charge_k, req_k)
            cur = c.execute(
                """INSERT INTO payments
                   (clinic_id,patient_id,amount_kurus,method,status,applied_charge_id,note,created_by,created_at)
                   VALUES (?,?,?,'avans_mahsup','completed',?,?,?,?)""",
                (cid, pid, settle_k, target_cid, f"Avans mahsubu (Hizmet #{target_cid}: {ch['description'][:60]})", u["id"], iso_now()),
            )
            mid = cur.lastrowid
            fin = compute_patient_finance_summary(c, cid, pid, tl)
            c.commit()
        write_audit(u["id"], u["email"], "kasa.advance_settle", f"patient:{pid}:charge:{target_cid}", u["ip_h"],
                    {"settled_kurus": settle_k}, clinic_id=cid)
        return {"ok": True, "settlement_id": mid, "charge_id": target_cid, "settled_amount": tl(settle_k), "finance_summary": fin}

    @app.get("/app/api/patients/{pid}/installments")
    def list_patient_installments(pid: int, u: dict = Depends(require_perm("patient_view", "finance_view"))):
        cid = u["clinic_id"]
        _check_doc_own_patient(pid, u)
        rows = q("SELECT * FROM payment_installments WHERE clinic_id=? AND patient_id=? ORDER BY installment_no, due_date", cid, pid)
        today_s = date.today().isoformat()
        for r in rows:
            r["amount"] = tl(r.pop("amount_kurus"))
            r["paid_amount"] = tl(r.pop("paid_kurus"))
            r["remaining_amount"] = round(r["amount"] - r["paid_amount"], 2)
            if r["status"] == "pending" and r["due_date"] < today_s:
                r["status"] = "overdue"
        return rows

    @app.post("/app/api/patients/{pid}/installments")
    def create_patient_installments(pid: int, b: InstallmentPlanIn, u: dict = Depends(require_perm("finance_edit"))):
        cid = u["clinic_id"]
        _check_doc_own_patient(pid, u)
        if not q1("SELECT id FROM patients WHERE id=? AND clinic_id=?", pid, cid):
            raise HTTPException(404, "hasta yok")
        if b.charge_id is not None and not q1("SELECT id FROM charges WHERE id=? AND clinic_id=? AND patient_id=? AND voided_at IS NULL", b.charge_id, cid, pid):
            raise HTTPException(404, "İlişkili hizmet borcu bu hasta/klinik için bulunamadı")
        total_k = kurus(b.total_amount)
        cnt = b.installment_count
        base_k = total_k // cnt
        rem_k = total_k - (base_k * cnt)
        try:
            start_d = date.fromisoformat(b.first_due_date[:10])
        except ValueError:
            raise HTTPException(422, "Geçersiz taksit başlangıç tarihi (YYYY-MM-DD olmalıdır)")
        t_now = iso_now()
        ids = []
        with db_lock, db() as c:
            for i in range(cnt):
                amt_i = base_k + (rem_k if i == cnt - 1 else 0)
                due_i = (start_d + timedelta(days=30 * i)).isoformat()
                cur = c.execute(
                    """INSERT INTO payment_installments
                       (clinic_id,patient_id,charge_id,installment_no,total_installments,amount_kurus,paid_kurus,due_date,status,note,created_by,created_at)
                       VALUES (?,?,?,?,?,?,0,?,'pending',?,?,?)""",
                    (cid, pid, b.charge_id, i + 1, cnt, amt_i, due_i, b.note.strip(), u["id"], t_now),
                )
                ids.append(cur.lastrowid)
            c.commit()
        write_audit(u["id"], u["email"], "installment.plan_create", f"patient:{pid}", u["ip_h"],
                    {"count": cnt, "total_kurus": total_k}, clinic_id=cid)
        return {"ok": True, "installment_ids": ids, "count": cnt, "total_amount": tl(total_k)}

    @app.post("/app/api/installments/{iid}/pay")
    def pay_installment(iid: int, b: InstallmentPayIn, u: dict = Depends(require_perm("finance_edit"))):
        cid = u["clinic_id"]
        inst_chk = q1("SELECT patient_id FROM payment_installments WHERE id=? AND clinic_id=?", iid, cid)
        if inst_chk and inst_chk.get("patient_id"):
            _check_doc_own_patient(int(inst_chk["patient_id"]), u)
        with db_lock, db() as c:
            inst = c.execute("SELECT * FROM payment_installments WHERE id=? AND clinic_id=?", (iid, cid)).fetchone()
            if not inst or inst["status"] in ("paid", "voided"):
                raise HTTPException(404, "Ödenecek açık taksit bulunamadı")
            rem_k = int(inst["amount_kurus"]) - int(inst["paid_kurus"])
            pay_k = kurus(b.amount) if b.amount is not None else rem_k
            if pay_k <= 0 or pay_k > rem_k:
                raise HTTPException(422, f"Taksit ödeme tutarı kalan taksit borcunu ({tl(rem_k):.2f} TL) aşamaz")
            t_now = iso_now()
            cur_p = c.execute(
                """INSERT INTO payments
                   (clinic_id,patient_id,amount_kurus,method,status,applied_charge_id,note,created_by,created_at)
                   VALUES (?,?,?,?,'completed',?,?,?,?)""",
                (cid, inst["patient_id"], pay_k, b.method, inst["charge_id"],
                 f"Taksit #{inst['installment_no']}/{inst['total_installments']} ödemesi", u["id"], t_now),
            )
            pay_id = cur_p.lastrowid
            new_paid_k = int(inst["paid_kurus"]) + pay_k
            new_st = "paid" if new_paid_k >= int(inst["amount_kurus"]) else "pending"
            c.execute("UPDATE payment_installments SET paid_kurus=?, status=?, paid_payment_id=? WHERE id=?",
                      (new_paid_k, new_st, pay_id, iid))
            fin = compute_patient_finance_summary(c, cid, inst["patient_id"], tl)
            c.commit()
        write_audit(u["id"], u["email"], "installment.pay", f"installment:{iid}", u["ip_h"], {"paid_kurus": pay_k}, clinic_id=cid)
        return {"ok": True, "payment_id": pay_id, "installment_status": new_st, "finance_summary": fin}

    @app.get("/app/api/doctors/revenue-report")
    def doctor_revenue_report(u: dict = Depends(require_perm("doctor_reports"))):
        cid = u["clinic_id"]
        docs = q("SELECT id, full_name, role, job_title, share_pct FROM staff_users WHERE clinic_id=? AND role IN ('owner','doctor') AND active=1 ORDER BY id", cid)
        out = []
        for d in docs:
            did = d["id"]
            owned_cnt = q1("SELECT count(*) AS n FROM patients WHERE clinic_id=? AND primary_doctor_id=? AND active=1", cid, did)["n"]
            odo_cnt = q1("SELECT count(*) AS n FROM tooth_records WHERE clinic_id=? AND doctor_id=? AND status IN ('treated','filling','root_canal','crown','bridge','implant')", cid, did)["n"]
            ch_rows = q("SELECT amount_kurus, gross_amount_kurus, discount_kurus FROM charges WHERE clinic_id=? AND doctor_id=? AND voided_at IS NULL", cid, did)
            perf_cnt = max(int(odo_cnt or 0), len(ch_rows))
            net_k = sum(int(r["amount_kurus"] or 0) for r in ch_rows)
            disc_k = sum(int(r["discount_kurus"] or 0) for r in ch_rows)
            gross_k = sum(int(r["gross_amount_kurus"] or (int(r["amount_kurus"] or 0) + int(r["discount_kurus"] or 0))) for r in ch_rows)
            pct = Decimal(str(d["share_pct"] or 0))
            doc_share_k = int((Decimal(net_k) * pct / Decimal(100)).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
            clinic_share_k = net_k - doc_share_k
            out.append({
                "doctor_id": did,
                "full_name": d["full_name"],
                "share_pct": float(pct),
                "owned_patients_count": owned_cnt,
                "performed_procedures_count": perf_cnt,
                "gross_billed": tl(gross_k),
                "discount_total": tl(disc_k),
                "net_billed": tl(net_k),
                "doctor_hakedis": tl(doc_share_k),
                "clinic_share": tl(clinic_share_k),
            })
        return out

    # Tedarikçi, Gider ve Günlük Kasa Kapanışı (Bölüm 12)
    @app.get("/app/api/suppliers")
    def list_suppliers(u: dict = Depends(require_perm("inventory_manage"))):
        rows = q("SELECT * FROM suppliers WHERE clinic_id=? ORDER BY id DESC", u["clinic_id"])
        for r in rows:
            r["balance"] = tl(r.pop("balance_kurus"))
        return rows

    @app.post("/app/api/suppliers")
    def create_supplier(b: SupplierIn, u: dict = Depends(require_perm("inventory_manage"))):
        sid = ex(
            "INSERT INTO suppliers (clinic_id,name,contact_name,phone,email,tax_no,balance_kurus,note,created_at) VALUES (?,?,?,?,?,?,0,?,?)",
            u["clinic_id"], b.name.strip(), b.contact_name.strip(), b.phone.strip(), b.email.strip(), b.tax_no.strip(), b.note.strip(), iso_now(),
        )
        write_audit(u["id"], u["email"], "supplier.create", f"supplier:{sid}", u["ip_h"], {"name": b.name}, clinic_id=u["clinic_id"])
        return {"id": sid}

    @app.get("/app/api/expenses")
    def list_expenses(u: dict = Depends(require_perm("finance_view"))):
        rows = q(
            """SELECT e.*, s.name AS supplier_name FROM expenses e
               LEFT JOIN suppliers s ON s.id=e.supplier_id AND s.clinic_id=e.clinic_id
               WHERE e.clinic_id=? ORDER BY e.id DESC LIMIT 200""",
            u["clinic_id"],
        )
        for r in rows:
            r["amount"] = tl(r.pop("amount_kurus"))
        return rows

    @app.post("/app/api/expenses")
    def create_expense(b: ExpenseIn, u: dict = Depends(require_perm("finance_view", "finance_edit"))):
        cid = u["clinic_id"]
        if b.supplier_id is not None and not q1("SELECT id FROM suppliers WHERE id=? AND clinic_id=?", b.supplier_id, cid):
            raise HTTPException(404, "Seçilen tedarikçi bu klinikte bulunamadı")
        amt_k = kurus(b.amount)
        eid = ex(
            "INSERT INTO expenses (clinic_id,supplier_id,category,description,amount_kurus,method,paid_at,created_by) VALUES (?,?,?,?,?,?,?,?)",
            cid, b.supplier_id, b.category, b.description.strip(), amt_k, b.method, iso_now(), u["id"],
        )
        write_audit(u["id"], u["email"], "expense.create", f"expense:{eid}", u["ip_h"], {"amount_kurus": amt_k, "category": b.category}, clinic_id=cid)
        return {"id": eid, "amount": tl(amt_k)}

    @app.get("/app/api/kasa/closings")
    def list_cash_closings(u: dict = Depends(require_perm("finance_view"))):
        rows = q(
            """SELECT cc.*, s.full_name AS closed_by_name FROM cash_closings cc
               LEFT JOIN staff_users s ON s.id=cc.closed_by
               WHERE cc.clinic_id=? ORDER BY cc.id DESC LIMIT 60""",
            u["clinic_id"],
        )
        for r in rows:
            for k in ("opening_balance", "total_in", "total_out", "cash_in", "card_in", "bank_in", "closing_balance", "physical_counted", "diff"):
                r[k] = tl(r.pop(f"{k}_kurus"))
        return rows

    @app.post("/app/api/kasa/closings")
    def create_cash_closing(b: CashClosingIn, u: dict = Depends(require_perm("finance_view", "finance_edit"))):
        cid = u["clinic_id"]
        c_date = (b.closing_date or datetime.now(TZ).strftime("%Y-%m-%d"))[:10]
        try:
            date.fromisoformat(c_date)
        except ValueError:
            raise HTTPException(422, "Geçersiz kapanış tarihi")
        if q1("SELECT id FROM cash_closings WHERE clinic_id=? AND closing_date=?", cid, c_date):
            raise HTTPException(409, f"{c_date} tarihi için günlük kasa kapanışı zaten yapılmıştır")
        pays = q(
            "SELECT amount_kurus, method, status FROM payments WHERE clinic_id=? AND voided_at IS NULL AND substr(CAST(created_at AS TEXT),1,10)=?",
            cid, c_date,
        )
        exps = q(
            "SELECT amount_kurus, method FROM expenses WHERE clinic_id=? AND voided_at IS NULL AND substr(CAST(paid_at AS TEXT),1,10)=?",
            cid, c_date,
        )
        cash_in_k = sum(int(p["amount_kurus"]) for p in pays if (p["status"] or "completed") == "completed" and p["method"] == "nakit")
        card_in_k = sum(int(p["amount_kurus"]) for p in pays if (p["status"] or "completed") == "completed" and p["method"] in ("kart", "kredi_karti", "banka_karti", "taksitli"))
        bank_in_k = sum(int(p["amount_kurus"]) for p in pays if (p["status"] or "completed") == "completed" and p["method"] == "havale")
        cash_refund_out_k = sum(int(p["amount_kurus"]) for p in pays if p["status"] == "refunded" and p["method"] == "nakit")
        refund_out_k = sum(int(p["amount_kurus"]) for p in pays if p["status"] == "refunded")
        cash_exp_out_k = sum(int(e["amount_kurus"]) for e in exps if e["method"] == "nakit")
        exp_out_k = sum(int(e["amount_kurus"]) for e in exps)

        open_k = kurus(b.opening_balance)
        tot_in_k = cash_in_k + card_in_k + bank_in_k
        tot_out_k = refund_out_k + exp_out_k
        # Fiziksel nakit çekmecesi kapanış bakiyesi (Açılış + Nakit Giriş - Nakit Çıkış)
        close_k = open_k + cash_in_k - (cash_refund_out_k + cash_exp_out_k)
        phys_k = kurus(b.physical_counted)
        diff_k = phys_k - close_k

        cc_id = ex(
            """INSERT INTO cash_closings
               (clinic_id,closing_date,opening_balance_kurus,total_in_kurus,total_out_kurus,cash_in_kurus,card_in_kurus,bank_in_kurus,
                closing_balance_kurus,physical_counted_kurus,diff_kurus,note,closed_by,closed_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            cid, c_date, open_k, tot_in_k, tot_out_k, cash_in_k, card_in_k, bank_in_k, close_k, phys_k, diff_k, b.note.strip(), u["id"], iso_now(),
        )
        write_audit(u["id"], u["email"], "kasa.daily_closing", f"closing:{cc_id}", u["ip_h"],
                    {"date": c_date, "closing_kurus": close_k, "diff_kurus": diff_k}, clinic_id=cid)
        return {
            "id": cc_id,
            "closing_date": c_date,
            "opening_balance": tl(open_k),
            "total_in": tl(tot_in_k),
            "total_out": tl(tot_out_k),
            "cash_in": tl(cash_in_k),
            "card_in": tl(card_in_k),
            "bank_in": tl(bank_in_k),
            "closing_balance": tl(close_k),
            "physical_counted": tl(phys_k),
            "diff": tl(diff_k),
        }

    def _check_doc_own_patient(pid: int, u: dict) -> dict:
        cid = u["clinic_id"]
        p = q1("SELECT * FROM patients WHERE id=? AND clinic_id=?", pid, cid)
        if not p:
            raise HTTPException(404, "hasta yok")
        perms = u.get("permissions") or resolve_permissions(u.get("role"), u.get("job_title"), u.get("permissions_json"))
        if perms.get("doctor_own_patients_only") and u.get("role") != "owner":
            uid = u["id"]
            if p.get("primary_doctor_id") != uid and p.get("created_by") != uid:
                has_rel = (
                    q1("SELECT 1 FROM appointments WHERE clinic_id=? AND patient_id=? AND doctor_id=? LIMIT 1", cid, pid, uid)
                    or q1("SELECT 1 FROM tooth_records WHERE clinic_id=? AND patient_id=? AND doctor_id=? LIMIT 1", cid, pid, uid)
                    or q1("SELECT 1 FROM charges WHERE clinic_id=? AND patient_id=? AND doctor_id=? LIMIT 1", cid, pid, uid)
                )
                if not has_rel:
                    raise HTTPException(403, "Yalnızca kendi sorumlu olduğunuz veya işlem yaptığınız hastaları görüntüleyebilirsiniz")
        return p

    # ------------------------------------------------------------------
    # 7) PERIODONTAL ÇİZELGE, DİJİTAL TEDAVİ ONAMI, LABORATUVAR & İMPLANT LOT (BÖLÜM 8, 9, 18)
    # ------------------------------------------------------------------
    @app.get("/app/api/patients/{pid}/periodontal")
    def list_periodontal_exams(pid: int, u: dict = Depends(require_perm("patient_view"))):
        cid = u["clinic_id"]
        _check_doc_own_patient(pid, u)
        rows = q(
            """SELECT pe.*, s.full_name AS doctor_name FROM periodontal_exams pe
               LEFT JOIN staff_users s ON s.id=pe.doctor_id
               WHERE pe.clinic_id=? AND pe.patient_id=? ORDER BY pe.exam_date DESC, pe.id DESC""",
            cid, pid,
        )
        for r in rows:
            r["measurements"] = json.loads(r.pop("measurements_json") or "{}")
            r["doctor_approved"] = bool(r["doctor_approved"])
        comparison = None
        if len(rows) >= 2:
            latest, prev = rows[0], rows[1]
            comparison = {
                "latest_date": latest["exam_date"],
                "previous_date": prev["exam_date"],
                "delta_mean_pd": round(float(latest["mean_pd"]) - float(prev["mean_pd"]), 2),
                "delta_max_pd": int(latest["max_pd"]) - int(prev["max_pd"]),
                "delta_bop_pct": round(float(latest["bop_pct"]) - float(prev["bop_pct"]), 1),
                "delta_plaque_pct": round(float(latest["plaque_pct"]) - float(prev["plaque_pct"]), 1),
            }
        return {"exams": rows, "comparison_with_previous": comparison}

    @app.post("/app/api/patients/{pid}/periodontal")
    def create_periodontal_exam(pid: int, b: PerioExamIn, u: dict = Depends(require_perm("patient_edit"))):
        if u["role"] not in ("owner", "doctor"):
            raise HTTPException(403, "Periodontal klinik ölçüm kaydı yalnızca diş hekimi onayıyla girilebilir")
        cid = u["clinic_id"]
        _check_doc_own_patient(pid, u)
        if b.doctor_id is not None and not q1("SELECT id FROM staff_users WHERE id=? AND clinic_id=?", b.doctor_id, cid):
            raise HTTPException(404, "Seçilen hekim bu klinikte bulunamadı")
        if not b.teeth:
            raise HTTPException(400, "En az bir diş için periodontal ölçüm girilmelidir")
        all_pds: list[int] = []
        all_bop: list[bool] = []
        all_plq: list[bool] = []
        serialized: dict[str, Any] = {}
        for fdi_str, tm in b.teeth.items():
            try:
                fdi_num = int(fdi_str)
            except (ValueError, TypeError):
                raise HTTPException(400, f"Geçersiz FDI diş numarası: {fdi_str}")
            if fdi_num not in VALID_FDI_NUMBERS:
                raise HTTPException(400, f"Geçersiz FDI diş numarası: {fdi_num}")
            cal_vals = [int(p) + int(g) for p, g in zip(tm.pd, tm.gm)]
            all_pds.extend(int(x) for x in tm.pd)
            all_bop.extend(bool(x) for x in tm.bop)
            all_plq.extend(bool(x) for x in tm.plaque)
            serialized[str(fdi_num)] = {
                "pd": [int(x) for x in tm.pd],
                "gm": [int(x) for x in tm.gm],
                "cal": cal_vals,
                "bop": [bool(x) for x in tm.bop],
                "plaque": [bool(x) for x in tm.plaque],
                "mobility": tm.mobility,
                "furcation": tm.furcation,
            }
        mean_pd = round(sum(all_pds) / max(1, len(all_pds)), 2)
        max_pd = max(all_pds) if all_pds else 0
        bop_pct = round(100.0 * sum(1 for x in all_bop if x) / max(1, len(all_bop)), 1)
        plq_pct = round(100.0 * sum(1 for x in all_plq if x) / max(1, len(all_plq)), 1)
        ex_date = (b.exam_date or date.today().isoformat())[:10]
        pe_id = ex(
            """INSERT INTO periodontal_exams
               (clinic_id,patient_id,doctor_id,exam_date,measurements_json,mean_pd,max_pd,bop_pct,plaque_pct,doctor_approved,doctor_note,created_by,created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            cid, pid, b.doctor_id or u["id"], ex_date, json.dumps(serialized, ensure_ascii=False),
            mean_pd, max_pd, bop_pct, plq_pct, 1 if b.doctor_approved else 0, b.doctor_note.strip(), u["id"], iso_now(),
        )
        write_audit(u["id"], u["email"], "periodontal.create", f"patient:{pid}:perio:{pe_id}", u["ip_h"],
                    {"mean_pd": mean_pd, "max_pd": max_pd, "bop_pct": bop_pct}, clinic_id=cid)
        return {"id": pe_id, "mean_pd": mean_pd, "max_pd": max_pd, "bop_pct": bop_pct, "plaque_pct": plq_pct}

    # Dijital Tedavi Onamı (Bölüm 9 & 18)
    @app.get("/app/api/patients/{pid}/treatment-consents")
    def list_treatment_consents(request: Request, pid: int, u: dict = Depends(require_perm("patient_view"))):
        cid = u["clinic_id"]
        _check_doc_own_patient(pid, u)
        base_url = str(request.base_url).rstrip("/")
        rows = q("SELECT * FROM treatment_consents WHERE clinic_id=? AND patient_id=? ORDER BY id DESC", cid, pid)
        for r in rows:
            r["plan_items"] = json.loads(r.pop("plan_summary_json") or "[]")
            r["total_amount"] = tl(r.pop("total_amount_kurus"))
            r["sign_url"] = f"{base_url}/form/tedavi-onay/{r['token']}"
            r["legal_notice"] = LEGAL_CONSENT_NOTICE_TR
            r.pop("signature_svg_enc", None)
        return rows

    @app.post("/app/api/patients/{pid}/treatment-consents")
    def create_treatment_consent(request: Request, pid: int, b: TreatmentConsentCreateIn, u: dict = Depends(require_perm("patient_edit"))):
        cid = u["clinic_id"]
        _check_doc_own_patient(pid, u)
        if b.doctor_id is not None and not q1("SELECT id FROM staff_users WHERE id=? AND clinic_id=?", b.doctor_id, cid):
            raise HTTPException(404, "Seçilen hekim bu klinikte bulunamadı")
        if b.custom_items:
            items = b.custom_items
            try:
                tot_k = sum(kurus(Decimal(str(x.get("amount") or 0))) for x in items)
            except Exception:
                raise HTTPException(422, "Tedavi kalemlerinde geçersiz tutar değeri")
            if tot_k < 0:
                raise HTTPException(422, "Tedavi planı toplam tutarı negatif olamaz")
        else:
            odo_rows = q(
                "SELECT tooth_fdi, surface, status, procedure_name, amount_kurus FROM tooth_records WHERE clinic_id=? AND patient_id=? ORDER BY id",
                cid, pid,
            )
            items = [
                {"tooth_fdi": r["tooth_fdi"], "surface": r["surface"], "status": r["status"],
                 "procedure_name": r["procedure_name"], "amount": tl(r["amount_kurus"])}
                for r in odo_rows
            ]
            tot_k = sum(int(r["amount_kurus"] or 0) for r in odo_rows)
        plan_json = json.dumps(items, ensure_ascii=False)
        content_sha = hashlib.sha256(f"{cid}|{pid}|{b.document_version}|{plan_json}|{tot_k}".encode()).hexdigest()
        tok = secrets.token_urlsafe(24)
        t_now = iso_now()
        exp_at = (now_utc() + timedelta(days=7)).isoformat()
        status = "signed" if (b.signer_name and len(b.signer_name.strip()) >= 2) else "pending"
        sig_enc = enc(b.signature_text or b.signer_name.strip()) if status == "signed" else ""
        signed_at = t_now if status == "signed" else None
        tc_id = ex(
            """INSERT INTO treatment_consents
               (clinic_id,patient_id,doctor_id,token,plan_summary_json,total_amount_kurus,document_version,content_sha256,
                signer_name,signature_svg_enc,consent_type,status,signed_at,expires_at,created_by,created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,'electronic_approval',?,?,?,?,?)""",
            cid, pid, b.doctor_id or u["id"], tok, plan_json, tot_k, b.document_version, content_sha,
            (b.signer_name or "").strip(), sig_enc, status, signed_at, exp_at, u["id"], t_now,
        )
        base_url = str(request.base_url).rstrip("/")
        write_audit(u["id"], u["email"], "treatment_consent.create", f"patient:{pid}:consent:{tc_id}", u["ip_h"],
                    {"version": b.document_version, "sha256": content_sha[:16], "status": status}, clinic_id=cid)
        return {
            "id": tc_id,
            "token": tok,
            "status": status,
            "document_version": b.document_version,
            "content_sha256": content_sha,
            "total_amount": tl(tot_k),
            "sign_url": f"{base_url}/form/tedavi-onay/{tok}",
            "url": f"{base_url}/form/tedavi-onay/{tok}",
            "legal_notice": LEGAL_CONSENT_NOTICE_TR,
            "legal_notice_tr": LEGAL_CONSENT_NOTICE_TR,
        }

    @app.get("/form/tedavi-onay/{token}", response_class=HTMLResponse)
    def view_treatment_consent_form(token: str):
        tc = q1("SELECT tc.*, p.display_name, c.name AS clinic_name FROM treatment_consents tc JOIN patients p ON p.id=tc.patient_id JOIN clinics c ON c.id=tc.clinic_id WHERE tc.token=?", token)
        if not tc:
            return HTMLResponse("<!doctype html><meta charset=utf-8><body><h2>Onay belgesi bulunamadı.</h2></body>", status_code=404)
        items = json.loads(tc["plan_summary_json"] or "[]")
        rows_html = "".join(
            f"<tr><td>Diş #{html.escape(str(x.get('tooth_fdi','-')))} ({html.escape(str(x.get('surface','FULL')))})</td>"
            f"<td>{html.escape(str(x.get('procedure_name','-')))}</td>"
            f"<td style='text-align:right'>{html.escape(str(x.get('amount',0)))} TL</td></tr>"
            for x in items
        ) or "<tr><td colspan='3'>Genel tedavi planı</td></tr>"
        csrf_val = html.escape(_form_csrf(token, int(datetime.now(timezone.utc).timestamp()) + 3600), quote=True)
        signed_banner = (
            f"<div style='background:#DCFCE7;color:#15803D;padding:12px;border-radius:8px;font-weight:700'>"
            f"Bu tedavi planı {html.escape(tc['signed_at'] or '')} tarihinde {html.escape(tc['signer_name'])} tarafından onaylanmıştır.</div>"
            if tc["status"] == "signed"
            else f"""<form method="post">
                <input type="hidden" name="csrf_token" value="{csrf_val}">
                <label style="display:block;margin:12px 0"><input type="checkbox" name="accept_plan" value="1" required> Tedavi planı kalemlerini, tahmini tutarı ve bilgilendirme metnini okudum, onaylıyorum.</label>
                <label style="display:block;margin:12px 0">Ad Soyad (İmza): <input type="text" name="signer_name" required minlength="2" maxlength="80" placeholder="Adınızı ve soyadınızı yazınız" style="width:100%;padding:10px;margin-top:4px"></label>
                <button type="submit" style="width:100%;background:#0F766E;color:#fff;border:0;padding:14px;border-radius:8px;font-weight:700;font-size:16px">Tedavi Planını Onayla ve İmzala</button>
            </form>"""
        )
        return HTMLResponse(f"""<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
        <title>Dijital Tedavi Planı Onayı</title></head>
        <body style="font-family:system-ui;background:#F8FAFC;color:#0A2540;padding:16px">
        <main style="max-width:640px;margin:auto;background:#fff;padding:20px;border-radius:12px;border:1px solid #E2E8F0">
        <h1 style="font-size:20px;margin-top:0">{html.escape(tc['clinic_name'])} · Dijital Tedavi Planı Onayı</h1>
        <p><strong>Hasta:</strong> {html.escape(tc['display_name'] or '')} · <strong>Belge Sürümü:</strong> {html.escape(tc['document_version'])} · <strong>SHA-256:</strong> <code>{tc['content_sha256'][:16]}...</code></p>
        <table style="width:100%;border-collapse:collapse;margin:12px 0" border="1" cellpadding="8">
        <thead><tr style="background:#F1F5F9"><th>Diş / Yüzey</th><th>İşlem</th><th>Tutar</th></tr></thead>
        <tbody>{rows_html}</tbody>
        <tfoot><tr><th colspan="2" style="text-align:right">Toplam Planlanan Tutar</th><th style="text-align:right">{tl(tc['total_amount_kurus']):,.2f} TL</th></tr></tfoot>
        </table>
        <p style="font-size:12.5px;color:#475569;background:#F1F5F9;padding:10px;border-radius:8px">{html.escape(LEGAL_CONSENT_NOTICE_TR)}</p>
        {signed_banner}
        </main></body></html>""")

    @app.post("/form/tedavi-onay/{token}", response_class=HTMLResponse)
    async def submit_treatment_consent_form(token: str, request: Request):
        _rate_limit(f"tc_sign:{client_ip(request)}", 10, 60)
        tc = q1("SELECT * FROM treatment_consents WHERE token=?", token)
        if not tc:
            raise HTTPException(404, "Onay belgesi bulunamadı")
        if tc["status"] == "signed":
            raise HTTPException(409, "Bu tedavi onam belgesi daha önce imzalanmıştır ve değiştirilemez")
        if tc.get("expires_at"):
            try:
                exp_dt = datetime.fromisoformat(str(tc["expires_at"]).replace("Z", "+00:00"))
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                if exp_dt < now_utc():
                    raise HTTPException(410, "Bu tedavi onam bağlantısının geçerlilik süresi dolmuştur")
            except HTTPException:
                raise
            except Exception:
                raise HTTPException(410, "Geçersiz veya süresi dolmuş onam bağlantısı")
        form = dict(await request.form())
        if not _verify_form_csrf(token, str(form.get("csrf_token") or "")):
            raise HTTPException(403, "Form oturumu geçersiz veya süresi dolmuş; lütfen sayfayı yenileyin")
        signer = (str(form.get("signer_name") or "")).strip()
        accepted = str(form.get("accept_plan") or "") in ("1", "true", "on")
        if not accepted or len(signer) < 2:
            return HTMLResponse("<!doctype html><meta charset=utf-8><body><h2>Lütfen onay kutusunu işaretleyin ve adınızı soyadınızı yazın.</h2></body>", status_code=400)
        if len(signer) > 80:
            raise HTTPException(400, "İmza adı en fazla 80 karakter olabilir")
        t_now = iso_now()
        sig_payload = json.dumps({"signer": signer, "signed_at": t_now, "sha256": tc["content_sha256"]}, ensure_ascii=False)
        with db_lock, db() as c:
            cur = c.execute(
                "UPDATE treatment_consents SET signer_name=?, signature_svg_enc=?, status='signed', signed_at=? WHERE id=? AND status='pending'",
                (signer, enc(sig_payload), t_now, tc["id"]),
            )
            c.commit()
            if cur.rowcount == 0:
                raise HTTPException(409, "Bu tedavi onam belgesi daha önce imzalanmıştır ve değiştirilemez")
        write_audit(None, f"patient:{tc['patient_id']}", "treatment_consent.sign", f"consent:{tc['id']}",
                    meta={"signer": signer, "version": tc["document_version"]}, clinic_id=tc["clinic_id"])
        return HTMLResponse("<!doctype html><meta charset=utf-8><body><h2>Tedavi planı onayınız başarıyla kaydedildi. Teşekkür ederiz.</h2></body>")

    # Laboratuvar İş Emirleri (BÖLÜM 9 & 18)
    @app.get("/app/api/lab-orders")
    def list_lab_orders(patient_id: int | None = None, u: dict = Depends(require_perm("view"))):
        cid = u["clinic_id"]
        if patient_id is not None:
            _check_doc_own_patient(patient_id, u)
        sql = """SELECT lo.*, p.display_name AS patient_name, s.full_name AS doctor_name
                 FROM lab_orders lo
                 LEFT JOIN patients p ON p.id=lo.patient_id
                 LEFT JOIN staff_users s ON s.id=lo.doctor_id
                 WHERE lo.clinic_id=?"""
        args: list[Any] = [cid]
        if patient_id is not None:
            sql += " AND lo.patient_id=?"
            args.append(patient_id)
        else:
            perms = u.get("permissions") or resolve_permissions(u.get("role"), u.get("job_title"), u.get("permissions_json"))
            if perms.get("doctor_own_patients_only") and u.get("role") != "owner":
                sql += " AND (lo.doctor_id=? OR p.primary_doctor_id=?)"
                args.extend([u["id"], u["id"]])
        sql += " ORDER BY lo.id DESC"
        rows = q(sql, *args)
        today_s = date.today().isoformat()
        for r in rows:
            r["cost"] = tl(r.pop("cost_kurus"))
            r["is_delayed"] = bool(r["status"] in ("sent", "rehearsal") and r["due_date"] and r["due_date"][:10] < today_s)
        return rows

    @app.post("/app/api/lab-orders")
    def create_lab_order(b: LabOrderIn, u: dict = Depends(require_perm("create"))):
        cid = u["clinic_id"]
        _check_doc_own_patient(b.patient_id, u)
        if not q1("SELECT id FROM patients WHERE id=? AND clinic_id=?", b.patient_id, cid):
            raise HTTPException(404, "hasta yok")
        if b.doctor_id is not None and not q1("SELECT id FROM staff_users WHERE id=? AND clinic_id=?", b.doctor_id, cid):
            raise HTTPException(404, "Seçilen hekim bu klinikte bulunamadı")
        if b.tooth_fdi is not None and b.tooth_fdi not in VALID_FDI_NUMBERS:
            raise HTTPException(400, "Geçersiz FDI diş numarası")
        s_date = (b.sent_date or date.today().isoformat())[:10]
        d_date = b.due_date[:10]
        cost_k = kurus(b.cost)
        lid = ex(
            """INSERT INTO lab_orders
               (clinic_id,patient_id,doctor_id,tooth_fdi,lab_name,procedure_type,shade_color,sent_date,due_date,cost_kurus,status,note,created_by,created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            cid, b.patient_id, b.doctor_id or u["id"], b.tooth_fdi, b.lab_name.strip(), b.procedure_type.strip(),
            b.shade_color.strip(), s_date, d_date, cost_k, b.status, b.note.strip(), u["id"], iso_now(),
        )
        today_s = date.today().isoformat()
        is_delayed = b.status in ("sent", "rehearsal") and d_date < today_s
        if is_delayed:
            ex("INSERT INTO alerts (clinic_id,patient_id,kind,detail,created_at) VALUES (?,?,'lab_gecikme',?,?)",
               cid, b.patient_id, f"Laboratuvar gecikme uyarısı: {b.lab_name} - {b.procedure_type} (Teslim tarihi: {d_date})", iso_now())
        write_audit(u["id"], u["email"], "lab_order.create", f"lab_order:{lid}", u["ip_h"],
                    {"lab": b.lab_name, "due": d_date, "delayed": is_delayed}, clinic_id=cid)
        return {"id": lid, "is_delayed": is_delayed, "cost": tl(cost_k)}

    @app.patch("/app/api/lab-orders/{lid}")
    def update_lab_order(lid: int, b: LabOrderPatchIn, u: dict = Depends(require_perm("edit"))):
        cid = u["clinic_id"]
        row = q1("SELECT * FROM lab_orders WHERE id=? AND clinic_id=?", lid, cid)
        if not row:
            raise HTTPException(404, "laboratuvar iş emri yok")
        if row.get("patient_id"):
            _check_doc_own_patient(int(row["patient_id"]), u)
        deliv_d = (b.delivered_date or (date.today().isoformat() if b.status == "delivered" else row["delivered_date"]))
        new_note = b.note if b.note is not None else row["note"]
        ex("UPDATE lab_orders SET status=?, delivered_date=?, note=? WHERE id=? AND clinic_id=?",
           b.status, deliv_d, new_note, lid, cid)
        write_audit(u["id"], u["email"], "lab_order.update", f"lab_order:{lid}", u["ip_h"], {"status": b.status}, clinic_id=cid)
        return {"ok": True, "id": lid, "status": b.status}

    # İmplant ve Lot Takibi (BÖLÜM 9 & 18 — Dürüst ÜTS Hazırlık Yapısı)
    @app.get("/app/api/implants")
    def list_implant_records(patient_id: int | None = None, lot: str = "", u: dict = Depends(require_perm("view"))):
        cid = u["clinic_id"]
        if patient_id is not None:
            _check_doc_own_patient(patient_id, u)
        sql = """SELECT ir.*, p.display_name AS patient_name, s.full_name AS doctor_name
                 FROM implant_records ir
                 LEFT JOIN patients p ON p.id=ir.patient_id
                 LEFT JOIN staff_users s ON s.id=ir.doctor_id
                 WHERE ir.clinic_id=?"""
        args: list[Any] = [cid]
        if patient_id is not None:
            sql += " AND ir.patient_id=?"
            args.append(patient_id)
        else:
            perms = u.get("permissions") or resolve_permissions(u.get("role"), u.get("job_title"), u.get("permissions_json"))
            if perms.get("doctor_own_patients_only") and u.get("role") != "owner":
                sql += " AND (ir.doctor_id=? OR p.primary_doctor_id=?)"
                args.extend([u["id"], u["id"]])
        if lot.strip():
            sql += " AND (ir.lot_number LIKE ? OR ir.serial_number LIKE ? OR ir.uts_barcode LIKE ?)"
            lk = f"%{lot.strip()}%"
            args.extend([lk, lk, lk])
        sql += " ORDER BY ir.id DESC"
        rows = q(sql, *args)
        return {
            "uts_live_connected": False,
            "uts_honesty_notice_tr": (
                "Sağlık Bakanlığı ÜTS (Ürün Takip Sistemi) canlı devlet API bağlantısı bu ortamda aktif değildir. "
                "Kayıtlar; lot/seri geri çağırma izlenebilirliği, hasta implant pasaportu ve ÜTS portalına manuel/CSV "
                "bildirim hazırlığı için tutulmaktadır."
            ),
            "records": rows,
        }

    @app.post("/app/api/implants")
    def create_implant_record(b: ImplantRecordIn, u: dict = Depends(require_perm("patient_edit"))):
        cid = u["clinic_id"]
        _check_doc_own_patient(b.patient_id, u)
        if not q1("SELECT id FROM patients WHERE id=? AND clinic_id=?", b.patient_id, cid):
            raise HTTPException(404, "hasta yok")
        if b.doctor_id is not None and not q1("SELECT id FROM staff_users WHERE id=? AND clinic_id=?", b.doctor_id, cid):
            raise HTTPException(404, "Seçilen hekim bu klinikte bulunamadı")
        if b.tooth_fdi not in VALID_FDI_NUMBERS:
            raise HTTPException(400, "Geçersiz FDI diş numarası")
        used_d = (b.used_at or date.today().isoformat())[:10]
        iid = ex(
            """INSERT INTO implant_records
               (clinic_id,patient_id,doctor_id,tooth_fdi,brand,model,diameter_mm,length_mm,lot_number,serial_number,
                expiry_date,used_at,supplier,document_ref,uts_barcode,uts_notification_status,note,created_by,created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'not_connected_prepared',?,?,?)""",
            cid, b.patient_id, b.doctor_id or u["id"], b.tooth_fdi, b.brand.strip(), b.model.strip(),
            b.diameter_mm, b.length_mm, b.lot_number.strip(), b.serial_number.strip(), b.expiry_date.strip(),
            used_d, b.supplier.strip(), b.document_ref.strip(), b.uts_barcode.strip(), b.note.strip(), u["id"], iso_now(),
        )
        write_audit(u["id"], u["email"], "implant.create", f"implant:{iid}", u["ip_h"],
                    {"brand": b.brand, "lot": b.lot_number, "tooth": b.tooth_fdi}, clinic_id=cid)
        return {"id": iid, "uts_live_connected": False, "uts_notification_status": "not_connected_prepared"}

    # ------------------------------------------------------------------
    # 8) HASTA MEDYA / RÖNTGEN / DICOM / FOTOĞRAF LİSTELEME VE SİLME (BÖLÜM 12, 16, 18)
    # ------------------------------------------------------------------
    @app.get("/app/api/patients/{pid}/media")
    def list_patient_media(pid: int, u: dict = Depends(require_perm("patient_view"))):
        cid = u["clinic_id"]
        _check_doc_own_patient(pid, u)
        rows = q(
            """SELECT pm.*, s.full_name AS uploaded_by_name FROM patient_media pm
               LEFT JOIN staff_users s ON s.id=pm.uploaded_by
               WHERE pm.clinic_id=? AND pm.patient_id=? ORDER BY pm.id DESC""",
            cid, pid,
        )
        for r in rows:
            r["is_dicom"] = bool(r["is_dicom"])
            r["disclaimer"] = media.QC_DISCLAIMER_TR
        before_list = [r for r in rows if r["category"] == "photo" and r["stage"] == "before"]
        after_list = [r for r in rows if r["category"] == "photo" and r["stage"] == "after"]
        return {
            "disclaimer": media.QC_DISCLAIMER_TR,
            "files": rows,
            "before_after_summary": {"before_count": len(before_list), "after_count": len(after_list)},
        }

    @app.get("/app/api/patients/{pid}/media/{mid}")
    def download_patient_media(pid: int, mid: int, u: dict = Depends(require_perm("patient_view"))):
        cid = u["clinic_id"]
        _check_doc_own_patient(pid, u)
        row = q1("SELECT * FROM patient_media WHERE id=? AND patient_id=? AND clinic_id=?", mid, pid, cid)
        if not row:
            raise HTTPException(404, "dosya kaydı bulunamadı")
        enc_fn = Path(row["encrypted_path"]).name
        allowed_roots = (_media_dir().resolve(), (root_dir / "encrypted_media").resolve())
        fp = (allowed_roots[0] / enc_fn).resolve()
        if not fp.is_file():
            fp_alt = (allowed_roots[1] / enc_fn).resolve()
            fp = fp_alt if fp_alt.is_file() else (root_dir / row["encrypted_path"]).resolve()
        if not any(fp.is_relative_to(ar) for ar in allowed_roots):
            raise HTTPException(403, "Geçersiz medya dosya yolu")
        if not fp.is_file():
            raise HTTPException(404, "şifreli medya dosyası diskte bulunamadı")
        raw_bytes = _get_fernet().decrypt(fp.read_bytes())
        mime_t = row.get("mime_type") or "application/octet-stream"
        disp_mode = "inline" if mime_t.startswith("image/") and "svg" not in mime_t.lower() else "attachment"
        safe_fn = re.sub(r"[^a-zA-Z0-9._-]", "_", row.get("original_filename") or "media.bin")[:120] or "media.bin"
        return Response(
            content=raw_bytes,
            media_type=mime_t,
            headers={
                "content-disposition": f'{disp_mode}; filename="{safe_fn}"',
                "x-content-type-options": "nosniff",
            },
        )

    @app.delete("/app/api/patients/{pid}/media/{mid}")
    def delete_patient_media(pid: int, mid: int, u: dict = Depends(require_perm("delete_cancel"))):
        cid = u["clinic_id"]
        _check_doc_own_patient(pid, u)
        row = q1("SELECT * FROM patient_media WHERE id=? AND patient_id=? AND clinic_id=?", mid, pid, cid)
        if not row:
            raise HTTPException(404, "dosya kaydı bulunamadı")
        try:
            enc_fn = Path(row["encrypted_path"]).name
            for d_cand in (_media_dir(), root_dir / "encrypted_media"):
                fp = d_cand / enc_fn
                if fp.is_file():
                    fp.unlink(missing_ok=True)
        except Exception:
            pass
        ex("DELETE FROM patient_media WHERE id=? AND clinic_id=?", mid, cid)
        write_audit(u["id"], u["email"], "patient.media_delete", f"patient:{pid}:media:{mid}", u["ip_h"], clinic_id=cid)
        return {"ok": True}

    # ------------------------------------------------------------------
    # 9) PERSONEL MESLEKLERİ (14 MESLEK) VE GRANÜLER YETKİLENDİRME (BÖLÜM 17)
    # ------------------------------------------------------------------
    @app.get("/app/api/staff/professions-catalog")
    def get_staff_professions_catalog(u: dict = Depends(require_perm("view"))):
        return {
            "professions": STAFF_PROFESSIONS,
            "permission_keys": PERMISSION_KEYS,
            "permission_labels": PERMISSION_LABELS_TR,
            "role_defaults": ROLE_DEFAULT_PERMISSIONS,
        }

    @app.patch("/app/api/staff/{sid}/permissions")
    def update_staff_permissions(sid: int, b: StaffPermissionsPatchIn, u: dict = Depends(require_perm("staff_manage"))):
        cid = u["clinic_id"]
        st = q1("SELECT * FROM staff_users WHERE id=? AND clinic_id=?", sid, cid)
        if not st:
            raise HTTPException(404, "personel bulunamadı")
        if u["role"] != "owner":
            if sid == u["id"]:
                raise HTTPException(403, "Yönetici olmayan personel kendi rol veya yetkilerini değiştiremez")
            if st["role"] == "owner" or b.role == "owner":
                raise HTTPException(403, "Yönetici (owner) rolü yalnızca klinik sahibi tarafından atanabilir veya düzenlenebilir")
        new_jt = b.job_title.strip().lower() if b.job_title else (st.get("job_title") or "secretary")
        if new_jt not in STAFF_PROFESSIONS:
            raise HTTPException(400, f"Geçersiz meslek seçimi: {new_jt}")
        new_role = b.role or st["role"]
        if sid == u["id"] and new_role != "owner":
            raise HTTPException(400, "Kendi yönetici rolünüzü düşüremezsiniz")
        new_share = float(b.share_pct) if b.share_pct is not None else float(st.get("share_pct") or 0)
        cur_perms = json.loads(st.get("permissions_json") or "{}")
        caller_perms = u.get("permissions") or resolve_permissions(u.get("role"), u.get("job_title"), u.get("permissions_json"))
        if b.permissions is not None:
            for k, v in b.permissions.items():
                if k in PERMISSION_KEYS:
                    if u["role"] != "owner" and bool(v) and not caller_perms.get(k, False):
                        raise HTTPException(403, f"Kendi sahip olmadığınız '{k}' yetkisini başka bir personele veremezsiniz")
                    cur_perms[k] = bool(v)
        if sid == u["id"]:
            cur_perms["view"] = True
            cur_perms["staff_manage"] = True
        cur_sched = json.loads(st.get("working_schedule_json") or "{}")
        if b.working_schedule is not None:
            cur_sched.update(b.working_schedule)

        ex(
            "UPDATE staff_users SET job_title=?, role=?, share_pct=?, permissions_json=?, working_schedule_json=? WHERE id=? AND clinic_id=?",
            new_jt, new_role, new_share, json.dumps(cur_perms, ensure_ascii=False), json.dumps(cur_sched, ensure_ascii=False), sid, cid,
        )
        # Rol değiştiğinde (ör. yetki/rol düşürme veya no_access) hedef kullanıcının eski oturumlarını anında iptal et (OWASP ASVS L2.2)
        if sid != u["id"] and new_role != st["role"]:
            ex("UPDATE sessions SET revoked=1 WHERE user_id=?", sid)
        eff = resolve_permissions(new_role, new_jt, cur_perms)
        write_audit(u["id"], u["email"], "staff.permissions_update", f"staff:{sid}", u["ip_h"],
                    {"job_title": new_jt, "role": new_role, "permissions": cur_perms}, clinic_id=cid)
        return {"ok": True, "id": sid, "job_title": new_jt, "role": new_role, "effective_permissions": eff}

    # ------------------------------------------------------------------
    # 10) YAPAY ZEKA MALİYETİ, KOTA VE BRÜT KÂR ANALİZİ (BÖLÜM 13)
    # ------------------------------------------------------------------
    @app.get("/app/api/ai-costs")
    def get_ai_cost_report(days: int = Query(30, ge=1, le=365), u: dict = Depends(require_perm("finance_view"))):
        cid = u["clinic_id"]
        cutoff = (now_utc() - timedelta(days=days)).isoformat()
        rows = q(
            """SELECT COALESCE(m.layer,'-') AS layer, count(*) AS replies, COALESCE(sum(m.tokens_in),0) AS tin, COALESCE(sum(m.tokens_out),0) AS tout
               FROM message_log m LEFT JOIN patients p ON p.id=m.patient_id
               WHERE m.direction='out' AND COALESCE(p.clinic_id, m.clinic_id, 1)=? AND m.created_at >= ?
               GROUP BY m.layer ORDER BY replies DESC""",
            cid, cutoff,
        )
        cinfo = q1("SELECT ai_monthly_token_limit, ai_monthly_budget_try, ai_hard_stop FROM clinics WHERE id=?", cid) or {}
        rep = compute_ai_cost_report(
            rows,
            monthly_token_limit=int(cinfo.get("ai_monthly_token_limit") or 1_500_000),
            monthly_budget_try=float(cinfo.get("ai_monthly_budget_try") or 250.0),
            hard_stop=bool(cinfo.get("ai_hard_stop", 1)),
        )
        if u.get("is_hq"):
            all_rows = q(
                """SELECT COALESCE(m.layer,'-') AS layer, count(*) AS replies, COALESCE(sum(m.tokens_in),0) AS tin, COALESCE(sum(m.tokens_out),0) AS tout
                   FROM message_log m WHERE m.direction='out' AND m.created_at >= ? GROUP BY m.layer""",
                cutoff,
            )
            sys_rep = compute_ai_cost_report(all_rows, monthly_token_limit=4_500_000, monthly_budget_try=750.0)
            rep["system_wide_summary"] = {
                "total_requests": sys_rep["total_requests"],
                "total_tokens": sys_rep["total_tokens"],
                "estimated_cost_try": sys_rep["estimated_cost_try"],
            }
        return rep

    @app.post("/app/api/ai-costs/quota")
    def update_ai_quota(b: AIQuotaIn, u: dict = Depends(require_perm("system_settings"))):
        cid = u["clinic_id"]
        ex("UPDATE clinics SET ai_monthly_token_limit=?, ai_monthly_budget_try=?, ai_hard_stop=? WHERE id=?",
           b.monthly_token_limit, b.monthly_budget_try, 1 if b.hard_stop else 0, cid)
        write_audit(u["id"], u["email"], "ai.quota_update", f"clinic:{cid}", u["ip_h"], b.model_dump(), clinic_id=cid)
        return {"ok": True, **b.model_dump()}

    # ------------------------------------------------------------------
    # 11) SATIŞ CRM (LEADS), ONLİNE RANDEVU SAYFASI VE CSV RAPOR DIŞA AKTARMA (BÖLÜM 15, 18, 19)
    # ------------------------------------------------------------------
    @app.get("/app/api/leads")
    def list_sales_leads(u: dict = Depends(hq_owner)):
        rows = q("SELECT * FROM leads ORDER BY id DESC LIMIT 200")
        for r in rows:
            try:
                r["contact"] = dec(r.pop("contact_enc"))
            except Exception:
                r["contact"] = "***"
            r["yurt_disi_riza"] = bool(r.get("yurt_disi_riza", 0))
        return rows

    def _validate_public_booking_slot(cl: dict, st_dt_utc: datetime, end_dt_utc: datetime) -> None:
        if st_dt_utc < now_utc() + timedelta(minutes=15):
            raise HTTPException(422, "Geçmiş veya 15 dakikadan daha yakın bir saate online randevu alınamaz")
        local_s = st_dt_utc.astimezone(TZ)
        local_e = end_dt_utc.astimezone(TZ)
        try:
            wh = json.loads(cl.get("working_hours_json") or "{}")
        except Exception:
            wh = {}
        wd = local_s.weekday()
        slot_rng = wh.get("sun") if wd == 6 else (wh.get("sat") if wd == 5 else wh.get("mon_fri", ["09:00", "19:00"]))
        if not slot_rng or not isinstance(slot_rng, (list, tuple)) or len(slot_rng) != 2:
            raise HTTPException(422, "Seçilen gün klinik çalışma takviminde kapalıdır")
        try:
            sh, sm = (int(x) for x in str(slot_rng[0]).split(":", 1))
            eh, em = (int(x) for x in str(slot_rng[1]).split(":", 1))
        except Exception:
            sh, sm, eh, em = 9, 0, 19, 0
        s_min = local_s.hour * 60 + local_s.minute
        e_min = local_e.hour * 60 + local_e.minute
        if local_s.date() != local_e.date() or s_min < (sh * 60 + sm) or e_min > (eh * 60 + em):
            raise HTTPException(422, f"Seçilen saat klinik çalışma saatleri ({slot_rng[0]}-{slot_rng[1]}) dışındadır")

    def _execute_public_booking(clinic_slug: str, b: PublicBookIn, request: Request) -> dict[str, Any]:
        if (b.website or "").strip():
            return {"ok": True, "appointment_id": None, "chair": None, "source": "website", "campaign_id": None}
        if not b.kvkk_consent:
            raise HTTPException(400, "KVKK aydınlatma onayı zorunludur")
        _rate_limit(f"pub_book_ip:{client_ip(request)}", 5, 3600)
        cl = q1("SELECT * FROM clinics WHERE slug=? AND active=1", clinic_slug)
        if not cl and clinic_slug in ("merkez", "merkez-poliklinik"):
            cl = q1("SELECT * FROM clinics WHERE id=1 AND active=1")
        if not cl:
            raise HTTPException(404, "klinik bulunamadı")
        cid = int(cl["id"])
        np = norm_phone(b.phone)
        if len(np) < 10:
            raise HTTPException(400, "Geçerli bir telefon numarası giriniz")
        ph = phone_hmac(np)
        _rate_limit(f"pub_book_ph:{cid}:{ph[:24]}", 3, 3600)
        st_dt = (b.starts_at if b.starts_at.tzinfo else b.starts_at.replace(tzinfo=TZ)).astimezone(timezone.utc)
        end_dt = st_dt + timedelta(minutes=30)
        _validate_public_booking_slot(cl, st_dt, end_dt)
        det_src = detect_acquisition_source(b.source, b.utm_source, b.utm_medium, request.headers.get("referer"))
        camp = None
        if b.campaign_code:
            camp = q1("SELECT id FROM campaigns WHERE clinic_id=? AND code=?", cid, b.campaign_code.strip())
        elif b.utm_campaign:
            camp = q1("SELECT id FROM campaigns WHERE clinic_id=? AND (utm_campaign=? OR code=?)", cid, b.utm_campaign.strip(), b.utm_campaign.strip())
        camp_id = int(camp["id"]) if camp else None

        with db_lock, db() as c:
            busy = c.execute(
                "SELECT starts_at, duration_min, chair FROM appointments WHERE clinic_id=? AND status IN ('booked','confirmed')",
                (cid,),
            ).fetchall()
            chosen_chair = None
            for ch_idx in range(1, int(cl.get("chairs") or 2) + 1):
                ch_str = str(ch_idx)
                clash = False
                for ex_a in busy:
                    if str(ex_a["chair"]) != ch_str:
                        continue
                    raw_st = ex_a["starts_at"]
                    ex_s = raw_st if isinstance(raw_st, datetime) else datetime.fromisoformat(str(raw_st).replace("Z", "+00:00"))
                    if ex_s.tzinfo is None:
                        ex_s = ex_s.replace(tzinfo=TZ)
                    ex_s_utc = ex_s.astimezone(timezone.utc)
                    ex_e_utc = ex_s_utc + timedelta(minutes=int(ex_a["duration_min"] or 30))
                    if ex_s_utc < end_dt and ex_e_utc > st_dt:
                        clash = True
                        break
                if not clash:
                    chosen_chair = ch_str
                    break
            if not chosen_chair:
                raise HTTPException(409, "Seçilen saatte tüm koltuklar dolu; lütfen başka bir saat seçiniz")

            t_now = iso_now()
            ex_p = c.execute("SELECT id, first_source, active FROM patients WHERE clinic_id=? AND phone_hmac=?", (cid, ph)).fetchone()
            is_new_patient = False
            if ex_p:
                if not ex_p["active"]:
                    raise HTTPException(409, "Bu telefon numarası arşivlenmiş kayda aittir; randevu için lütfen kliniği doğrudan arayınız")
                pid = ex_p["id"]
                c.execute(
                    "UPDATE patients SET last_source=?, campaign_id=COALESCE(?, campaign_id) WHERE id=?",
                    (det_src, camp_id, pid),
                )
            else:
                is_new_patient = True
                cur_p = c.execute(
                    """INSERT INTO patients
                       (clinic_id,phone_hmac,phone_enc,display_name,lang,channel,first_source,last_source,campaign_id,utm_source,utm_medium,utm_campaign,active,created_at)
                       VALUES (?,?,?,?,'tr','wa',?,?,?,?,?,?,1,?)""",
                    (cid, ph, enc(np), b.name.strip(), det_src, det_src, camp_id, b.utm_source[:80], b.utm_medium[:80], b.utm_campaign[:120], t_now),
                )
                pid = cur_p.lastrowid

            cur_a = c.execute(
                """INSERT INTO appointments
                   (clinic_id,patient_id,starts_at,duration_min,treatment,chair,status,source,campaign_id,created_at)
                   VALUES (?,?,?,30,?,?,'booked',?,?,?)""",
                (cid, pid, st_dt.isoformat(), b.treatment.strip(), chosen_chair, det_src, camp_id, t_now),
            )
            aid = cur_a.lastrowid
            if camp_id:
                v_hash = _visitor_hash(request, camp_id)
                ua_s = (request.headers.get("user-agent") or "")[:120]
                for ev_t in (["form_submit", "patient_created", "appointment_booked"] if is_new_patient else ["form_submit", "appointment_booked"]):
                    c.execute(
                        """INSERT INTO campaign_events
                           (clinic_id,campaign_id,event_type,source,utm_source,utm_medium,utm_campaign,visitor_hash,is_bot,is_unique,patient_id,appointment_id,user_agent_summary,created_at)
                           VALUES (?,?,?,?,?,?,?,?,0,1,?,?,?,?)""",
                        (cid, camp_id, ev_t, det_src, b.utm_source[:80], b.utm_medium[:80], b.utm_campaign[:120], v_hash, pid, aid, ua_s, t_now),
                    )
            c.commit()
        return {"ok": True, "appointment_id": aid, "chair": chosen_chair, "source": det_src, "campaign_id": camp_id}

    @app.get("/randevu/{clinic_slug}", response_class=HTMLResponse)
    def public_online_booking_page(clinic_slug: str):
        cl = q1("SELECT id, name, city, address, phone FROM clinics WHERE slug=? AND active=1", clinic_slug)
        if not cl and clinic_slug in ("merkez", "merkez-poliklinik"):
            cl = q1("SELECT id, name, city, address, phone, slug FROM clinics WHERE id=1 AND active=1")
        if not cl:
            raise HTTPException(404, "klinik bulunamadı")
        min_dt = (datetime.now(TZ) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M")
        return HTMLResponse(f"""<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
        <title>{html.escape(cl['name'])} · Online Randevu</title>
        <style>body{{font-family:system-ui,-apple-system,sans-serif;background:#F8FAFC;color:#0A2540;padding:16px;margin:0}}main{{max-width:520px;margin:20px auto;background:#fff;padding:24px;border-radius:14px;border:1px solid #E2E8F0}}label{{display:block;font-size:14px;font-weight:600;margin:12px 0 4px}}input,select{{width:100%;box-sizing:border-box;padding:11px 12px;border:1px solid #CBD5E1;border-radius:8px;font-size:15px}}.hp{{position:absolute;left:-9999px;opacity:0}}.chk{{display:flex;align-items:flex-start;gap:8px;font-weight:400;margin:14px 0}}.chk input{{width:auto;margin-top:3px}}button{{width:100%;background:#0F766E;color:#fff;border:0;border-radius:10px;padding:13px;font-size:16px;font-weight:700;cursor:pointer}}</style></head>
        <body><main>
        <h1 style="font-size:20px;margin-top:0">{html.escape(cl['name'])} · Online Randevu</h1>
        <p style="color:#475569;font-size:14px">{html.escape(cl['address'] or cl['city'])}</p>
        <p style="font-size:14px">Online randevu oluşturmak için bilgilerinizi girin; koltuk uygunluğu anında kontrol edilir.</p>
        <form method="post" action="/randevu/{html.escape(clinic_slug, quote=True)}">
          <div class="hp" aria-hidden="true"><label for="website">Website</label><input id="website" name="website" type="text" tabindex="-1" autocomplete="off"></div>
          <label for="name">Ad Soyad</label>
          <input id="name" name="name" type="text" required minlength="2" maxlength="80" placeholder="Adınız ve soyadınız">
          <label for="phone">Telefon Numarası</label>
          <input id="phone" name="phone" type="tel" required minlength="10" maxlength="30" placeholder="05XX XXX XX XX">
          <label for="starts_at">Randevu Tarihi ve Saati</label>
          <input id="starts_at" name="starts_at" type="datetime-local" required min="{min_dt}">
          <label for="treatment">Talep Edilen İşlem</label>
          <select id="treatment" name="treatment">
            <option value="İlk Muayene">İlk Muayene</option>
            <option value="Diş Taşı Temizliği">Diş Taşı Temizliği</option>
            <option value="İmplant Danışmanlığı">İmplant Danışmanlığı</option>
            <option value="Zirkonyum / Estetik">Zirkonyum / Estetik</option>
            <option value="Acil Ağrı Muayenesi">Acil Ağrı Muayenesi</option>
          </select>
          <label class="chk"><input type="checkbox" name="kvkk_consent" value="1" required> <span>KVKK aydınlatma metnini okudum ve randevu iletişimi için onay veriyorum.</span></label>
          <button type="submit">Online Randevuyu Onayla</button>
        </form>
        </main></body></html>""")

    @app.post("/randevu/{clinic_slug}", response_class=HTMLResponse)
    async def public_online_booking_form_submit(clinic_slug: str, request: Request):
        f = dict(await request.form())
        raw_dt = str(f.get("starts_at") or "").strip()
        try:
            parsed_dt = datetime.fromisoformat(raw_dt)
        except ValueError:
            return HTMLResponse("<!doctype html><meta charset=utf-8><body><h2>Geçersiz tarih veya saat seçimi.</h2><p><a href=\"/randevu/" + html.escape(clinic_slug, quote=True) + "\">Geri Dön</a></p></body>", status_code=422)
        payload = PublicBookIn(
            name=str(f.get("name") or "").strip()[:80],
            phone=str(f.get("phone") or "").strip()[:30],
            starts_at=parsed_dt,
            treatment=(str(f.get("treatment") or "İlk Muayene").strip()[:100] or "İlk Muayene"),
            kvkk_consent=str(f.get("kvkk_consent") or "") in ("1", "true", "on"),
            website=str(f.get("website") or "")[:200],
        )
        res = _execute_public_booking(clinic_slug, payload, request)
        return HTMLResponse(
            f"<!doctype html><html lang='tr'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Randevu Onayı</title></head>"
            f"<body style='font-family:system-ui;background:#F8FAFC;color:#0A2540;padding:24px'><main style='max-width:520px;margin:auto;background:#fff;padding:24px;border-radius:12px;border:1px solid #CBD5E1'>"
            f"<h1 style='font-size:20px;color:#0F766E'>Randevunuz Oluşturuldu</h1>"
            f"<p>Randevu numaranız: <strong>#{html.escape(str(res.get('appointment_id') or '-'))}</strong> (Koltuk {html.escape(str(res.get('chair') or '-'))}).</p>"
            f"<p><a href='/'>Ana Sayfaya Dön</a></p></main></body></html>"
        )

    @app.post("/api/public/book/{clinic_slug}")
    def public_online_book_appointment(clinic_slug: str, b: PublicBookIn, request: Request):
        return _execute_public_booking(clinic_slug, b, request)

    @app.post("/app/api/appointments/recurring")
    def create_recurring_appointments(b: RecurringAppointmentIn, u: dict = Depends(require_perm("patient_edit"))):
        cid = u["clinic_id"]
        _check_doc_own_patient(b.patient_id, u)
        pt = q1("SELECT id, primary_doctor_id FROM patients WHERE id=? AND clinic_id=?", b.patient_id, cid)
        if not pt:
            raise HTTPException(404, "hasta bulunamadı")
        if b.doctor_id is not None:
            doc = q1("SELECT id FROM staff_users WHERE id=? AND clinic_id=? AND active=1", b.doctor_id, cid)
            if not doc:
                raise HTTPException(400, "Geçersiz hekim seçimi (bu kliniğe ait değil)")
        base_dt = b.starts_at if b.starts_at.tzinfo else b.starts_at.replace(tzinfo=TZ)
        base_local = base_dt.astimezone(TZ)
        slots: list[tuple[datetime, datetime]] = []
        for idx in range(b.occurrences):
            if b.frequency == "weekly":
                cur_local = base_local + timedelta(days=7 * idx)
            elif b.frequency == "biweekly":
                cur_local = base_local + timedelta(days=14 * idx)
            else:
                cur_local = base_local + timedelta(days=30 * idx)
            end_local = cur_local + timedelta(minutes=b.duration_min)
            if cur_local.hour < 8 or (end_local.hour > 20 or (end_local.hour == 20 and end_local.minute > 0)):
                raise HTTPException(400, f"{idx + 1}. seans ({cur_local.strftime('%Y-%m-%d %H:%M')}) çalışma saatleri (08:00-20:00) dışında")
            slots.append((cur_local.astimezone(timezone.utc), end_local.astimezone(timezone.utc)))

        created_ids: list[int] = []
        with db_lock, db() as c:
            for idx, (s_utc, e_utc) in enumerate(slots):
                day_prefix = s_utc.astimezone(TZ).strftime("%Y-%m-%d")
                existing = c.execute(
                    "SELECT id, starts_at, duration_min, chair, doctor_id FROM appointments WHERE clinic_id=? AND status IN ('booked','confirmed') AND substr(CAST(starts_at AS TEXT),1,10)=?",
                    (cid, day_prefix),
                ).fetchall()
                for ex_row in existing:
                    raw_st = ex_row["starts_at"]
                    ex_s = raw_st if isinstance(raw_st, datetime) else datetime.fromisoformat(str(raw_st).replace("Z", "+00:00"))
                    if ex_s.tzinfo is None:
                        ex_s = ex_s.replace(tzinfo=timezone.utc)
                    else:
                        ex_s = ex_s.astimezone(timezone.utc)
                    ex_e = ex_s + timedelta(minutes=int(ex_row["duration_min"] or 30))
                    if s_utc < ex_e and e_utc > ex_s:
                        if str(ex_row["chair"]) == str(b.chair):
                            raise HTTPException(409, f"{idx + 1}. seansta ({day_prefix}) Koltuk {b.chair} dolu (randevu #{ex_row['id']})")
                        if b.doctor_id and ex_row["doctor_id"] and int(ex_row["doctor_id"]) == int(b.doctor_id):
                            raise HTTPException(409, f"{idx + 1}. seansta ({day_prefix}) seçilen hekim başka randevuda (#{ex_row['id']})")
            for idx, (s_utc, _) in enumerate(slots):
                cur_a = c.execute(
                    """INSERT INTO appointments (clinic_id, patient_id, starts_at, duration_min, treatment, chair, status, source, doctor_id, created_at)
                       VALUES (?,?,?,?,?,?,'booked','panel',?,?)""",
                    (
                        cid,
                        b.patient_id,
                        s_utc.astimezone(TZ).isoformat(timespec="seconds"),
                        b.duration_min,
                        f"{b.treatment} (Seans {idx + 1}/{b.occurrences})",
                        b.chair,
                        b.doctor_id,
                        iso_now(),
                    ),
                )
                created_ids.append(cur_a.lastrowid)
            c.commit()
        write_audit(u["id"], u["email"], "appointment.recurring_create", f"patient:{b.patient_id}", u["ip_h"], {"count": len(created_ids), "frequency": b.frequency}, clinic_id=cid)
        return {"ok": True, "created_count": len(created_ids), "appointment_ids": created_ids, "frequency": b.frequency}

    def _csv_safe_row(vals: list[Any]) -> list[Any]:
        out = []
        for v in vals:
            if isinstance(v, str) and v and v[0] in ("=", "+", "-", "@", "\t", "\r"):
                try:
                    float(v)
                    out.append(v)
                except ValueError:
                    out.append("'" + v)
            else:
                out.append(v)
        return out

    @app.get("/app/api/export/{kind}.csv")
    def export_report_csv(kind: Literal["patients", "kasa", "appointments", "inventory", "campaigns", "doctor_shares"], u: dict = Depends(require_perm("export"))):
        cid = u["clinic_id"]
        buf = io.StringIO()
        buf.write("\ufeff")  # Excel Türkçe karakter uyumu için UTF-8 BOM
        w = csv.writer(buf)
        if kind == "patients":
            w.writerow(["ID", "Ad Soyad", "İlk Kaynak", "Son Kaynak", "Dil", "Sorumlu Doktor ID", "Kayıt Tarihi"])
            for r in q("SELECT id, display_name, first_source, last_source, lang, primary_doctor_id, created_at FROM patients WHERE clinic_id=? ORDER BY id DESC", cid):
                w.writerow(_csv_safe_row([r["id"], r["display_name"], r["first_source"], r["last_source"], r["lang"], r["primary_doctor_id"] or "", r["created_at"]]))
        elif kind == "kasa":
            w.writerow(["Tür", "ID", "Hasta ID", "Açıklama / Yöntem", "Brüt (TL)", "İndirim (TL)", "Net (TL)", "Durum", "Tarih"])
            for r in q("SELECT id, patient_id, description, gross_amount_kurus, discount_kurus, amount_kurus, voided_at, created_at FROM charges WHERE clinic_id=? ORDER BY id DESC", cid):
                w.writerow(_csv_safe_row(["Hizmet", r["id"], r["patient_id"], r["description"], tl(r["gross_amount_kurus"] or r["amount_kurus"]), tl(r["discount_kurus"] or 0), tl(r["amount_kurus"]), "İptal" if r["voided_at"] else "Aktif", r["created_at"]]))
            for r in q("SELECT id, patient_id, method, amount_kurus, status, voided_at, created_at FROM payments WHERE clinic_id=? ORDER BY id DESC", cid):
                w.writerow(_csv_safe_row(["Tahsilat", r["id"], r["patient_id"], r["method"], tl(r["amount_kurus"]), 0, tl(r["amount_kurus"]), "İptal" if r["voided_at"] else (r["status"] or "completed"), r["created_at"]]))
        elif kind == "appointments":
            w.writerow(["ID", "Hasta ID", "Tarih/Saat", "Süre (dk)", "Tedavi", "Koltuk", "Doktor ID", "Durum", "Kaynak"])
            for r in q("SELECT id, patient_id, starts_at, duration_min, treatment, chair, doctor_id, status, source FROM appointments WHERE clinic_id=? ORDER BY starts_at DESC", cid):
                w.writerow(_csv_safe_row([r["id"], r["patient_id"], r["starts_at"], r["duration_min"], r["treatment"], r["chair"], r["doctor_id"] or "", r["status"], r["source"]]))
        elif kind == "inventory":
            w.writerow(["ID", "Kategori", "Ürün", "SKU", "Birim", "Stok", "Alt Sınır", "Birim Maliyet (TL)", "Tedarikçi", "Lot", "SKT", "Depo"])
            for r in q("SELECT * FROM inventory_items WHERE clinic_id=? AND active=1 ORDER BY id", cid):
                w.writerow(_csv_safe_row([r["id"], r.get("category", ""), r["name"], r["sku"] or "", r["unit"], r["qty"], r["min_qty"], tl(r["unit_cost_kurus"]), r.get("supplier", ""), r.get("lot_number", ""), r.get("expiry_date", ""), r.get("warehouse", "")]))
        elif kind == "campaigns":
            w.writerow(["ID", "Kampanya", "Kod", "Kanal", "UTM Source", "UTM Campaign", "Beyan Tıklama", "Oluşturulma"])
            for r in q("SELECT * FROM campaigns WHERE clinic_id=? ORDER BY id DESC", cid):
                w.writerow(_csv_safe_row([r["id"], r["name"], r.get("code", ""), r.get("channel", ""), r.get("utm_source", ""), r.get("utm_campaign", ""), r["clicks"], r["created_at"]]))
        elif kind == "doctor_shares":
            w.writerow(["Doktor ID", "Ad Soyad", "Pay (%)", "Sorumlu Hasta", "Yapılan İşlem", "Brüt Hizmet (TL)", "Net Hizmet (TL)", "Hekim Hakediş (TL)", "Klinik Payı (TL)"])
            for r in doctor_revenue_report(u):
                w.writerow(_csv_safe_row([r["doctor_id"], r["full_name"], r["share_pct"], r["owned_patients_count"], r["performed_procedures_count"], r["gross_billed"], r["net_billed"], r["doctor_hakedis"], r["clinic_share"]]))
        write_audit(u["id"], u["email"], f"export.{kind}_csv", f"clinic:{cid}", u["ip_h"], clinic_id=cid)
        return PlainTextResponse(
            buf.getvalue(),
            media_type="text/csv; charset=utf-8",
            headers={"content-disposition": f'attachment; filename="dentacore-{kind}-{cid}.csv"'},
        )

    # Statik yolların (/app/api/patients/check-duplicate gibi) parametreli yollardan (/app/api/patients/{pid}) önce eşleşmesini garanti et
    app.router.routes.sort(key=lambda r: (1 if "{" in getattr(r, "path", "") else 0))


def register_enterprise_routes_for_pg(app: FastAPI) -> None:
    """PostgreSQL bulut katmanı (`api/app/main.py`) ile SQLite (`run_local.py`) arasında %100 uç ve çalışma zamanı eşitliği sağlar."""
    import atexit
    import threading
    from . import core, panel
    _pg_lock = threading.RLock()
    _pg_pool_holder: dict[str, Any] = {"pool": None, "url": ""}
    root_dir = Path(__file__).resolve().parents[2]

    def _sql_pg(sql: str) -> tuple[str, bool]:
        s = sql.strip()
        had_or_ignore = "INSERT OR IGNORE INTO" in s.upper()
        if had_or_ignore:
            s = re.sub(r"INSERT\s+OR\s+IGNORE\s+INTO", "INSERT INTO", s, flags=re.IGNORECASE)
            if "ON CONFLICT" not in s.upper():
                s = s.rstrip(";") + " ON CONFLICT DO NOTHING"
        s_low = s.lower()
        if any(tbl in s_low for tbl in ("patients", "staff_users", "clinics", "inventory_items")):
            s = re.sub(r"\bactive\s*=\s*1\b", "active=TRUE", s)
            s = re.sub(r"\bactive\s*=\s*0\b", "active=FALSE", s)
            if "insert into patients" in s_low and ",1,?)" in s:
                s = s.replace(",1,?)", ",TRUE,?)")
        if "sessions" in s_low:
            s = re.sub(r"\brevoked\s*=\s*1\b", "revoked=TRUE", s)
            s = re.sub(r"\brevoked\s*=\s*0\b", "revoked=FALSE", s)
        s = s.replace("?", "%s")
        is_ins = s.upper().startswith("INSERT ") and "RETURNING" not in s.upper() and not had_or_ignore
        return s, is_ins

    class _PgCompatCursor:
        def __init__(self, cur: Any, lastrowid: int = 0):
            self._cur = cur
            self.lastrowid = lastrowid
            self.rowcount = getattr(cur, "rowcount", 0)

        def fetchone(self):
            return self._cur.fetchone()

        def fetchall(self):
            return self._cur.fetchall()

    class _PgCompatConn:
        def __init__(self, raw_conn: Any, is_pg: bool, pool: Any = None):
            self._raw = raw_conn
            self._is_pg = is_pg
            self._pool = pool
            self._released = False

        def execute(self, sql: str, params: Any = ()) -> _PgCompatCursor:
            if not self._is_pg:
                cur = self._raw.execute(sql, params)
                return _PgCompatCursor(cur, int(getattr(cur, "lastrowid", 0) or 0))
            q_str, add_ret = _sql_pg(sql)
            if add_ret:
                cur = self._raw.execute(q_str + " RETURNING id", params)
                row = cur.fetchone()
                lid = int(row["id"]) if row and "id" in row else 0
                return _PgCompatCursor(cur, lid)
            cur = self._raw.execute(q_str, params)
            return _PgCompatCursor(cur, 0)

        def commit(self) -> None:
            self._raw.commit()

        def rollback(self) -> None:
            self._raw.rollback()

        def close(self) -> None:
            if self._released:
                return
            self._released = True
            if self._pool is not None:
                self._pool.putconn(self._raw)
            else:
                self._raw.close()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            try:
                if exc_type is None:
                    self._raw.commit()
                else:
                    self._raw.rollback()
            finally:
                self.close()

    def _get_pg_pool(db_url: str):
        with _pg_lock:
            if _pg_pool_holder["pool"] is not None and _pg_pool_holder["url"] == db_url:
                return _pg_pool_holder["pool"]
            from psycopg.rows import dict_row
            from psycopg_pool import ConnectionPool
            pool = ConnectionPool(
                conninfo=db_url,
                min_size=1,
                max_size=10,
                kwargs={"row_factory": dict_row},
                open=True,
            )
            _pg_pool_holder["pool"] = pool
            _pg_pool_holder["url"] = db_url
            atexit.register(lambda p=pool: p.close())
            return pool

    def _get_conn() -> _PgCompatConn:
        db_url = os.environ.get("DATABASE_URL", "")
        if db_url.startswith("postgres"):
            pool = _get_pg_pool(db_url)
            return _PgCompatConn(pool.getconn(), True, pool=pool)
        db_p = os.environ.get("DC_DB_PATH") or str(root_dir / "dentacore_local.db")
        c = sqlite3.connect(db_p, check_same_thread=False)
        c.row_factory = sqlite3.Row
        return _PgCompatConn(c, False)

    def _q(sql: str, *args: Any) -> list[dict]:
        with _pg_lock, _get_conn() as c:
            rows = c.execute(sql, args).fetchall()
            return [dict(r) for r in rows]

    def _q1(sql: str, *args: Any) -> dict | None:
        rows = _q(sql, *args)
        return rows[0] if rows else None

    def _ex(sql: str, *args: Any) -> int:
        with _pg_lock, _get_conn() as c:
            cur = c.execute(sql, args)
            c.commit()
            return int(cur.lastrowid or 0)

    def _write_audit(actor_id: Any, actor: str, action: str, target: str = "", ip_h: str = "", meta: dict | None = None, clinic_id: int = 1) -> None:
        from . import security as sec_mod
        ts = datetime.now(TZ).isoformat(timespec="seconds")
        m_json = json.dumps(meta or {}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        act_id = int(actor_id) if str(actor_id or "").isdigit() else None
        with _pg_lock, _get_conn() as c:
            if c._is_pg:
                c.execute("SELECT pg_advisory_xact_lock(74210001)")
            prev_row = c.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            prev_h = (prev_row["hash"] if prev_row and prev_row["hash"] else "0" * 64)
            h = sec_mod.audit_digest(prev_h, ts, str(actor), action, target, m_json)
            c.execute(
                "INSERT INTO audit_log (clinic_id,ts,actor_id,actor,action,target,ip_hash,meta,prev_hash,hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (clinic_id, ts, act_id, str(actor), action, target, ip_h, m_json, prev_h, h),
            )
            c.commit()

    register_enterprise_routes(
        app,
        {
            "q": _q,
            "q1": _q1,
            "ex": _ex,
            "db": _get_conn,
            "db_lock": _pg_lock,
            "current_user": panel.current_user,
            "write_audit": _write_audit,
            "enc": core.enc,
            "dec": core.dec,
            "norm_phone": core.norm_phone,
            "phone_hmac": core.phone_hmac,
            "mask_phone": panel.mask_phone,
            "tl": panel.tl,
            "kurus": panel.kurus,
            "iso_now": lambda: datetime.now(TZ).isoformat(timespec="seconds"),
            "now_utc": lambda: datetime.now(timezone.utc),
            "client_ip": panel.client_ip,
            "root_dir": root_dir,
            "fernet": core.fernet() if os.environ.get("DATA_ENCRYPTION_KEY") else None,
            "fernet_factory": core.fernet,
            "phone_hmac_key": core.S.phone_hmac_key,
            "limiter": lambda: panel.limiter,
        },
    )

