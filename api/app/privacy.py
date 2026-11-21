"""KVKK hasta verisi politikası: dışa aktarma ve anonimleştirme kapsamı TEK yerde.

`patient_id` taşıyan HER tablo POLICY'de sınıflandırılmalıdır. tests/test_privacy.py bunu canlı PostgreSQL şemasına
karşı doğrular: yeni bir hasta tablosu eklenip buraya yazılmazsa test başarısız olur (kapsam dışında sessizce kalmaz).

Eylemler (anonymize):
  special  panel.py içindeki özel mantık (kimlik alanları, şifreli alanlar, kuyruklar)
  scrub    satır kalır; serbest metin / tanımlayıcı alanlar boşaltılır (SCRUB tablosu ve scrub_in_tx)
  delete   satırlar silinir
  purge    dosyalar nesne deposundan silinir, sonra satırlar silinir (patient_media)
  keep     bilerek korunur; `why` alanı hukuki/operasyonel gerekçeyi taşır

Bu modül hukuki danışmanlık değildir. Saklama süreleri (vergi, hasta dosyası, UTS) klinik sahibi ve hukuk
danışmanı tarafından doğrulanmalıdır; `keep` gerekçeleri o doğrulamaya kadar varsayımdır.
"""
from __future__ import annotations

import asyncio
import re

from . import inbox, media
from .core import dec_msg_body, q

POLICY: dict[str, dict] = {
    "patients": {"anonymize": "special", "why": "Kimlik alanları anonim değerlerle değiştirilir; satır finans kayıtlarının bağı için kalır."},
    "consents": {"anonymize": "special", "why": "Rıza kayıtları geri çekilmiş işaretlenir; metin özeti/sürümü ispat için kalır."},
    "anamnesis": {"anonymize": "special", "why": "Cevaplar ve imzalayan adı anonimleştirilir."},
    "anamnesis_tokens": {"anonymize": "delete", "why": "Tek kullanımlık bağlantı belirteçleri; veri içermez."},
    "appointments": {"anonymize": "scrub", "why": "Randevu zamanı/tedavi istatistik için kalır; serbest metin silinir."},
    "waitlist": {"anonymize": "special", "why": "Pasif yapılır; teklifleri silinir."},
    "postop_checks": {"anonymize": "special", "why": "Silinir."},
    "message_log": {"anonymize": "special", "why": "Mesaj gövdesi boşaltılır; meta (yön/katman/zaman) istatistik için kalır."},
    "alerts": {"anonymize": "special", "why": "Ayrıntı metni genel ifadeyle değiştirilir."},
    "tooth_records": {"anonymize": "scrub", "why": "Diş/işlem kodları ve tutarlar kalır; not silinir."},
    "charges": {"anonymize": "keep", "why": "Mali kayıt (saklama yükümlülüğü varsayımı); ON DELETE RESTRICT. Açıklama serbest metindir: sahip/hukuk onayı gerekir."},
    "payments": {"anonymize": "keep", "why": "Mali kayıt (saklama yükümlülüğü varsayımı); ON DELETE RESTRICT."},
    "treatment_plans": {"anonymize": "keep", "why": "Serbest metin alanı yok (tedavi adı, durum, sayaçlar)."},
    "treatment_consents": {"anonymize": "special", "why": "İmza adı/metni/çizimi ve tarayıcı bilgisi silinir; bağlantı belirteci geçersiz kılınır."},
    "periodontal_exams": {"anonymize": "scrub", "why": "Ölçümler kalır (kimliksiz); notlar silinir."},
    "lab_orders": {"anonymize": "scrub", "why": "Laboratuvar iş kaydı kalır; not silinir."},
    "implant_records": {"anonymize": "scrub", "why": "İmplant lot/seri/ÜTS izlenebilirlik alanları kalır (tıbbi cihaz izlenebilirliği varsayımı); not silinir."},
    "payment_installments": {"anonymize": "scrub", "why": "Taksit tutarları kalır (mali); not silinir."},
    "patient_group_members": {"anonymize": "delete", "why": "Grup/pazarlama üyeliği; anonim hasta mesaj almamalı."},
    "patient_media": {"anonymize": "purge", "why": "Görüntüler hastayı belirler (sağlık verisi): önce depodan dosya, sonra satır silinir."},
    "campaign_events": {"anonymize": "scrub", "why": "Hasta bağı kopar; ziyaretçi/tarayıcı tanımlayıcıları boşaltılır, sayımlar kalır."},
}

INDIRECT = {"webhook_inbox": "Bekleyen/ölü mesaj yükü (şifreli) anonimleştirmede NULL'lanır; sender_key hasta telefonundan türetilir."}

SCRUB: dict[str, dict[str, object]] = {
    "appointments": {"cancel_reason": "", "satisfaction_reply": ""},
    "tooth_records": {"note": ""},
    "periodontal_exams": {"doctor_note": "", "note": ""},
    "lab_orders": {"note": ""},
    "implant_records": {"note": ""},
    "payment_installments": {"note": ""},
}

# Mali kayıtlarda bilerek korunan serbest metin sütunları (test, bunların DIŞINDA kalıntı arar).
PRESERVED_FREE_TEXT = {("charges", "description"), ("charges", "void_reason"), ("charges", "discount_reason"),
                       ("payments", "note"), ("payments", "void_reason"), ("tooth_records", "discount_reason")}

# Dışa aktarma bölümleri: bölüm -> (tablo, sütunlar, klinik_filtresi_var_mı)
EXPORT_SECTIONS: dict[str, tuple[str, str, bool]] = {
    "treatment_plans": ("treatment_plans", "id, treatment, planned_at, status, last_contact_at, followups_sent", False),
    "treatment_consents": ("treatment_consents",
                           "id, doctor_id, plan_summary_json, total_amount_kurus, document_version, content_sha256, signer_name, "
                           "signature_text, consent_type, status, signed_at, expires_at, created_at", True),
    "periodontal_exams": ("periodontal_exams",
                          "id, doctor_id, exam_date, teeth_json, measurements_json, bop_pct, plaque_pct, plaque_index_pct, "
                          "bleeding_index_pct, mean_pd, max_pd, doctor_approved, doctor_note, note, created_at", True),
    "lab_orders": ("lab_orders", "id, tooth_fdi, lab_name, procedure_type, work_type, shade, sent_date, due_date, delivered_date, "
                                 "cost_kurus, status, note, created_at", True),
    "implant_records": ("implant_records",
                        "id, tooth_fdi, brand, model, diameter_mm, length_mm, lot_number, serial_number, expiry_date, placed_at, "
                        "supplier, document_ref, uts_notification_status, torque_ncm, note, created_at", True),
    "payment_installments": ("payment_installments", "id, charge_id, installment_no, total_installments, title, due_date, "
                                                     "amount_kurus, paid_kurus, status, paid_at, note, created_at", True),
    "group_memberships": ("patient_group_members", "id, group_id, reason, added_at", True),
    "media_files": ("patient_media", "id, category, stage, original_filename, mime_type, file_size_bytes, sha256_hash, "
                                     "qc_verdict, note, created_at", True),
    "campaign_events": ("campaign_events", "id, campaign_id, event_type, source, utm_source, utm_medium, utm_campaign, created_at", True),
    "alerts": ("alerts", "id, kind, detail, created_at, acknowledged_at", True),
    "messages": ("message_log", "id, direction, layer, intent, created_at, body, delivery_status", True),
}


async def export_sections(cid: int, pid: int) -> dict[str, list[dict]]:
    """Panel dışa aktarmasına eklenen bölümler. Dosya baytları dahil DEĞİLDİR; media_files yalnızca üst veridir."""
    out: dict[str, list[dict]] = {}
    for key, (table, cols, scoped) in EXPORT_SECTIONS.items():
        sql = f"SELECT {cols} FROM {table} WHERE patient_id=%s" + (" AND clinic_id=%s" if scoped else "") + " ORDER BY id"
        rows = await (q(sql, pid, cid) if scoped else q(sql, pid))
        if key == "messages":
            for r in rows:
                r["body"] = dec_msg_body(r.get("body"))
        if key == "media_files":
            for r in rows:
                r["download_path"] = f"/app/api/patients/{pid}/media/{r['id']}"
        out[key] = rows
    return out


def inbox_sender_keys(cid: int, phone: str) -> list[str]:
    """Hasta telefonundan webhook_inbox.sender_key adayları (wa/ig; ham, 'ig:' önekli/öneksiz, yalnız rakam)."""
    cands = {phone}
    if phone.startswith("ig:"):
        cands.add(phone[3:])
    digits = re.sub(r"\D", "", phone)
    if digits:
        cands.add(digits)
    return sorted({inbox.sender_key(ch, cid, c) for ch in ("wa", "ig") for c in cands if c})


async def purge_media(cid: int, pid: int) -> dict:
    """Hasta dosyalarını depodan (yerel/S3) siler, SONRA satırı siler. Depo hatasında o satır KALIR ve failed'a girer;
    böylece silinemeyen dosya sahipsiz (yetim) kalmaz ve işlem yeniden denenebilir."""
    rows = await q("SELECT id, encrypted_path FROM patient_media WHERE patient_id=%s AND clinic_id=%s ORDER BY id", pid, cid)
    deleted, failed = 0, []
    for r in rows:
        path = str(r.get("encrypted_path") or "")
        try:
            if path:
                await asyncio.to_thread(media.delete_stored, path)
        except Exception:  # MediaStorageError, OSError, botocore hataları
            failed.append(int(r["id"]))
            continue
        await q("DELETE FROM patient_media WHERE id=%s AND clinic_id=%s", r["id"], cid)
        deleted += 1
    return {"deleted": deleted, "failed": failed}


async def scrub_in_tx(t, cid: int, pid: int, phone: str) -> dict:
    """panel anonimleştirmesinin işlem (transaction) bağlamında çalışır; hata olursa hepsi geri alınır."""
    done: dict[str, int] = {}
    for table, cols in SCRUB.items():
        sets = ", ".join(f"{c}=%s" for c in cols)
        rows = await t.q(f"UPDATE {table} SET {sets} WHERE clinic_id=%s AND patient_id=%s RETURNING id", *cols.values(), cid, pid)
        done[table] = len(rows or [])
    rows = await t.q(
        "UPDATE patients SET notes='', birth_date=NULL, click_id='', utm_source='', utm_medium='', utm_campaign='' "
        "WHERE id=%s AND clinic_id=%s RETURNING id", pid, cid)
    done["patients_extra"] = len(rows or [])
    rows = await t.q(
        "UPDATE treatment_consents SET signer_name='Anonimleştirildi', signature_text='', signature_svg_enc='', "
        "signed_user_agent='', signed_ip_hash='', token='anon-'||md5(random()::text||id::text) "
        "WHERE clinic_id=%s AND patient_id=%s RETURNING id", cid, pid)
    done["treatment_consents"] = len(rows or [])
    rows = await t.q("DELETE FROM patient_group_members WHERE clinic_id=%s AND patient_id=%s RETURNING id", cid, pid)
    done["patient_group_members"] = len(rows or [])
    rows = await t.q(
        "UPDATE campaign_events SET patient_id=NULL, visitor_hash='', user_agent_summary='', click_id='' "
        "WHERE clinic_id=%s AND patient_id=%s RETURNING id", cid, pid)
    done["campaign_events"] = len(rows or [])
    rows = []
    keys = inbox_sender_keys(cid, phone) if phone else []
    if keys:
        rows = await t.q(
            "UPDATE webhook_inbox SET payload_enc=NULL, status='done', processed_at=now(), last_error='anonymized' "
            "WHERE clinic_id=%s AND sender_key = ANY(%s) AND status IN ('pending','dead') RETURNING id", cid, keys)
    done["webhook_inbox"] = len(rows or [])
    return done
