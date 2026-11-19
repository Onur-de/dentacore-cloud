"""DentaCore Klinik Katalog, ISO 3950 FDI Diş Anatomisi, 14 Meslek & 15 Granüler Yetki (RBAC),
Banka Anlaşması İndirim Matematiği, Kampanya Bot/Kaynak Algılayıcı ve AI Maliyet Hesaplayıcı.
Saf Python — SQLite (`run_local.py`) ve PostgreSQL (`api/app/panel.py`) tarafından ortak kullanılır.
"""
from __future__ import annotations

import json
import re
from datetime import date, datetime
from decimal import Decimal, ROUND_HALF_UP
from typing import Any

# ==============================================================================
# 1. ISO 3950 FDI 52 DİŞ ANATOMİK KATALOĞU (32 Daimi: 11-48 + 20 Süt: 51-85)
# ==============================================================================
_PERM_NAMES = {
    1: ("Santral Kesici (Ön Keser)", "incisor", 1),
    2: ("Lateral Kesici (Yan Keser)", "incisor", 1),
    3: ("Kanin (Köpek Dişi)", "canine", 1),
    4: ("1. Küçük Azı (1. Premolar)", "premolar", 2),
    5: ("2. Küçük Azı (2. Premolar)", "premolar", 2),
    6: ("1. Büyük Azı (1. Molar)", "molar", 3),
    7: ("2. Büyük Azı (2. Molar)", "molar", 3),
    8: ("3. Büyük Azı (20 Yaş Dişi / 3. Molar)", "molar", 3),
}

_DECID_NAMES = {
    1: ("Süt Santral Kesici", "incisor", 1),
    2: ("Süt Lateral Kesici", "incisor", 1),
    3: ("Süt Kanin (Köpek Dişi)", "canine", 1),
    4: ("1. Süt Azı (1. Süt Molar)", "molar", 3),
    5: ("2. Süt Azı (2. Süt Molar)", "molar", 3),
}

_QUADRANT_META = {
    1: ("permanent", "upper", "right", "Sağ Üst Çene (1. Kadran)"),
    2: ("permanent", "upper", "left", "Sol Üst Çene (2. Kadran)"),
    3: ("permanent", "lower", "left", "Sol Alt Çene (3. Kadran)"),
    4: ("permanent", "lower", "right", "Sağ Alt Çene (4. Kadran)"),
    5: ("deciduous", "upper", "right", "Sağ Üst Çene Süt (5. Kadran)"),
    6: ("deciduous", "upper", "left", "Sol Üst Çene Süt (6. Kadran)"),
    7: ("deciduous", "lower", "left", "Sol Alt Çene Süt (7. Kadran)"),
    8: ("deciduous", "lower", "right", "Sağ Alt Çene Süt (8. Kadran)"),
}


def _build_fdi_catalog() -> dict[int, dict[str, Any]]:
    cat: dict[int, dict[str, Any]] = {}
    for q_num, (dentition, jaw, side, q_label) in _QUADRANT_META.items():
        names_map = _PERM_NAMES if dentition == "permanent" else _DECID_NAMES
        for pos, (t_name, kind, roots) in names_map.items():
            fdi = q_num * 10 + pos
            side_tr = "Sağ" if side == "right" else "Sol"
            jaw_tr = "Üst" if jaw == "upper" else "Alt"
            cat[fdi] = {
                "fdi": fdi,
                "quadrant": q_num,
                "position": pos,
                "dentition": dentition,
                "jaw": jaw,
                "side": side,
                "kind": kind,
                "roots": roots,
                "short_name": f"{side_tr} {jaw_tr} {t_name.split(' (')[0]}",
                "full_name": f"Diş #{fdi} · {side_tr} {jaw_tr} {t_name}",
                "anatomical_location": q_label,
            }
    return cat


FDI_TOOTH_CATALOG: dict[int, dict[str, Any]] = _build_fdi_catalog()
VALID_FDI_NUMBERS: frozenset[int] = frozenset(FDI_TOOTH_CATALOG.keys())

ODO_ALL_STATUSES = (
    "healthy",
    "caries",
    "planned",
    "treated",
    "filling",
    "root_canal",
    "crown",
    "bridge",
    "implant",
    "extraction",
    "missing",
    "postponed",
    "cancelled",
)
# Yalnız gerçekleştirilmiş (tamamlanmış) tedaviler hastaya finansal borç oluşturur.
# Planlanan (planned), çürük tespiti (caries), ertelendi (postponed) veya iptal (cancelled) ASLA borç yazmaz!
ODO_BILLABLE_STATUSES = frozenset({"treated", "filling", "root_canal", "crown", "bridge", "implant"})
ODO_PLANNED_STATUSES = frozenset({"planned", "caries", "extraction"})

DEFAULT_TREATMENT_CATALOG = [
    {"code": "TDB-101", "name": "İlk Diş Hekimi Muayenesi & Panoramik Planlama", "category": "Teşhis", "default_price_try": "750.00", "default_status": "treated"},
    {"code": "TDB-201", "name": "Kompozit Dolgu (Tek Yüzey)", "category": "Restoratif", "default_price_try": "2500.00", "default_status": "filling"},
    {"code": "TDB-202", "name": "Kompozit Dolgu (İki Yüzey - MO/DO)", "category": "Restoratif", "default_price_try": "3200.00", "default_status": "filling"},
    {"code": "TDB-203", "name": "Kompozit Dolgu (Üç Yüzey - MOD)", "category": "Restoratif", "default_price_try": "3900.00", "default_status": "filling"},
    {"code": "TDB-301", "name": "Kanal Tedavisi (Tek Kanal - Endodonti)", "category": "Endodonti", "default_price_try": "4800.00", "default_status": "root_canal"},
    {"code": "TDB-303", "name": "Kanal Tedavisi (Çok Kanallı Büyük Azı)", "category": "Endodonti", "default_price_try": "7200.00", "default_status": "root_canal"},
    {"code": "TDB-401", "name": "Zirkonyum Tam Seramik Kron (Kaplama)", "category": "Protez", "default_price_try": "8500.00", "default_status": "crown"},
    {"code": "TDB-402", "name": "Zirkonyum Köprü Gövde / Üyesi", "category": "Protez", "default_price_try": "8000.00", "default_status": "bridge"},
    {"code": "TDB-405", "name": "E-Max Lamina Veneer (Yaprak Porselen)", "category": "Estetik", "default_price_try": "11500.00", "default_status": "crown"},
    {"code": "TDB-501", "name": "Kemik İçi Dental İmplant Uygulaması", "category": "Cerrahi / İmplant", "default_price_try": "18500.00", "default_status": "implant"},
    {"code": "TDB-505", "name": "Basit Diş Çekimi", "category": "Cerrahi", "default_price_try": "2200.00", "default_status": "treated"},
    {"code": "TDB-506", "name": "Gömülü 20 Yaş Dişi Cerrahi Çekimi", "category": "Cerrahi", "default_price_try": "6500.00", "default_status": "treated"},
    {"code": "TDB-601", "name": "Diş Taşı Temizliği (Detartraj - Çift Çene)", "category": "Periodontoloji", "default_price_try": "3000.00", "default_status": "treated"},
    {"code": "TDB-602", "name": "Subgingival Küretaj (Kadran Başına)", "category": "Periodontoloji", "default_price_try": "4500.00", "default_status": "treated"},
]


# ==============================================================================
# 2. HASTA GELİŞ KANALLARI (13 KAYNAK) & BOT / UTM ALGILAYICI
# ==============================================================================
PATIENT_SOURCE_LABELS: dict[str, str] = {
    "instagram": "Instagram",
    "facebook": "Facebook",
    "tiktok": "TikTok",
    "google_ads": "Google Ads",
    "google": "Google (Organik)",
    "website": "Web Sitesi",
    "whatsapp": "WhatsApp",
    "phone": "Telefon",
    "qr": "QR Kod",
    "referral": "Tavsiye / Referans",
    "patient_referral": "Mevcut Hasta Yönlendirmesi",
    "walk_in": "Klinik Ziyareti",
    "other": "Diğer",
}
VALID_PATIENT_SOURCES: frozenset[str] = frozenset(PATIENT_SOURCE_LABELS.keys())

_SOURCE_ALIASES = {
    "wa": "whatsapp",
    "whatsapp_direct": "whatsapp",
    "ig": "instagram",
    "instagram_dm": "instagram",
    "fb": "facebook",
    "meta": "instagram",
    "meta_ads": "instagram",
    "gads": "google_ads",
    "adwords": "google_ads",
    "organik": "google",
    "google_organic": "google",
    "web": "website",
    "campaign_form": "website",
    "telefon": "phone",
    "tavsiye": "referral",
    "referans": "referral",
    "doctor_referral": "referral",
    "returning": "referral",
    "hasta_yonlendirmesi": "patient_referral",
    "klinik": "walk_in",
    "corporate": "other",
    "diger": "other",
}


def normalize_source(raw: str | None, default: str = "whatsapp") -> str:
    if not raw:
        return default
    s = raw.strip().lower()
    if s in VALID_PATIENT_SOURCES:
        return s
    return _SOURCE_ALIASES.get(s, default)


def detect_acquisition_source(
    explicit_source: str | None = None,
    utm_source: str | None = None,
    utm_medium: str | None = None,
    referrer: str | None = None,
    click_id: str | None = None,
    gclid: str | None = None,
    fbclid: str | None = None,
    ttclid: str | None = None,
    default: str = "website",
    default_source: str | None = None,
) -> str:
    eff_default = normalize_source(default_source or default, "website")
    exp_clean = (explicit_source or "").strip().lower()
    has_tracking = any((utm_source, utm_medium, gclid, fbclid, ttclid, click_id))
    if exp_clean and exp_clean in (VALID_PATIENT_SOURCES | set(_SOURCE_ALIASES.keys())) and not (has_tracking and exp_clean in ("website", "web", "other", "diger")):
        return normalize_source(exp_clean, eff_default)
    us = (utm_source or "").strip().lower()
    um = (utm_medium or "").strip().lower()
    ref = (referrer or "").strip().lower()
    cid_s = (click_id or "").strip().lower()
    if gclid or cid_s.startswith("gclid") or ("google" in us and any(k in um for k in ("cpc", "ppc", "ads", "paid"))):
        return "google_ads"
    if "tiktok" in us or ttclid or cid_s.startswith("ttclid") or "tiktok.com" in ref:
        return "tiktok"
    if "instagram" in us or "ig" == us or fbclid or cid_s.startswith("fbclid") or "instagram.com" in ref:
        return "instagram" if ("instagram" in us or "ig" == us or "instagram.com" in ref or not us) else "facebook"
    if "facebook" in us or "fb" == us or "facebook.com" in ref:
        return "facebook"
    if "whatsapp" in us or "wa" == us or "wa.me" in ref:
        return "whatsapp"
    if "qr" in us or "qr" in um:
        return "qr"
    if "google" in us or "google." in ref:
        return "google"
    return normalize_source(us or explicit_source, eff_default)


_BOT_UA_RE = re.compile(
    r"(bot|crawler|spider|preview|facebookexternalhit|facebot|twitterbot|whatsapp|telegrambot|"
    r"slackbot|discordbot|linkedinbot|googlebot|bingbot|yandex|baiduspider|ahrefsbot|semrushbot|"
    r"mj12bot|dotbot|petalbot|bytespider|headlesschrome|phantomjs|slurp|curl/|wget/|python-requests|"
    r"go-http-client|apache-httpclient| PostmanRuntime)",
    re.IGNORECASE,
)


def is_bot_traffic(user_agent: str | None, is_prefetch: bool = False) -> bool:
    if is_prefetch:
        return True
    ua = (user_agent or "").strip()
    if not ua or len(ua) < 12:
        return True
    return bool(_BOT_UA_RE.search(ua))


# ==============================================================================
# 3. 14 PERSONEL MESLEĞİ & 15 GRANÜLER SİSTEM YETKİSİ (RBAC)
# ==============================================================================
STAFF_PROFESSIONS: dict[str, dict[str, Any]] = {
    "clinic_manager": {"label": "Klinik Yöneticisi", "default_role": "owner"},
    "dentist": {"label": "Diş Hekimi", "default_role": "doctor"},
    "specialist_dentist": {"label": "Uzman Diş Hekimi", "default_role": "doctor"},
    "secretary": {"label": "Sekreter", "default_role": "secretary"},
    "dental_assistant": {"label": "Diş Hekimi Asistanı", "default_role": "clinical_support"},
    "dental_technician": {"label": "Diş Teknikeri", "default_role": "lab_tech"},
    "lab_technician": {"label": "Laboratuvar Teknikeri", "default_role": "lab_tech"},
    "accounting": {"label": "Muhasebe Personeli", "default_role": "accounting"},
    "finance": {"label": "Finans Personeli", "default_role": "accounting"},
    "cleaning": {"label": "Temizlik Personeli", "default_role": "no_access"},
    "hospitality": {"label": "Çay ve Servis Personeli", "default_role": "no_access"},
    "warehouse": {"label": "Depo ve Stok Personeli", "default_role": "warehouse"},
    "patient_relations": {"label": "Hasta İlişkileri Personeli", "default_role": "secretary"},
    "other": {"label": "Diğer", "default_role": "no_access"},
}

PERMISSION_KEYS: tuple[str, ...] = (
    "view",
    "create",
    "edit",
    "delete_cancel",
    "export",
    "finance_view",
    "finance_edit",
    "patient_view",
    "patient_edit",
    "campaign_manage",
    "inventory_manage",
    "doctor_reports",
    "staff_manage",
    "system_settings",
    "audit_logs",
    "doctor_own_patients_only",
)

PERMISSION_LABELS_TR: dict[str, str] = {
    "view": "Görüntüleme (Panel Giriş)",
    "create": "Kayıt Oluşturma",
    "edit": "Kayıt Düzenleme",
    "delete_cancel": "Silme / İptal Etme",
    "export": "Rapor ve Veri Dışa Aktarma",
    "finance_view": "Finans ve Kasa Görüntüleme",
    "finance_edit": "Finans, Tahsilat ve İndirim Düzenleme",
    "patient_view": "Hasta Verileri Görüntüleme",
    "patient_edit": "Hasta ve Tedavi Verileri Düzenleme",
    "campaign_manage": "Kampanya Yönetimi",
    "inventory_manage": "Stok ve Envanter Yönetimi",
    "doctor_reports": "Doktor Hakediş ve Gelir Raporları",
    "staff_manage": "Personel ve Yetki Yönetimi",
    "system_settings": "Sistem Ayarları",
    "audit_logs": "Denetim Kayıtları (Audit Log)",
    "doctor_own_patients_only": "Yalnız Kendi Hastalarını ve Finansını Görsün",
}

ROLE_DEFAULT_PERMISSIONS: dict[str, dict[str, bool]] = {
    "owner": {k: (False if k == "doctor_own_patients_only" else True) for k in PERMISSION_KEYS},
    "doctor": {
        "view": True, "create": True, "edit": True, "delete_cancel": True, "export": False,
        "finance_view": True, "finance_edit": True, "patient_view": True, "patient_edit": True,
        "campaign_manage": False, "inventory_manage": True, "doctor_reports": True,
        "staff_manage": False, "system_settings": False, "audit_logs": False,
        "doctor_own_patients_only": False,
    },
    "secretary": {
        "view": True, "create": True, "edit": True, "delete_cancel": False, "export": False,
        "finance_view": False, "finance_edit": True, "patient_view": True, "patient_edit": True,
        "campaign_manage": False, "inventory_manage": False, "doctor_reports": False,
        "staff_manage": False, "system_settings": False, "audit_logs": False,
        "doctor_own_patients_only": False,
    },
    "accounting": {
        "view": True, "create": True, "edit": True, "delete_cancel": True, "export": True,
        "finance_view": True, "finance_edit": True, "patient_view": True, "patient_edit": False,
        "campaign_manage": True, "inventory_manage": True, "doctor_reports": True,
        "staff_manage": False, "system_settings": False, "audit_logs": False,
        "doctor_own_patients_only": False,
    },
    "clinical_support": {
        "view": True, "create": True, "edit": True, "delete_cancel": False, "export": False,
        "finance_view": False, "finance_edit": False, "patient_view": True, "patient_edit": False,
        "campaign_manage": False, "inventory_manage": True, "doctor_reports": False,
        "staff_manage": False, "system_settings": False, "audit_logs": False,
        "doctor_own_patients_only": False,
    },
    "lab_tech": {
        "view": True, "create": True, "edit": True, "delete_cancel": False, "export": False,
        "finance_view": False, "finance_edit": False, "patient_view": True, "patient_edit": False,
        "campaign_manage": False, "inventory_manage": True, "doctor_reports": False,
        "staff_manage": False, "system_settings": False, "audit_logs": False,
        "doctor_own_patients_only": False,
    },
    "warehouse": {
        "view": True, "create": True, "edit": True, "delete_cancel": False, "export": True,
        "finance_view": False, "finance_edit": False, "patient_view": False, "patient_edit": False,
        "campaign_manage": False, "inventory_manage": True, "doctor_reports": False,
        "staff_manage": False, "system_settings": False, "audit_logs": False,
        "doctor_own_patients_only": False,
    },
    "no_access": {k: False for k in PERMISSION_KEYS},
}


def resolve_permissions(role: str | None, job_title: str | None = None, custom_json: str | dict | None = None) -> dict[str, bool]:
    eff_role = (role or "").strip().lower()
    if eff_role not in ROLE_DEFAULT_PERMISSIONS:
        jt = (job_title or "").strip().lower()
        eff_role = STAFF_PROFESSIONS.get(jt, {}).get("default_role", "secretary")
    base = dict(ROLE_DEFAULT_PERMISSIONS.get(eff_role, ROLE_DEFAULT_PERMISSIONS["no_access"]))
    if custom_json:
        try:
            overrides = json.loads(custom_json) if isinstance(custom_json, str) else custom_json
            if isinstance(overrides, dict):
                for k, v in overrides.items():
                    if k in PERMISSION_KEYS:
                        base[k] = bool(v)
        except Exception:
            pass
    return base


# ==============================================================================
# 4. BANKA ANLAŞMALARI VE OTOMATİK İNDİRİM HESAPLAYICI (DECIMAL / KURUŞ)
# ==============================================================================
def compute_bank_discount(
    gross_kurus: int,
    agreement: dict[str, Any] | None,
    procedure_name: str = "",
    manual_discount_kurus: int = 0,
    ref_date: str | None = None,
) -> dict[str, Any]:
    """Anlaşmalı banka kurallarını doğrular ve kuruş hassasiyetinde indirim hesaplar."""
    gross_k = max(0, int(gross_kurus))
    man_k = max(0, int(manual_discount_kurus))
    if not agreement:
        total_disc = min(gross_k, man_k)
        return {
            "eligible": False,
            "ineligible_reason": None,
            "gross_kurus": gross_k,
            "bank_discount_kurus": 0,
            "manual_discount_kurus": total_disc,
            "total_discount_kurus": total_disc,
            "net_kurus": gross_k - total_disc,
            "bank_agreement_id": None,
            "bank_name": None,
            "discount_pct": 0.0,
            "explanation": f"Manuel indirim: {total_disc / 100:.2f} TL" if total_disc > 0 else "İndirim yok",
        }

    today_s = (ref_date or date.today().isoformat())[:10]
    if not bool(agreement.get("active", 1)):
        return {
            "eligible": False,
            "ineligible_reason": "Banka anlaşması pasif durumda",
            "gross_kurus": gross_k,
            "bank_discount_kurus": 0,
            "manual_discount_kurus": min(gross_k, man_k),
            "total_discount_kurus": min(gross_k, man_k),
            "net_kurus": gross_k - min(gross_k, man_k),
            "bank_agreement_id": agreement.get("id"),
            "bank_name": agreement.get("bank_name"),
            "discount_pct": 0.0,
            "explanation": "Banka anlaşması pasif olduğu için indirim uygulanmadı",
        }

    start_d = (agreement.get("start_date") or "")[:10]
    end_d = (agreement.get("end_date") or "")[:10]
    if (start_d and today_s < start_d) or (end_d and today_s > end_d):
        return {
            "eligible": False,
            "ineligible_reason": f"Anlaşma tarih aralığı ({start_d or '-'} / {end_d or '-'}) dışında",
            "gross_kurus": gross_k,
            "bank_discount_kurus": 0,
            "manual_discount_kurus": min(gross_k, man_k),
            "total_discount_kurus": min(gross_k, man_k),
            "net_kurus": gross_k - min(gross_k, man_k),
            "bank_agreement_id": agreement.get("id"),
            "bank_name": agreement.get("bank_name"),
            "discount_pct": 0.0,
            "explanation": "Banka anlaşmasının süresi dolmuş veya henüz başlamamış",
        }

    app_tr = (agreement.get("applicable_treatments") or "all").strip().lower()
    if app_tr not in ("", "all", "tümü", "hepsi", "*"):
        allowed_tokens = [t.strip() for t in app_tr.split(",") if t.strip()]
        proc_low = (procedure_name or "").lower()
        if allowed_tokens and not any(tok in proc_low for tok in allowed_tokens):
            return {
                "eligible": False,
                "ineligible_reason": f"Bu işlem ({procedure_name}) anlaşma kapsamında ({app_tr}) değil",
                "gross_kurus": gross_k,
                "bank_discount_kurus": 0,
                "manual_discount_kurus": min(gross_k, man_k),
                "total_discount_kurus": min(gross_k, man_k),
                "net_kurus": gross_k - min(gross_k, man_k),
                "bank_agreement_id": agreement.get("id"),
                "bank_name": agreement.get("bank_name"),
                "discount_pct": 0.0,
                "explanation": "İşlem türü anlaşma kapsamında olmadığı için otomatik indirim uygulanmadı",
            }

    dtype = (agreement.get("discount_type") or "percentage").lower()
    pct = Decimal(str(agreement.get("discount_pct") or 0))
    if dtype == "fixed":
        bank_disc_k = int(agreement.get("fixed_discount_kurus") or 0)
    else:
        bank_disc_k = int((Decimal(gross_k) * pct / Decimal(100)).quantize(Decimal("1"), rounding=ROUND_HALF_UP))

    max_cap_k = int(agreement.get("max_discount_kurus") or 0)
    if max_cap_k > 0 and bank_disc_k > max_cap_k:
        bank_disc_k = max_cap_k
    bank_disc_k = min(gross_k, max(0, bank_disc_k))

    combinable = bool(agreement.get("combinable", 0))
    if combinable and man_k > 0:
        total_disc_k = min(gross_k, bank_disc_k + man_k)
        eff_man_k = total_disc_k - bank_disc_k
    elif man_k > 0 and not combinable:
        # Birleştirilemez anlaşmada daha yüksek olan indirim uygulanır
        capped_man = min(gross_k, man_k)
        if capped_man > bank_disc_k:
            total_disc_k = capped_man
            eff_man_k = capped_man
            bank_disc_k = 0
        else:
            total_disc_k = bank_disc_k
            eff_man_k = 0
    else:
        total_disc_k = bank_disc_k
        eff_man_k = 0

    net_k = gross_k - total_disc_k
    bname = agreement.get("bank_name") or "Anlaşmalı Banka"
    if bank_disc_k > 0:
        exp = f"{bname} İndirimi (%{pct}): -{bank_disc_k / 100:.2f} TL"
        if max_cap_k > 0 and bank_disc_k == max_cap_k:
            exp += f" (Üst sınır {max_cap_k / 100:.2f} TL uygulandı)"
        if eff_man_k > 0:
            exp += f" + Ek İndirim: -{eff_man_k / 100:.2f} TL"
    elif eff_man_k > 0:
        exp = f"Özel / Manuel İndirim: -{eff_man_k / 100:.2f} TL ({bname} anlaşmasından yüksek)"
    else:
        exp = "İndirim yok"
    return {
        "eligible": True,
        "ineligible_reason": None,
        "gross_kurus": gross_k,
        "bank_discount_kurus": bank_disc_k,
        "manual_discount_kurus": eff_man_k,
        "total_discount_kurus": total_disc_k,
        "net_kurus": net_k,
        "bank_agreement_id": agreement.get("id"),
        "bank_name": bname,
        "discount_pct": float(pct),
        "explanation": exp,
    }


# ==============================================================================
# 5. HASTA GRUBU / ETİKET ETİK DOĞRULAYICI (BÖLÜM 10)
# ==============================================================================
_TR_ASCII_MAP = str.maketrans("ıİğĞüÜşŞöÖçÇâÂîÎûÛ013457", "iigguussooccaaiiuuoieast")
_FORBIDDEN_INSULT_RE = re.compile(
    r"(?:^|[^a-z0-9])(dolandiric|hirsiz|deli|manyak|aptal|salak|gerizekal|serefsiz|ahlaksiz|cingene|pislik|sahtekar|psikopat|terbiyesiz|edepsiz|yalanc|kara\s*[-_]?\s*liste|blacklist)",
    re.IGNORECASE,
)


def validate_ethical_group_tag(name: str, reason: str = "") -> tuple[bool, str]:
    combined = f"{name} {reason}".strip().translate(_TR_ASCII_MAP).lower()
    if _FORBIDDEN_INSULT_RE.search(combined):
        return False, "Etiket veya açıklama hakaret, ayrımcılık, kara liste veya doğrulanmamış suçlama içeremez. Lütfen nesnel klinik/operasyonel bir neden yazın (örn. '3 kez habersiz randevuya gelmedi')."
    return True, "OK"


# ==============================================================================
# 6. YAPAY ZEKA MALİYET VE KOTA HESAPLAYICI (BÖLÜM 13)
# ==============================================================================
AI_MODEL_CATALOG = {
    "L1": {"provider": "DentaCore Yerel Kural Motoru", "model": "L1-Deterministik (0 Token)", "in_per_1m_usd": Decimal("0"), "out_per_1m_usd": Decimal("0")},
    "L2": {"provider": "DentaCore Yerel Anahtar Sınıflandırıcı", "model": "L2-Anahtar/SSS (0 Token)", "in_per_1m_usd": Decimal("0"), "out_per_1m_usd": Decimal("0")},
    "L3": {"provider": "Google Gemini / OpenAI Uyumlu API", "model": "gemini-2.5-flash-lite / gpt-4o-mini", "in_per_1m_usd": Decimal("0.15"), "out_per_1m_usd": Decimal("0.60")},
}
USD_TRY_RATE = Decimal("50.47")
PACKAGE_NET_PRICE_TRY = Decimal("3500.00")


def compute_ai_cost_report(
    layer_rows: list[dict[str, Any]],
    monthly_token_limit: int = 1_500_000,
    monthly_budget_try: float = 250.0,
    hard_stop: bool = True,
    actual_billed_try: float | None = None,
) -> dict[str, Any]:
    total_replies = 0
    free_replies = 0
    total_tin = 0
    total_tout = 0
    est_usd = Decimal("0")
    breakdown = []

    for r in layer_rows:
        lyr = str(r.get("layer") or "-")
        prefix = lyr[:2].upper() if len(lyr) >= 2 else "L1"
        meta = AI_MODEL_CATALOG.get(prefix, AI_MODEL_CATALOG["L1"])
        rep = int(r.get("replies") or r.get("cevap") or 0)
        tin = int(r.get("tin") or 0)
        tout = int(r.get("tout") or 0)
        total_replies += rep
        if prefix in ("L1", "L2") or (tin == 0 and tout == 0):
            free_replies += rep
        total_tin += tin
        total_tout += tout
        c_usd = (Decimal(tin) * meta["in_per_1m_usd"] / Decimal(1_000_000)) + (Decimal(tout) * meta["out_per_1m_usd"] / Decimal(1_000_000))
        c_try = (c_usd * USD_TRY_RATE).quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP)
        est_usd += c_usd
        breakdown.append({
            "layer": lyr,
            "provider": meta["provider"],
            "model": meta["model"],
            "replies": rep,
            "tin": tin,
            "tout": tout,
            "estimated_cost_usd": float(c_usd.quantize(Decimal("0.0001"))),
            "estimated_cost_try": float(c_try),
            "cost_per_op_try": float((c_try / Decimal(rep)).quantize(Decimal("0.0001"))) if rep > 0 else 0.0,
        })

    est_try = (est_usd * USD_TRY_RATE).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    total_tokens = total_tin + total_tout
    limit_tok = max(1, int(monthly_token_limit or 1_500_000))
    usage_pct = round(100.0 * total_tokens / limit_tok, 2)
    gross_margin_after_ai_try = PACKAGE_NET_PRICE_TRY - est_try
    gross_margin_pct = round(float((gross_margin_after_ai_try / PACKAGE_NET_PRICE_TRY) * Decimal(100)), 2)

    return {
        "cost_nature_tr": "TAHMİNİ MODEL KULLANIM MALİYETİ (Token sayılarına ve resmî birim fiyatlara dayalı tahmini işletme gideridir; harici sağlayıcı kesin faturası değildir).",
        "package_price_try": float(PACKAGE_NET_PRICE_TRY),
        "subscription_price_try": float(PACKAGE_NET_PRICE_TRY),
        "usd_try_rate": float(USD_TRY_RATE),
        "total_requests": total_replies,
        "zero_token_requests": free_replies,
        "zero_token_ratio_pct": round(100.0 * free_replies / total_replies, 1) if total_replies > 0 else 100.0,
        "tokens_in": total_tin,
        "tokens_out": total_tout,
        "total_tokens": total_tokens,
        "estimated_cost_usd": float(est_usd.quantize(Decimal("0.0001"))),
        "estimated_cost_try": float(est_try),
        "actual_billed_try": actual_billed_try,
        "cost_per_request_try": float((est_try / Decimal(total_replies)).quantize(Decimal("0.0001"))) if total_replies > 0 else 0.0,
        "monthly_token_limit": limit_tok,
        "monthly_budget_try": float(monthly_budget_try),
        "quota_usage_pct": usage_pct,
        "quota_warning_80": usage_pct >= 80.0,
        "quota_exceeded_100": usage_pct >= 100.0,
        "hard_stop_enabled": bool(hard_stop),
        "gross_profit_after_ai_try": float(gross_margin_after_ai_try),
        "gross_margin_pct": gross_margin_pct,
        "gross_margin_after_ai_pct": gross_margin_pct,
        "layers": breakdown,
    }
