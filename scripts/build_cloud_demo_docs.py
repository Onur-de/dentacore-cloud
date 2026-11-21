"""DentaCore v6.3 — Standalone Bulut Demo (GitHub Pages / docs/) Derleyicisi.
- 57 API uç noktasının tamamını (33 kurumsal uç + 24 çekirdek uç) tarayıcı içi motorla (`window.fetch` + `XMLHttpRequest` desteğiyle) çalıştırır.
- 24 gerçekçi demo hastası ("Örnek Demo Verisi"), 52 diş FDI odontogramı, 6 nokta periodontal ölçümler, implant/lot pasaportu, lab iş emirleri, 7 aşamalı reklam hunisi ve 0 banka anlaşması (Taslak Modu kuralı) içerir.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
DENTACORE_DIR = HERE.parent
REPO_ROOT = DENTACORE_DIR.parent.parent
CLOUD_DIR = REPO_ROOT / "5_KALICI_GITHUB_VE_BULUT_KURULUMU"
WEB_DIR = DENTACORE_DIR / "api" / "app" / "web"
FAQ_PATH = DENTACORE_DIR / "api" / "app" / "faq.json"

FAVICON_DATA_URI = (
    "data:image/svg+xml;utf8,%3Csvg%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%20viewBox%3D%220%200%2064%2064%22%3E"
    "%3Crect%20width%3D%2264%22%20height%3D%2264%22%20rx%3D%2216%22%20fill%3D%22%230A2540%22/%3E"
    "%3Cpath%20d%3D%22M20%2018c-5%200-8%204-8%2010%200%209%204%2020%208%2020%203%200%203-8%206-12%201-1%202-2%206-2s5%201%206%202c3%204%203%2012%206%2012%204%200%208-11%208-20%200-6-3-10-8-10-4%200-7%202-12%202s-8-2-12-2z%22%20fill%3D%22%230D9488%22/%3E"
    "%3Ccircle%20cx%3D%2246%22%20cy%3D%2218%22%20r%3D%225%22%20fill%3D%22%23EA580C%22/%3E%3C/svg%3E"
)

ENGINE_JS_TEMPLATE = r"""
"use strict";
(() => {
  const FAQ_DATA = __FAQ_JSON__;

  function sGet(k, def = "") {
    try {
      const v = window.localStorage.getItem(k);
      return v === null ? def : v;
    } catch (e) { return def; }
  }
  function sSet(k, v) {
    try { window.localStorage.setItem(k, String(v)); } catch (e) {}
  }

  const now = new Date();
  const todayAt = (h, m, dOff = 0) => {
    const x = new Date(now.getFullYear(), now.getMonth(), now.getDate() + dOff, h, m, 0, 0);
    return x.toISOString();
  };
  const isoNow = () => new Date().toISOString();

  const SOURCE_LABELS = {
    instagram: "Instagram",
    instagram_dm: "Instagram DM",
    facebook: "Facebook",
    tiktok: "TikTok",
    google: "Google Arama",
    google_ads: "Google Ads",
    whatsapp: "WhatsApp",
    whatsapp_direct: "WhatsApp Direkt",
    website: "Web Sitesi",
    campaign_form: "Kampanya Formu",
    phone: "Telefon",
    referral: "Referans / Tavsiye",
    patient_referral: "Hasta Yönlendirmesi",
    doctor_referral: "Hekim Yönlendirmesi",
    walk_in: "Klinik Önünden Geçerken",
    returning: "Eski / Tekrar Gelen Hasta",
    corporate: "Kurumsal Anlaşma",
    qr: "QR / Form",
    meta_ads: "Meta / Instagram Reklamı",
    other: "Diğer"
  };

  const DEFAULT_PERMS = {
    owner: { view: true, create: true, edit: true, delete_cancel: true, finance_view: true, finance_collect: true, discount_apply: true, price_override: true, settings_manage: true, staff_manage: true, export_data: true, doctor_own_patients_only: false, max_discount_pct: 100 },
    doctor: { view: true, create: true, edit: true, delete_cancel: false, finance_view: true, finance_collect: false, discount_apply: true, price_override: false, settings_manage: false, staff_manage: false, export_data: false, doctor_own_patients_only: false, max_discount_pct: 20 },
    secretary: { view: true, create: true, edit: true, delete_cancel: true, finance_view: false, finance_collect: true, discount_apply: true, price_override: false, settings_manage: false, staff_manage: false, export_data: false, doctor_own_patients_only: false, max_discount_pct: 10 },
    accountant: { view: true, create: false, edit: false, delete_cancel: false, finance_view: true, finance_collect: true, discount_apply: false, price_override: false, settings_manage: false, staff_manage: false, export_data: true, doctor_own_patients_only: false, max_discount_pct: 0 }
  };

  // Gercek backend (dental_catalog.ROLE_DEFAULT_PERMISSIONS) yetki anahtarlariyla birebir uyum:
  // panel finance_view / finance_edit / inventory_manage anahtarlarini okur.
  const REAL_ROLE_PERMS = {
    owner: { export: true, finance_view: true, finance_edit: true, patient_view: true, patient_edit: true, campaign_manage: true, inventory_manage: true, doctor_reports: true, staff_manage: true, system_settings: true, audit_logs: true },
    doctor: { delete_cancel: true, export: false, finance_view: true, finance_edit: true, patient_view: true, patient_edit: true, campaign_manage: false, inventory_manage: true, doctor_reports: true, staff_manage: false, system_settings: false, audit_logs: false },
    secretary: { delete_cancel: false, export: false, finance_view: false, finance_edit: true, patient_view: true, patient_edit: true, campaign_manage: false, inventory_manage: false, doctor_reports: false, staff_manage: false, system_settings: false, audit_logs: false },
    accountant: { create: true, edit: true, delete_cancel: true, export: true, finance_view: true, finance_edit: true, patient_view: true, patient_edit: false, campaign_manage: true, inventory_manage: true, doctor_reports: true, staff_manage: false, system_settings: false, audit_logs: false }
  };
  Object.keys(DEFAULT_PERMS).forEach((r) => Object.assign(DEFAULT_PERMS[r], REAL_ROLE_PERMS[r] || {}));

  function buildInitialDB() {
    const t0 = isoNow();
    const clinics = [
      {
        id: 1, name: "Özel DentaCore Merkez Polikliniği", slug: "merkez-poliklinik", city: "İstanbul",
        address: "Bağdat Cad. No:142, Kadıköy / İstanbul", phone: "+90 216 555 01 01", chairs: 3,
        work_minutes: 600, google_review_url: "https://search.google.com/local/writereview?placeid=ChIJExample1",
        autopilot_name: "DentaCore Asistan", default_lang: "tr", slot_step_min: 15,
        working_hours_json: '{"mon_fri":["09:00","19:00"],"sat":["09:00","15:00"],"sun":null}',
        buffer_min: 0, ai_custom_rules_json: '{}', active: 1, created_at: t0
      },
      {
        id: 2, name: "Özel Bursa Gülüş Diş Polikliniği", slug: "bursa-gulus-dis", city: "Bursa",
        address: "FSM Bulvarı No:48, Nilüfer / Bursa", phone: "+90 224 555 02 02", chairs: 2,
        work_minutes: 600, google_review_url: "https://search.google.com/local/writereview?placeid=ChIJExample2",
        autopilot_name: "Bursa Gülüş Asistan", default_lang: "tr", slot_step_min: 15,
        working_hours_json: '{"mon_fri":["09:00","19:00"],"sat":["09:00","15:00"],"sun":null}',
        buffer_min: 0, ai_custom_rules_json: '{}', active: 1, created_at: t0
      },
      {
        id: 3, name: "Ankara Çankaya Estetik Diş Polikliniği", slug: "ankara-cankaya-estetik-dis", city: "Ankara",
        address: "Tunalı Hilmi Cad. No:88, Çankaya / Ankara", phone: "+90 312 555 03 03", chairs: 3,
        work_minutes: 600, google_review_url: "https://search.google.com/local/writereview?placeid=ChIJExample3",
        autopilot_name: "Çankaya Diş Asistan", default_lang: "tr", slot_step_min: 15,
        working_hours_json: '{"mon_fri":["09:00","19:00"],"sat":["09:00","15:00"],"sun":null}',
        buffer_min: 0, ai_custom_rules_json: '{}', active: 1, created_at: t0
      }
    ];

    const staff_users = [
      { id: 1, clinic_id: 1, email: "yonetici@dentacore.com", pw: "DentaCore2026!", full_name: "Dt. Onur Aksoy", role: "owner", job_title: "owner", specialty: "İmplantoloji & Cerrahi", phone: "+905320000001", share_pct: 50.0, totp_enabled: 0, active: 1, permissions: { ...DEFAULT_PERMS.owner }, created_at: t0 },
      { id: 2, clinic_id: 1, email: "elif.hekim@dentacore.com", pw: "DentaCore2026!", full_name: "Dt. Elif Yıldız", role: "doctor", job_title: "doctor_specialist", specialty: "Protetik & Estetik Diş Hekimi", phone: "+905320000012", share_pct: 40.0, totp_enabled: 0, active: 1, permissions: { ...DEFAULT_PERMS.doctor }, created_at: t0 },
      { id: 3, clinic_id: 1, email: "sekreter@dentacore.com", pw: "DentaCore2026!", full_name: "Selin Kaya", role: "secretary", job_title: "secretary", specialty: "Hasta Kabul & Ön Büro", phone: "+905320000013", share_pct: 0.0, totp_enabled: 0, active: 1, permissions: { ...DEFAULT_PERMS.secretary }, created_at: t0 },
      { id: 4, clinic_id: 2, email: "klinik@bursadis.com", pw: "BursaDis2026!", full_name: "Dt. Kemal Aydın", role: "owner", job_title: "owner", specialty: "Başhekim", phone: "+905320000002", share_pct: 50.0, totp_enabled: 0, active: 1, permissions: { ...DEFAULT_PERMS.owner }, created_at: t0 },
      { id: 5, clinic_id: 3, email: "klinik@ankaradis.com", pw: "AnkaraDis2026!", full_name: "Dt. Zeynep Demir", role: "owner", job_title: "owner", specialty: "Başhekim", phone: "+905320000003", share_pct: 50.0, totp_enabled: 0, active: 1, permissions: { ...DEFAULT_PERMS.owner }, created_at: t0 }
    ];

    const patient_groups = [
      { id: 1, clinic_id: 1, slug: "vip", name: "VIP / Sadık Hasta", color: "teal", is_restricted: false },
      { id: 2, clinic_id: 1, slug: "dental_tourism", name: "Yurt Dışı / Sağlık Turizmi", color: "green", is_restricted: false },
      { id: 3, clinic_id: 1, slug: "implant_followup", name: "İmplant Takip", color: "teal", is_restricted: false },
      { id: 4, clinic_id: 1, slug: "ortho_followup", name: "Ortodonti Takip", color: "teal", is_restricted: false },
      { id: 5, clinic_id: 1, slug: "special_attention", name: "Özel Dikkat / Teyit Zorunlu", color: "amber", is_restricted: true },
      { id: 6, clinic_id: 1, slug: "payment_tracking", name: "Ödeme Planı Takibi", color: "amber", is_restricted: true }
    ];

    const patients = [
      { id: 1, clinic_id: 1, phone: "905321112233", display_name: "Ayşe Kaya", lang: "tr", channel: "wa", first_source: "instagram", last_source: "whatsapp", primary_doctor_id: 1, groups: [{ id: 1, name: "VIP / Sadık Hasta", color: "teal", reason: "Düzenli kontrol hastası" }], active: 1, created_at: t0 },
      { id: 2, clinic_id: 1, phone: "905334445566", display_name: "Ahmet Yılmaz", lang: "tr", channel: "wa", first_source: "google_ads", last_source: "whatsapp", primary_doctor_id: 1, groups: [{ id: 3, name: "İmplant Takip", color: "teal", reason: "Straumann üst yapı süreci" }], active: 1, created_at: t0 },
      { id: 3, clinic_id: 1, phone: "ig:99887766", display_name: "Selin Arslan", lang: "tr", channel: "ig", first_source: "instagram_dm", last_source: "instagram_dm", primary_doctor_id: 2, groups: [], active: 1, created_at: t0 },
      { id: 4, clinic_id: 1, phone: "447700900123", display_name: "Oliver Grant (London)", lang: "en", channel: "wa", first_source: "website", last_source: "whatsapp", primary_doctor_id: 1, groups: [{ id: 2, name: "Yurt Dışı / Sağlık Turizmi", color: "green", reason: "All-on-4 Londra paketi" }], active: 1, created_at: t0 },
      { id: 5, clinic_id: 2, phone: "905357778899", display_name: "Murat Çelik", lang: "tr", channel: "wa", first_source: "phone", last_source: "whatsapp", primary_doctor_id: 4, groups: [], active: 1, created_at: t0 },
      { id: 6, clinic_id: 3, phone: "905361112233", display_name: "Mehmet Öz (Ankara)", lang: "tr", channel: "wa", first_source: "referral", last_source: "whatsapp", primary_doctor_id: 5, groups: [], active: 1, created_at: t0 },
      { id: 7, clinic_id: 3, phone: "905374445566", display_name: "Zehra Ak (Ankara)", lang: "tr", channel: "wa", first_source: "instagram", last_source: "whatsapp", primary_doctor_id: 5, groups: [], active: 1, created_at: t0 },
      { id: 8, clinic_id: 1, phone: "4915123456789", display_name: "Örnek Demo · Lukas Weber (Berlin)", lang: "de", channel: "wa", first_source: "google_ads", last_source: "whatsapp", primary_doctor_id: 1, groups: [{ id: 2, name: "Yurt Dışı / Sağlık Turizmi", color: "green", reason: "Zirkonyum 20 diş" }], active: 1, created_at: t0 },
      { id: 9, clinic_id: 1, phone: "971501234567", display_name: "Örnek Demo · Fatima Al-Mansoor (Dubai)", lang: "ar", channel: "wa", first_source: "instagram", last_source: "whatsapp", primary_doctor_id: 2, groups: [{ id: 2, name: "Yurt Dışı / Sağlık Turizmi", color: "green", reason: "Hollywood Smile E-max" }], active: 1, created_at: t0 },
      { id: 10, clinic_id: 1, phone: "905322010010", display_name: "Örnek Demo · Burak Demirtaş", lang: "tr", channel: "wa", first_source: "patient_referral", last_source: "whatsapp", primary_doctor_id: 1, groups: [{ id: 3, name: "İmplant Takip", color: "teal", reason: "Sol alt 36-37 implant" }], active: 1, created_at: t0 },
      { id: 11, clinic_id: 1, phone: "905322010011", display_name: "Örnek Demo · Elif Naz Şahin", lang: "tr", channel: "wa", first_source: "tiktok", last_source: "whatsapp", primary_doctor_id: 2, groups: [{ id: 4, name: "Ortodonti Takip", color: "teal", reason: "Şeffaf plak seans 4" }], active: 1, created_at: t0 },
      { id: 12, clinic_id: 1, phone: "905322010012", display_name: "Örnek Demo · Caner Karadağ", lang: "tr", channel: "wa", first_source: "google", last_source: "phone", primary_doctor_id: 1, groups: [], active: 1, created_at: t0 },
      { id: 13, clinic_id: 1, phone: "905322010013", display_name: "Örnek Demo · Derya Soylu", lang: "tr", channel: "wa", first_source: "doctor_referral", last_source: "whatsapp", primary_doctor_id: 2, groups: [{ id: 1, name: "VIP / Sadık Hasta", color: "teal", reason: "Hekim yönlendirmesi" }], active: 1, created_at: t0 },
      { id: 14, clinic_id: 1, phone: "79161234567", display_name: "Örnek Demo · Elena Sokolova (Moscow)", lang: "ru", channel: "wa", first_source: "website", last_source: "whatsapp", primary_doctor_id: 2, groups: [{ id: 2, name: "Yurt Dışı / Sağlık Turizmi", color: "green", reason: "Lamine 12 diş" }], active: 1, created_at: t0 },
      { id: 15, clinic_id: 1, phone: "905322010015", display_name: "Örnek Demo · Hakan Koçak", lang: "tr", channel: "wa", first_source: "walk_in", last_source: "phone", primary_doctor_id: 1, groups: [], active: 1, created_at: t0 },
      { id: 16, clinic_id: 1, phone: "905322010016", display_name: "Örnek Demo · Merve Aydınlı", lang: "tr", channel: "ig", first_source: "instagram_dm", last_source: "instagram_dm", primary_doctor_id: 2, groups: [], active: 1, created_at: t0 },
      { id: 17, clinic_id: 1, phone: "905322010017", display_name: "Örnek Demo · Serkan Öztürk", lang: "tr", channel: "wa", first_source: "facebook", last_source: "whatsapp", primary_doctor_id: 1, groups: [{ id: 6, name: "Ödeme Planı Takibi", color: "amber", reason: "3 taksitli implant planı" }], active: 1, created_at: t0 },
      { id: 18, clinic_id: 1, phone: "33612345678", display_name: "Örnek Demo · Claire Dubois (Paris)", lang: "fr", channel: "wa", first_source: "google_ads", last_source: "whatsapp", primary_doctor_id: 2, groups: [{ id: 2, name: "Yurt Dışı / Sağlık Turizmi", color: "green", reason: "Zirkonyum + Beyazlatma" }], active: 1, created_at: t0 },
      { id: 19, clinic_id: 1, phone: "31612345678", display_name: "Örnek Demo · Jan van Dijk (Amsterdam)", lang: "nl", channel: "wa", first_source: "campaign_form", last_source: "whatsapp", primary_doctor_id: 1, groups: [{ id: 2, name: "Yurt Dışı / Sağlık Turizmi", color: "green", reason: "All-on-6 üst çene" }], active: 1, created_at: t0 },
      { id: 20, clinic_id: 1, phone: "905322010020", display_name: "Örnek Demo · Gökhan Erdem", lang: "tr", channel: "wa", first_source: "corporate", last_source: "whatsapp", primary_doctor_id: 1, groups: [], active: 1, created_at: t0 },
      { id: 21, clinic_id: 1, phone: "905322010021", display_name: "Örnek Demo · Pınar Yalçın", lang: "tr", channel: "wa", first_source: "qr", last_source: "whatsapp", primary_doctor_id: 2, groups: [], active: 1, created_at: t0 },
      { id: 22, clinic_id: 1, phone: "905322010022", display_name: "Örnek Demo · Tolga Kılıç", lang: "tr", channel: "wa", first_source: "returning", last_source: "whatsapp", primary_doctor_id: 1, groups: [{ id: 1, name: "VIP / Sadık Hasta", color: "teal", reason: "2023'ten beri kayıtlı" }], active: 1, created_at: t0 },
      { id: 23, clinic_id: 1, phone: "905322010023", display_name: "Örnek Demo · Yasemin Bozkurt", lang: "tr", channel: "wa", first_source: "instagram", last_source: "whatsapp", primary_doctor_id: 2, groups: [], active: 1, created_at: t0 },
      { id: 24, clinic_id: 1, phone: "905322010024", display_name: "Örnek Demo · Emre Çetinkaya", lang: "tr", channel: "wa", first_source: "whatsapp_direct", last_source: "whatsapp", primary_doctor_id: 1, groups: [], active: 1, created_at: t0 }
    ];

    const treatment_catalog = [
      { id: 1, clinic_id: 1, code: "MUAY-01", name: "İlk Diş Hekimi Muayenesi & Panoramik Planlama", category: "Teşhis", default_price: 1500, default_status: "treated" },
      { id: 2, clinic_id: 1, code: "DOL-101", name: "Kompozit Estetik Dolgu (Tek Yüzey)", category: "Restoratif", default_price: 3200, default_status: "filling" },
      { id: 3, clinic_id: 1, code: "KAN-201", name: "Kanal Tedavisi (Endodonti - Tek/Çok Kök)", category: "Endodonti", default_price: 6500, default_status: "root_canal" },
      { id: 4, clinic_id: 1, code: "IMP-301", name: "Straumann Kemik Seviyesi İmplant Cerrahisi", category: "Cerrahi", default_price: 22000, default_status: "implant" },
      { id: 5, clinic_id: 1, code: "ZIR-401", name: "Monolitik Zirkonyum Kron / Üst Yapı", category: "Protez", default_price: 8500, default_status: "crown" },
      { id: 6, clinic_id: 1, code: "CEK-501", name: "Yirmi Yaş Gömülü Diş Cerrahi Çekimi", category: "Cerrahi", default_price: 5500, default_status: "extraction" },
      { id: 7, clinic_id: 1, code: "PER-601", name: "Subgingival Küretaj & Periodontal Tedavi", category: "Periodontoloji", default_price: 4800, default_status: "treated" }
    ];

    const tooth_records = [
      { id: 1, clinic_id: 1, patient_id: 1, tooth_fdi: 16, surface: "O", status: "filling", procedure_code: "DOL-101", procedure_name: "Kompozit Estetik Dolgu", amount_kurus: 320000, gross_amount_kurus: 320000, discount_kurus: 0, doctor_id: 1, doctor_name: "Dt. Onur Aksoy", note: "Örnek Demo Verisi · Oklüzal kompozit", created_at: t0 },
      { id: 2, clinic_id: 1, patient_id: 1, tooth_fdi: 38, surface: "FULL", status: "extraction", procedure_code: "CEK-501", procedure_name: "Yirmi Yaş Cerrahi Çekim", amount_kurus: 450000, gross_amount_kurus: 450000, discount_kurus: 0, doctor_id: 1, doctor_name: "Dt. Onur Aksoy", note: "Örnek Demo Verisi · Cerrahi çekim", created_at: t0 },
      { id: 3, clinic_id: 1, patient_id: 1, tooth_fdi: 26, surface: "FULL", status: "planned", procedure_code: "ZIR-401", procedure_name: "Zirkonyum Kron Planı", amount_kurus: 850000, gross_amount_kurus: 850000, discount_kurus: 0, doctor_id: 2, doctor_name: "Dt. Elif Yıldız", note: "Örnek Demo Verisi · Planlanan (borç oluşturmaz)", created_at: t0 },
      { id: 4, clinic_id: 1, patient_id: 2, tooth_fdi: 36, surface: "FULL", status: "implant", procedure_code: "IMP-301", procedure_name: "Straumann İmplant + Zirkonyum", amount_kurus: 1850000, gross_amount_kurus: 1850000, discount_kurus: 0, doctor_id: 1, doctor_name: "Dt. Onur Aksoy", note: "Örnek Demo Verisi · Tamamlandı", created_at: t0 }
    ];

    const periodontal_exams = [
      { id: 1, clinic_id: 1, patient_id: 1, doctor_id: 1, exam_date: t0.slice(0, 10), mean_pd: 3.5, max_pd: 5, bleeding_index_pct: 33.3, plaque_index_pct: 33.3, doctor_approved: 1, note: "Örnek Demo Verisi · 16 nolu dişte 5mm cep gözlendi", created_at: t0 }
    ];

    const lab_orders = [
      { id: 1, clinic_id: 1, patient_id: 2, patient_name: "Ahmet Yılmaz", doctor_id: 1, doctor_name: "Dt. Onur Aksoy", tooth_fdi: 36, lab_name: "Örnek Demo · Ege Dijital Dental Lab", work_type: "Zirkonyum İmplant Üst Yapı", procedure_type: "Zirkonyum İmplant Üst Yapı", shade: "A2", shade_color: "A2", sent_at: t0.slice(0, 10), due_date: todayAt(12, 0, 3).slice(0, 10), cost_try: 3200, status: "in_rehearsal", note: "Örnek Demo Verisi · Metal desteksiz prova", created_at: t0 },
      { id: 2, clinic_id: 1, patient_id: 3, patient_name: "Selin Arslan", doctor_id: 2, doctor_name: "Dt. Elif Yıldız", tooth_fdi: 11, lab_name: "Örnek Demo · Boğaziçi Seramik Lab", work_type: "E-max Lamine x6", procedure_type: "E-max Lamine x6", shade: "BL2", shade_color: "BL2", sent_at: t0.slice(0, 10), due_date: todayAt(12, 0, 2).slice(0, 10), cost_try: 9600, status: "sent", note: "Örnek Demo Verisi · Dijital gülüş tasarımı", created_at: t0 }
    ];

    const implant_records = [
      { id: 1, clinic_id: 1, patient_id: 2, patient_name: "Ahmet Yılmaz", doctor_id: 1, doctor_name: "Dt. Onur Aksoy", tooth_fdi: 36, brand: "Straumann", model: "BLT SLA Roxolid", diameter_mm: 4.1, length_mm: 10.0, lot_number: "STR-2026-8841", barcode_udi: "07613327194821", uts_barcode: "07613327194821", expiry_date: "2029-06-30", supplier: "Örnek Demo Distribütör", uts_notification_status: "not_connected_prepared", created_at: t0 }
    ];

    const anamnesis = [
      { id: 1, patient_id: 1, answers: { kan_sulandirici: "evet", diyabet: "evet", ilaclar: "Coraspin 100mg" }, red_flags: ["kan_sulandirici", "diyabet"], signer_name: "Ayşe Kaya", signed_at: t0 }
    ];

    const consents = [
      { id: 1, patient_id: 1, kind: "saglik_verisi_acik_riza", text_version: "2026-11", channel: "web_form", granted_at: t0, revoked_at: null }
    ];

    const treatment_consents = [
      { id: 1, clinic_id: 1, patient_id: 1, token: "demo-tc-token-1", document_version: "2026-11-v1", signer_name: "Ayşe Kaya", status: "signed", signed_at: t0, total_amount_try: 7700, created_at: t0 }
    ];

    const appointments = [
      { id: 1, clinic_id: 1, patient_id: 2, starts_at: todayAt(10, 0, 0), duration_min: 45, treatment: "İmplant Kontrol", chair: "1", doctor_id: 1, status: "confirmed", source: "whatsapp_ai", created_at: t0 },
      { id: 2, clinic_id: 1, patient_id: 1, starts_at: todayAt(11, 30, 0), duration_min: 60, treatment: "Yirmi Yaş Cerrahi Çekim", chair: "1", doctor_id: 1, status: "booked", source: "panel", created_at: t0 },
      { id: 3, clinic_id: 1, patient_id: 3, starts_at: todayAt(14, 0, 0), duration_min: 45, treatment: "Zirkonyum Prova", chair: "2", doctor_id: 2, status: "confirmed", source: "instagram_ai", created_at: t0 },
      { id: 4, clinic_id: 1, patient_id: 4, starts_at: todayAt(15, 30, 0), duration_min: 60, treatment: "All-on-4 Ön Değerlendirme", chair: "3", doctor_id: 1, status: "confirmed", source: "whatsapp_ai", created_at: t0 },
      { id: 5, clinic_id: 1, patient_id: 8, starts_at: todayAt(10, 30, 1), duration_min: 60, treatment: "Örnek Demo · Zirkonyum Ölçü Seansı", chair: "2", doctor_id: 2, status: "booked", source: "whatsapp_ai", created_at: t0 },
      { id: 6, clinic_id: 2, patient_id: 5, starts_at: todayAt(13, 0, 0), duration_min: 30, treatment: "Kanal Tedavisi", chair: "1", doctor_id: 4, status: "confirmed", source: "panel", created_at: t0 },
      { id: 7, clinic_id: 3, patient_id: 6, starts_at: todayAt(11, 0, 0), duration_min: 45, treatment: "Estetik Lamine Prova", chair: "1", doctor_id: 5, status: "confirmed", source: "panel", created_at: t0 },
      { id: 8, clinic_id: 3, patient_id: 7, starts_at: todayAt(13, 0, 0), duration_min: 30, treatment: "Diş Beyazlatma", chair: "2", doctor_id: 5, status: "booked", source: "whatsapp_ai", created_at: t0 }
    ];

    const waitlist = [
      { id: 1, patient_id: 3, treatment: "Zirkonyum", earliest: t0, active: 1, created_at: t0 },
      { id: 2, patient_id: 4, treatment: "herhangi", earliest: t0, active: 1, created_at: t0 }
    ];

    const slot_offers = [
      { id: 1, appointment_id: 2, waitlist_id: 1, patient_id: 3, patient: "Selin Arslan", starts_at: todayAt(16, 30, 0), treatment: "Zirkonyum Prova", chair: "2", wave: 1, status: "sent", sent_at: t0 }
    ];

    const inventory_items = [
      { id: 1, clinic_id: 1, name: "Straumann Kemik Seviyesi İmplant 4.1x10", sku: "STR-4110", category: "İmplant", unit: "adet", qty: 2, min_qty: 5, unit_cost_kurus: 420000, supplier: "Straumann TR", lot_number: "STR-2026-8841", expiry_date: "2029-06-30", warehouse: "Ana Depo", active: 1, created_at: t0 },
      { id: 2, clinic_id: 1, name: "3M Filtek Ultimate Kompozit A2", sku: "3M-A2", category: "Sarf Malzeme", unit: "tüp", qty: 14, min_qty: 4, unit_cost_kurus: 115000, supplier: "Örnek Dental Medikal", lot_number: "3M-9912", expiry_date: "2028-11-01", warehouse: "Ana Depo", active: 1, created_at: t0 },
      { id: 3, clinic_id: 3, name: "Ivoclar IPS e.max Press Blok", sku: "EMAX-A1", category: "Protez", unit: "adet", qty: 6, min_qty: 3, unit_cost_kurus: 240000, supplier: "Ivoclar TR", lot_number: "IV-2026", expiry_date: "2029-01-15", warehouse: "Ana Depo", active: 1, created_at: t0 }
    ];

    const stock_moves = [
      { id: 1, item_id: 1, delta: 2, qty_after: 2, reason: "İlk stok", move_type: "in", actor_id: 1, created_at: t0 },
      { id: 2, item_id: 2, delta: 14, qty_after: 14, reason: "Satın alma", move_type: "in", actor_id: 1, created_at: t0 },
      { id: 3, item_id: 3, delta: 6, qty_after: 6, reason: "İlk stok", move_type: "in", actor_id: 5, created_at: t0 }
    ];

    const charges = [
      { id: 1, clinic_id: 1, patient_id: 1, description: "Cerrahi Çekim + Panoramik Görüntüleme", amount_kurus: 450000, gross_amount_kurus: 450000, discount_kurus: 0, doctor_id: 1, doctor_name: "Dt. Onur Aksoy", created_by: 1, created_at: t0, voided_at: null, void_reason: null },
      { id: 2, clinic_id: 1, patient_id: 2, description: "İmplant Üst Yapı + Zirkonyum Kron x2", amount_kurus: 1850000, gross_amount_kurus: 1850000, discount_kurus: 0, doctor_id: 1, doctor_name: "Dt. Onur Aksoy", created_by: 1, created_at: t0, voided_at: null, void_reason: null },
      { id: 3, clinic_id: 1, patient_id: 8, description: "Örnek Demo · Zirkonyum Gülüş Tasarımı Ön Paket", amount_kurus: 3200000, gross_amount_kurus: 3400000, discount_kurus: 200000, doctor_id: 2, doctor_name: "Dt. Elif Yıldız", created_by: 2, created_at: t0, voided_at: null, void_reason: null },
      { id: 4, clinic_id: 3, patient_id: 6, description: "E-max Lamine x4", amount_kurus: 2400000, gross_amount_kurus: 2400000, discount_kurus: 0, doctor_id: 5, doctor_name: "Dt. Zeynep Demir", created_by: 5, created_at: t0, voided_at: null, void_reason: null }
    ];

    const payments = [
      { id: 1, clinic_id: 1, patient_id: 2, amount_kurus: 1850000, method: "kart", status: "completed", is_advance: 0, created_by: 1, created_at: t0, voided_at: null, void_reason: null },
      { id: 2, clinic_id: 1, patient_id: 8, amount_kurus: 2000000, method: "havale", status: "completed", is_advance: 0, created_by: 1, created_at: t0, voided_at: null, void_reason: null },
      { id: 3, clinic_id: 3, patient_id: 6, amount_kurus: 1200000, method: "kart", status: "completed", is_advance: 0, created_by: 5, created_at: t0, voided_at: null, void_reason: null }
    ];

    const suppliers = [
      { id: 1, clinic_id: 1, name: "Örnek Demo · Ege Dijital Dental Laboratuvarı", category: "Laboratuvar", contact_person: "Kaan Bey", phone: "+90 216 444 00 11", balance_try: 12800 },
      { id: 2, clinic_id: 1, name: "Örnek Demo · Straumann Türkiye Distribütörü", category: "İmplant & Cerrahi", contact_person: "Merve Hanım", phone: "+90 212 333 00 22", balance_try: 0 }
    ];

    const expenses = [
      { id: 1, clinic_id: 1, supplier_id: 1, supplier_name: "Örnek Demo · Ege Dijital Dental Laboratuvarı", category: "laboratuvar", description: "Örnek Demo · Zirkonyum & E-max Lab Faturası", amount_try: 12800, method: "havale", paid_at: t0.slice(0, 10), created_at: t0 }
    ];

    const cash_closings = [
      { id: 1, clinic_id: 1, closing_date: t0.slice(0, 10), total_in_try: 38500, total_out_try: 12800, closing_balance_try: 25700, physical_counted_try: 25700, diff_try: 0, note: "Örnek Demo Verisi · Gün sonu tam mutabakat" }
    ];

    const alerts = [
      { id: 1, clinic_id: 1, patient_id: 1, kind: "anamnez_kirmizi", detail: "KIRMIZI BAYRAK: Ayşe Kaya (#1) bugünkü randevusu öncesi kan_sulandirici + diyabet bildirdi.", created_at: t0, acknowledged_at: null },
      { id: 2, clinic_id: 1, patient_id: null, kind: "stok_kritik", detail: "Stok kritik seviyede: Straumann Kemik Seviyesi İmplant 4.1x10 (2 adet, alt sınır 5)", created_at: t0, acknowledged_at: null },
      { id: 3, clinic_id: 3, patient_id: 6, kind: "gorsel_alindi", detail: "Mehmet Öz (#6) gülüş tasarımı ön fotoğrafı yükledi.", created_at: t0, acknowledged_at: null }
    ];

    const message_templates = [
      { id: 1, clinic_id: 1, name: "randevu_hatirlatma", channel: "whatsapp", lang: "tr", category: "UTILITY", body: "Sayın {{1}}, yarın saat {{2}} için kliniğimizde randevunuz vardır. Onay için 1 yazınız.", status: "APPROVED", created_at: t0 },
      { id: 2, clinic_id: 1, name: "bekleme_listesi_teklif", channel: "whatsapp", lang: "tr", category: "UTILITY", body: "Bugün saat {{1}} için {{2}} koltuğunda yer açıldı. Almak için EVET yazınız.", status: "APPROVED", created_at: t0 },
      { id: 3, clinic_id: 3, name: "randevu_hatirlatma", channel: "whatsapp", lang: "tr", category: "UTILITY", body: "Sayın {{1}}, yarın saat {{2}} Ankara Çankaya şubemizde randevunuz vardır.", status: "APPROVED", created_at: t0 }
    ];

    const campaigns = [
      { id: 1, clinic_id: 1, code: "META-IMP-2026", name: "ÖRNEK VERİ · İstanbul İmplant & Zirkonyum Meta Kampanyası", source: "meta_ads", channel: "instagram", budget_try: 25000, clicks: 420, unique_clicks: 380, bot_clicks: 22, duplicate_clicks: 18, conversations: 86, leads_count: 86, appointments_booked: 24, attended_appointments: 19, completed_treatments: 14, revenue_kurus: 14800000, collected_revenue_try: 148000, is_sample: 1, created_at: t0 },
      { id: 2, clinic_id: 1, code: "GADS-SMILE-EU", name: "ÖRNEK VERİ · Avrupa Sağlık Turizmi Google Ads Kampanyası", source: "google_ads", channel: "google_ads", budget_try: 35000, clicks: 310, unique_clicks: 285, bot_clicks: 15, duplicate_clicks: 10, conversations: 52, leads_count: 52, appointments_booked: 16, attended_appointments: 14, completed_treatments: 11, revenue_kurus: 21500000, collected_revenue_try: 215000, is_sample: 1, created_at: t0 }
    ];

    const message_log = [];
    let mid = 1;
    for (let dOff = 0; dOff < 14; dOff++) {
      const tsDay = new Date(now.getTime() - dOff * 86400000).toISOString();
      const cnt = 3 + ((14 - dOff) % 5);
      for (let k = 0; k < cnt; k++) {
        message_log.push({ id: mid++, clinic_id: 1, patient_id: 2, direction: "in", layer: null, intent: "wa:text", body: "İmplant kontrol randevum ve konum bilgisi nedir?", delivery_status: "received", tokens_in: 0, tokens_out: 0, created_at: tsDay });
        message_log.push({ id: mid++, clinic_id: 1, patient_id: 2, direction: "out", layer: "L1-sss", intent: "konum", body: "Merhabalar, Bağdat Cad. No:142 Kadıköy adresindeyiz.", delivery_status: "dry_run", tokens_in: 0, tokens_out: 0, created_at: tsDay });
      }
    }
    message_log.push({ id: mid++, clinic_id: 1, patient_id: 4, direction: "out", layer: "L3-ana-model", intent: "genel", body: "Hello Oliver, your All-on-4 consultation is confirmed.", delivery_status: "dry_run", tokens_in: 140, tokens_out: 85, created_at: t0 });

    const audit_log = [
      { id: 1, clinic_id: 1, ts: t0, actor_id: null, actor: "system", action: "clinic.bootstrap", target: "clinic:1,clinic:2", meta: "{}", prev_hash: "0000000000000000", hash: "a94f82e17c3b50129d8e41fa7b23c901" },
      { id: 2, clinic_id: 3, ts: t0, actor_id: 5, actor: "klinik@ankaradis.com", action: "clinic.seed", target: "clinic:3", meta: "{}", prev_hash: "a94f82e17c3b50129d8e41fa7b23c901", hash: "f31c60b82e149a77c04d2189b6e5312a" },
      { id: 3, clinic_id: 1, ts: t0, actor_id: 1, actor: "yonetici@dentacore.com", action: "auth.login", target: "clinic:1", meta: "{}", prev_hash: "f31c60b82e149a77c04d2189b6e5312a", hash: "7c8e9104b2d56f318a902e47c1184bf0" }
    ];

    return {
      clinics, staff_users, patient_groups, patients, treatment_catalog, tooth_records,
      periodontal_exams, lab_orders, implant_records, anamnesis, consents, treatment_consents,
      appointments, waitlist, slot_offers, inventory_items, stock_moves, charges, payments,
      suppliers, expenses, cash_closings, bank_agreements: [], installment_plans: [], media_files: [],
      alerts, message_templates, campaigns, message_log, audit_log
    };
  }

  let DB = buildInitialDB();
  try {
    const saved = sGet("dc_v63_cloud_db", "");
    if (saved) {
      const parsed = JSON.parse(saved);
      if (parsed && Array.isArray(parsed.clinics) && parsed.clinics.length >= 3 && Array.isArray(parsed.patients) && parsed.patients.length >= 20) {
        DB = parsed;
      }
    }
  } catch (e) {}

  function saveDB() {
    try { sSet("dc_v63_cloud_db", JSON.stringify(DB)); } catch (e) {}
  }

  window.__DC_STATE = {
    loggedInUser: DB.staff_users[0],
    activeClinicId: 1,
    csrf: "dc-csrf-v63-token"
  };
  sSet("dc_has_session", "1");

  function tl(kurus) { return Math.round((Number(kurus || 0) / 100) * 100) / 100; }
  function toKurus(val) { return Math.round(Number(val || 0) * 100); }
  function maskPhone(p) {
    if (!p) return "***";
    if (String(p).startsWith("ig:")) return "Instagram";
    const d = String(p).replace(/\D/g, "");
    return d.length >= 10 ? `+${d.slice(0,2)} ${d.slice(2,3)}** *** ${d.slice(-4,-2)} ${d.slice(-2)}` : "***";
  }
  function normPhone(p) {
    let d = String(p || "").replace(/\D/g, "");
    if (d.startsWith("00")) d = d.slice(2);
    if (d.startsWith("0") && d.length === 11) d = "90" + d.slice(1);
    if (d.length === 10 && d.startsWith("5")) d = "90" + d;
    return d;
  }
  function nextId(arr) { return arr && arr.length ? Math.max(...arr.map(x => Number(x.id) || 0)) + 1 : 1; }

  function addAudit(action, target = "", meta = {}) {
    const u = window.__DC_STATE.loggedInUser;
    const cid = window.__DC_STATE.activeClinicId || 1;
    const last = DB.audit_log[DB.audit_log.length - 1];
    const prev = last ? last.hash : "0000000000000000";
    const id = nextId(DB.audit_log);
    const rawStr = `${prev}|${id}|${action}|${target}`;
    let h = 0;
    for (let i = 0; i < rawStr.length; i++) h = ((h << 5) - h + rawStr.charCodeAt(i)) | 0;
    const hex = (Math.abs(h).toString(16).padStart(8, "0") + id.toString(16).padStart(4, "0") + "9f8e7d6c5b4a").slice(0, 32);
    DB.audit_log.push({
      id, clinic_id: cid, ts: isoNow(), actor_id: u ? u.id : null,
      actor: u ? u.email : "system", action, target, meta: JSON.stringify(meta),
      prev_hash: prev, hash: hex
    });
    saveDB();
  }

  function normText(t) {
    return String(t || "").replace(/ı/g, "i").replace(/İ/g, "i").normalize("NFKD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/\s+/g, " ").trim();
  }
  function detectLang(text) {
    const raw = String(text || "").toLowerCase();
    if (/[\u0590-\u05FF]/.test(raw)) return "he";
    if (/[\u0600-\u06FF]/.test(raw)) return /[پچژگک]/.test(raw) ? "fa" : "ar";
    if (/[\u0370-\u03FF]/.test(raw)) return "el";
    if (/[\u0400-\u04FF]/.test(raw)) return /[іїєґ]/.test(raw) ? "uk" : "ru";
    if (/[əƏ]/.test(raw)) return "az";
    if (/[ğşıİĞŞ]/.test(text || "")) return "tr";
    const n = normText(text);
    if (/\b(how|much|price|where|tooth|appointment|hello)\b/.test(n)) return "en";
    if (/\b(wie|viel|kostet|zahn|termin|hallo)\b/.test(n)) return "de";
    return "tr";
  }

  function simulateRoute(text, langOverride, clinicObj) {
    const lang = (langOverride && FAQ_DATA.supported_langs.includes(langOverride)) ? langOverride : detectLang(text);
    const n = normText(text);
    const facts = { ...FAQ_DATA.facts, clinic: clinicObj.name, adres: clinicObj.address || FAQ_DATA.facts.adres, telefon: clinicObj.phone || FAQ_DATA.facts.telefon };
    const fmt = (s) => {
      let r = String(s || "");
      for (const [k, v] of Object.entries(facts)) r = r.split("{" + k + "}").join(String(v));
      return r.replace(/\.{2,}/g, ".").trim();
    };
    const pick = (tbl) => fmt((tbl && (tbl[lang] || tbl.en || tbl.tr)) || "");
    for (const [lg, pat] of Object.entries(FAQ_DATA.emergency.patterns)) {
      if (new RegExp(normText(pat)).test(n)) {
        return { answer: pick(FAQ_DATA.emergency.answers), layer: "L1-acil", intent: "acil", lang, tokens_in: 0, tokens_out: 0, alert: "acil", handoff: true };
      }
    }
    for (const [name, spec] of Object.entries(FAQ_DATA.intents)) {
      for (const [, pStr] of Object.entries(spec.patterns)) {
        if (new RegExp(normText(pStr)).test(n)) {
          return { answer: pick(spec.answers), layer: "L1-sss", intent: name, lang, tokens_in: 0, tokens_out: 0, alert: null, handoff: false };
        }
      }
    }
    for (const [k, patStr] of Object.entries(FAQ_DATA.classifier_keywords)) {
      if (new RegExp(normText(patStr)).test(n) && FAQ_DATA.templates[k]) {
        return { answer: pick(FAQ_DATA.templates[k]), layer: "L2-anahtar", intent: k, lang, tokens_in: 0, tokens_out: 0, alert: k === "sikayet" ? "sikayet" : null, handoff: true };
      }
    }
    return { answer: pick(FAQ_DATA.templates.insan), layer: "L2-şablon", intent: "genel", lang, tokens_in: 0, tokens_out: 0, alert: null, handoff: true };
  }

  const origFetch = window.fetch.bind(window);
  window.fetch = async function(input, init = {}) {
    const urlStr = typeof input === "string" ? input : (input && input.url ? input.url : "");
    let parsedUrl;
    try { parsedUrl = new URL(urlStr, window.location.origin); } catch (e) { return origFetch(input, init); }
    const path = parsedUrl.pathname;
    const qs = parsedUrl.searchParams;
    const method = (init.method || "GET").toUpperCase();
    let body = null;
    if (init.body && typeof init.body === "string") {
      try { body = JSON.parse(init.body); } catch (e) { body = null; }
    }

    const jsonResp = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
    const textResp = (txt, mime = "text/plain; charset=utf-8") => new Response(txt, { status: 200, headers: { "Content-Type": mime } });

    const u = window.__DC_STATE.loggedInUser;
    const cid = window.__DC_STATE.activeClinicId || (u ? u.clinic_id : 1);
    const curClinic = DB.clinics.find(c => c.id === cid) || DB.clinics[0];

    if (path === "/health") return jsonResp({ ok: true, mode: "cloud-static-demo", db_ok: true, wal_mode: "wal", webhook_queue_depth: 0, workers_ready: 8 });
    if (path === "/lead" && method === "POST") return jsonResp({ ok: true });

    if (path === "/auth/login" && method === "POST") {
      const em = String((body && body.email) || "").trim().toLowerCase();
      const pw = String((body && body.password) || "");
      const found = DB.staff_users.find(s => s.email.toLowerCase() === em && s.active);
      if (!found || (found.pw && found.pw !== pw)) return jsonResp({ detail: "E-posta veya parola hatalı" }, 401);
      window.__DC_STATE.loggedInUser = found;
      window.__DC_STATE.activeClinicId = found.clinic_id;
      addAudit("auth.login", `clinic:${found.clinic_id}`);
      const isHq = (found.clinic_id === 1 && found.role === "owner");
      const perms = found.permissions || DEFAULT_PERMS[found.role] || DEFAULT_PERMS.secretary;
      return jsonResp({
        ok: true, csrf: window.__DC_STATE.csrf,
        user: { id: found.id, clinic_id: found.clinic_id, email: found.email, full_name: found.full_name, role: found.role, job_title: found.job_title || found.role, permissions: perms, totp_enabled: Boolean(found.totp_enabled), is_hq: isHq }
      });
    }
    if (path === "/auth/logout" && method === "POST") {
      window.__DC_STATE.loggedInUser = null;
      return jsonResp({ ok: true });
    }
    if (path === "/auth/me") {
      if (!u) return jsonResp({ detail: "oturum yok" }, 401);
      const isHq = (u.clinic_id === 1 && u.role === "owner");
      const perms = u.permissions || DEFAULT_PERMS[u.role] || DEFAULT_PERMS.secretary;
      return jsonResp({
        csrf: window.__DC_STATE.csrf,
        user: { id: u.id, clinic_id: cid, email: u.email, full_name: u.full_name, role: u.role, job_title: u.job_title || u.role, permissions: perms, totp_enabled: Boolean(u.totp_enabled), is_hq: isHq },
        clinic: curClinic.name, clinic_id: cid, home_clinic_id: u.clinic_id, idle_seconds: 900, is_demo: true
      });
    }
    if (path === "/auth/password" && method === "POST") return jsonResp({ ok: true });
    if (path === "/auth/totp/setup" && method === "POST") return jsonResp({ secret: "JBSWY3DPEHPK3PXP", uri: "otpauth://totp/DentaCore?secret=JBSWY3DPEHPK3PXP" });
    if (path === "/auth/totp/enable" && method === "POST") return jsonResp({ ok: true });
    if (path === "/auth/sessions/revoke-all" && method === "POST") { window.__DC_STATE.loggedInUser = null; return jsonResp({ ok: true }); }

    if (path === "/app/api/demo/simulate-flow" && method === "POST") {
      const pid = nextId(DB.patients);
      const pName = `Örnek Demo Verisi · Deniz Aksoy #${pid}`;
      DB.patients.unshift({
        id: pid, clinic_id: cid, phone: `90539888${String(1000 + pid).slice(-4)}`, display_name: pName,
        lang: "tr", channel: "wa", first_source: "instagram", last_source: "whatsapp", primary_doctor_id: 1,
        groups: [{ id: 1, name: "VIP / Sadık Hasta", color: "teal", reason: "Canlı demo akışı" }], active: 1, created_at: isoNow()
      });
      const aid = nextId(DB.appointments);
      const slotIso = todayAt(16, 0, 0);
      DB.appointments.push({
        id: aid, clinic_id: cid, patient_id: pid, starts_at: slotIso, duration_min: 45,
        treatment: "Örnek Demo · İmplant & Zirkonyum Muayene", chair: "2", doctor_id: 1,
        status: "confirmed", source: "whatsapp_ai", created_at: isoNow()
      });
      saveDB();
      return jsonResp({
        ok: true, patient_id: pid, patient_name: pName, appointment_id: aid, slot: "Bugün 16:00 (Koltuk 2)",
        steps: [
          "1. Meta Reklam Tıklaması ([Ref: META-IMP-2026]) algılandı ve ilk kaynak kilitlendi",
          "2. WhatsApp AI L1 yönlendirici <50ms içinde 0 token ile yanıt verdi",
          `3. Hasta kartı (${pName}) ve takvim koltuğu (16:00 K2) otomatik bağlandı`
        ]
      });
    }

    if (path === "/app/api/overview") {
      const todayYmd = new Date().toISOString().slice(0, 10);
      const appts = DB.appointments.filter(a => a.clinic_id === cid);
      const todayActive = appts.filter(a => a.starts_at.slice(0, 10) === todayYmd && ["booked", "confirmed"].includes(a.status));
      const occ = Math.round(100 * todayActive.reduce((s, a) => s + a.duration_min, 0) / Math.max(1, curClinic.chairs * curClinic.work_minutes));
      const done = appts.filter(a => a.status === "done").length || 18;
      const noshow = appts.filter(a => a.status === "noshow").length || 1;
      const validCharges = DB.charges.filter(c => c.clinic_id === cid && !c.voided_at);
      const validPays = DB.payments.filter(p => p.clinic_id === cid && !p.voided_at);
      const billed = validCharges.reduce((s, c) => s + c.amount_kurus, 0);
      const paid = validPays.reduce((s, p) => s + p.amount_kurus, 0);
      const msgs = DB.message_log.filter(m => (m.clinic_id || 1) === cid);
      const outM = msgs.filter(m => m.direction === "out");
      const free = outM.filter(m => (m.layer || "").startsWith("L1")).length;
      const series = [];
      for (let i = 13; i >= 0; i--) {
        const dObj = new Date(Date.now() - i * 86400000);
        const dYmd = dObj.toISOString().slice(0, 10);
        const lbl = `${String(dObj.getDate()).padStart(2, "0")}.${String(dObj.getMonth() + 1).padStart(2, "0")}`;
        const mc = msgs.filter(m => m.direction === "in" && m.created_at.slice(0, 10) === dYmd).length || (3 + (i % 4));
        const ac = appts.filter(a => a.starts_at.slice(0, 10) === dYmd).length || (2 + (i % 3));
        series.push({ day: lbl, msgs: mc, appts: ac });
      }
      const cPats = new Set(DB.patients.filter(p => p.clinic_id === cid).map(p => p.id));
      return jsonResp({
        today: { appointments: todayActive.length, confirmed: todayActive.filter(a => a.status === "confirmed").length, occupancy: occ },
        attendance_30d: { done, noshow, noshow_rate: Math.round(100 * noshow / Math.max(1, done + noshow)) },
        loss: { noshow_30d_try: 3500, avg_ticket_try: 3500 },
        month: { billed_try: tl(billed), paid_try: tl(paid) },
        tokens_30d: { replies: outM.length, llm_free_pct: outM.length ? Math.round(100 * free / outM.length) : 96, tokens: 225 },
        counts: {
          alerts: DB.alerts.filter(a => a.clinic_id === cid && !a.acknowledged_at).length,
          waitlist: DB.waitlist.filter(w => w.active && cPats.has(w.patient_id)).length,
          refills: 4,
          low_stock: DB.inventory_items.filter(i => i.clinic_id === cid && i.active && i.min_qty > 0 && i.qty <= i.min_qty).length,
          postop_alarms: 0
        },
        series
      });
    }

    if (path === "/app/api/appointments/available" && method === "GET") {
      const dateStr = qs.get("date") || new Date().toISOString().slice(0, 10);
      const slots = ["09:30", "10:30", "11:00", "13:30", "14:30", "15:00", "16:00", "17:00", "17:30"].map(tm => ({
        starts_at: `${dateStr}T${tm}:00`,
        time: tm,
        end_time: tm.replace(":30", ":00").replace(":00", ":30"),
        available_chairs: ["1", "2", "3"].slice(0, curClinic.chairs || 2)
      }));
      return jsonResp({ date: dateStr, duration: Number(qs.get("duration") || 30), chairs: curClinic.chairs || 2, closed: false, working_hours: ["09:00", "19:00"], slots });
    }

    if (path === "/app/api/appointments/recurring" && method === "POST") {
      const baseDt = new Date(body.starts_at || Date.now());
      const ids = [];
      for (let i = 0; i < (Number(body.occurrences) || 3); i++) {
        const dt = new Date(baseDt.getTime() + i * 7 * 86400000);
        const aid = nextId(DB.appointments);
        DB.appointments.push({
          id: aid, clinic_id: cid, patient_id: Number(body.patient_id), starts_at: dt.toISOString(),
          duration_min: Number(body.duration_min || 30), treatment: `${body.treatment} (Seans ${i + 1})`,
          chair: String(body.chair || "1"), doctor_id: body.doctor_id ? Number(body.doctor_id) : 1,
          status: "booked", source: "panel", created_at: isoNow()
        });
        ids.push(aid);
      }
      saveDB();
      return jsonResp({ ok: true, created_count: ids.length, appointment_ids: ids });
    }

    if (path === "/app/api/appointments" && method === "GET") {
      const sDt = qs.get("start") ? new Date(qs.get("start")) : new Date(0);
      const eDt = qs.get("end") ? new Date(qs.get("end")) : new Date(Date.now() + 365 * 86400000);
      const out = DB.appointments
        .filter(a => a.clinic_id === cid)
        .filter(a => { const dt = new Date(a.starts_at); return dt >= sDt && dt < eDt; })
        .sort((a, b) => new Date(a.starts_at) - new Date(b.starts_at))
        .map(a => {
          const pat = DB.patients.find(p => p.id === a.patient_id);
          const doc = DB.staff_users.find(s => s.id === a.doctor_id);
          const rf = DB.anamnesis.some(x => x.patient_id === a.patient_id && x.red_flags && x.red_flags.length > 0);
          const gStart = new Date(a.starts_at).toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
          const gEnd = new Date(new Date(a.starts_at).getTime() + a.duration_min * 60000).toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
          return {
            ...a,
            patient: pat ? pat.display_name : `Hasta #${a.patient_id}`,
            doctor: doc ? doc.full_name : null,
            red_flag: rf,
            google_cal_url: `https://calendar.google.com/calendar/render?action=TEMPLATE&text=${encodeURIComponent((pat ? pat.display_name : "Hasta") + " - " + a.treatment)}&dates=${gStart}/${gEnd}`
          };
        });
      return jsonResp(out);
    }

    if (path === "/app/api/appointments" && method === "POST") {
      let pid = body.patient_id ? Number(body.patient_id) : null;
      if (!pid) {
        const ph = normPhone(body.phone || "");
        if (ph.length < 10) return jsonResp({ detail: "Hasta seçin veya geçerli telefon girin" }, 400);
        let pat = DB.patients.find(p => p.clinic_id === cid && normPhone(p.phone) === ph);
        if (!pat) {
          pat = { id: nextId(DB.patients), clinic_id: cid, phone: ph, display_name: body.name || "Yeni Hasta", lang: "tr", channel: "wa", first_source: body.source || "phone", last_source: body.source || "phone", active: 1, created_at: isoNow() };
          DB.patients.push(pat);
        }
        pid = pat.id;
      }
      const aid = nextId(DB.appointments);
      DB.appointments.push({
        id: aid, clinic_id: cid, patient_id: pid, starts_at: body.starts_at,
        duration_min: Number(body.duration_min || 30), treatment: body.treatment,
        chair: String(body.chair || "1"), doctor_id: body.doctor_id ? Number(body.doctor_id) : 1,
        status: "booked", source: "panel", created_at: isoNow()
      });
      addAudit("appointment.create", `appointment:${aid}`, { chair: body.chair });
      return jsonResp({ id: aid, patient_id: pid });
    }

    const mApptPatch = path.match(/^\/app\/api\/appointments\/(\d+)$/);
    if (mApptPatch && method === "PATCH") {
      const aid = Number(mApptPatch[1]);
      const appt = DB.appointments.find(a => a.id === aid && a.clinic_id === cid);
      if (!appt) return jsonResp({ detail: "randevu yok" }, 404);
      Object.assign(appt, {
        starts_at: body.starts_at || appt.starts_at,
        duration_min: body.duration_min ? Number(body.duration_min) : appt.duration_min,
        chair: body.chair ? String(body.chair) : appt.chair,
        treatment: body.treatment || appt.treatment,
        doctor_id: body.doctor_id !== undefined ? body.doctor_id : appt.doctor_id
      });
      saveDB();
      return jsonResp({ ok: true, id: aid });
    }

    const mApptStatus = path.match(/^\/app\/api\/appointments\/(\d+)\/status$/);
    if (mApptStatus && method === "POST") {
      const aid = Number(mApptStatus[1]);
      const appt = DB.appointments.find(a => a.id === aid && a.clinic_id === cid);
      if (!appt) return jsonResp({ detail: "randevu yok" }, 404);
      appt.status = body.status;
      saveDB();
      if (body.status === "cancelled") return jsonResp({ ok: true, waitlist_offers: 2 });
      return jsonResp({ ok: true, status: body.status });
    }

    if (path === "/app/api/calendar-links") {
      const base = window.location.origin;
      const icsUrl = `${base}/calendar/klinik-${cid}-akisi.ics`;
      const webcalUrl = `webcal://${window.location.host || "localhost:8000"}/calendar/klinik-${cid}-akisi.ics`;
      return jsonResp({
        ics_url: icsUrl, webcal_url: webcalUrl,
        google_subscribe_url: `https://calendar.google.com/calendar/r?cid=${encodeURIComponent(webcalUrl)}`,
        iphone_guide: "Ayarlar > Takvim > Hesaplar > Hesap Ekle > Diğer > Abone Olunan Takvim Ekle kısmına webcal adresini yapıştırın.",
        android_guide: "Her randevudaki '+ Android' butonuna basarak Google Takvime ekleyin veya Google Takvim webde URL ile abone olun."
      });
    }

    if (path === "/app/api/patient-groups" && method === "GET") return jsonResp(DB.patient_groups || []);
    if (path === "/app/api/bank-agreements" && method === "GET") return jsonResp(DB.bank_agreements || []);
    if (path === "/app/api/bank-agreements" && method === "POST") {
      if (!DB.bank_agreements) DB.bank_agreements = [];
      const bid = nextId(DB.bank_agreements);
      DB.bank_agreements.push({ id: bid, clinic_id: cid, bank_name: body.bank_name, card_family: body.card_family || "", discount_pct: Number(body.discount_pct || 0), max_installments: Number(body.max_installments || 1), commission_pct: Number(body.commission_pct || 0), active: 1 });
      saveDB();
      return jsonResp({ id: bid });
    }
    if (path === "/app/api/treatment-catalog" && method === "GET") return jsonResp(DB.treatment_catalog || []);

    if (path === "/app/api/patients/check-duplicate" && method === "GET") {
      const ph = normPhone(qs.get("phone") || "");
      const found = DB.patients.find(p => p.clinic_id === cid && normPhone(p.phone) === ph);
      return jsonResp({ duplicate: Boolean(found), patient: found ? { id: found.id, display_name: found.display_name } : null });
    }

    if (path === "/app/api/patients/import-csv" && method === "POST") {
      const lines = String((body && body.csv_text) || "").split(/\r?\n/).map(l => l.trim()).filter(Boolean);
      let imported = 0, duplicates = 0;
      lines.forEach((ln, idx) => {
        if (idx === 0 && ln.toLowerCase().includes("telefon")) return;
        const parts = ln.split(",");
        if (parts.length < 2) return;
        const ph = normPhone(parts[1]);
        if (DB.patients.some(p => p.clinic_id === cid && normPhone(p.phone) === ph)) { duplicates++; return; }
        DB.patients.push({
          id: nextId(DB.patients), clinic_id: cid, phone: ph, display_name: parts[0].trim(),
          first_source: (parts[2] || "other").trim(), last_source: (parts[2] || "other").trim(),
          lang: (parts[3] || "tr").trim(), channel: "wa", active: 1, created_at: isoNow()
        });
        imported++;
      });
      saveDB();
      return jsonResp({ ok: true, imported, duplicates, errors_count: 0 });
    }

    if (path === "/app/api/patients" && method === "GET") {
      const s = (qs.get("search") || "").trim().toLowerCase();
      const gid = qs.get("group_id") || "";
      const src = qs.get("source") || "";
      const out = DB.patients
        .filter(p => p.clinic_id === cid && p.active !== 0)
        .filter(p => !s || (p.display_name || "").toLowerCase().includes(s) || (p.phone || "").includes(s))
        .filter(p => !src || p.first_source === src || p.last_source === src)
        .filter(p => !gid || (p.groups || []).some(g => String(g.id) === String(gid)))
        .sort((a, b) => b.id - a.id)
        .map(p => {
          const billed = DB.charges.filter(c => c.patient_id === p.id && !c.voided_at).reduce((acc, c) => acc + c.amount_kurus, 0);
          const paid = DB.payments.filter(y => y.patient_id === p.id && !y.voided_at && (y.status || "completed") === "completed").reduce((acc, y) => acc + y.amount_kurus, 0);
          const plannedK = (DB.tooth_records || []).filter(r => r.patient_id === p.id && r.status === "planned").reduce((acc, r) => acc + (r.amount_kurus || 0), 0);
          const rf = DB.anamnesis.some(a => a.patient_id === p.id && a.red_flags && a.red_flags.length > 0);
          const pAppts = DB.appointments.filter(a => a.patient_id === p.id).sort((a, b) => new Date(b.starts_at) - new Date(a.starts_at));
          const doc = DB.staff_users.find(d => d.id === p.primary_doctor_id);
          const fSrc = p.first_source || "whatsapp";
          const lSrc = p.last_source || fSrc;
          return {
            id: p.id, display_name: p.display_name, lang: p.lang, channel: p.channel,
            first_source: fSrc, first_source_label: SOURCE_LABELS[fSrc] || fSrc,
            last_source: lSrc, last_source_label: SOURCE_LABELS[lSrc] || lSrc,
            primary_doctor_id: p.primary_doctor_id || null,
            primary_doctor_name: doc ? doc.full_name : "-",
            groups: p.groups || [],
            balance: Math.max(0, tl(billed - paid)),
            planned_total: tl(plannedK),
            red_flag: rf,
            last_appt: pAppts[0] ? pAppts[0].starts_at : null
          };
        });
      return jsonResp(out);
    }

    if (path === "/app/api/patients" && method === "POST") {
      const ph = normPhone(body.phone || "");
      if (ph.length < 10) return jsonResp({ detail: "Geçerli telefon girin" }, 400);
      const exPat = DB.patients.find(p => p.clinic_id === cid && normPhone(p.phone) === ph);
      if (exPat) return jsonResp({ id: exPat.id, duplicate: true, existing_name: exPat.display_name });
      const pid = nextId(DB.patients);
      const fSrc = body.first_source || "phone";
      DB.patients.push({
        id: pid, clinic_id: cid, phone: ph, display_name: body.name,
        lang: body.lang || "tr", channel: "wa", first_source: fSrc, last_source: fSrc,
        primary_doctor_id: body.primary_doctor_id || 1, groups: [], active: 1, created_at: isoNow()
      });
      addAudit("patient.create", `patient:${pid}`);
      return jsonResp({ id: pid, duplicate: false });
    }

    const mPatGet = path.match(/^\/app\/api\/patients\/(\d+)$/);
    if (mPatGet && method === "GET") {
      const pid = Number(mPatGet[1]);
      const reveal = qs.get("reveal") === "true";
      const p = DB.patients.find(x => x.id === pid && x.clinic_id === cid);
      if (!p) return jsonResp({ detail: "hasta yok" }, 404);
      const ch = DB.charges.filter(c => c.patient_id === pid).map(c => ({ ...c, amount: tl(c.amount_kurus), discount: tl(c.discount_kurus || 0) }));
      const py = DB.payments.filter(y => y.patient_id === pid).map(y => ({ ...y, amount: tl(y.amount_kurus), status: y.status || "completed" }));
      const billedGross = DB.charges.filter(c => c.patient_id === pid && !c.voided_at).reduce((acc, c) => acc + (c.gross_amount_kurus || c.amount_kurus), 0);
      const discTotal = DB.charges.filter(c => c.patient_id === pid && !c.voided_at).reduce((acc, c) => acc + (c.discount_kurus || 0), 0);
      const billedNet = DB.charges.filter(c => c.patient_id === pid && !c.voided_at).reduce((acc, c) => acc + c.amount_kurus, 0);
      const paid = DB.payments.filter(y => y.patient_id === pid && !y.voided_at && (y.status || "completed") === "completed").reduce((acc, y) => acc + y.amount_kurus, 0);
      const plannedK = (DB.tooth_records || []).filter(r => r.patient_id === pid && r.status === "planned").reduce((acc, r) => acc + (r.amount_kurus || 0), 0);
      const doc = DB.staff_users.find(d => d.id === p.primary_doctor_id);
      const fSrc = p.first_source || "whatsapp";
      const lSrc = p.last_source || fSrc;
      return jsonResp({
        id: p.id, name: p.display_name, display_name: p.display_name, lang: p.lang, channel: p.channel,
        active: p.active !== 0,
        first_source: fSrc, first_source_label: SOURCE_LABELS[fSrc] || fSrc,
        last_source: lSrc, last_source_label: SOURCE_LABELS[lSrc] || lSrc,
        primary_doctor_id: p.primary_doctor_id || null,
        primary_doctor_name: doc ? doc.full_name : "Atanmadı",
        created_at: p.created_at, created_by_name: "Dt. Onur Aksoy",
        groups: p.groups || [],
        phone: reveal ? p.phone : maskPhone(p.phone),
        tel_href: `tel:+${normPhone(p.phone)}`,
        balance: Math.max(0, tl(billedNet - paid)),
        finance_summary: {
          planned_total: tl(plannedK),
          completed_gross: tl(billedGross),
          discount_total: tl(discTotal),
          completed_net_debt: tl(billedNet),
          collected_paid: tl(paid),
          pending_payment: 0,
          failed_payment: 0,
          refunded_total: 0,
          available_advance: Math.max(0, tl(paid - billedNet)),
          net_remaining_debt: Math.max(0, tl(billedNet - paid))
        },
        appointments: DB.appointments.filter(a => a.patient_id === pid).sort((a, b) => new Date(b.starts_at) - new Date(a.starts_at)),
        charges: ch, payments: py,
        periodontal_exams: (DB.periodontal_exams || []).filter(pe => pe.patient_id === pid),
        lab_orders: (DB.lab_orders || []).filter(lo => lo.patient_id === pid),
        implant_records: (DB.implant_records || []).filter(ir => ir.patient_id === pid),
        media_files: (DB.media_files || []).filter(mf => mf.patient_id === pid),
        treatment_consents: (DB.treatment_consents || []).filter(tc => tc.patient_id === pid),
        anamnesis: DB.anamnesis.filter(a => a.patient_id === pid),
        consents: DB.consents.filter(c => c.patient_id === pid),
        timeline: [
          { ts: p.created_at, title: "Hasta Kartı Oluşturuldu", detail: `İlk Kaynak: ${SOURCE_LABELS[fSrc] || fSrc} (Değiştirilemez kilitli)` }
        ],
        anamnesis_links: {}
      });
    }
    if (mPatGet && method === "PATCH") {
      const pid = Number(mPatGet[1]);
      const p = DB.patients.find(x => x.id === pid && x.clinic_id === cid);
      if (!p) return jsonResp({ detail: "hasta yok" }, 404);
      if (body.name) p.display_name = body.name;
      if (body.lang) p.lang = body.lang;
      if (body.primary_doctor_id !== undefined) p.primary_doctor_id = body.primary_doctor_id;
      if (body.last_source) p.last_source = body.last_source;
      if (body.first_source && body.manual_first_source_change) p.first_source = body.first_source;
      saveDB();
      return jsonResp({ ok: true });
    }

    const mPatGrp = path.match(/^\/app\/api\/patients\/(\d+)\/groups$/);
    if (mPatGrp && method === "POST") {
      const pid = Number(mPatGrp[1]);
      const p = DB.patients.find(x => x.id === pid && x.clinic_id === cid);
      const grp = (DB.patient_groups || []).find(g => g.id === Number(body.group_id));
      if (p && grp) {
        p.groups = p.groups || [];
        p.groups.push({ id: grp.id, name: grp.name, color: grp.color, reason: body.reason || "" });
        saveDB();
      }
      return jsonResp({ ok: true });
    }

    const mPatOdo = path.match(/^\/app\/api\/patients\/(\d+)\/odontogram$/);
    if (mPatOdo && method === "GET") {
      const pid = Number(mPatOdo[1]);
      const recs = (DB.tooth_records || []).filter(r => r.clinic_id === cid && r.patient_id === pid).map(r => ({
        ...r,
        amount_try: tl(r.amount_kurus || 0),
        gross_amount_try: tl(r.gross_amount_kurus || r.amount_kurus || 0),
        discount_try: tl(r.discount_kurus || 0)
      }));
      return jsonResp({
        patient_id: pid, clinic_id: cid, records: recs,
        summary: {
          total_records: recs.length,
          treated_count: recs.filter(r => ["treated","filling","implant","crown","bridge","root_canal"].includes(r.status)).length,
          planned_count: recs.filter(r => ["planned","caries","extraction","postponed"].includes(r.status)).length,
          planned_amount_try: tl(recs.filter(r => r.status === "planned").reduce((s, r) => s + (r.amount_kurus || 0), 0)),
          completed_net_try: tl(recs.filter(r => r.status !== "planned").reduce((s, r) => s + (r.amount_kurus || 0), 0)),
          discount_total_try: tl(recs.reduce((s, r) => s + (r.discount_kurus || 0), 0))
        }
      });
    }
    if (mPatOdo && method === "POST") {
      const pid = Number(mPatOdo[1]);
      const rid = nextId(DB.tooth_records);
      const grossK = toKurus(body.amount || 0);
      const discK = toKurus(body.discount || 0);
      const netK = Math.max(0, grossK - discK);
      const doc = DB.staff_users.find(d => d.id === Number(body.doctor_id || (u ? u.id : 1)));
      DB.tooth_records.unshift({
        id: rid, clinic_id: cid, patient_id: pid, tooth_fdi: Number(body.tooth_fdi),
        surface: body.surface || "FULL", status: body.status || "planned",
        procedure_code: body.procedure_code || "", procedure_name: body.procedure_name || "İşlem",
        amount_kurus: netK, gross_amount_kurus: grossK, discount_kurus: discK,
        doctor_id: doc ? doc.id : 1, doctor_name: doc ? doc.full_name : "Dt. Onur Aksoy",
        note: body.note || "", created_at: isoNow()
      });
      const billable = ["treated","filling","implant","crown","bridge","root_canal"].includes(body.status);
      if (billable && body.auto_charge !== false && netK > 0) {
        DB.charges.unshift({
          id: nextId(DB.charges), clinic_id: cid, patient_id: pid,
          description: `Diş #${body.tooth_fdi} (${body.surface || "FULL"}) - ${body.procedure_name}`,
          amount_kurus: netK, gross_amount_kurus: grossK, discount_kurus: discK,
          doctor_id: doc ? doc.id : 1, doctor_name: doc ? doc.full_name : "Dt. Onur Aksoy",
          created_by: u ? u.id : 1, created_at: isoNow(), voided_at: null
        });
      }
      saveDB();
      return jsonResp({ id: rid, billed: billable, net_try: tl(netK), discount_try: tl(discK) });
    }
    const mPatOdoItem = path.match(/^\/app\/api\/patients\/(\d+)\/odontogram\/(\d+)$/);
    if (mPatOdoItem && method === "PATCH") {
      const rid = Number(mPatOdoItem[2]);
      const rec = (DB.tooth_records || []).find(r => r.id === rid);
      if (rec && body.status) rec.status = body.status;
      saveDB();
      return jsonResp({ ok: true });
    }
    if (mPatOdoItem && method === "DELETE") {
      const rid = Number(mPatOdoItem[2]);
      DB.tooth_records = (DB.tooth_records || []).filter(r => r.id !== rid);
      saveDB();
      return jsonResp({ ok: true });
    }

    const mPatPerio = path.match(/^\/app\/api\/patients\/(\d+)\/periodontal$/);
    if (mPatPerio && method === "POST") {
      const pid = Number(mPatPerio[1]);
      DB.periodontal_exams.unshift({
        id: nextId(DB.periodontal_exams), clinic_id: cid, patient_id: pid,
        exam_date: isoNow().slice(0, 10), mean_pd: 3.4, max_pd: 5, bleeding_index_pct: 33.3, plaque_index_pct: 33.3,
        note: body.doctor_note || "", created_at: isoNow()
      });
      saveDB();
      return jsonResp({ ok: true });
    }

    const mPatTc = path.match(/^\/app\/api\/patients\/(\d+)\/treatment-consents$/);
    if (mPatTc && method === "POST") {
      const pid = Number(mPatTc[1]);
      const url = `${window.location.origin}/#tedavi-onam-${pid}`;
      return jsonResp({ ok: true, url, legal_notice_tr: "Bu onay 5070 sayılı Nitelikli Elektronik İmza değildir; zaman damgalı dijital form onayıdır." });
    }

    const mPatAnam = path.match(/^\/app\/api\/patients\/(\d+)\/anamnesis$/);
    if (mPatAnam && method === "POST") {
      const pid = Number(mPatAnam[1]);
      return jsonResp({ link: `${window.location.origin}/#anamnez-${pid}`, dry_run: true, delivery: "dry_run" });
    }

    if (path === "/app/api/lab-orders" && method === "POST") {
      const lid = nextId(DB.lab_orders);
      DB.lab_orders.unshift({
        id: lid, clinic_id: cid, patient_id: Number(body.patient_id), tooth_fdi: body.tooth_fdi,
        lab_name: body.lab_name, work_type: body.procedure_type, shade: body.shade_color || "A2",
        due_date: body.due_date, status: "sent", created_at: isoNow()
      });
      saveDB();
      return jsonResp({ id: lid });
    }
    if (path === "/app/api/implants" && method === "POST") {
      const iid = nextId(DB.implant_records);
      DB.implant_records.unshift({
        id: iid, clinic_id: cid, patient_id: Number(body.patient_id), tooth_fdi: Number(body.tooth_fdi || 36),
        brand: body.brand, model: body.model, diameter_mm: body.diameter_mm || 4.1, length_mm: body.length_mm || 10,
        lot_number: body.lot_number, barcode_udi: body.uts_barcode || "", created_at: isoNow()
      });
      saveDB();
      return jsonResp({ id: iid });
    }

    if (path === "/app/api/waitlist" && method === "GET") {
      const cPats = new Map(DB.patients.filter(p => p.clinic_id === cid).map(p => [p.id, p]));
      return jsonResp(DB.waitlist.filter(w => w.active && cPats.has(w.patient_id)).map(w => ({ ...w, patient: cPats.get(w.patient_id).display_name })));
    }
    if (path === "/app/api/waitlist" && method === "POST") {
      const wid = nextId(DB.waitlist);
      DB.waitlist.push({ id: wid, patient_id: Number(body.patient_id), treatment: body.treatment || "herhangi", earliest: isoNow(), active: 1, created_at: isoNow() });
      saveDB();
      return jsonResp({ id: wid });
    }
    if (path === "/app/api/waitlist/offers" && method === "GET") return jsonResp(DB.slot_offers || []);
    const mOfferResp = path.match(/^\/app\/api\/waitlist\/offers\/(\d+)\/respond$/);
    if (mOfferResp && method === "POST") {
      const oid = Number(mOfferResp[1]);
      const off = (DB.slot_offers || []).find(o => o.id === oid);
      if (off) off.status = body.action === "accept" ? "won" : "lost";
      saveDB();
      return jsonResp({ ok: true, status: off ? off.status : "won" });
    }
    const mWaitRm = path.match(/^\/app\/api\/waitlist\/(\d+)\/remove$/);
    if (mWaitRm && method === "POST") {
      const w = DB.waitlist.find(x => x.id === Number(mWaitRm[1]));
      if (w) w.active = 0;
      saveDB();
      return jsonResp({ ok: true });
    }

    if (path === "/app/api/alerts" && method === "GET") return jsonResp(DB.alerts.filter(a => a.clinic_id === cid && !a.acknowledged_at).sort((a, b) => b.id - a.id));
    const mAlertAck = path.match(/^\/app\/api\/alerts\/(\d+)\/ack$/);
    if (mAlertAck && method === "POST") {
      const al = DB.alerts.find(a => a.id === Number(mAlertAck[1]) && a.clinic_id === cid);
      if (al) al.acknowledged_at = isoNow();
      saveDB();
      return jsonResp({ ok: true });
    }

    if (path === "/app/api/inventory" && method === "GET") {
      return jsonResp(DB.inventory_items.filter(i => i.clinic_id === cid && i.active).map(r => {
        const uc = tl(r.unit_cost_kurus);
        return { ...r, unit_cost: uc, value: Math.round(r.qty * uc * 100) / 100, low: Boolean(r.min_qty > 0 && r.qty <= r.min_qty), expired: false };
      }));
    }
    if (path === "/app/api/inventory" && method === "POST") {
      const iid = nextId(DB.inventory_items);
      const qVal = Number(body.qty || 0);
      DB.inventory_items.push({
        id: iid, clinic_id: cid, name: body.name, sku: body.sku || "", category: body.category || "Sarf Malzeme", unit: body.unit || "adet",
        qty: qVal, min_qty: Number(body.min_qty || 0), unit_cost_kurus: toKurus(body.unit_cost || 0), supplier: body.supplier || "", lot_number: body.lot_number || "", expiry_date: body.expiry_date || "", warehouse: body.warehouse || "Ana Depo", active: 1, created_at: isoNow()
      });
      saveDB();
      return jsonResp({ id: iid });
    }
    const mInvMove = path.match(/^\/app\/api\/inventory\/(\d+)\/move$/);
    if (mInvMove && method === "POST") {
      const iid = Number(mInvMove[1]);
      const it = DB.inventory_items.find(i => i.id === iid && i.clinic_id === cid);
      if (!it) return jsonResp({ detail: "ürün yok" }, 404);
      const dVal = Number(body.delta || 0);
      if (it.qty + dVal < 0) return jsonResp({ detail: "Stok yetersiz" }, 409);
      it.qty = Math.round((it.qty + dVal) * 100) / 100;
      DB.stock_moves.unshift({ id: nextId(DB.stock_moves), item_id: iid, delta: dVal, qty_after: it.qty, reason: body.reason || "Hareket", move_type: body.move_type || (dVal > 0 ? "in" : "out"), actor_id: u ? u.id : 1, created_at: isoNow() });
      saveDB();
      return jsonResp({ ok: true, qty: it.qty });
    }
    const mInvMoves = path.match(/^\/app\/api\/inventory\/(\d+)\/moves$/);
    if (mInvMoves && method === "GET") {
      const iid = Number(mInvMoves[1]);
      return jsonResp(DB.stock_moves.filter(m => m.item_id === iid).map(m => ({ ...m, actor: "Dt. Onur Aksoy" })));
    }

    if (path === "/app/api/charges" && method === "POST") {
      const cidId = nextId(DB.charges);
      const grossK = toKurus(body.amount);
      const discK = toKurus(body.discount || 0);
      const netK = Math.max(0, grossK - discK);
      DB.charges.unshift({
        id: cidId, clinic_id: cid, patient_id: Number(body.patient_id), description: body.description,
        amount_kurus: netK, gross_amount_kurus: grossK, discount_kurus: discK,
        doctor_id: body.doctor_id ? Number(body.doctor_id) : 1, created_by: u ? u.id : 1, created_at: isoNow(), voided_at: null
      });
      saveDB();
      return jsonResp({ id: cidId });
    }
    if (path === "/app/api/payments" && method === "POST") {
      const pidId = nextId(DB.payments);
      DB.payments.unshift({
        id: pidId, clinic_id: cid, patient_id: Number(body.patient_id), amount_kurus: toKurus(body.amount),
        method: body.method || "kart", status: body.status || "completed", is_advance: body.allow_advance ? 1 : 0,
        created_by: u ? u.id : 1, created_at: isoNow(), voided_at: null
      });
      saveDB();
      return jsonResp({ id: pidId });
    }
    const mPayRef = path.match(/^\/app\/api\/payments\/(\d+)\/refund$/);
    if (mPayRef && method === "POST") {
      const pidId = nextId(DB.payments);
      DB.payments.unshift({
        id: pidId, clinic_id: cid, patient_id: 1, amount_kurus: toKurus(body.amount),
        method: "iade", status: "refunded", created_by: u ? u.id : 1, created_at: isoNow(), voided_at: null
      });
      saveDB();
      return jsonResp({ ok: true, id: pidId });
    }
    const mVoid = path.match(/^\/app\/api\/(charges|payments)\/(\d+)\/void$/);
    if (mVoid && method === "POST") {
      const arr = mVoid[1] === "charges" ? DB.charges : DB.payments;
      const item = arr.find(x => x.id === Number(mVoid[2]) && x.clinic_id === cid);
      if (item) { item.voided_at = isoNow(); item.void_reason = body.reason; }
      saveDB();
      return jsonResp({ ok: true });
    }

    if (path === "/app/api/kasa") {
      const chAll = DB.charges.filter(c => c.clinic_id === cid);
      const pyAll = DB.payments.filter(p => p.clinic_id === cid);
      const billed = chAll.filter(x => !x.voided_at).reduce((s, x) => s + x.amount_kurus, 0);
      const paid = pyAll.filter(x => !x.voided_at && (x.status || "completed") === "completed").reduce((s, x) => s + x.amount_kurus, 0);
      const methods = {};
      pyAll.filter(x => !x.voided_at && (x.status || "completed") === "completed").forEach(x => { methods[x.method] = (methods[x.method] || 0) + x.amount_kurus; });
      const patName = (pid) => (DB.patients.find(p => p.id === pid) || {}).display_name || `Hasta #${pid}`;
      const entries = [
        ...chAll.map(x => ({ type: "hizmet", id: x.id, created_at: x.created_at, patient: patName(x.patient_id), info: x.description, amount: tl(x.amount_kurus), voided_at: x.voided_at })),
        ...pyAll.map(x => ({ type: "tahsilat", id: x.id, created_at: x.created_at, patient: patName(x.patient_id), info: x.method, amount: tl(x.amount_kurus), voided_at: x.voided_at }))
      ].sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
      const shares = DB.staff_users.filter(s => s.clinic_id === cid && ["owner", "doctor"].includes(s.role) && s.active).map(d => {
        const dbilled = chAll.filter(x => !x.voided_at && x.doctor_id === d.id).reduce((s, x) => s + x.amount_kurus, 0);
        return { full_name: d.full_name, share_pct: d.share_pct, billed: tl(dbilled), share_try: tl(Math.round(dbilled * d.share_pct / 100)) };
      });
      return jsonResp({
        billed: tl(billed), paid: tl(paid), receivable: Math.max(0, tl(billed - paid)),
        methods: Object.entries(methods).map(([k, v]) => ({ method: k, amount: tl(v) })),
        entries, shares
      });
    }
    if (path === "/app/api/doctors/revenue-report" && method === "GET") {
      const chAll = DB.charges.filter(c => c.clinic_id === cid && !c.voided_at);
      const doctors = DB.staff_users.filter(s => s.clinic_id === cid && ["owner", "doctor"].includes(s.role) && s.active).map(d => {
        const dCh = chAll.filter(c => c.doctor_id === d.id);
        const netT = tl(dCh.reduce((s, c) => s + c.amount_kurus, 0));
        const discT = tl(dCh.reduce((s, c) => s + (c.discount_kurus || 0), 0));
        const ownedCnt = DB.patients.filter(p => p.clinic_id === cid && p.primary_doctor_id === d.id).length;
        return {
          doctor_id: d.id, full_name: d.full_name, specialty: d.specialty || "Diş Hekimi",
          owned_patients_count: ownedCnt, treated_patients_count: new Set(dCh.map(c => c.patient_id)).size || 2,
          procedures_count: dCh.length || 3, gross_try: netT + discT, discount_try: discT, net_revenue_try: netT,
          collected_try: netT, share_pct: d.share_pct, hakedis_net_base_try: Math.round(netT * d.share_pct) / 100,
          hakedis_collected_base_try: Math.round(netT * d.share_pct) / 100
        };
      });
      return jsonResp({ doctors });
    }
    if (path === "/app/api/suppliers" && method === "GET") return jsonResp(DB.suppliers || []);
    if (path === "/app/api/suppliers" && method === "POST") {
      const sid = nextId(DB.suppliers);
      DB.suppliers.push({ id: sid, clinic_id: cid, name: body.name, category: body.category || "Genel", contact_person: body.contact_name || "", phone: body.phone || "", balance_try: 0 });
      saveDB();
      return jsonResp({ id: sid });
    }
    if (path === "/app/api/expenses" && method === "GET") {
      const supMap = new Map((DB.suppliers || []).map((sp) => [sp.id, sp.name]));
      return jsonResp((DB.expenses || []).filter((e) => e.clinic_id === undefined || e.clinic_id === cid).map((e) => ({ ...e, amount: e.amount !== undefined ? e.amount : Number(e.amount_try || 0), supplier_name: e.supplier_name || supMap.get(e.supplier_id) || null })));
    }
    if (path === "/app/api/expenses" && method === "POST") {
      const eid = nextId(DB.expenses);
      DB.expenses.unshift({ id: eid, clinic_id: cid, category: body.category || "malzeme", description: body.description, amount_try: Number(body.amount || 0), method: body.method || "havale", paid_at: isoNow().slice(0, 10) });
      saveDB();
      return jsonResp({ id: eid });
    }
    if (path === "/app/api/kasa/closings" && method === "GET") return jsonResp(DB.cash_closings || []);
    if (path === "/app/api/kasa/closings" && method === "POST") {
      const cidClose = nextId(DB.cash_closings);
      const sysBal = 25700;
      const phys = Number(body.physical_counted || sysBal);
      const diff = Math.round((phys - sysBal) * 100) / 100;
      DB.cash_closings.unshift({ id: cidClose, clinic_id: cid, closing_date: body.closing_date || isoNow().slice(0, 10), total_in_try: 38500, total_out_try: 12800, closing_balance_try: sysBal, physical_counted_try: phys, diff_try: diff, note: body.note || "" });
      saveDB();
      return jsonResp({ id: cidClose, diff_try: diff });
    }

    if (path === "/app/api/token-stats") {
      return jsonResp([
        { layer: "L1-sss", replies: 64, tin: 0, tout: 0 },
        { layer: "L1-acil", replies: 4, tin: 0, tout: 0 },
        { layer: "L2-anahtar", replies: 12, tin: 0, tout: 0 },
        { layer: "L3-ana-model", replies: 3, tin: 420, tout: 260 }
      ]);
    }
    if (path === "/app/api/ai-costs" && method === "GET") {
      return jsonResp({
        period_days: 30, total_messages: 83, free_l1_l2_messages: 80, llm_l3_messages: 3,
        free_ratio_pct: 96.4, tokens_in: 420, tokens_out: 260, total_tokens: 680,
        cost_usd: 0.0004, cost_try: 0.02, avg_cost_per_patient_try: 0.001, avg_cost_per_appointment_try: 0.002,
        monthly_quota_try: 500, quota_usage_pct: 0.1, alert_threshold_pct: 80, quota_warning: false, quota_exceeded: false,
        fx_usd_try: 36.5, fx_source: "sabit_referans_kur",
        package_price_try: 3500, subscription_price_try: 3500, usd_try_rate: 36.5, total_requests: 83, zero_token_requests: 80, zero_token_ratio_pct: 96.4,
        estimated_cost_usd: 0.0004, estimated_cost_try: 0.02, actual_billed_try: 0, cost_per_request_try: 0.0002, monthly_token_limit: 1500000, monthly_budget_try: 250,
        quota_warning_80: false, quota_exceeded_100: false, hard_stop_enabled: false, gross_profit_after_ai_try: 3499.98, gross_margin_pct: 99.99, gross_margin_after_ai_pct: 99.99,
        pricing_transparency_tr: "L1/L2 deterministik katmanlar 0 token ve 0 TL maliyetle çalışır; yalnızca L3 LLM çağrıları gerçek token tarifesiyle hesaplanır.",
        by_layer: [
          { layer: "L1-sss", replies: 64, tokens_in: 0, tokens_out: 0, total_tokens: 0, cost_usd: 0, cost_try: 0 },
          { layer: "L1-acil", replies: 4, tokens_in: 0, tokens_out: 0, total_tokens: 0, cost_usd: 0, cost_try: 0 },
          { layer: "L2-anahtar", replies: 12, tokens_in: 0, tokens_out: 0, total_tokens: 0, cost_usd: 0, cost_try: 0 },
          { layer: "L3-ana-model", replies: 3, tokens_in: 420, tokens_out: 260, total_tokens: 680, cost_usd: 0.0004, cost_try: 0.02 }
        ]
      });
    }
    if (path === "/app/api/ai-costs/quota" && method === "POST") return jsonResp({ ok: true });

    if (path === "/app/api/staff/professions-catalog" && method === "GET") {
      return jsonResp({
        professions: [
          ["owner", "Klinik Sahibi / Başhekim"],
          ["doctor_specialist", "Uzman Diş Hekimi"],
          ["doctor_general", "Diş Hekimi"],
          ["secretary", "Sekreter / Ön Büro"],
          ["patient_coordinator", "Hasta Koordinatörü"],
          ["assistant", "Diş Hekimi Asistanı"],
          ["accountant", "Muhasebe / Finans"],
          ["call_center", "Çağrı Merkezi"],
          ["cleaning", "Temizlik / Destek Personeli (Panelsiz)"]
        ],
        permission_keys: [
          ["view", "Panel Görüntüleme"],
          ["create", "Yeni Kayıt / Randevu Oluşturma"],
          ["edit", "Kayıt Düzenleme"],
          ["delete_cancel", "İptal ve Silme"],
          ["finance_view", "Finans ve Ciro Görüntüleme"],
          ["finance_collect", "Tahsilat Alma"],
          ["discount_apply", "İndirim Uygulama"],
          ["price_override", "Fiyat Değiştirme"],
          ["settings_manage", "Ayarlar Yönetimi"],
          ["staff_manage", "Personel ve Yetki Yönetimi"],
          ["export_data", "Rapor / CSV Dışa Aktarma"],
          ["doctor_own_patients_only", "Yalnızca Kendi Hastalarını Görsün"]
        ]
      });
    }

    if (path === "/app/api/staff" && method === "GET") {
      return jsonResp(DB.staff_users.filter(s => s.clinic_id === cid).map(s => ({
        id: s.id, email: s.email, full_name: s.full_name, role: s.role,
        job_title: s.job_title || s.role, job_title_label: s.specialty || s.role,
        specialty: s.specialty || "", share_pct: s.share_pct, totp_enabled: Boolean(s.totp_enabled),
        active: Boolean(s.active), whatsapp: Boolean(s.phone),
        permissions: s.permissions || DEFAULT_PERMS[s.role] || DEFAULT_PERMS.secretary
      })));
    }
    if (path === "/app/api/staff" && method === "POST") {
      const sid = nextId(DB.staff_users);
      DB.staff_users.push({
        id: sid, clinic_id: cid, email: body.email || `personel${sid}@dentacore.com`, pw: body.password || "DentaCore2026!",
        full_name: body.full_name, role: body.role || "secretary", job_title: body.job_title || body.role || "secretary",
        specialty: body.specialty || "", phone: body.phone || null, share_pct: Number(body.share_pct || 0),
        totp_enabled: 0, active: 1, permissions: { ...(DEFAULT_PERMS[body.role] || DEFAULT_PERMS.secretary) }, created_at: isoNow()
      });
      saveDB();
      return jsonResp({ id: sid });
    }
    const mStaffPerm = path.match(/^\/app\/api\/staff\/(\d+)\/permissions$/);
    if (mStaffPerm && method === "PATCH") {
      const st = DB.staff_users.find(s => s.id === Number(mStaffPerm[1]) && s.clinic_id === cid);
      if (st && body.permissions) st.permissions = { ...(st.permissions || {}), ...body.permissions };
      saveDB();
      return jsonResp({ ok: true });
    }
    const mStaffAct = path.match(/^\/app\/api\/staff\/(\d+)\/active$/);
    if (mStaffAct && method === "POST") {
      const st = DB.staff_users.find(s => s.id === Number(mStaffAct[1]) && s.clinic_id === cid);
      if (st) st.active = body.active ? 1 : 0;
      saveDB();
      return jsonResp({ ok: true });
    }

    if (path === "/app/api/audit") return jsonResp(DB.audit_log.filter(a => a.clinic_id === cid).slice().reverse());
    if (path === "/app/api/audit/verify") return jsonResp({ ok: true, checked: DB.audit_log.length });

    if (path === "/app/api/conversations" && method === "GET") {
      const rows = DB.patients.filter(p => p.clinic_id === cid).sort((a, b) => b.id - a.id).map(p => {
        const logs = DB.message_log.filter(m => m.patient_id === p.id).sort((a, b) => b.id - a.id);
        const outLogs = logs.filter(l => l.direction === "out");
        return {
          id: p.id, display_name: p.display_name, channel: p.channel, lang: p.lang,
          last_at: logs[0] ? logs[0].created_at : p.created_at,
          last_body: logs[0] ? logs[0].body : "Merhabalar, randevu ve tedavi bilgisi almak istiyorum.",
          last_layer: outLogs[0] ? outLogs[0].layer : "L1-sss",
          last_intent: logs[0] ? logs[0].intent : "konum",
          msg_count: logs.length || 2
        };
      });
      return jsonResp(rows);
    }
    const mConvMsgs = path.match(/^\/app\/api\/conversations\/(\d+)\/messages$/);
    if (mConvMsgs && method === "GET") {
      const pid = Number(mConvMsgs[1]);
      const logs = DB.message_log.filter(m => m.patient_id === pid);
      return jsonResp(logs.length ? logs : [
        { id: 1, direction: "in", body: "Merhabalar, kliniğinizin konumu ve randevu saatleri nedir?", created_at: isoNow() },
        { id: 2, direction: "out", layer: "L1-sss", delivery_status: "dry_run", body: "Merhabalar, Bağdat Cad. No:142 Kadıköy adresindeyiz. Hafta içi 09:00-19:00 arası hizmet veriyoruz.", created_at: isoNow() }
      ]);
    }
    if (path === "/app/api/conversations/simulate" && method === "POST") {
      const res = simulateRoute(body.text || "", body.lang || "", curClinic);
      return jsonResp(res);
    }
    const mConvSend = path.match(/^\/app\/api\/conversations\/(\d+)\/send$/);
    if (mConvSend && method === "POST") {
      const pid = Number(mConvSend[1]);
      DB.message_log.push({ id: nextId(DB.message_log), clinic_id: cid, patient_id: pid, direction: "out", layer: "panel-manuel", intent: "personel", body: body.text || "", delivery_status: "dry_run", tokens_in: 0, tokens_out: 0, created_at: isoNow() });
      saveDB();
      return jsonResp({ ok: true, dry_run: true, status: "dry_run" });
    }

    if (path === "/app/api/templates" && method === "GET") return jsonResp(DB.message_templates.filter(t => t.clinic_id === cid).sort((a, b) => b.id - a.id));
    if (path === "/app/api/templates" && method === "POST") {
      const tid = nextId(DB.message_templates);
      DB.message_templates.push({ id: tid, clinic_id: cid, name: body.name, channel: body.channel || "whatsapp", lang: body.lang || "tr", category: body.category || "UTILITY", body: body.body, status: "APPROVED", created_at: isoNow() });
      saveDB();
      return jsonResp({ id: tid });
    }

    if (path === "/app/api/analytics") {
      const appts = DB.appointments.filter(a => a.clinic_id === cid);
      const camps = DB.campaigns.filter(c => c.clinic_id === cid).map(c => ({ ...c, revenue_try: tl(c.revenue_kurus) }));
      return jsonResp({ total_appts_30d: appts.length, off_hours_appts: 3, off_hours_pct: 38, campaigns: camps });
    }
    if (path === "/app/api/campaigns/report" && method === "GET") {
      const camps = DB.campaigns.filter(c => c.clinic_id === cid).map(c => ({
        ...c, revenue_try: tl(c.revenue_kurus), collected_revenue_try: c.collected_revenue_try || tl(c.revenue_kurus)
      }));
      return jsonResp({
        campaigns: camps,
        tracking_methodology_tr: "Bot (Meta/Google/Headless crawler) ve 30 dk mükerrer tıklamalar otomatik filtrelenir; 7 aşamalı huni (Ham Tık -> Tekil Ziyaretçi -> Hasta -> Randevu -> Gelen -> Tedavi -> Tahsilat) kuruş kesinliğinde izlenir."
      });
    }
    if (path === "/app/api/campaigns/funnel" && method === "GET") {
      const camps = DB.campaigns.filter(c => c.clinic_id === cid);
      return jsonResp({ campaigns: camps });
    }
    if (path === "/app/api/campaigns" && method === "POST") {
      const cidId = nextId(DB.campaigns);
      DB.campaigns.unshift({
        id: cidId, clinic_id: cid, code: body.code || `KMP-${cidId}`, name: body.name,
        source: body.channel || body.source || "instagram", channel: body.channel || body.source || "instagram",
        budget_try: Number(body.budget || 0), clicks: Number(body.clicks || 0), unique_clicks: Number(body.clicks || 0),
        bot_clicks: 0, duplicate_clicks: 0, conversations: Number(body.conversations || 0), leads_count: Number(body.conversations || 0),
        appointments_booked: Number(body.appointments_booked || 0), attended_appointments: Number(body.appointments_booked || 0),
        completed_treatments: 0, revenue_kurus: toKurus(body.revenue_try || 0), collected_revenue_try: Number(body.revenue_try || 0),
        is_sample: 0, created_at: isoNow()
      });
      saveDB();
      return jsonResp({ id: cidId });
    }

    if (path === "/app/api/clinics" && method === "GET") {
      return jsonResp(DB.clinics.map(c => {
        const ow = DB.staff_users.find(s => s.clinic_id === c.id && s.role === "owner");
        const paidK = DB.payments.filter(p => p.clinic_id === c.id && !p.voided_at).reduce((s, p) => s + p.amount_kurus, 0);
        const icsUrl = `${window.location.origin}/calendar/klinik-${c.id}.ics`;
        const webcalUrl = `webcal://${window.location.host || "localhost:8000"}/calendar/klinik-${c.id}.ics`;
        return {
          ...c, active: Boolean(c.active), owner_email: ow ? ow.email : "-",
          staff_count: DB.staff_users.filter(s => s.clinic_id === c.id && s.active).length,
          patient_count: DB.patients.filter(p => p.clinic_id === c.id).length,
          active_appts: DB.appointments.filter(a => a.clinic_id === c.id && ["booked", "confirmed"].includes(a.status)).length,
          paid_try: tl(paidK), ics_url: icsUrl, webcal_url: webcalUrl
        };
      }));
    }
    if (path === "/app/api/clinics" && method === "POST") {
      const newCid = nextId(DB.clinics);
      const slug = String(body.clinic_name || "klinik").toLowerCase().replace(/[^a-z0-9]+/g, "-") + "-" + newCid;
      DB.clinics.push({ id: newCid, name: body.clinic_name, slug, city: body.city || "İstanbul", address: body.address || "", phone: body.phone || "", chairs: Number(body.chairs || 2), work_minutes: 600, google_review_url: "", autopilot_name: "DentaCore Asistan", default_lang: "tr", slot_step_min: 15, active: 1, created_at: isoNow() });
      const uid = nextId(DB.staff_users);
      DB.staff_users.push({ id: uid, clinic_id: newCid, email: body.owner_email, pw: body.owner_password, full_name: body.owner_name, role: "owner", phone: body.phone || null, share_pct: 50.0, totp_enabled: 0, active: 1, created_at: isoNow() });
      saveDB();
      return jsonResp({ clinic_id: newCid, user_id: uid, email: body.owner_email, slug, login_url: window.location.href, ics_url: `${window.location.origin}/calendar/klinik-${newCid}.ics`, webcal_url: `webcal://localhost/calendar/klinik-${newCid}.ics` });
    }
    const mClinicSw = path.match(/^\/app\/api\/clinics\/(\d+)\/switch$/);
    if (mClinicSw && method === "POST") {
      const targetCid = Number(mClinicSw[1]);
      const targetC = DB.clinics.find(c => c.id === targetCid);
      if (!targetC) return jsonResp({ detail: "klinik yok" }, 404);
      window.__DC_STATE.activeClinicId = targetCid;
      return jsonResp({ ok: true, clinic_id: targetCid, clinic: targetC.name });
    }

    if (path === "/app/api/settings" && method === "GET") return jsonResp(curClinic);
    if (path === "/app/api/settings" && method === "POST") {
      Object.assign(curClinic, body || {});
      saveDB();
      return jsonResp({ ok: true });
    }
    if (path === "/app/api/settings/ai-rules" && method === "POST") {
      curClinic.ai_custom_rules_json = JSON.stringify(body || {});
      saveDB();
      return jsonResp({ ok: true, ai_custom_rules: body });
    }
    if (path === "/app/api/ecosystem-status") {
      return jsonResp({
        omniroute: { ok: true, url: "http://127.0.0.1:20128 (Bulut Senkron Aktif)" },
        headroom: { ok: true, url: "http://127.0.0.1:8787 (CCR Kayıpsız Sıkıştırma)" },
        ai_office: { ok: true, url: "http://127.0.0.1:20140 (AI Office Orkestratör)" },
        langs: 16, security_headers: 12,
        apps: [
          { id: "open-generative-ai", name: "Open Generative AI", ok: true },
          { id: "voicestudio", name: "VoiceStudio", ok: true },
          { id: "open-seo", name: "OpenSEO", ok: true },
          { id: "appflowy", name: "AppFlowy", ok: true },
          { id: "openwhispr", name: "OpenWhispr", ok: true },
          { id: "openproject", name: "OpenProject CE", ok: true },
          { id: "cal-diy", name: "Cal.diy", ok: true },
          { id: "chatwoot", name: "Chatwoot Community", ok: true },
          { id: "cap", name: "Cap", ok: true }
        ]
      });
    }
    if (path === "/app/api/assistant" && method === "POST") {
      const txt = String((body && body.question) || "").toLowerCase();
      if (["kasa", "tahsilat", "ciro"].some(k => txt.includes(k))) {
        const p = DB.payments.filter(x => x.clinic_id === cid && !x.voided_at).reduce((s, x) => s + x.amount_kurus, 0);
        return jsonResp({ answer: `Toplam tahsilat: ${tl(p).toLocaleString("tr-TR")} TL (0 LLM tokenı harcandı).`, tokens: 0 });
      }
      return jsonResp({ answer: "Bugün 4 aktif randevu, %96 L1/L2 bedava yanıt oranı ve 0 bekleyen kritik hata bulunmaktadır.", tokens: 0 });
    }
    if (path.startsWith("/app/api/export/")) {
      return textResp("id,ad,kaynak\n1,Ayse Kaya,Instagram\n", "text/csv; charset=utf-8");
    }

    return origFetch(input, init);
  };
})();
"""


def strip_font_faces(css: str) -> str:
    return re.sub(r"@font-face\s*\{[^}]*\}\s*", "", css)


def build_all() -> None:
    faq_raw = FAQ_PATH.read_text(encoding="utf-8")
    faq_compact = json.dumps(json.loads(faq_raw), ensure_ascii=False, separators=(",", ":"))
    engine_js = ENGINE_JS_TEMPLATE.replace("__FAQ_JSON__", faq_compact)

    index_html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    css_file = WEB_DIR / "landing.css" if (WEB_DIR / "landing.css").exists() else WEB_DIR / "site.css"
    js_file = WEB_DIR / "landing.js" if (WEB_DIR / "landing.js").exists() else WEB_DIR / "site.js"
    site_css = strip_font_faces(css_file.read_text(encoding="utf-8"))
    site_js = js_file.read_text(encoding="utf-8")

    app_html = (WEB_DIR / "app.html").read_text(encoding="utf-8")
    app_css = strip_font_faces((WEB_DIR / "app.css").read_text(encoding="utf-8"))
    app_js = (WEB_DIR / "app.js").read_text(encoding="utf-8")

    # Statik demo sayfasında (file://, github.io, localhost) demo hesap kutusu her zaman aktif olsun
    app_js_demo = app_js.replace(
        'const IS_DEMO_HOST = ["localhost", "127.0.0.1"].includes(location.hostname) || location.hostname.endsWith(".github.io");',
        "const IS_DEMO_HOST = true;",
    )

    font_link = '<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Plus+Jakarta+Sans:wght@600;700;800&display=swap" rel="stylesheet">'

    # 1. Landing (index.html & tanitim.html)
    pure_landing = index_html
    pure_landing = pure_landing.replace(
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        '<meta id="dc-viewport" name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">',
    )
    pure_landing = pure_landing.replace('<link rel="icon" href="/static/favicon.svg" type="image/svg+xml">', f'<link rel="icon" href="{FAVICON_DATA_URI}" type="image/svg+xml">')
    pure_landing = pure_landing.replace('<link rel="stylesheet" href="/static/landing.css">', f"{font_link}\n<style>{site_css}</style>")
    pure_landing = pure_landing.replace('<link rel="stylesheet" href="/static/site.css">', f"{font_link}\n<style>{site_css}</style>")
    pure_landing = pure_landing.replace('src="/static/favicon.svg"', f'src="{FAVICON_DATA_URI}"')
    pure_landing = pure_landing.replace('href="/app"', 'href="panel.html"')
    pure_landing = pure_landing.replace('<a class="brand" href="/">', '<a class="brand" href="./">')
    pure_landing = pure_landing.replace('<script src="/static/landing.js" defer></script>', f"<script>{engine_js}</script>\n<script>{site_js}</script>")
    pure_landing = pure_landing.replace('<script src="/static/landing.js"></script>', f"<script>{engine_js}</script>\n<script>{site_js}</script>")
    pure_landing = pure_landing.replace('<script src="/static/site.js" defer></script>', f"<script>{engine_js}</script>\n<script>{site_js}</script>")
    pure_landing = pure_landing.replace('<script src="/static/site.js"></script>', f"<script>{engine_js}</script>\n<script>{site_js}</script>")

    # 2. Panel (panel.html, app.html, app/index.html)
    pure_panel = app_html
    pure_panel = pure_panel.replace(
        '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">',
        '<meta id="dc-viewport" name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">',
    )
    pure_panel = pure_panel.replace(
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        '<meta id="dc-viewport" name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">',
    )
    pure_panel = pure_panel.replace('<link rel="icon" href="/static/favicon.svg" type="image/svg+xml">', f'<link rel="icon" href="{FAVICON_DATA_URI}" type="image/svg+xml">')
    pure_panel = pure_panel.replace('<link rel="stylesheet" href="/static/app.css">', f"{font_link}\n<style>{app_css}</style>")
    pure_panel = pure_panel.replace('<script src="/static/app.js" defer></script>', f"<script>{engine_js}</script>\n<script>{app_js_demo}</script>")
    pure_panel = pure_panel.replace('<script src="/static/app.js"></script>', f"<script>{engine_js}</script>\n<script>{app_js_demo}</script>")
    pure_panel = pure_panel.replace('"/static/favicon.svg"', f'"{FAVICON_DATA_URI}"')

    pure_landing = pure_landing.replace('<link rel="manifest" href="/manifest.webmanifest">', '<link rel="manifest" href="manifest.webmanifest">')
    pure_landing = pure_landing.replace('<link rel="apple-touch-icon" href="/static/apple-touch-icon.png">', f'<link rel="apple-touch-icon" href="{FAVICON_DATA_URI}">')
    pure_landing = pure_landing.replace('navigator.serviceWorker.register("/sw.js"', 'navigator.serviceWorker.register("sw.js"')
    pure_landing = pure_landing.replace('{ scope: "/" }', '{ scope: "./" }')

    pure_panel = pure_panel.replace('<link rel="manifest" href="/manifest.webmanifest">', '<link rel="manifest" href="manifest.webmanifest">')
    pure_panel = pure_panel.replace('<link rel="apple-touch-icon" href="/static/apple-touch-icon.png">', f'<link rel="apple-touch-icon" href="{FAVICON_DATA_URI}">')
    pure_panel = pure_panel.replace('navigator.serviceWorker.register("/sw.js"', 'navigator.serviceWorker.register("sw.js"')
    pure_panel = pure_panel.replace('{ scope: "/" }', '{ scope: "./" }')

    docs_dir = CLOUD_DIR / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)
    (docs_dir / "app").mkdir(parents=True, exist_ok=True)
    (docs_dir / ".nojekyll").write_text("", encoding="utf-8")
    (docs_dir / "index.html").write_text(pure_landing, encoding="utf-8")
    (docs_dir / "tanitim.html").write_text(pure_landing, encoding="utf-8")
    (docs_dir / "panel.html").write_text(pure_panel, encoding="utf-8")
    (docs_dir / "app.html").write_text(pure_panel, encoding="utf-8")
    (docs_dir / "app" / "index.html").write_text(pure_panel, encoding="utf-8")
    static_sw = (
        '"use strict";\n'
        'self.addEventListener("install", () => self.skipWaiting());\n'
        'self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));\n'
    )
    (docs_dir / "sw.js").write_text(static_sw, encoding="utf-8")
    (docs_dir / "app" / "sw.js").write_text(static_sw, encoding="utf-8")
    static_manifest = json.dumps(
        {
            "name": "DentaCore Klinik İşletim Sistemi",
            "short_name": "DentaCore",
            "start_url": "panel.html",
            "display": "standalone",
            "background_color": "#F7F8FA",
            "theme_color": "#0A2540",
            "icons": [{"src": FAVICON_DATA_URI, "sizes": "64x64", "type": "image/svg+xml"}],
        },
        ensure_ascii=False,
    )
    (docs_dir / "manifest.webmanifest").write_text(static_manifest, encoding="utf-8")
    (docs_dir / "app" / "manifest.webmanifest").write_text(static_manifest, encoding="utf-8")
    wa_dir = REPO_ROOT / "WhatsApp_Gonderim"
    if wa_dir.exists():
        wa_landing = pure_landing.replace('href="panel.html"', 'href="2_Birebir_Yonetim_Paneli.html"').replace('<a class="brand" href="./">', '<a class="brand" href="1_Birebir_Tanitim_Sitesi.html">')
        (wa_dir / "1_Birebir_Tanitim_Sitesi.html").write_text(wa_landing, encoding="utf-8")
        (wa_dir / "2_Birebir_Yonetim_Paneli.html").write_text(pure_panel, encoding="utf-8")
    print("Built standalone cloud demo docs:", docs_dir)


if __name__ == "__main__":
    build_all()
