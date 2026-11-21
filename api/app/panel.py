"""Klinik yönetim paneli API'si: personel girişi (scrypt + TOTP), oturum/CSRF, rol bazlı erişim,
takvim, hastalar, bekleme listesi, uyarılar, envanter, kasa, ekip, denetim kaydı, web sitesi talepleri."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path
from typing import Literal
from urllib.parse import quote
from zoneinfo import ZoneInfo

import httpx
from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, Response
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, field_validator

from . import cal, media, modules, security as sec
from .core import (S, add_alert, dec, dec_msg_body, enc, env, has_consent, ip_hash, log_msg, norm_phone, phone_hmac, q, q1, tx, upsert_patient)
from .dental_catalog import (PATIENT_SOURCE_LABELS, PERMISSION_LABELS_TR, detect_acquisition_source, is_bot_traffic, resolve_permissions)
from .router import TokenRouter

TZ = ZoneInfo("Europe/Istanbul")
router = APIRouter()
limiter = sec.RateLimiter()          # main.py açılışta Redis bağlar
MUTATING = {"POST", "PUT", "PATCH", "DELETE"}


def kurus(v: Decimal | float | int | str) -> int:
    return int((Decimal(str(v if v is not None else 0)) * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def tl(k: int | None) -> float:
    return round((k or 0) / 100, 2)


def mask_phone(p: str) -> str:
    if p.startswith("ig:"):
        return "Instagram"
    d = re.sub(r"\D", "", p)
    return f"+{d[:2]} {d[2:3]}** *** {d[-4:-2]} {d[-2:]}" if len(d) >= 10 else "***"


def client_ip(request: Request) -> str:
    # XFF sağdan okunur (TRUSTED_PROXY_HOPS); sola eklenen sahte IP'ler rate-limit'i atlatamaz (CWE-290).
    return sec.client_ip_from(request.headers.get("x-forwarded-for"), request.client.host if request.client else None)


# ======================================================================== kimlik doğrulama
async def current_user(request: Request) -> dict:
    raw = request.cookies.get(sec.COOKIE, "")
    if not raw:
        raise HTTPException(401, "oturum yok")
    s = await q1("""SELECT s.id_hash, s.csrf, s.last_seen, s.expires_at, s.active_clinic_id,
                           u.id, u.clinic_id AS home_clinic_id, u.email, u.full_name, u.role,
                           u.job_title, u.permissions_json, u.totp_enabled, u.share_pct,
                           coalesce(c.name, %s) AS clinic_name, coalesce(c.address, '') AS clinic_address
                    FROM sessions s JOIN staff_users u ON u.id = s.user_id
                    LEFT JOIN clinics c ON c.id = COALESCE(s.active_clinic_id, u.clinic_id)
                    WHERE s.id_hash=%s AND NOT s.revoked AND u.active AND s.expires_at > now()""", S.clinic, sec.session_hash(raw))
    now = datetime.now(timezone.utc)
    if not s or (now - s["last_seen"]).total_seconds() > sec.IDLE_SECONDS:
        if s:
            await q("UPDATE sessions SET revoked=true WHERE id_hash=%s", s["id_hash"])
        raise HTTPException(401, "oturum süresi doldu")
    if request.method in MUTATING:
        origin = request.headers.get("origin")
        if origin and origin.split("://", 1)[-1] != request.headers.get("host", ""):
            raise HTTPException(403, "köken reddedildi")
        if not hmac.compare_digest(request.headers.get("x-csrf-token", ""), s["csrf"]):
            raise HTTPException(403, "CSRF doğrulaması başarısız")
    perms = resolve_permissions(s.get("role"), s.get("job_title"), s.get("permissions_json"))
    if not perms.get("view", False) and not request.url.path.startswith("/auth/"):
        raise HTTPException(403, "Sistem görüntüleme yetkiniz bulunmamaktadır")
    if (now - s["last_seen"]).total_seconds() > 60:
        await q("UPDATE sessions SET last_seen=now() WHERE id_hash=%s", s["id_hash"])
    s["ip_h"] = ip_hash(client_ip(request))
    s["home_clinic_id"] = int(s.get("home_clinic_id") or 1)
    s["is_hq"] = (s["home_clinic_id"] == 1 and s["role"] == "owner")
    active_cid = int(s.get("active_clinic_id") or s["home_clinic_id"])
    if not s["is_hq"] and active_cid != s["home_clinic_id"]:
        active_cid = s["home_clinic_id"]
    s["clinic_id"] = active_cid
    s["permissions"] = perms
    return s


def require_perm(*perm_keys: str):
    async def dep(u: dict = Depends(current_user)) -> dict:
        perms = u.get("permissions") or resolve_permissions(u.get("role"), u.get("job_title"), u.get("permissions_json"))
        for pk in perm_keys:
            if not perms.get(pk, False):
                lbl = PERMISSION_LABELS_TR.get(pk, pk)
                raise HTTPException(403, f"Bu işlem için '{lbl}' ({pk}) yetkisi gereklidir")
        return u
    return dep


async def _enforce_doc_own_patient_pg(cid: int, pid: int, u: dict) -> None:
    perms = u.get("permissions") or {}
    if perms.get("doctor_own_patients_only") and u.get("role") != "owner":
        p = await q1("SELECT primary_doctor_id, created_by FROM patients WHERE id=%s AND clinic_id=%s", pid, cid)
        if not p:
            raise HTTPException(404, "hasta yok")
        uid = u["id"]
        if p.get("primary_doctor_id") != uid and p.get("created_by") != uid:
            owns = (
                await q1("SELECT 1 FROM appointments WHERE clinic_id=%s AND patient_id=%s AND doctor_id=%s LIMIT 1", cid, pid, uid)
                or await q1("SELECT 1 FROM tooth_records WHERE clinic_id=%s AND patient_id=%s AND doctor_id=%s LIMIT 1", cid, pid, uid)
                or await q1("SELECT 1 FROM charges WHERE clinic_id=%s AND patient_id=%s AND doctor_id=%s LIMIT 1", cid, pid, uid)
            )
            if not owns:
                raise HTTPException(403, "Yalnızca kendi sorumluluğunuzdaki veya tedavisini yaptığınız hastaları görüntüleyebilirsiniz")


def need(*roles: str):
    async def dep(u: dict = Depends(current_user)) -> dict:
        if roles and u["role"] not in roles:
            raise HTTPException(403, "bu işlem için yetkiniz yok")
        return u
    return dep


ANY = need()
OWNER = need("owner")
CLINICAL = need("owner", "doctor")


def need_hq():
    async def dep(u: dict = Depends(OWNER)) -> dict:
        if not u.get("is_hq"):
            raise HTTPException(403, "Bu işlem yalnızca platform/merkez yönetici (HQ) yetkisindedir")
        return u
    return dep


HQ_OWNER = need_hq()


async def log(u: dict, action: str, target: str = "", meta: dict | None = None):
    await sec.audit(u["id"], u["email"], action, target, u.get("ip_h", ""), meta, clinic_id=int(u.get("clinic_id") or 1))


class LoginIn(BaseModel):
    email: str = Field(max_length=200)
    password: str = Field(max_length=200)
    totp: str | None = Field(default=None, max_length=8)


@router.post("/auth/login")
async def login(body: LoginIn, request: Request, response: Response):
    email = body.email.strip().lower()
    ip = client_ip(request)
    if not await limiter.hit(f"ip:{ip}", 50, 900) or not await limiter.hit(f"em:{email}", 15, 900):
        raise HTTPException(429, "Çok fazla deneme. 15 dakika sonra tekrar deneyin.")
    u = await q1("SELECT * FROM staff_users WHERE email=%s AND active", email)
    now = datetime.now(timezone.utc)
    if u and u["locked_until"] and u["locked_until"] > now:
        raise HTTPException(423, "Hesap geçici olarak kilitli. Daha sonra tekrar deneyin.")
    ok = await asyncio.to_thread(sec.verify_password, body.password, u["pw_hash"] if u else sec.dummy_hash())

    async def _record_fail():
        if u["locked_until"] and u["locked_until"] <= now:
            await q("UPDATE staff_users SET failed_count=1, locked_until=NULL WHERE id=%s", u["id"])
        else:
            await q("""UPDATE staff_users SET failed_count=failed_count+1,
                       locked_until = CASE WHEN failed_count+1 >= 10 THEN now() + interval '15 minutes' ELSE NULL END
                       WHERE id=%s""", u["id"])

    if not u or not ok:
        if u:
            await _record_fail()
        await sec.audit(u["id"] if u else None, email, "auth.fail", "", ip_hash(ip), clinic_id=int(u.get("clinic_id") or 1) if u else 1)
        raise HTTPException(401, "E-posta veya parola hatalı")
    if u["totp_enabled"]:
        if not body.totp:
            return {"need_totp": True}
        step = sec.totp_verify(dec(u["totp_secret_enc"]), body.totp, u["totp_last_step"])
        if step is None:
            await _record_fail()
            await sec.audit(u["id"], email, "auth.totp_fail", "", ip_hash(ip), clinic_id=int(u.get("clinic_id") or 1))
            raise HTTPException(401, "Doğrulama kodu hatalı")
        await q("UPDATE staff_users SET totp_last_step=%s WHERE id=%s", step, u["id"])
    perms_u = resolve_permissions(u["role"], u.get("job_title"), u.get("permissions_json"))
    if not perms_u.get("view", False):
        raise HTTPException(403, "Bu personel hesabının yönetim paneli görüntüleme yetkisi bulunmamaktadır")
    raw, h = sec.new_session_token()
    csrf = sec.new_session_token()[0]
    home_cid = int(u.get("clinic_id") or 1)
    is_hq = (home_cid == 1 and u["role"] == "owner")
    await q("""INSERT INTO sessions (id_hash, user_id, active_clinic_id, csrf, expires_at, ua)
               VALUES (%s,%s,%s,%s, now() + make_interval(secs => %s), %s)""",
            h, u["id"], home_cid, csrf, sec.ABSOLUTE_SECONDS, (request.headers.get("user-agent") or "")[:200])
    await q("UPDATE staff_users SET failed_count=0, locked_until=NULL WHERE id=%s", u["id"])
    await limiter.reset(f"em:{email}")
    await sec.audit(u["id"], email, "auth.login", f"clinic:{home_cid}", ip_hash(ip), clinic_id=home_cid)
    response.headers["set-cookie"] = sec.cookie_header(raw)
    return {"ok": True, "csrf": csrf, "user": {"id": u["id"], "clinic_id": home_cid, "email": u["email"],
                                               "full_name": u["full_name"], "role": u["role"], "totp_enabled": u["totp_enabled"],
                                               "is_hq": is_hq}}


@router.post("/auth/logout")
async def logout(response: Response, u: dict = Depends(ANY)):
    await q("UPDATE sessions SET revoked=true WHERE id_hash=%s", u["id_hash"])
    await log(u, "auth.logout")
    response.headers["set-cookie"] = sec.clear_cookie_header()
    return {"ok": True}


@router.get("/auth/me")
async def me(u: dict = Depends(ANY)):
    return {"csrf": u["csrf"],
            "user": {"id": u["id"], "clinic_id": u["clinic_id"], "email": u["email"], "full_name": u["full_name"],
                     "role": u["role"], "totp_enabled": u["totp_enabled"], "is_hq": u["is_hq"]},
            "clinic": u.get("clinic_name") or S.clinic,
            "clinic_id": u["clinic_id"],
            "home_clinic_id": u["home_clinic_id"],
            "idle_seconds": sec.IDLE_SECONDS}


class ReauthIn(BaseModel):
    password: str = Field(max_length=200)


async def _reauth(u: dict, pw: str):
    row = await q1("SELECT pw_hash FROM staff_users WHERE id=%s", u["id"])
    if not await asyncio.to_thread(sec.verify_password, pw, row["pw_hash"]):
        await log(u, "auth.reauth_fail")
        raise HTTPException(400, "Parola hatalı")


async def _hash_pw(pw: str) -> str:
    try:
        return await asyncio.to_thread(sec.hash_password, pw)
    except ValueError as e:
        raise HTTPException(400, str(e)) from None


@router.post("/auth/totp/setup")
async def totp_setup(body: ReauthIn, u: dict = Depends(ANY)):
    await _reauth(u, body.password)
    secret = sec.new_totp_secret()
    await q("UPDATE staff_users SET totp_secret_enc=%s, totp_enabled=false, totp_last_step=0 WHERE id=%s", enc(secret), u["id"])
    await log(u, "auth.totp_setup")
    return {"secret": secret, "uri": sec.totp_uri(secret, u["email"])}


class CodeIn(BaseModel):
    code: str = Field(max_length=8)


@router.post("/auth/totp/enable")
async def totp_enable(body: CodeIn, u: dict = Depends(ANY)):
    row = await q1("SELECT totp_secret_enc, totp_last_step FROM staff_users WHERE id=%s", u["id"])
    if not row or not row["totp_secret_enc"]:
        raise HTTPException(400, "Önce kurulum başlatın")
    step = sec.totp_verify(dec(row["totp_secret_enc"]), body.code, row["totp_last_step"])
    if step is None:
        raise HTTPException(400, "Kod hatalı")
    await q("UPDATE staff_users SET totp_enabled=true, totp_last_step=%s WHERE id=%s", step, u["id"])
    await log(u, "auth.totp_enabled")
    return {"ok": True}


class PwIn(BaseModel):
    current: str = Field(max_length=200)
    new: str = Field(min_length=12, max_length=200)


@router.post("/auth/password")
async def change_password(body: PwIn, u: dict = Depends(ANY)):
    await _reauth(u, body.current)
    h = await _hash_pw(body.new)
    await q("UPDATE staff_users SET pw_hash=%s WHERE id=%s", h, u["id"])
    await q("UPDATE sessions SET revoked=true WHERE user_id=%s AND id_hash<>%s", u["id"], u["id_hash"])
    await log(u, "auth.password_changed")
    return {"ok": True}


@router.post("/auth/sessions/revoke-all")
async def revoke_all(response: Response, u: dict = Depends(ANY)):
    await q("UPDATE sessions SET revoked=true WHERE user_id=%s", u["id"])
    await log(u, "auth.revoke_all")
    response.headers["set-cookie"] = sec.clear_cookie_header()
    return {"ok": True}


async def bootstrap_owner():
    """İlk açılışta hiç personel yoksa .env'deki OWNER_EMAIL / OWNER_PASSWORD ile yönetici hesabı açılır."""
    await q("""INSERT INTO clinics (id, name, slug) VALUES (1, %s, 'merkez-klinik')
               ON CONFLICT (id) DO NOTHING""", S.clinic)
    await q("SELECT setval(pg_get_serial_sequence('clinics', 'id'), GREATEST((SELECT coalesce(max(id), 1) FROM clinics), 1))")
    if await q1("SELECT 1 FROM staff_users LIMIT 1"):
        return
    email, pw = env("OWNER_EMAIL").strip().lower(), env("OWNER_PASSWORD")
    if not email or len(pw) < 12:
        from .prodcheck import is_production
        if is_production():
            raise RuntimeError("Üretimde ilk açılış için OWNER_EMAIL ve en az 12 karakterli OWNER_PASSWORD gerekli (hiç personel kaydı yok)")
        return
    h = await asyncio.to_thread(sec.hash_password, pw)
    await q("INSERT INTO staff_users (clinic_id, email, full_name, role, pw_hash) VALUES (1,%s,%s,'owner',%s)",
            email, env("DOCTOR_DISPLAY_NAME", "Klinik Yöneticisi"), h)
    await sec.audit(None, "system", "staff.bootstrap_owner", email)


# ======================================================================== genel bakış
def day_bounds(d: datetime) -> tuple[datetime, datetime]:
    s = d.astimezone(TZ).replace(hour=0, minute=0, second=0, microsecond=0)
    return s, s + timedelta(days=1)


@router.get("/app/api/overview")
async def overview(u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    cinfo = await q1("SELECT chairs, work_minutes FROM clinics WHERE id=%s", cid)
    chairs = (cinfo and cinfo["chairs"]) or S.chairs
    work_min = (cinfo and cinfo["work_minutes"]) or S.work_minutes
    s, e = day_bounds(datetime.now(TZ))
    today = await q("SELECT status, duration_min FROM appointments WHERE clinic_id=%s AND starts_at >= %s AND starts_at < %s", cid, s, e)
    active = [a for a in today if a["status"] in ("booked", "confirmed")]
    occ = round(100 * sum(a["duration_min"] for a in active) / max(1, chairs * work_min))
    att = await q1("""SELECT count(*) FILTER (WHERE status='done') AS done, count(*) FILTER (WHERE status='noshow') AS noshow
                      FROM appointments WHERE clinic_id=%s AND starts_at > now() - interval '30 days' AND starts_at < now()""", cid)
    noshow_rate = round(100 * att["noshow"] / max(1, att["done"] + att["noshow"]))
    avg = await q1("SELECT avg(amount_kurus)::bigint AS a FROM charges WHERE clinic_id=%s AND voided_at IS NULL AND created_at > now() - interval '90 days'", cid)
    avg_ticket = (avg["a"] if avg and avg["a"] else int(Decimal(env("AVG_TICKET_TRY", "2500")) * 100))
    ms = s.replace(day=1)
    money = await q1("""SELECT (SELECT coalesce(sum(amount_kurus),0) FROM charges WHERE clinic_id=%s AND voided_at IS NULL AND created_at >= %s) AS billed,
                               (SELECT coalesce(sum(amount_kurus),0) FROM payments WHERE clinic_id=%s AND voided_at IS NULL AND created_at >= %s) AS paid""",
                     cid, ms, cid, ms)
    tok = await q1("""SELECT count(*) AS total, count(*) FILTER (WHERE m.layer LIKE 'L1%%') AS free,
                             coalesce(sum(m.tokens_in + m.tokens_out),0) AS tokens
                      FROM message_log m LEFT JOIN patients p ON p.id=m.patient_id
                      WHERE m.direction='out' AND m.created_at > now() - interval '30 days'
                        AND COALESCE(p.clinic_id, m.clinic_id, 1)=%s""", cid)
    misc = await q1("""SELECT (SELECT count(*) FROM alerts WHERE clinic_id=%s AND acknowledged_at IS NULL) AS alerts,
                              (SELECT count(*) FROM waitlist w JOIN patients p ON p.id=w.patient_id WHERE p.clinic_id=%s AND w.active) AS waitlist,
                              (SELECT count(*) FROM alerts WHERE clinic_id=%s AND kind='koltuk_dolduruldu' AND created_at > now() - interval '30 days') AS refills,
                              (SELECT count(*) FROM inventory_items WHERE clinic_id=%s AND active AND qty <= min_qty AND min_qty > 0) AS low_stock,
                              (SELECT count(*) FROM postop_checks pc JOIN patients p ON p.id=pc.patient_id WHERE p.clinic_id=%s AND pc.alarm AND pc.answered_at > now() - interval '7 days') AS postop_alarms""",
                    cid, cid, cid, cid, cid)
    start = s - timedelta(days=13)
    series = await q("""SELECT d AS day,
                          (SELECT count(*) FROM message_log m LEFT JOIN patients p ON p.id=m.patient_id WHERE m.direction='in' AND COALESCE(p.clinic_id, m.clinic_id, 1)=%s AND m.created_at >= d AND m.created_at < d + interval '1 day') AS msgs,
                          (SELECT count(*) FROM appointments a WHERE a.clinic_id=%s AND a.created_at >= d AND a.created_at < d + interval '1 day') AS appts
                        FROM generate_series(%s::timestamptz, %s::timestamptz, interval '1 day') d ORDER BY d""", cid, cid, start, s)
    can_fin_view = bool((u.get("permissions") or {}).get("finance_view", False))
    res_ov = {
        "today": {"appointments": len(active), "confirmed": sum(1 for a in active if a["status"] == "confirmed"), "occupancy": occ},
        "attendance_30d": {"done": att["done"], "noshow": att["noshow"], "noshow_rate": noshow_rate},
        "tokens_30d": {"replies": tok["total"], "llm_free_pct": round(100 * tok["free"] / tok["total"]) if tok["total"] else None,
                       "tokens": tok["tokens"]},
        "counts": misc,
        "series": [{"day": (start + timedelta(days=i)).strftime("%d.%m"), "msgs": r["msgs"], "appts": r["appts"]}
                   for i, r in enumerate(series)],
    }
    if can_fin_view:
        res_ov["loss"] = {"noshow_30d_try": tl(att["noshow"] * avg_ticket), "avg_ticket_try": tl(avg_ticket)}
        res_ov["month"] = {"billed_try": tl(money["billed"]), "paid_try": tl(money["paid"])}
    return res_ov


# ======================================================================== takvim
class ApptCreate(BaseModel):
    patient_id: int | None = None
    phone: str | None = Field(default=None, max_length=30)
    name: str | None = Field(default=None, max_length=80)
    starts_at: datetime
    duration_min: int = Field(30, ge=5, le=480)
    treatment: str = Field(min_length=2, max_length=80)
    chair: str = Field("1", max_length=10)
    doctor_id: int | None = None


@router.get("/app/api/appointments")
async def list_appts(start: datetime, end: datetime, u: dict = Depends(ANY)):
    if end - start > timedelta(days=62):
        raise HTTPException(400, "aralık en fazla 62 gün")
    cid = u["clinic_id"]
    perms = u.get("permissions") or {}
    sql_a = """SELECT a.id, a.starts_at, a.duration_min, a.treatment, a.chair, a.status, a.source, a.patient_id,
                      p.display_name AS patient, d.full_name AS doctor,
                      EXISTS (SELECT 1 FROM anamnesis x WHERE x.patient_id=a.patient_id AND cardinality(x.red_flags) > 0) AS red_flag
               FROM appointments a LEFT JOIN patients p ON p.id=a.patient_id LEFT JOIN staff_users d ON d.id=a.doctor_id
               WHERE a.clinic_id=%s AND a.starts_at >= %s AND a.starts_at < %s"""
    args_a: list = [cid, start, end]
    if perms.get("doctor_own_patients_only") and u.get("role") != "owner":
        sql_a += " AND (a.doctor_id=%s OR p.primary_doctor_id=%s)"
        args_a.extend([u["id"], u["id"]])
    sql_a += " ORDER BY a.starts_at"
    rows = await q(sql_a, *args_a)
    for r in rows:
        r["google_cal_url"] = cal.google_calendar_url(r, u.get("clinic_name") or S.clinic, u.get("clinic_address") or "")
    return rows


@router.get("/app/api/appointments/{aid}/ics")
async def appt_ics(aid: int, u: dict = Depends(ANY)):
    r = await q1("""SELECT a.id, a.patient_id, a.starts_at, a.duration_min, a.treatment, a.chair, a.status,
                           p.display_name AS patient, d.full_name AS doctor
                    FROM appointments a LEFT JOIN patients p ON p.id=a.patient_id LEFT JOIN staff_users d ON d.id=a.doctor_id
                    WHERE a.id=%s AND a.clinic_id=%s""", aid, u["clinic_id"])
    if not r:
        raise HTTPException(404, "randevu yok")
    if r.get("patient_id"):
        await _enforce_doc_own_patient_pg(u["clinic_id"], int(r["patient_id"]), u)
    body = cal.appointment_ics(r, u.get("clinic_name") or S.clinic, u.get("clinic_address") or "")
    return PlainTextResponse(body, media_type="text/calendar; charset=utf-8",
                             headers={"content-disposition": f'attachment; filename="randevu-{aid}.ics"'})


async def _build_calendar_links(request: Request, cid: int, version: int) -> dict:
    tok = cal.calendar_feed_token(cid, version=version)
    base = str(request.base_url).rstrip("/")
    ics_url = f"{base}/calendar/{tok}.ics"
    webcal_url = "webcal://" + ics_url.split("://", 1)[-1]
    google_subscribe_url = "https://calendar.google.com/calendar/r?cid=" + quote(webcal_url, safe="")
    return {
        "ics_url": ics_url,
        "webcal_url": webcal_url,
        "google_subscribe_url": google_subscribe_url,
        "token_version": version,
        "expires_days": 90,
        "iphone_guide": "Ayarlar > Takvim > Hesaplar > Hesap Ekle > Diğer > Abone Olunan Takvim Ekle kısmına webcal adresini yapıştırın veya bağlantıya doğrudan dokunun.",
        "android_guide": "Her randevudaki '+ Android / Google Takvim' butonuna basarak Google Takviminize ekleyin veya Diğer Takvimler > URL ile bölümüne ics adresini girin.",
    }


@router.get("/app/api/calendar-links")
async def calendar_links(request: Request, u: dict = Depends(ANY)):
    c = await q1("SELECT coalesce(cal_token_version, 1) AS ver FROM clinics WHERE id=%s", u["clinic_id"])
    ver = int(c["ver"]) if c else 1
    return await _build_calendar_links(request, u["clinic_id"], ver)


@router.post("/app/api/calendar-links/rotate")
async def calendar_links_rotate(request: Request, u: dict = Depends(OWNER)):
    cid = u["clinic_id"]
    c = await q1("UPDATE clinics SET cal_token_version = coalesce(cal_token_version, 1) + 1 WHERE id=%s RETURNING cal_token_version", cid)
    ver = int(c["cal_token_version"]) if c else 2
    await log(u, "calendar.token_rotate", f"clinic:{cid}", {"version": ver})
    return await _build_calendar_links(request, cid, ver)


@router.get("/app/api/calendar/all.ics")
async def calendar_all_ics(u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    perms = u.get("permissions") or {}
    sql_ics = """SELECT a.id, a.starts_at, a.duration_min, a.treatment, a.chair, a.status,
                        p.display_name AS patient, d.full_name AS doctor
                 FROM appointments a LEFT JOIN patients p ON p.id=a.patient_id LEFT JOIN staff_users d ON d.id=a.doctor_id
                 WHERE a.clinic_id=%s AND a.status IN ('booked','confirmed')"""
    args_ics: list = [cid]
    if perms.get("doctor_own_patients_only") and u.get("role") != "owner":
        sql_ics += " AND (a.doctor_id=%s OR p.primary_doctor_id=%s)"
        args_ics.extend([u["id"], u["id"]])
    sql_ics += " ORDER BY a.starts_at LIMIT 500"
    rows = await q(sql_ics, *args_ics)
    body = cal.feed_ics(rows, u.get("clinic_name") or S.clinic, u.get("clinic_address") or "")
    return PlainTextResponse(body, media_type="text/calendar; charset=utf-8",
                             headers={"content-disposition": f'attachment; filename="dentacore-klinik-{cid}-takvim.ics"'})


@router.get("/calendar/{token}.ics")
async def calendar_feed(token: str):
    parsed = cal.verify_feed_token_parts(token)
    if not parsed:
        raise HTTPException(403, "geçersiz veya süresi dolmuş takvim bağlantısı")
    cid, ver = parsed
    c = await q1("SELECT name, address, coalesce(cal_token_version, 1) AS ver FROM clinics WHERE id=%s AND active", cid)
    if not c or int(c["ver"]) != ver:
        raise HTTPException(403, "takvim bağlantısı iptal edilmiş veya geçersiz")
    cname = c["name"] or S.clinic
    caddr = c["address"] or ""
    rows = await q("""SELECT a.id, a.starts_at, a.duration_min, a.treatment, a.chair, a.status,
                             p.display_name AS patient, d.full_name AS doctor
                      FROM appointments a LEFT JOIN patients p ON p.id=a.patient_id LEFT JOIN staff_users d ON d.id=a.doctor_id
                      WHERE a.clinic_id=%s AND a.starts_at > now() - interval '30 days'
                      ORDER BY a.starts_at LIMIT 500""", cid)
    return PlainTextResponse(cal.feed_ics(rows, cname, caddr), media_type="text/calendar; charset=utf-8")


DEFAULT_WORKING_HOURS_JSON = '{"mon_fri":["09:00","19:00"],"sat":["09:00","15:00"],"sun":null}'
VALID_FDI_TEETH = {
    *{n for qd in (10, 20, 30, 40) for n in range(qd + 1, qd + 9)},
    *{n for qd in (50, 60, 70, 80) for n in range(qd + 1, qd + 6)},
}


def _parse_hhmm(val: str) -> int:
    parts = str(val or "00:00").strip().split(":")
    return int(parts[0]) * 60 + (int(parts[1]) if len(parts) > 1 else 0)


def validate_working_hours(starts: datetime, duration_min: int, working_hours_json: str | None = None):
    s_loc = (starts if starts.tzinfo else starts.replace(tzinfo=TZ)).astimezone(TZ)
    e_loc = (s_loc + timedelta(minutes=duration_min)).astimezone(TZ)
    if s_loc.date() != e_loc.date():
        raise HTTPException(422, "Randevu aynı gün içinde başlamalı ve bitmelidir")
    try:
        wh = json.loads(working_hours_json or DEFAULT_WORKING_HOURS_JSON)
        if not isinstance(wh, dict):
            wh = json.loads(DEFAULT_WORKING_HOURS_JSON)
    except Exception:
        wh = json.loads(DEFAULT_WORKING_HOURS_JSON)

    wd = s_loc.weekday()
    day_keys = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
    dkey = day_keys[wd]
    if dkey in wh:
        hrs = wh[dkey]
    elif wd < 5:
        hrs = wh.get("mon_fri", ["09:00", "19:00"])
    elif wd == 5:
        hrs = wh.get("sat", ["09:00", "15:00"])
    else:
        hrs = wh.get("sun", None)

    if not hrs or not isinstance(hrs, (list, tuple)) or len(hrs) < 2 or not hrs[0] or not hrs[1]:
        raise HTTPException(422, "Seçilen gün klinik kapalıdır (kapalı güne randevu oluşturulamaz)")

    open_m = _parse_hhmm(hrs[0])
    close_m = _parse_hhmm(hrs[1])
    s_m = s_loc.hour * 60 + s_loc.minute
    e_m = e_loc.hour * 60 + e_loc.minute
    if s_m < open_m or e_m > close_m:
        raise HTTPException(422, f"Randevu saati klinik çalışma saatleri ({hrs[0]}-{hrs[1]}) dışındadır")


async def _require_active_patient(pid: int, cid: int) -> dict:
    p = await q1("SELECT * FROM patients WHERE id=%s AND clinic_id=%s", pid, cid)
    if not p:
        raise HTTPException(404, "hasta yok")
    if not p.get("active", True):
        raise HTTPException(409, "Arşivlenmiş hasta için yeni işlem oluşturulamaz; önce aktifleştirin")
    return p


@router.get("/app/api/appointments/available")
async def available_appts(
    date: str | None = None,
    duration: int = Query(30, ge=5, le=480),
    chair: str | None = None,
    u: dict = Depends(ANY),
):
    cid = u["clinic_id"]
    if date:
        try:
            target_date = datetime.strptime(date, "%Y-%m-%d").date()
        except ValueError:
            raise HTTPException(400, "Geçersiz tarih formatı (YYYY-MM-DD olmalı)") from None
    else:
        target_date = datetime.now(TZ).date()
    cinfo = await q1("SELECT chairs, slot_step_min, working_hours_json, buffer_min FROM clinics WHERE id=%s", cid) or {
        "chairs": S.chairs, "slot_step_min": 15, "working_hours_json": DEFAULT_WORKING_HOURS_JSON, "buffer_min": 0,
    }
    max_chairs = max(1, int(cinfo.get("chairs") or S.chairs))
    step_min = max(5, int(cinfo.get("slot_step_min") or 30))
    buf_min = max(0, int(cinfo.get("buffer_min") or 0))
    if chair is not None:
        if not str(chair).isdigit() or not (1 <= int(chair) <= max_chairs):
            raise HTTPException(400, f"Geçersiz koltuk numarası (bu şubede {max_chairs} koltuk var)")
        chair_list = [str(chair)]
    else:
        chair_list = [str(i) for i in range(1, max_chairs + 1)]
    day_start_loc = datetime(target_date.year, target_date.month, target_date.day, 0, 0, tzinfo=TZ)
    try:
        wh = json.loads(cinfo.get("working_hours_json") or DEFAULT_WORKING_HOURS_JSON)
    except Exception:
        wh = json.loads(DEFAULT_WORKING_HOURS_JSON)
    wd = day_start_loc.weekday()
    day_keys = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
    hrs = wh.get(day_keys[wd]) if day_keys[wd] in wh else (wh.get("mon_fri", ["09:00", "19:00"]) if wd < 5 else (wh.get("sat", ["09:00", "15:00"]) if wd == 5 else wh.get("sun")))
    if not hrs or not isinstance(hrs, (list, tuple)) or len(hrs) < 2 or not hrs[0] or not hrs[1]:
        return {"date": target_date.isoformat(), "duration": duration, "chairs": max_chairs, "closed": True, "slots": []}
    open_m, close_m = _parse_hhmm(hrs[0]), _parse_hhmm(hrs[1])
    day_end_loc = day_start_loc + timedelta(days=1)
    active_rows = await q(
        "SELECT starts_at, duration_min, chair FROM appointments WHERE clinic_id=%s AND status IN ('booked','confirmed') AND starts_at >= %s AND starts_at < %s",
        cid, day_start_loc - timedelta(hours=12), day_end_loc + timedelta(hours=12),
    )
    busy: list[tuple[datetime, datetime, str]] = []
    for ex_a in active_rows:
        s2 = ex_a["starts_at"] if ex_a["starts_at"].tzinfo else ex_a["starts_at"].replace(tzinfo=TZ)
        e2 = s2 + timedelta(minutes=int(ex_a["duration_min"] or 30) + buf_min)
        busy.append((s2, e2, str(ex_a["chair"])))
    min_start = datetime.now(timezone.utc) - timedelta(minutes=1)
    slots: list[dict] = []
    cur_m = open_m
    while cur_m + duration <= close_m:
        cand_s = day_start_loc + timedelta(minutes=cur_m)
        if cand_s >= min_start:
            cand_e = cand_s + timedelta(minutes=duration + buf_min)
            free_chairs = [ch for ch in chair_list if not any(s2 < cand_e and e2 > cand_s and ch2 == ch for s2, e2, ch2 in busy)]
            if free_chairs:
                slots.append({
                    "starts_at": cand_s.isoformat(),
                    "time": cand_s.strftime("%H:%M"),
                    "end_time": (cand_s + timedelta(minutes=duration)).strftime("%H:%M"),
                    "available_chairs": free_chairs,
                })
        cur_m += step_min
    return {
        "date": target_date.isoformat(), "duration": duration, "chairs": max_chairs, "closed": False,
        "working_hours": [f"{open_m // 60:02d}:{open_m % 60:02d}", f"{close_m // 60:02d}:{close_m % 60:02d}"],
        "slots": slots,
    }


@router.post("/app/api/appointments")
async def create_appt(b: ApptCreate, u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    cinfo = await q1("SELECT chairs, working_hours_json, buffer_min FROM clinics WHERE id=%s", cid)
    max_chairs = int((cinfo and cinfo["chairs"]) or S.chairs)
    if not b.chair.isdigit() or not (1 <= int(b.chair) <= max_chairs):
        raise HTTPException(400, f"Geçersiz koltuk numarası (bu şubede {max_chairs} koltuk var)")
    starts = b.starts_at if b.starts_at.tzinfo else b.starts_at.replace(tzinfo=TZ)
    if starts < datetime.now(timezone.utc) - timedelta(minutes=5):
        raise HTTPException(400, "Geçmiş tarihe randevu oluşturulamaz")
    validate_working_hours(starts, b.duration_min, (cinfo and cinfo.get("working_hours_json")) or DEFAULT_WORKING_HOURS_JSON)
    if b.doctor_id is not None:
        if not await q1("SELECT id FROM staff_users WHERE id=%s AND clinic_id=%s", b.doctor_id, cid):
            raise HTTPException(404, "hekim yok")
    pid = b.patient_id
    if pid is not None:
        await _enforce_doc_own_patient_pg(cid, pid, u)
        await _require_active_patient(pid, cid)
    else:
        if not b.phone or len(norm_phone(b.phone)) < 10:
            raise HTTPException(400, "Hasta seçin veya geçerli telefon girin")
        ex_p = await q1("SELECT id, active FROM patients WHERE clinic_id=%s AND phone_hmac=%s", cid, phone_hmac(b.phone))
        if ex_p:
            if not ex_p.get("active", True):
                raise HTTPException(409, "Arşivlenmiş hasta için yeni işlem oluşturulamaz; önce aktifleştirin")
            pid = ex_p["id"]
            await _enforce_doc_own_patient_pg(cid, pid, u)
    buf_min = max(0, int((cinfo and cinfo.get("buffer_min")) or 0))
    ends = starts + timedelta(minutes=b.duration_min + buf_min)
    async with tx() as t:
        # Aynı koltuğa eşzamanlı iki kayıt yarışını engelle
        await t.q("SELECT pg_advisory_xact_lock(hashtext(%s))", f"chair:{cid}:{b.chair}")
        clash = await t.q1("""SELECT id FROM appointments WHERE clinic_id=%s AND chair=%s AND status IN ('booked','confirmed')
                              AND starts_at < %s AND starts_at + make_interval(mins => duration_min + %s) > %s LIMIT 1""",
                           cid, b.chair, ends, buf_min, starts)
        if clash:
            raise HTTPException(409, f"Koltuk {b.chair} bu saatte dolu (randevu #{clash['id']})")
        if b.doctor_id is not None:
            doc_clash = await t.q1("""SELECT id FROM appointments WHERE clinic_id=%s AND doctor_id=%s AND status IN ('booked','confirmed')
                                      AND starts_at < %s AND starts_at + make_interval(mins => duration_min + %s) > %s LIMIT 1""",
                                   cid, b.doctor_id, ends, buf_min, starts)
            if doc_clash:
                raise HTTPException(409, f"Seçilen hekim bu saatte başka koltukta dolu (randevu #{doc_clash['id']})")
        if pid is None:
            p_norm = norm_phone(b.phone or "")
            p_row = await t.q1(
                """INSERT INTO patients (clinic_id, phone_hmac, phone_enc, display_name, lang)
                   VALUES (%s,%s,%s,%s,'tr')
                   ON CONFLICT (clinic_id, phone_hmac) DO UPDATE
                     SET display_name = COALESCE(patients.display_name, EXCLUDED.display_name)
                   RETURNING id""",
                cid, phone_hmac(p_norm), enc(p_norm), b.name,
            )
            pid = p_row["id"]
        r = await t.q1("""INSERT INTO appointments (clinic_id, patient_id, starts_at, duration_min, treatment, chair, doctor_id, source)
                          VALUES (%s,%s,%s,%s,%s,%s,%s,'panel') RETURNING id""", cid, pid, starts, b.duration_min, b.treatment, b.chair, b.doctor_id)
    await log(u, "appointment.create", f"appointment:{r['id']}", {"chair": b.chair})
    return {"id": r["id"], "patient_id": pid}


class ApptUpdate(BaseModel):
    starts_at: datetime | None = None
    duration_min: int | None = Field(default=None, ge=5, le=480)
    treatment: str | None = Field(default=None, min_length=2, max_length=80)
    chair: str | None = Field(default=None, max_length=10)
    doctor_id: int | None = None


@router.patch("/app/api/appointments/{aid}")
async def update_appt(aid: int, b: ApptUpdate, u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    cinfo = await q1("SELECT chairs, working_hours_json, buffer_min FROM clinics WHERE id=%s", cid)
    max_chairs = int((cinfo and cinfo["chairs"]) or S.chairs)
    buf_min = max(0, int((cinfo and cinfo.get("buffer_min")) or 0))
    async with tx() as t:
        cur_row = await t.q1("SELECT * FROM appointments WHERE id=%s AND clinic_id=%s", aid, cid)
        if not cur_row:
            raise HTTPException(404, "randevu yok")
        if cur_row.get("patient_id"):
            await _enforce_doc_own_patient_pg(cid, int(cur_row["patient_id"]), u)
        chair = str(b.chair if b.chair is not None else cur_row["chair"])
        if not chair.isdigit() or not (1 <= int(chair) <= max_chairs):
            raise HTTPException(400, f"Geçersiz koltuk numarası (bu şubede {max_chairs} koltuk var)")
        doc_id = b.doctor_id if b.doctor_id is not None else cur_row["doctor_id"]
        if doc_id is not None and not await t.q1("SELECT id FROM staff_users WHERE id=%s AND clinic_id=%s", doc_id, cid):
            raise HTTPException(404, "hekim yok")
        starts = (b.starts_at if b.starts_at.tzinfo else b.starts_at.replace(tzinfo=TZ)) if b.starts_at else cur_row["starts_at"]
        if starts < datetime.now(timezone.utc) - timedelta(minutes=5):
            raise HTTPException(400, "Geçmiş tarihe randevu taşınamaz")
        dur = b.duration_min if b.duration_min is not None else cur_row["duration_min"]
        validate_working_hours(starts, dur, (cinfo and cinfo.get("working_hours_json")) or DEFAULT_WORKING_HOURS_JSON)
        treat = b.treatment if b.treatment is not None else cur_row["treatment"]
        ends = starts + timedelta(minutes=dur + buf_min)
        await t.q("SELECT pg_advisory_xact_lock(hashtext(%s))", f"chair:{cid}:{chair}")
        clash = await t.q1(
            """SELECT id FROM appointments WHERE clinic_id=%s AND id<>%s AND chair=%s AND status IN ('booked','confirmed')
               AND starts_at < %s AND starts_at + make_interval(mins => duration_min + %s) > %s LIMIT 1""",
            cid, aid, chair, ends, buf_min, starts,
        )
        if clash:
            raise HTTPException(409, f"Koltuk {chair} bu saatte dolu (randevu #{clash['id']})")
        if doc_id is not None:
            doc_clash = await t.q1(
                """SELECT id FROM appointments WHERE clinic_id=%s AND id<>%s AND doctor_id=%s AND status IN ('booked','confirmed')
                   AND starts_at < %s AND starts_at + make_interval(mins => duration_min + %s) > %s LIMIT 1""",
                cid, aid, doc_id, ends, buf_min, starts,
            )
            if doc_clash:
                raise HTTPException(409, f"Seçilen hekim bu saatte başka koltukta dolu (randevu #{doc_clash['id']})")
        await t.q(
            "UPDATE appointments SET starts_at=%s, duration_min=%s, treatment=%s, chair=%s, doctor_id=%s WHERE id=%s AND clinic_id=%s",
            starts, dur, treat, chair, doc_id, aid, cid,
        )
    await log(u, "appointment.update", f"appointment:{aid}", {"chair": chair})
    return {"ok": True, "id": aid}


class StatusIn(BaseModel):
    status: Literal["booked", "confirmed", "done", "noshow", "cancelled"]


@router.post("/app/api/appointments/{aid}/status")
async def appt_status(aid: int, b: StatusIn, u: dict = Depends(require_perm("edit"))):
    cid = u["clinic_id"]
    if b.status == "cancelled" and not (u.get("permissions") or {}).get("delete_cancel", False):
        raise HTTPException(403, "Randevu iptal etme (delete_cancel) yetkiniz bulunmamaktadır")
    a = await q1("SELECT id, patient_id, status, starts_at, duration_min, chair, doctor_id, treatment, satisfaction_sent_at FROM appointments WHERE id=%s AND clinic_id=%s", aid, cid)
    if not a:
        raise HTTPException(404, "randevu yok")
    if a.get("patient_id"):
        await _enforce_doc_own_patient_pg(cid, int(a["patient_id"]), u)
    prev_status = a["status"]
    if b.status in ("booked", "confirmed") and prev_status not in ("booked", "confirmed"):
        cinfo = await q1("SELECT buffer_min FROM clinics WHERE id=%s", cid)
        buf_min = max(0, int((cinfo and cinfo.get("buffer_min")) or 0))
        starts = a["starts_at"] if a["starts_at"].tzinfo else a["starts_at"].replace(tzinfo=TZ)
        ends = starts + timedelta(minutes=int(a["duration_min"] or 30) + buf_min)
        clash = await q1(
            """SELECT id FROM appointments WHERE clinic_id=%s AND id<>%s AND chair=%s AND status IN ('booked','confirmed')
               AND starts_at < %s AND starts_at + make_interval(mins => duration_min + %s) > %s LIMIT 1""",
            cid, aid, str(a["chair"]), ends, buf_min, starts,
        )
        if clash:
            raise HTTPException(409, f"Koltuk {a['chair']} bu saatte artık dolu (randevu #{clash['id']}); randevu geri alınamıyor")
        if a.get("doctor_id") is not None:
            doc_clash = await q1(
                """SELECT id FROM appointments WHERE clinic_id=%s AND id<>%s AND doctor_id=%s AND status IN ('booked','confirmed')
                   AND starts_at < %s AND starts_at + make_interval(mins => duration_min + %s) > %s LIMIT 1""",
                cid, aid, a["doctor_id"], ends, buf_min, starts,
            )
            if doc_clash:
                raise HTTPException(409, f"Seçilen hekim bu saatte artık başka koltukta dolu (randevu #{doc_clash['id']}); randevu geri alınamıyor")
        await q("UPDATE slot_offers SET status='expired' WHERE appointment_id=%s AND status='sent'", aid)
    if b.status == "cancelled":
        await modules.cancel_and_refill(aid, reason="panel_iptal", clinic_id=cid)
        offers = await q1("SELECT count(*) AS n FROM slot_offers WHERE appointment_id=%s", aid)
        await log(u, "appointment.cancel", f"appointment:{aid}", {"offers": offers["n"]})
        return {"ok": True, "waitlist_offers": offers["n"]}
    await q("UPDATE appointments SET status=%s WHERE id=%s AND clinic_id=%s", b.status, aid, cid)
    if b.status == "done" and a["patient_id"] and not a.get("satisfaction_sent_at"):
        await modules.request_feedback(a["patient_id"], appt_id=aid, clinic_id=cid, treatment=a.get("treatment") or "tedavi")
    audit_action = "appointment.undo_cancel" if (prev_status == "cancelled" and b.status == "booked") else f"appointment.{b.status}"
    await log(u, audit_action, f"appointment:{aid}", {"from": prev_status, "to": b.status})
    return {"ok": True, "status": b.status}


# ======================================================================== hastalar
class PatientIn(BaseModel):
    phone: str = Field(max_length=30)
    name: str = Field(min_length=2, max_length=80)
    lang: Literal["tr", "en", "de", "ar", "ru", "fr", "nl", "es", "it", "fa", "az", "uk", "bg", "ro", "el", "he"] = "tr"


BAL_SQL = """(SELECT coalesce(sum(amount_kurus),0) FROM charges c WHERE c.patient_id=p.id AND c.voided_at IS NULL)
           - (SELECT coalesce(sum(amount_kurus),0) FROM payments y WHERE y.patient_id=p.id AND y.voided_at IS NULL)"""


@router.get("/app/api/patients")
async def list_patients(search: str = "", include_archived: bool = False, u: dict = Depends(require_perm("patient_view"))):
    cid = u["clinic_id"]
    perms = u.get("permissions") or {}
    can_fin_view = bool(perms.get("finance_view", False))
    search = search.strip()[:60]
    act_clause = "" if include_archived else " AND p.active"
    if search and len(re.sub(r"\D", "", search)) >= 10:
        where, args = f"p.clinic_id=%s{act_clause} AND p.phone_hmac=%s", [cid, phone_hmac(search)]
    elif search:
        where, args = f"p.clinic_id=%s{act_clause} AND p.display_name ILIKE %s", [cid, f"%{search}%"]
    else:
        where, args = f"p.clinic_id=%s{act_clause}", [cid]
    if perms.get("doctor_own_patients_only") and u.get("role") != "owner":
        where += """ AND (p.primary_doctor_id=%s OR p.created_by=%s
                         OR EXISTS (SELECT 1 FROM appointments ap WHERE ap.patient_id=p.id AND ap.doctor_id=%s)
                         OR EXISTS (SELECT 1 FROM tooth_records tr WHERE tr.patient_id=p.id AND tr.doctor_id=%s))"""
        args.extend([u["id"], u["id"], u["id"], u["id"]])
    rows = await q(f"""SELECT p.id, p.display_name, p.lang, p.channel, p.active, p.created_at, {BAL_SQL} AS balance,
                              EXISTS (SELECT 1 FROM anamnesis x WHERE x.patient_id=p.id AND cardinality(x.red_flags) > 0) AS red_flag,
                              (SELECT max(starts_at) FROM appointments a WHERE a.patient_id=p.id) AS last_appt
                       FROM patients p WHERE {where} ORDER BY p.created_at DESC LIMIT 200""", *args)  # nosec B608  # noqa: S608
    for r in rows:
        r["balance"] = tl(r["balance"]) if can_fin_view else 0.0
    return rows


@router.post("/app/api/patients")
async def create_patient(b: PatientIn, u: dict = Depends(require_perm("patient_edit", "create"))):
    if len(norm_phone(b.phone)) < 10:
        raise HTTPException(400, "Geçerli telefon girin")
    pid = await upsert_patient(b.phone, lang=b.lang, name=b.name, clinic_id=u["clinic_id"])
    await log(u, "patient.create", f"patient:{pid}")
    return {"id": pid}


@router.get("/app/api/patients/{pid}")
async def get_patient(pid: int, reveal: bool = False, u: dict = Depends(require_perm("patient_view"))):
    cid = u["clinic_id"]
    await _enforce_doc_own_patient_pg(cid, pid, u)
    p = await q1(f"SELECT p.*, {BAL_SQL} AS balance FROM patients p WHERE p.id=%s AND p.clinic_id=%s", pid, cid)  # nosec B608  # noqa: S608
    if not p:
        raise HTTPException(404, "hasta yok")
    phone = dec(p["phone_enc"])
    await log(u, "patient.reveal_phone" if reveal else "patient.view", f"patient:{pid}")
    appts = await q("SELECT id, starts_at, treatment, status, chair FROM appointments WHERE patient_id=%s ORDER BY starts_at DESC LIMIT 50", pid)
    charges = await q("SELECT id, description, amount_kurus, created_at, voided_at FROM charges WHERE patient_id=%s ORDER BY created_at DESC LIMIT 100", pid)
    pays = await q("SELECT id, amount_kurus, method, created_at, voided_at FROM payments WHERE patient_id=%s ORDER BY created_at DESC LIMIT 100", pid)
    anam = await q("SELECT id, red_flags, signed_at FROM anamnesis WHERE patient_id=%s ORDER BY signed_at DESC LIMIT 5", pid)
    consents = await q("SELECT id, kind, text_version, text_sha256, channel, granted_at, revoked_at FROM consents WHERE patient_id=%s ORDER BY granted_at DESC", pid)
    for c in charges + pays:
        c["amount"] = tl(c.pop("amount_kurus"))
    if u["role"] not in ("owner", "doctor"):
        for a in anam:
            if a.get("red_flags"):
                a["red_flags"] = ["Klinik Uyarı (Hekim Kontrolü)"]
    can_fin_view = bool((u.get("permissions") or {}).get("finance_view", False))
    res_p = {
        "id": p["id"], "name": p["display_name"], "lang": p["lang"], "channel": p["channel"],
        "active": bool(p.get("active", True)),
        "phone": phone if reveal else mask_phone(phone),
        "balance": tl(p["balance"]) if can_fin_view else 0.0,
        "finance_summary": {"balance": tl(p["balance"])} if can_fin_view else {"masked": True},
        "appointments": appts,
        "payments": pays if can_fin_view else [],
        "anamnesis": anam, "consents": consents,
        "anamnesis_links": {a["id"]: modules.sign(f"/view/anamnez/{a['id']}", ttl=900) for a in anam} if u["role"] in ("owner", "doctor") else {},
    }
    if can_fin_view:
        res_p["charges"] = charges
    return res_p


class ConsentRevokeIn(BaseModel):
    kind: Literal["kvkk_aydinlatma", "saglik_verisi_acik_riza", "iletisim", "yurt_disi_aktarim", "all"] | None = None
    consent_id: int | None = None


@router.post("/app/api/patients/{pid}/consents/revoke")
async def revoke_patient_consent(pid: int, b: ConsentRevokeIn, u: dict = Depends(OWNER)):
    cid = u["clinic_id"]
    p = await q1("SELECT id FROM patients WHERE id=%s AND clinic_id=%s", pid, cid)
    if not p:
        raise HTTPException(404, "hasta yok")
    if b.consent_id is not None:
        rows = await q(
            "UPDATE consents SET revoked_at=now() WHERE id=%s AND patient_id=%s AND revoked_at IS NULL RETURNING id, kind, revoked_at",
            b.consent_id, pid,
        )
    elif b.kind and b.kind != "all":
        rows = await q(
            "UPDATE consents SET revoked_at=now() WHERE patient_id=%s AND kind=%s AND revoked_at IS NULL RETURNING id, kind, revoked_at",
            pid, b.kind,
        )
    else:
        rows = await q(
            "UPDATE consents SET revoked_at=now() WHERE patient_id=%s AND revoked_at IS NULL RETURNING id, kind, revoked_at",
            pid,
        )
    await log(u, "patient.consent_revoke", f"patient:{pid}", {"kind": b.kind or f"id:{b.consent_id}", "count": len(rows)})
    return {"ok": True, "patient_id": pid, "revoked_count": len(rows)}


@router.get("/app/api/patients/{pid}/export")
async def export_patient_data(pid: int, u: dict = Depends(OWNER)):
    cid = u["clinic_id"]
    p = await q1("SELECT * FROM patients WHERE id=%s AND clinic_id=%s", pid, cid)
    if not p:
        raise HTTPException(404, "hasta yok")
    try:
        phone = dec(p["phone_enc"])
    except Exception:
        phone = "***"
    anam_rows = await q("SELECT id, answers_enc, red_flags, signer_name, signature_sha256, signed_at FROM anamnesis WHERE patient_id=%s ORDER BY id", pid)
    anam_out = []
    for a in anam_rows:
        try:
            ans = json.loads(dec(a["answers_enc"]))
        except Exception:
            ans = {}
        anam_out.append({
            "id": a["id"], "answers": ans, "red_flags": a.get("red_flags") or [],
            "signer_name": a["signer_name"], "signature_sha256": a["signature_sha256"], "signed_at": a["signed_at"],
        })
    charges = await q("SELECT id, description, amount_kurus, created_at, voided_at, void_reason FROM charges WHERE patient_id=%s ORDER BY id", pid)
    pays = await q("SELECT id, amount_kurus, method, created_at, voided_at, void_reason FROM payments WHERE patient_id=%s ORDER BY id", pid)
    for c in charges + pays:
        c["amount"] = tl(c.pop("amount_kurus"))
    await log(u, "patient.export", f"patient:{pid}")
    return {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "clinic_id": cid,
        "patient": {
            "id": p["id"], "display_name": p["display_name"], "phone": phone,
            "lang": p["lang"], "channel": p["channel"], "active": bool(p.get("active", True)), "created_at": p["created_at"],
        },
        "consents": await q("SELECT id, kind, text_version, text_sha256, channel, granted_at, revoked_at FROM consents WHERE patient_id=%s ORDER BY id", pid),
        "anamnesis": anam_out,
        "appointments": await q("SELECT id, starts_at, duration_min, treatment, chair, status, source, created_at FROM appointments WHERE patient_id=%s ORDER BY id", pid),
        "tooth_records": await q("SELECT id, tooth_fdi, surface, status, procedure_code, procedure_name, note, created_at FROM tooth_records WHERE patient_id=%s AND clinic_id=%s ORDER BY id", pid, cid),
        "charges": charges,
        "payments": pays,
        "waitlist": await q("SELECT id, treatment, earliest, active, created_at FROM waitlist WHERE patient_id=%s ORDER BY id", pid),
        "postop_checks": await q("SELECT id, procedure, stage, due_at, sent_at, pain_score, answered_at, alarm FROM postop_checks WHERE patient_id=%s ORDER BY id", pid),
    }


async def _anonymize_patient_impl(pid: int, u: dict) -> dict:
    cid = u["clinic_id"]
    p = await q1("SELECT id FROM patients WHERE id=%s AND clinic_id=%s", pid, cid)
    if not p:
        raise HTTPException(404, "hasta yok")
    now_s = datetime.now(timezone.utc).isoformat()
    anon_hmac = hmac.new(os.environ.get("PHONE_HMAC_KEY", "").encode(), f"anon:{cid}:{pid}:{secrets.token_hex(8)}".encode(), hashlib.sha256).hexdigest()
    anon_enc = enc(f"anon-{pid}")
    anon_ans = enc(json.dumps({"anonymized": True, "at": now_s}))
    anon_sig = hashlib.sha256(f"anon:{pid}:{now_s}".encode()).hexdigest()
    async with tx() as t:
        await t.q(
            "UPDATE patients SET display_name=%s, phone_hmac=%s, phone_enc=%s, notes_enc=NULL, active=false WHERE id=%s AND clinic_id=%s",
            f"Anonim Hasta #{pid}", anon_hmac, anon_enc, pid, cid,
        )
        await t.q(
            "UPDATE anamnesis SET signer_name='Anonimleştirildi', answers_enc=%s, red_flags='{}', signature_sha256=%s WHERE patient_id=%s",
            anon_ans, anon_sig, pid,
        )
        await t.q("DELETE FROM anamnesis_tokens WHERE patient_id=%s", pid)
        await t.q("DELETE FROM slot_offers WHERE waitlist_id IN (SELECT id FROM waitlist WHERE patient_id=%s)", pid)
        await t.q("DELETE FROM postop_checks WHERE patient_id=%s", pid)
        await t.q("UPDATE message_log SET body='', delivery_error=NULL WHERE patient_id=%s", pid)
        await t.q("UPDATE consents SET revoked_at=coalesce(revoked_at, now()) WHERE patient_id=%s", pid)
        await t.q("UPDATE alerts SET detail=%s, acknowledged_at=coalesce(acknowledged_at, now()) WHERE patient_id=%s",
                  f"Anonimleştirilmiş hasta (#{pid}) kaydı.", pid)
        await t.q("UPDATE waitlist SET active=false WHERE patient_id=%s", pid)
    await log(u, "patient.anonymize", f"patient:{pid}", {"financial_records_preserved": True})
    return {"ok": True, "patient_id": pid, "anonymized": True, "financial_records_preserved": True}


@router.post("/app/api/patients/{pid}/anonymize")
async def anonymize_patient(pid: int, u: dict = Depends(OWNER)):
    return await _anonymize_patient_impl(pid, u)


@router.delete("/app/api/patients/{pid}")
async def delete_patient(pid: int, u: dict = Depends(OWNER)):
    return await _anonymize_patient_impl(pid, u)


class OdontogramIn(BaseModel):
    tooth_fdi: int
    surface: Literal["M", "D", "O", "B", "L", "FULL"] = "FULL"
    status: Literal["healthy", "caries", "planned", "treated", "implant", "crown", "root_canal", "missing", "extraction"] = "planned"
    procedure_code: str = Field("", max_length=40)
    procedure_name: str = Field(min_length=2, max_length=120)
    amount: Decimal = Field(Decimal(0), ge=0, le=10_000_000)
    doctor_id: int | None = None
    note: str = Field("", max_length=300)
    auto_charge: bool = False
    idempotency_key: str | None = Field(default=None, max_length=80)

    @field_validator("tooth_fdi")
    @classmethod
    def check_fdi(cls, v: int) -> int:
        if v not in VALID_FDI_TEETH:
            raise ValueError("Geçersiz FDI diş numarası (11-48 daimi veya 51-85 süt dişi olmalı)")
        return v


class OdontogramUpdateIn(BaseModel):
    surface: Literal["M", "D", "O", "B", "L", "FULL"] | None = None
    status: Literal["healthy", "caries", "planned", "treated", "implant", "crown", "root_canal", "missing", "extraction"] | None = None
    procedure_code: str | None = Field(default=None, max_length=40)
    procedure_name: str | None = Field(default=None, min_length=2, max_length=120)
    amount: Decimal | None = Field(default=None, ge=0, le=10_000_000)
    doctor_id: int | None = None
    note: str | None = Field(default=None, max_length=300)


@router.get("/app/api/patients/{pid}/odontogram")
async def get_odontogram(pid: int, u: dict = Depends(require_perm("patient_view"))):
    cid = u["clinic_id"]
    await _enforce_doc_own_patient_pg(cid, pid, u)
    p = await q1("SELECT id FROM patients WHERE id=%s AND clinic_id=%s", pid, cid)
    if not p:
        raise HTTPException(404, "hasta yok")
    rows = await q(
        """SELECT t.*, s.full_name AS doctor_name
           FROM tooth_records t LEFT JOIN staff_users s ON s.id=t.doctor_id
           WHERE t.clinic_id=%s AND t.patient_id=%s ORDER BY t.tooth_fdi, t.id DESC""",
        cid, pid,
    )
    for r in rows:
        r["amount_try"] = tl(r["amount_kurus"])
    return {
        "patient_id": pid,
        "clinic_id": cid,
        "records": rows,
        "summary": {
            "total_records": len(rows),
            "treated_count": sum(1 for r in rows if r["status"] in ("treated", "implant", "crown", "root_canal")),
            "planned_count": sum(1 for r in rows if r["status"] in ("planned", "caries", "extraction")),
        },
    }


ODO_BILLABLE_STATUSES = frozenset({"treated", "implant", "crown", "root_canal"})


def _odo_charge_key(rid: int, client_key: str | None = None) -> str:
    return f"odo:{int(rid)}:{(client_key or '')[:60]}"[:80]


def _odo_charge_desc(fdi: int, surface: str, name: str) -> str:
    return f"Diş #{fdi} ({surface}) - {name}"[:120]


async def _odo_linked_charges(t, cid: int, pid: int, rec: dict) -> list:
    rows = await t.q("SELECT id FROM charges WHERE clinic_id=%s AND patient_id=%s AND voided_at IS NULL AND idempotency_key LIKE %s",
                     cid, pid, f"odo:{int(rec['id'])}:%")
    if rows:
        return [r["id"] for r in rows]
    rows = await t.q(
        """SELECT id FROM charges WHERE clinic_id=%s AND patient_id=%s AND voided_at IS NULL AND description=%s AND amount_kurus=%s
           AND (idempotency_key IS NULL OR idempotency_key NOT LIKE 'odo:%%') ORDER BY id LIMIT 1""",
        cid, pid, _odo_charge_desc(rec["tooth_fdi"], rec["surface"], rec["procedure_name"]), rec["amount_kurus"])
    return [r["id"] for r in rows]


@router.post("/app/api/patients/{pid}/odontogram")
async def add_odontogram_record(pid: int, b: OdontogramIn, u: dict = Depends(CLINICAL)):
    cid = u["clinic_id"]
    await _enforce_doc_own_patient_pg(cid, pid, u)
    await _require_active_patient(pid, cid)
    if b.doctor_id is not None and not await q1("SELECT id FROM staff_users WHERE id=%s AND clinic_id=%s", b.doctor_id, cid):
        raise HTTPException(404, "hekim yok")
    amt_k = kurus(b.amount)
    charge_id = None
    charge_skipped = None
    async with tx() as t:
        rec = await t.q1(
            """INSERT INTO tooth_records
               (clinic_id, patient_id, tooth_fdi, surface, status, procedure_code, procedure_name, amount_kurus, doctor_id, note)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
            cid, pid, b.tooth_fdi, b.surface, b.status, b.procedure_code, b.procedure_name, amt_k, b.doctor_id or u["id"], b.note,
        )
        if b.auto_charge and amt_k > 0 and b.status not in ODO_BILLABLE_STATUSES:
            charge_skipped = "planned_not_billable"  # P0-1: plan borç değildir
        elif b.auto_charge and amt_k > 0:
            if b.idempotency_key:
                dup = await t.q1("SELECT id FROM charges WHERE clinic_id=%s AND (idempotency_key=%s OR idempotency_key LIKE %s)",
                                 cid, b.idempotency_key, f"odo:%:{b.idempotency_key[:60]}")
                if dup:
                    raise HTTPException(409, "Bu odontogram hizmet borçlandırması zaten işlendi")
            ch = await t.q1(
                """INSERT INTO charges (clinic_id, patient_id, description, amount_kurus, doctor_id, created_by, idempotency_key)
                   VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
                cid, pid, _odo_charge_desc(b.tooth_fdi, b.surface, b.procedure_name), amt_k, b.doctor_id or u["id"], u["id"],
                _odo_charge_key(rec["id"], b.idempotency_key),
            )
            charge_id = ch["id"]
    await log(u, "odontogram.create", f"patient:{pid}:tooth:{b.tooth_fdi}",
              {"surface": b.surface, "status": b.status, "charge_id": charge_id, "charge_skipped": charge_skipped})
    return {"id": rec["id"], "tooth_fdi": b.tooth_fdi, "surface": b.surface, "status": b.status, "charge_id": charge_id,
            "charge_skipped": charge_skipped}


@router.patch("/app/api/patients/{pid}/odontogram/{rid}")
async def update_odontogram_record(pid: int, rid: int, b: OdontogramUpdateIn, u: dict = Depends(CLINICAL)):
    cid = u["clinic_id"]
    await _enforce_doc_own_patient_pg(cid, pid, u)
    rec = await q1("SELECT * FROM tooth_records WHERE id=%s AND patient_id=%s AND clinic_id=%s", rid, pid, cid)
    if not rec:
        raise HTTPException(404, "diş kaydı yok")
    new_surface = b.surface if b.surface is not None else rec["surface"]
    new_status = b.status if b.status is not None else rec["status"]
    new_code = b.procedure_code if b.procedure_code is not None else rec["procedure_code"]
    new_name = b.procedure_name if b.procedure_name is not None else rec["procedure_name"]
    new_amt = kurus(b.amount) if b.amount is not None else rec["amount_kurus"]
    new_doc = b.doctor_id if b.doctor_id is not None else rec["doctor_id"]
    new_note = b.note if b.note is not None else rec["note"]
    voided: list = []
    new_charge_id = None
    async with tx() as t:
        linked = await _odo_linked_charges(t, cid, pid, rec)
        await t.q(
            """UPDATE tooth_records SET surface=%s, status=%s, procedure_code=%s, procedure_name=%s, amount_kurus=%s, doctor_id=%s, note=%s
               WHERE id=%s AND patient_id=%s AND clinic_id=%s""",
            new_surface, new_status, new_code, new_name, new_amt, new_doc, new_note, rid, pid, cid,
        )
        billable = new_status in ODO_BILLABLE_STATUSES and new_amt > 0
        changed = new_amt != rec["amount_kurus"] or new_surface != rec["surface"] or new_name != rec["procedure_name"]
        if linked and (not billable or changed):
            reason = "Diş kaydı tamamlanmadı/plana döndü" if not billable else "Diş kaydı tutarı/bilgisi güncellendi"
            for ch_id in linked:
                await t.q("UPDATE charges SET voided_at=now(), void_reason=%s WHERE id=%s AND clinic_id=%s AND voided_at IS NULL",
                          reason, ch_id, cid)
            voided, linked = list(linked), []
        if billable and not linked:
            ch = await t.q1(
                """INSERT INTO charges (clinic_id, patient_id, description, amount_kurus, doctor_id, created_by, idempotency_key)
                   VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
                cid, pid, _odo_charge_desc(rec["tooth_fdi"], new_surface, new_name), new_amt, new_doc or u["id"], u["id"],
                _odo_charge_key(rid, f"u{secrets.token_hex(6)}"),
            )
            new_charge_id = ch["id"]
    await log(u, "odontogram.update", f"tooth_record:{rid}", {"status": new_status, "voided_charges": voided, "charge_id": new_charge_id})
    return {"ok": True, "id": rid, "voided_charges": voided, "charge_id": new_charge_id}


@router.delete("/app/api/patients/{pid}/odontogram/{rid}")
async def delete_odontogram_record(pid: int, rid: int, u: dict = Depends(CLINICAL)):
    cid = u["clinic_id"]
    await _enforce_doc_own_patient_pg(cid, pid, u)
    rec = await q1("SELECT * FROM tooth_records WHERE id=%s AND patient_id=%s AND clinic_id=%s", rid, pid, cid)
    if not rec:
        raise HTTPException(404, "diş kaydı yok")
    async with tx() as t:
        linked = await _odo_linked_charges(t, cid, pid, rec)
        for ch_id in linked:
            await t.q("UPDATE charges SET voided_at=now(), void_reason=%s WHERE id=%s AND clinic_id=%s AND voided_at IS NULL",
                      "Diş kaydı silindi", ch_id, cid)
        await t.q("DELETE FROM tooth_records WHERE id=%s AND patient_id=%s AND clinic_id=%s", rid, pid, cid)
    await log(u, "odontogram.delete", f"tooth_record:{rid}", {"voided_charges": linked})
    return {"ok": True, "voided_charges": linked}


@router.post("/app/api/patients/{pid}/anamnesis")
async def send_anam(pid: int, u: dict = Depends(require_perm("patient_edit"))):
    await _enforce_doc_own_patient_pg(u["clinic_id"], pid, u)
    await _require_active_patient(pid, u["clinic_id"])
    link = await modules.send_anamnesis(pid)
    await log(u, "anamnesis.send", f"patient:{pid}")
    return {"link": link}


class PatientUpdateIn(BaseModel):
    phone: str | None = Field(default=None, max_length=30)
    name: str | None = Field(default=None, min_length=2, max_length=80)
    lang: Literal["tr", "en", "de", "ar", "ru", "fr", "nl", "es", "it", "fa", "az", "uk", "bg", "ro", "el", "he"] | None = None


@router.patch("/app/api/patients/{pid}")
async def update_patient(pid: int, b: PatientUpdateIn, u: dict = Depends(require_perm("patient_edit", "edit"))):
    cid = u["clinic_id"]
    await _enforce_doc_own_patient_pg(cid, pid, u)
    p = await q1("SELECT * FROM patients WHERE id=%s AND clinic_id=%s", pid, cid)
    if not p:
        raise HTTPException(404, "hasta yok")
    new_name = b.name if b.name is not None else p["display_name"]
    new_lang = b.lang if b.lang is not None else p["lang"]
    if b.phone is not None:
        if len(norm_phone(b.phone)) < 10:
            raise HTTPException(400, "Geçerli telefon girin")
        ph = phone_hmac(b.phone)
        pe = enc(norm_phone(b.phone))
    else:
        ph = p["phone_hmac"]
        pe = p["phone_enc"]
    await q("UPDATE patients SET display_name=%s, lang=%s, phone_hmac=%s, phone_enc=%s WHERE id=%s AND clinic_id=%s",
            new_name, new_lang, ph, pe, pid, cid)
    await log(u, "patient.update", f"patient:{pid}")
    return {"ok": True, "id": pid}


@router.post("/app/api/patients/{pid}/archive")
async def archive_patient(pid: int, u: dict = Depends(CLINICAL)):
    await _enforce_doc_own_patient_pg(u["clinic_id"], pid, u)
    r = await q1("UPDATE patients SET active=false WHERE id=%s AND clinic_id=%s RETURNING id", pid, u["clinic_id"])
    if not r:
        raise HTTPException(404, "hasta yok")
    await log(u, "patient.archive", f"patient:{pid}")
    return {"ok": True}


@router.post("/app/api/patients/{pid}/unarchive")
async def unarchive_patient(pid: int, u: dict = Depends(CLINICAL)):
    await _enforce_doc_own_patient_pg(u["clinic_id"], pid, u)
    r = await q1("UPDATE patients SET active=true WHERE id=%s AND clinic_id=%s RETURNING id", pid, u["clinic_id"])
    if not r:
        raise HTTPException(404, "hasta yok")
    await log(u, "patient.unarchive", f"patient:{pid}")
    return {"ok": True}


# ======================================================================== bekleme listesi & uyarılar
class WaitIn(BaseModel):
    patient_id: int
    treatment: str = Field("herhangi", max_length=80)


@router.get("/app/api/waitlist")
async def waitlist(u: dict = Depends(ANY)):
    return await q("""SELECT w.id, w.treatment, w.earliest, w.created_at, p.display_name AS patient, w.patient_id
                      FROM waitlist w JOIN patients p ON p.id=w.patient_id WHERE p.clinic_id=%s AND w.active ORDER BY w.created_at""", u["clinic_id"])


@router.get("/app/api/waitlist/offers")
async def list_waitlist_offers(status: str | None = None, u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    sql = """SELECT o.id, o.appointment_id, o.waitlist_id, o.wave, o.sent_at, o.status,
                    w.patient_id, w.treatment AS waitlist_treatment,
                    p.display_name AS patient,
                    a.starts_at, a.treatment, a.chair, a.status AS appointment_status
             FROM slot_offers o
             JOIN waitlist w ON w.id = o.waitlist_id
             JOIN patients p ON p.id = w.patient_id
             JOIN appointments a ON a.id = o.appointment_id
             WHERE p.clinic_id = %s AND a.clinic_id = %s"""
    args: list = [cid, cid]
    if status:
        sql += " AND o.status = %s"
        args.append(status)
    sql += " ORDER BY o.id DESC LIMIT 100"
    return await q(sql, *args)


@router.post("/app/api/waitlist")
async def add_wait(b: WaitIn, u: dict = Depends(ANY)):
    await _require_active_patient(b.patient_id, u["clinic_id"])
    r = await q1("INSERT INTO waitlist (patient_id, treatment) VALUES (%s,%s) RETURNING id", b.patient_id, b.treatment)
    await log(u, "waitlist.add", f"patient:{b.patient_id}")
    return {"id": r["id"]}


@router.post("/app/api/waitlist/{wid}/remove")
async def rm_wait(wid: int, u: dict = Depends(ANY)):
    w = await q1("SELECT w.id FROM waitlist w JOIN patients p ON p.id=w.patient_id WHERE w.id=%s AND p.clinic_id=%s", wid, u["clinic_id"])
    if not w:
        raise HTTPException(404, "bekleme kaydı yok")
    await q("UPDATE waitlist SET active=false WHERE id=%s", wid)
    await log(u, "waitlist.remove", f"waitlist:{wid}")
    return {"ok": True}


class OfferRespondIn(BaseModel):
    action: Literal["accept", "reject", "expire"] = "accept"


@router.post("/app/api/waitlist/offers/{oid}/respond")
async def respond_slot_offer(oid: int, b: OfferRespondIn, u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    async with tx() as t:
        off = await t.q1(
            """SELECT o.*, w.patient_id, p.clinic_id FROM slot_offers o
               JOIN waitlist w ON w.id=o.waitlist_id
               JOIN patients p ON p.id=w.patient_id
               WHERE o.id=%s AND p.clinic_id=%s FOR UPDATE""",
            oid, cid,
        )
        if not off:
            raise HTTPException(404, "teklif yok")
        if b.action == "reject":
            await t.q("UPDATE slot_offers SET status='lost' WHERE id=%s", oid)
            return {"ok": True, "status": "rejected"}
        if b.action == "expire":
            await t.q("UPDATE slot_offers SET status='expired' WHERE id=%s", oid)
            return {"ok": True, "status": "expired"}
        won = await t.q1(
            "UPDATE appointments SET status='booked', patient_id=%s WHERE id=%s AND clinic_id=%s AND status='cancelled' RETURNING id",
            off["patient_id"], off["appointment_id"], cid,
        )
        if not won:
            await t.q("UPDATE slot_offers SET status='lost' WHERE id=%s", oid)
            raise HTTPException(409, "Bu koltuk az önce başka bir hasta tarafından alındı")
        await t.q("UPDATE slot_offers SET status='won' WHERE id=%s", oid)
        await t.q("UPDATE slot_offers SET status='lost' WHERE appointment_id=%s AND id<>%s AND status='sent'", off["appointment_id"], oid)
        await t.q("UPDATE waitlist SET active=false WHERE id=%s", off["waitlist_id"])
    await log(u, "waitlist.offer_respond", f"offer:{oid}", {"action": b.action})
    return {"ok": True, "status": "won", "appointment_id": off["appointment_id"]}


@router.get("/app/api/alerts")
async def alerts(u: dict = Depends(ANY)):
    rows = await q("""SELECT id, patient_id, kind, detail, created_at FROM alerts
                      WHERE clinic_id=%s AND acknowledged_at IS NULL ORDER BY created_at DESC LIMIT 200""", u["clinic_id"])
    if u["role"] == "secretary":
        for r in rows:
            if r.get("kind") in ("anamnez_kirmizi", "postop_alarm", "acil"):
                r["detail"] = "Klinik Uyarı (Hekim Kontrolü)"
    return rows


@router.post("/app/api/alerts/{aid}/ack")
async def ack(aid: int, u: dict = Depends(ANY)):
    r = await q1("UPDATE alerts SET acknowledged_at=now() WHERE id=%s AND clinic_id=%s AND acknowledged_at IS NULL RETURNING id", aid, u["clinic_id"])
    if not r:
        raise HTTPException(404, "uyarı yok")
    await log(u, "alert.ack", f"alert:{aid}")
    return {"ok": True}


# ======================================================================== envanter
class ItemIn(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    sku: str | None = Field(default=None, max_length=40)
    unit: str = Field("adet", max_length=16)
    qty: Decimal = Field(Decimal(0), ge=0, le=1_000_000)
    min_qty: Decimal = Field(Decimal(0), ge=0, le=1_000_000)
    unit_cost: Decimal = Field(Decimal(0), ge=0, le=10_000_000)


class MoveIn(BaseModel):
    delta: Decimal = Field(ge=-1_000_000, le=1_000_000)
    reason: str = Field(min_length=2, max_length=120)

    @field_validator("delta")
    @classmethod
    def nonzero(cls, v):
        if v == 0:
            raise ValueError("miktar sıfır olamaz")
        return v


@router.get("/app/api/inventory")
async def inventory(u: dict = Depends(ANY)):
    rows = await q("""SELECT id, name, sku, unit, qty, min_qty, unit_cost_kurus, (qty <= min_qty AND min_qty > 0) AS low
                      FROM inventory_items WHERE clinic_id=%s AND active ORDER BY low DESC, name""", u["clinic_id"])
    for r in rows:
        r["unit_cost"] = tl(r.pop("unit_cost_kurus"))
        r["value"] = round(float(r["qty"]) * r["unit_cost"], 2)
    return rows


@router.post("/app/api/inventory")
async def add_item(b: ItemIn, u: dict = Depends(ANY)):
    async with tx() as t:
        r = await t.q1("""INSERT INTO inventory_items (clinic_id, name, sku, unit, qty, min_qty, unit_cost_kurus)
                          VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id""", u["clinic_id"], b.name, b.sku, b.unit, b.qty, b.min_qty, kurus(b.unit_cost))
        if b.qty > 0:
            await t.q("INSERT INTO stock_moves (item_id, delta, qty_after, reason, actor_id) VALUES (%s,%s,%s,'ilk stok',%s)",
                      r["id"], b.qty, b.qty, u["id"])
    await log(u, "inventory.create", f"item:{r['id']}")
    return {"id": r["id"]}


@router.post("/app/api/inventory/{iid}/move")
async def move(iid: int, b: MoveIn, u: dict = Depends(ANY)):
    async with tx() as t:
        exists = await t.q1("SELECT id FROM inventory_items WHERE id=%s AND clinic_id=%s AND active", iid, u["clinic_id"])
        if not exists:
            raise HTTPException(404, "ürün yok")
        it = await t.q1("""UPDATE inventory_items SET qty = qty + %s WHERE id=%s AND clinic_id=%s AND active AND qty + %s >= 0
                           RETURNING name, qty, min_qty, unit""", b.delta, iid, u["clinic_id"], b.delta)
        if not it:
            raise HTTPException(409, "Stok yetersiz")
        await t.q("INSERT INTO stock_moves (item_id, delta, qty_after, reason, actor_id) VALUES (%s,%s,%s,%s,%s)",
                  iid, b.delta, it["qty"], b.reason, u["id"])
    if b.delta < 0 and it["min_qty"] > 0 and it["qty"] <= it["min_qty"] < it["qty"] - b.delta:
        await q("INSERT INTO alerts (clinic_id, kind, detail) VALUES (%s,'stok_kritik',%s)",
                u["clinic_id"], f"Stok kritik seviyede: {it['name']} ({it['qty']} {it['unit']}, alt sınır {it['min_qty']})")
    await log(u, "inventory.move", f"item:{iid}", {"delta": str(b.delta)})
    return {"ok": True, "qty": it["qty"]}


class StockTransferIn(BaseModel):
    target_clinic_id: int
    qty: Decimal = Field(gt=0, le=1_000_000)
    reason: str = Field("Şubeler arası transfer", min_length=2, max_length=120)


@router.post("/app/api/inventory/{iid}/transfer")
async def transfer_item(iid: int, b: StockTransferIn, u: dict = Depends(CLINICAL)):
    cid = u["clinic_id"]
    if b.target_clinic_id == cid:
        raise HTTPException(400, "Hedef şube kaynak şubeyle aynı olamaz")
    async with tx() as t:
        if not await t.q1("SELECT id FROM clinics WHERE id=%s AND active", b.target_clinic_id):
            raise HTTPException(404, "hedef şube yok")
        src = await t.q1("SELECT * FROM inventory_items WHERE id=%s AND clinic_id=%s AND active FOR UPDATE", iid, cid)
        if not src:
            raise HTTPException(404, "ürün yok")
        upd = await t.q1(
            "UPDATE inventory_items SET qty = qty - %s WHERE id=%s AND clinic_id=%s AND active AND qty - %s >= 0 RETURNING qty",
            b.qty, iid, cid, b.qty,
        )
        if not upd:
            raise HTTPException(409, "Transfer için stok yetersiz")
        await t.q(
            "INSERT INTO stock_moves (item_id, delta, qty_after, reason, actor_id) VALUES (%s,%s,%s,%s,%s)",
            iid, -b.qty, upd["qty"], f"Transfer -> Şube #{b.target_clinic_id}: {b.reason}", u["id"],
        )
        dst = await t.q1("SELECT id FROM inventory_items WHERE clinic_id=%s AND name=%s AND active FOR UPDATE", b.target_clinic_id, src["name"])
        if dst:
            dst_upd = await t.q1("UPDATE inventory_items SET qty = qty + %s WHERE id=%s RETURNING id, qty", b.qty, dst["id"])
        else:
            dst_upd = await t.q1(
                """INSERT INTO inventory_items (clinic_id, name, sku, unit, qty, min_qty, unit_cost_kurus)
                   VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id, qty""",
                b.target_clinic_id, src["name"], src["sku"], src["unit"], b.qty, src["min_qty"], src["unit_cost_kurus"],
            )
        await t.q(
            "INSERT INTO stock_moves (item_id, delta, qty_after, reason, actor_id) VALUES (%s,%s,%s,%s,%s)",
            dst_upd["id"], b.qty, dst_upd["qty"], f"Transfer <- Şube #{cid}: {b.reason}", u["id"],
        )
    await log(u, "inventory.transfer", f"item:{iid}->clinic:{b.target_clinic_id}", {"qty": str(b.qty)})
    return {"ok": True, "src_qty": float(upd["qty"]), "dst_item_id": dst_upd["id"], "dst_qty": float(dst_upd["qty"])}


@router.get("/app/api/inventory/{iid}/moves")
async def moves(iid: int, u: dict = Depends(ANY)):
    if not await q1("SELECT id FROM inventory_items WHERE id=%s AND clinic_id=%s", iid, u["clinic_id"]):
        raise HTTPException(404, "ürün yok")
    return await q("""SELECT m.delta, m.qty_after, m.reason, m.created_at, s.full_name AS actor
                      FROM stock_moves m LEFT JOIN staff_users s ON s.id=m.actor_id
                      WHERE m.item_id=%s ORDER BY m.created_at DESC LIMIT 100""", iid)


# ======================================================================== kasa
class ChargeIn(BaseModel):
    patient_id: int
    description: str = Field(min_length=2, max_length=120)
    amount: Decimal = Field(gt=0, le=10_000_000)
    doctor_id: int | None = None
    discount: Decimal = Field(Decimal(0), ge=0, le=10_000_000)
    idempotency_key: str | None = Field(default=None, max_length=80)
    allow_duplicate: bool = False


class PaymentIn(BaseModel):
    patient_id: int
    amount: Decimal = Field(gt=0, le=10_000_000)
    method: Literal["nakit", "kart", "havale", "diger"]
    idempotency_key: str | None = Field(default=None, max_length=80)
    allow_advance: bool = False


class VoidIn(BaseModel):
    reason: str = Field(min_length=3, max_length=200)


@router.post("/app/api/charges")
async def add_charge(b: ChargeIn, u: dict = Depends(require_perm("finance_edit"))):
    if not await limiter.hit(f"chg:{u['id']}", 60, 60):
        raise HTTPException(429, "Çok fazla hizmet ekleme isteği")
    cid = u["clinic_id"]
    await _enforce_doc_own_patient_pg(cid, b.patient_id, u)
    await _require_active_patient(b.patient_id, cid)
    if b.doctor_id is not None and not await q1("SELECT id FROM staff_users WHERE id=%s AND clinic_id=%s", b.doctor_id, cid):
        raise HTTPException(404, "hekim yok")
    net_amount = b.amount - b.discount
    if net_amount <= 0:
        raise HTTPException(400, "Net hizmet tutarı pozitif olmalıdır")
    net_k = kurus(net_amount)
    desc = (f"{b.description} (İndirim: {b.discount} TL)" if b.discount > 0 else b.description)[:120]
    try:
        async with tx() as t:
            if b.idempotency_key:
                await t.q("SELECT pg_advisory_xact_lock(hashtext(%s))", f"chg:{cid}:{b.idempotency_key}")
                dup = await t.q1("SELECT id FROM charges WHERE clinic_id=%s AND idempotency_key=%s", cid, b.idempotency_key)
                if dup:
                    raise HTTPException(409, "Bu hizmet borçlandırması zaten işlendi (mükerrer işlem engellendi)")
            elif not b.allow_duplicate:
                recent_dup = await t.q1(
                    """SELECT id FROM charges WHERE clinic_id=%s AND patient_id=%s AND description=%s AND amount_kurus=%s
                       AND COALESCE(doctor_id,0)=COALESCE(%s,0) AND voided_at IS NULL AND created_at > now() - interval '15 seconds' LIMIT 1""",
                    cid, b.patient_id, desc, net_k, b.doctor_id,
                )
                if recent_dup:
                    raise HTTPException(409, "Aynı hizmet borcu az önce eklendi (çift tıklama / mükerrer borç engellendi)")
            r = await t.q1(
                """INSERT INTO charges (clinic_id, patient_id, description, amount_kurus, discount, doctor_id, created_by, idempotency_key)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
                cid, b.patient_id, desc, net_k, min(b.discount, Decimal(100)), b.doctor_id, u["id"], b.idempotency_key,
            )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(409, "Mükerrer hizmet borçlandırması engellendi") from None
    await log(u, "kasa.charge", f"charge:{r['id']}", {"kurus": net_k, "discount": str(b.discount)})
    return {"id": r["id"], "amount_try": tl(net_k), "net_kurus": net_k}


@router.post("/app/api/payments")
async def add_payment(b: PaymentIn, u: dict = Depends(require_perm("finance_edit"))):
    if not await limiter.hit(f"pay:{u['id']}", 60, 60):
        raise HTTPException(429, "Çok fazla tahsilat isteği")
    cid = u["clinic_id"]
    await _enforce_doc_own_patient_pg(cid, b.patient_id, u)
    await _require_active_patient(b.patient_id, cid)
    amt_k = kurus(b.amount)
    try:
        async with tx() as t:
            if b.idempotency_key:
                await t.q("SELECT pg_advisory_xact_lock(hashtext(%s))", f"pay:{cid}:{b.idempotency_key}")
                dup = await t.q1("SELECT id FROM payments WHERE clinic_id=%s AND idempotency_key=%s", cid, b.idempotency_key)
                if dup:
                    raise HTTPException(409, f"Bu ödeme isteği daha önce işlendi (idempotency #{dup['id']})")
            bal_row = await t.q1(
                """SELECT (SELECT coalesce(sum(amount_kurus),0) FROM charges WHERE clinic_id=%s AND patient_id=%s AND voided_at IS NULL)
                        - (SELECT coalesce(sum(amount_kurus),0) FROM payments WHERE clinic_id=%s AND patient_id=%s AND voided_at IS NULL) AS bal""",
                cid, b.patient_id, cid, b.patient_id,
            )
            balance_k = int((bal_row and bal_row["bal"]) or 0)
            if amt_k > max(0, balance_k) and not b.allow_advance:
                raise HTTPException(
                    422,
                    f"Hastanın açık bakiyesi {tl(max(0, balance_k)):.2f} TL; bakiye üstü tahsilat için avans onayı (allow_advance=true) gereklidir",
                )
            r = await t.q1(
                """INSERT INTO payments (clinic_id, patient_id, amount_kurus, method, created_by, idempotency_key)
                   VALUES (%s,%s,%s,%s,%s,%s) RETURNING id""",
                cid, b.patient_id, amt_k, b.method, u["id"], b.idempotency_key,
            )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(409, "Bu ödeme isteği daha önce işlendi (Mükerrer işlem engellendi)") from None
    await log(u, "kasa.payment", f"payment:{r['id']}", {"kurus": amt_k, "method": b.method})
    return {"id": r["id"]}


@router.post("/app/api/{kind}/{eid}/void")
async def void(kind: Literal["charges", "payments"], eid: int, b: VoidIn, u: dict = Depends(require_perm("finance_view", "finance_edit", "delete_cancel"))):
    sql = (
        "UPDATE charges SET voided_at=now(), void_reason=%s WHERE id=%s AND clinic_id=%s AND voided_at IS NULL RETURNING id"
        if kind == "charges"
        else "UPDATE payments SET voided_at=now(), void_reason=%s WHERE id=%s AND clinic_id=%s AND voided_at IS NULL RETURNING id"
    )
    r = await q1(sql, b.reason, eid, u["clinic_id"])
    if not r:
        raise HTTPException(404, "kayıt yok veya zaten iptal")
    await log(u, f"kasa.void_{kind}", f"{kind}:{eid}", {"reason": b.reason})
    return {"ok": True}


@router.get("/app/api/kasa")
async def kasa(start: datetime, end: datetime, u: dict = Depends(require_perm("finance_view"))):
    s_cmp = start if start.tzinfo else start.replace(tzinfo=TZ)
    e_cmp = end if end.tzinfo else end.replace(tzinfo=TZ)
    if s_cmp > e_cmp:
        raise HTTPException(422, "Başlangıç tarihi bitiş tarihinden büyük olamaz")
    cid = u["clinic_id"]
    t = await q1("""SELECT (SELECT coalesce(sum(amount_kurus),0) FROM charges WHERE clinic_id=%s AND voided_at IS NULL AND created_at >= %s AND created_at < %s) AS billed,
                           (SELECT coalesce(sum(amount_kurus),0) FROM payments WHERE clinic_id=%s AND voided_at IS NULL AND created_at >= %s AND created_at < %s) AS paid,
                           (SELECT coalesce(sum(amount_kurus),0) FROM charges WHERE clinic_id=%s AND voided_at IS NULL)
                         - (SELECT coalesce(sum(amount_kurus),0) FROM payments WHERE clinic_id=%s AND voided_at IS NULL) AS receivable""",
                 cid, start, end, cid, start, end, cid, cid)
    methods = await q("""SELECT method, sum(amount_kurus) AS k FROM payments WHERE clinic_id=%s AND voided_at IS NULL AND created_at >= %s AND created_at < %s
                         GROUP BY method ORDER BY k DESC""", cid, start, end)
    entries = await q("""SELECT 'hizmet' AS type, c.id, c.created_at, p.display_name AS patient, c.description AS info, c.amount_kurus, c.voided_at
                         FROM charges c JOIN patients p ON p.id=c.patient_id WHERE c.clinic_id=%s AND c.created_at >= %s AND c.created_at < %s
                         UNION ALL
                         SELECT 'tahsilat', y.id, y.created_at, p.display_name, y.method, y.amount_kurus, y.voided_at
                         FROM payments y JOIN patients p ON p.id=y.patient_id WHERE y.clinic_id=%s AND y.created_at >= %s AND y.created_at < %s
                         ORDER BY created_at DESC LIMIT 300""", cid, start, end, cid, start, end)
    for e in entries:
        e["amount"] = tl(e.pop("amount_kurus"))
    shares = []
    if u["role"] == "owner":
        shares = await q("""SELECT s.full_name, s.share_pct, coalesce(sum(c.amount_kurus),0) AS billed
                            FROM staff_users s LEFT JOIN charges c ON c.doctor_id=s.id AND c.clinic_id=%s AND c.voided_at IS NULL AND c.created_at >= %s AND c.created_at < %s
                            WHERE s.clinic_id=%s AND s.role IN ('owner','doctor') AND s.active GROUP BY s.id ORDER BY billed DESC""", cid, start, end, cid)
        for s in shares:
            s["share_try"] = tl(int(s["billed"] * s["share_pct"] / 100))
            s["billed"] = tl(s["billed"])
    return {"billed": tl(t["billed"]), "paid": tl(t["paid"]), "receivable": tl(t["receivable"]),
            "methods": [{"method": m["method"], "amount": tl(m["k"])} for m in methods], "entries": entries, "shares": shares}


# ======================================================================== ekip, denetim, maliyet
class StaffIn(BaseModel):
    email: str = Field(max_length=200)
    full_name: str = Field(min_length=2, max_length=80)
    role: Literal["owner", "doctor", "secretary", "accounting", "clinical_support", "lab_tech", "warehouse", "no_access"] = "secretary"
    job_title: str | None = Field(default=None, max_length=60)
    password: str = Field(min_length=12, max_length=200)
    phone: str | None = Field(default=None, max_length=30)
    share_pct: Decimal = Field(Decimal(0), ge=0, le=100)
    permissions: dict[str, bool] | None = None


@router.get("/app/api/staff")
async def staff(u: dict = Depends(ANY)):
    rows = await q("SELECT id, email, full_name, role, job_title, share_pct, totp_enabled, active, (phone_hmac IS NOT NULL) AS whatsapp FROM staff_users WHERE clinic_id=%s ORDER BY id", u["clinic_id"])
    if u["role"] != "owner":
        for r in rows:
            r.pop("email", None), r.pop("share_pct", None)
    return rows


@router.post("/app/api/staff")
async def add_staff(b: StaffIn, u: dict = Depends(OWNER)):
    email = b.email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise HTTPException(400, "Geçerli e-posta girin")
    h = await _hash_pw(b.password)
    jt = (b.job_title or b.role).strip().lower()
    p_json = json.dumps(b.permissions or {}, ensure_ascii=False)
    try:
        r = await q1("""INSERT INTO staff_users (clinic_id, email, full_name, role, job_title, permissions_json, pw_hash, phone_hmac, share_pct)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
                     u["clinic_id"], email, b.full_name, b.role, jt, p_json, h, phone_hmac(b.phone) if b.phone else None, b.share_pct)
    except Exception:
        raise HTTPException(409, "Bu e-posta veya telefon zaten kayıtlı") from None
    await log(u, "staff.create", f"staff:{r['id']}", {"role": b.role, "job_title": jt})
    return {"id": r["id"]}


class ActiveIn(BaseModel):
    active: bool


@router.post("/app/api/staff/{sid}/active")
async def staff_active(sid: int, b: ActiveIn, u: dict = Depends(OWNER)):
    if sid == u["id"] and not b.active:
        raise HTTPException(400, "Kendi hesabınızı kapatamazsınız")
    r = await q1("UPDATE staff_users SET active=%s WHERE id=%s AND clinic_id=%s RETURNING id", b.active, sid, u["clinic_id"])
    if not r:
        raise HTTPException(404, "personel yok")
    if not b.active:
        await q("UPDATE sessions SET revoked=true WHERE user_id=%s", sid)
    await log(u, "staff.activate" if b.active else "staff.deactivate", f"staff:{sid}")
    return {"ok": True}


# ======================================================================== zincir klinikler, mesajlar, şablonlar, analiz, ayarlar, asistan
class ClinicCreateIn(BaseModel):
    clinic_name: str = Field(min_length=2, max_length=120)
    city: str = Field("İstanbul", max_length=40)
    address: str = Field("", max_length=200)
    phone: str = Field("", max_length=30)
    chairs: int = Field(2, ge=1, le=200)
    owner_name: str = Field(min_length=2, max_length=80)
    owner_email: str = Field(max_length=200)
    owner_password: str = Field(min_length=12, max_length=200)


@router.get("/app/api/clinics")
async def list_clinics(request: Request, u: dict = Depends(OWNER)):
    where = "" if u["is_hq"] else "WHERE c.id = %s"
    args = () if u["is_hq"] else (u["home_clinic_id"],)
    rows = await q(f"""SELECT c.*,
                              (SELECT s.email FROM staff_users s WHERE s.clinic_id=c.id AND s.role='owner' ORDER BY s.id LIMIT 1) AS owner_email,
                              (SELECT count(*) FROM staff_users s WHERE s.clinic_id=c.id AND s.active) AS staff_count,
                              (SELECT count(*) FROM patients p WHERE p.clinic_id=c.id) AS patient_count,
                              (SELECT count(*) FROM appointments a WHERE a.clinic_id=c.id AND a.status IN ('booked','confirmed')) AS active_appts,
                              (SELECT coalesce(sum(y.amount_kurus),0) FROM payments y WHERE y.clinic_id=c.id AND y.voided_at IS NULL) AS paid_kurus
                       FROM clinics c {where} ORDER BY c.id""", *args)  # nosec B608  # noqa: S608
    base = str(request.base_url).rstrip("/")
    for c in rows:
        c["paid_try"] = tl(c.pop("paid_kurus", 0))
        tok = cal.calendar_feed_token(c["id"], version=int(c.get("cal_token_version") or 1))
        c["ics_url"] = f"{base}/calendar/{tok}.ics"
        c["webcal_url"] = "webcal://" + c["ics_url"].split("://", 1)[-1]
    return rows


@router.post("/app/api/clinics")
async def create_clinic(b: ClinicCreateIn, request: Request, u: dict = Depends(OWNER)):
    if not u["is_hq"]:
        raise HTTPException(403, "Yalnızca merkez yönetici (HQ) yeni klinik açabilir")
    email = b.owner_email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise HTTPException(400, "Geçerli yönetici e-postası girin")
    slug = re.sub(r"[^a-z0-9]+", "-", b.clinic_name.lower()).strip("-")[:40] + f"-{int(datetime.now().timestamp()) % 10000}"
    h = await _hash_pw(b.owner_password)
    async with tx() as t:
        c = await t.q1("""INSERT INTO clinics (name, slug, city, address, phone, chairs)
                          VALUES (%s,%s,%s,%s,%s,%s) RETURNING id""",
                       b.clinic_name, slug, b.city, b.address, b.phone, b.chairs)
        try:
            su = await t.q1("""INSERT INTO staff_users (clinic_id, email, full_name, role, pw_hash)
                               VALUES (%s,%s,%s,'owner',%s) RETURNING id""", c["id"], email, b.owner_name, h)
        except Exception:
            raise HTTPException(409, "Bu yönetici e-postası zaten kayıtlı") from None
        await t.q("""INSERT INTO message_templates (clinic_id, name, channel, lang, category, body, status)
                     VALUES (%s,'randevu_hatirlatma','whatsapp','tr','UTILITY','Sayın {{1}}, yarın {{2}} randevunuzu hatırlatırız.','APPROVED')""", c["id"])
    await log(u, "clinic.create", f"clinic:{c['id']}", {"email": email})
    base = str(request.base_url).rstrip("/")
    tok = cal.calendar_feed_token(c["id"])
    ics_url = f"{base}/calendar/{tok}.ics"
    webcal_url = "webcal://" + ics_url.split("://", 1)[-1]
    google_subscribe_url = "https://calendar.google.com/calendar/r?cid=" + quote(webcal_url, safe="")
    return {"clinic_id": c["id"], "user_id": su["id"], "email": email, "slug": slug,
            "login_url": f"{base}/app", "ics_url": ics_url, "webcal_url": webcal_url,
            "google_subscribe_url": google_subscribe_url}


@router.post("/app/api/clinics/{cid}/switch")
async def switch_clinic(cid: int, u: dict = Depends(OWNER)):
    if not u["is_hq"]:
        raise HTTPException(403, "Yalnızca merkez yönetici (HQ) klinik değiştirebilir")
    c = await q1("SELECT id, name FROM clinics WHERE id=%s AND active", cid)
    if not c:
        raise HTTPException(404, "klinik yok")
    await q("UPDATE sessions SET active_clinic_id=%s WHERE id_hash=%s", cid, u["id_hash"])
    await sec.audit(u["id"], u["email"], "clinic.switch", f"clinic:{cid}", u.get("ip_h", ""),
                    {"from": u["clinic_id"], "to": cid}, clinic_id=u["home_clinic_id"])
    return {"ok": True, "clinic_id": cid, "clinic": c["name"]}


@router.get("/app/api/conversations")
async def list_conversations(u: dict = Depends(require_perm("patient_view"))):
    cid = u["clinic_id"]
    perms = u.get("permissions") or {}
    where_c = "p.clinic_id=%s AND p.active"
    args_c: list = [cid]
    if perms.get("doctor_own_patients_only") and u.get("role") != "owner":
        where_c += """ AND (p.primary_doctor_id=%s OR p.created_by=%s
                            OR EXISTS (SELECT 1 FROM appointments ap WHERE ap.patient_id=p.id AND ap.doctor_id=%s)
                            OR EXISTS (SELECT 1 FROM tooth_records tr WHERE tr.patient_id=p.id AND tr.doctor_id=%s))"""
        args_c.extend([u["id"], u["id"], u["id"], u["id"]])
    rows = await q(
        f"""SELECT p.id, p.display_name, p.channel, p.lang,
                   (SELECT max(m.created_at) FROM message_log m WHERE m.patient_id=p.id) AS last_at,
                   (SELECT m.layer FROM message_log m WHERE m.patient_id=p.id AND m.direction='out' ORDER BY m.id DESC LIMIT 1) AS last_layer,
                   (SELECT m.intent FROM message_log m WHERE m.patient_id=p.id ORDER BY m.id DESC LIMIT 1) AS last_intent,
                   (SELECT m.body FROM message_log m WHERE m.patient_id=p.id AND m.body IS NOT NULL AND m.body <> '' ORDER BY m.id DESC LIMIT 1) AS last_body_raw,
                   (SELECT m.direction FROM message_log m WHERE m.patient_id=p.id AND m.body IS NOT NULL AND m.body <> '' ORDER BY m.id DESC LIMIT 1) AS last_dir_body,
                   (SELECT m.direction FROM message_log m WHERE m.patient_id=p.id ORDER BY m.id DESC LIMIT 1) AS last_dir_any,
                   (SELECT m.delivery_status FROM message_log m WHERE m.patient_id=p.id AND m.direction='out' ORDER BY m.id DESC LIMIT 1) AS last_delivery_status,
                   (SELECT m.delivery_error FROM message_log m WHERE m.patient_id=p.id AND m.direction='out' ORDER BY m.id DESC LIMIT 1) AS last_delivery_error,
                   (SELECT count(*) FROM message_log m WHERE m.patient_id=p.id) AS msg_count
            FROM patients p WHERE {where_c} ORDER BY last_at DESC NULLS LAST, p.id DESC LIMIT 100""",  # nosec B608  # noqa: S608
        *args_c,
    )
    for r in rows:
        raw_b = r.pop("last_body_raw", None)
        d_body = r.pop("last_dir_body", None)
        d_any = r.pop("last_dir_any", None)
        r["last_body"] = dec_msg_body(raw_b) if raw_b else None
        r["last_dir"] = d_body or d_any
    return rows


@router.get("/app/api/conversations/{pid}/messages")
async def list_conv_messages(pid: int, u: dict = Depends(require_perm("patient_view"))):
    cid = u["clinic_id"]
    await _enforce_doc_own_patient_pg(cid, pid, u)
    if not await q1("SELECT id FROM patients WHERE id=%s AND clinic_id=%s", pid, cid):
        raise HTTPException(404, "hasta yok")
    rows = await q(
        """SELECT id, direction, layer, intent, body, delivery_status, delivery_error, created_at
           FROM message_log WHERE patient_id=%s AND clinic_id=%s ORDER BY id DESC LIMIT 100""",
        pid, cid,
    )
    for r in rows:
        r["body"] = dec_msg_body(r.get("body"))
    return rows


class ReplyIn(BaseModel):
    text: str = Field(min_length=1, max_length=2000)


@router.post("/app/api/conversations/{pid}/send")
async def send_conversation(pid: int, b: ReplyIn, u: dict = Depends(require_perm("patient_edit"))):
    if not await limiter.hit(f"conv_send:{u['id']}", 30, 60):
        raise HTTPException(429, "Çok fazla mesaj gönderildi; lütfen 1 dakika bekleyin")
    await _enforce_doc_own_patient_pg(u["clinic_id"], pid, u)
    p = await _require_active_patient(pid, u["clinic_id"])
    from . import wa
    wa_res = await wa.send_text(dec(p["phone_enc"]), b.text)
    st = "dry_run" if (wa_res or {}).get("dry_run") else ("failed" if (wa_res or {}).get("error") else "sent")
    err = json.dumps(wa_res["error"], ensure_ascii=False)[:500] if (wa_res or {}).get("error") else None
    await log_msg(pid, "out", "panel-manuel", "personel", 0, 0, clinic_id=u["clinic_id"], body=b.text[:2000], delivery_status=st, delivery_error=err)
    await log(u, "conversation.send", f"patient:{pid}", {"status": st})
    return {"ok": st != "failed", "status": st, "dry_run": st == "dry_run", "error": err}


class TickIn(BaseModel):
    force: bool = False
    at: datetime | None = None


@router.post("/app/api/admin/scheduler/tick")
async def admin_scheduler_tick(b: TickIn | None = Body(default=None), u: dict = Depends(OWNER)):
    cid = u["clinic_id"]
    if not await limiter.hit(f"sched_tick:{cid}", 20, 60):
        raise HTTPException(429, "Çok fazla zamanlayıcı isteği gönderildi; lütfen 1 dakika bekleyin")
    now_dt = b.at if b and b.at else None
    respect = not (b.force if b else False)
    res = await modules.run_scheduler_tick(clinic_id=cid, now_dt=now_dt, respect_hours=respect)
    await log(u, "scheduler.tick", f"clinic:{cid}", {"reminders": res["reminders_sent"], "waves": res["waves_advanced"], "skipped": res["skipped_outside_hours"]})
    return res


@router.post("/app/api/reminders/send")
async def manual_send_reminders(b: TickIn | None = Body(default=None), u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    if not await limiter.hit(f"rem_send:{cid}", 20, 60):
        raise HTTPException(429, "Çok fazla hatırlatma isteği gönderildi; lütfen 1 dakika bekleyin")
    now_dt = b.at if b and b.at else None
    respect = not (b.force if b else False)
    res = await modules.run_scheduler_tick(clinic_id=cid, now_dt=now_dt, respect_hours=respect)
    await log(u, "reminders.send", f"clinic:{cid}", {"reminders": res["reminders_sent"]})
    return res


class TemplateIn(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    channel: Literal["whatsapp", "instagram"] = "whatsapp"
    lang: str = Field("tr", max_length=10)
    category: Literal["UTILITY", "MARKETING", "AUTHENTICATION"] = "UTILITY"
    body: str = Field(min_length=5, max_length=1024)


@router.get("/app/api/templates")
async def list_templates(u: dict = Depends(ANY)):
    return await q("SELECT * FROM message_templates WHERE clinic_id=%s ORDER BY id DESC", u["clinic_id"])


@router.post("/app/api/templates")
async def create_template(b: TemplateIn, u: dict = Depends(OWNER)):
    r = await q1("""INSERT INTO message_templates (clinic_id, name, channel, lang, category, body, status)
                    VALUES (%s,%s,%s,%s,%s,%s,'APPROVED') RETURNING id""",
                 u["clinic_id"], b.name, b.channel, b.lang, b.category, b.body)
    await log(u, "template.create", f"template:{r['id']}")
    return {"id": r["id"]}


@router.get("/app/api/analytics")
async def analytics(u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    appts = await q("SELECT starts_at, source, status FROM appointments WHERE clinic_id=%s AND created_at > now() - interval '30 days'", cid)
    total_appts = len(appts)
    off_hours = sum(1 for a in appts if a["starts_at"].astimezone(TZ).hour < 9 or a["starts_at"].astimezone(TZ).hour >= 19 or a["starts_at"].astimezone(TZ).weekday() == 6)
    camps = await q("SELECT * FROM campaigns WHERE clinic_id=%s ORDER BY id DESC", cid)
    for c in camps:
        c["revenue_try"] = tl(c.pop("revenue_kurus"))
    return {"total_appts_30d": total_appts, "off_hours_appts": off_hours,
            "off_hours_pct": round(100 * off_hours / total_appts) if total_appts else 0,
            "campaigns": camps}


class CampaignIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    source: str = Field("meta_ads", max_length=40)
    code: str | None = Field(default=None, max_length=60)
    utm_source: str = Field("", max_length=60)
    utm_medium: str = Field("cpc", max_length=60)
    utm_campaign: str = Field("", max_length=80)
    target_url: str = Field("/", max_length=300)
    clicks: int = Field(0, ge=0, le=10_000_000)
    conversations: int = Field(0, ge=0, le=10_000_000)
    appointments_booked: int = Field(0, ge=0, le=1_000_000)
    revenue_try: Decimal = Field(Decimal(0), ge=0, le=1_000_000_000)


@router.post("/app/api/campaigns")
async def add_campaign(b: CampaignIn, request: Request, u: dict = Depends(OWNER)):
    from .dental_catalog import normalize_source
    norm_s = normalize_source(b.source)
    legacy_s = "meta_ads" if norm_s in ("instagram", "meta_ads") else ("google_ads" if norm_s == "google_ads" else "organik")
    if b.code and b.code.strip():
        code = re.sub(r"[^a-z0-9_-]+", "-", b.code.strip().lower()).strip("-")[:48]
        if await q1("SELECT id FROM campaigns WHERE code=%s AND clinic_id<>%s", code, u["clinic_id"]):
            code = f"{code}-c{u['clinic_id']}"
    else:
        raw_code = re.sub(r"[^a-z0-9]+", "-", b.name.lower()).strip("-")[:32] or "kampanya"
        code = f"{raw_code}-{secrets.token_hex(2)}"
    utm_s = b.utm_source.strip() or norm_s
    utm_c = b.utm_campaign.strip() or code
    r = await q1(
        """INSERT INTO campaigns
           (clinic_id, name, source, code, channel, utm_source, utm_medium, utm_campaign, target_url, is_sample, clicks, conversations, appointments_booked, revenue_kurus)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,0,%s,%s,%s,%s) RETURNING id""",
        u["clinic_id"], b.name.strip(), legacy_s, code, norm_s, utm_s, b.utm_medium.strip(), utm_c,
        b.target_url.strip() or "/", b.clicks, b.conversations, b.appointments_booked, kurus(b.revenue_try),
    )
    base = str(request.base_url).rstrip("/")
    return {"id": r["id"], "code": code, "channel": norm_s, "tracking_url": f"{base}/c/{code}"}


class SettingsIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    city: str = Field("İstanbul", max_length=40)
    address: str = Field("", max_length=200)
    phone: str = Field("", max_length=30)
    autopilot_name: str = Field("DentaCore Asistan", max_length=60)
    default_lang: str = Field("tr", max_length=10)
    slot_step_min: int = Field(15, ge=5, le=60)
    google_review_url: str = Field("", max_length=250)
    working_hours_json: str | None = None
    buffer_min: int = Field(0, ge=0, le=120)
    ai_custom_rules_json: str | None = None
    wa_phone_id: str | None = Field(default=None, max_length=80)
    ig_handle: str | None = Field(default=None, max_length=80)


@router.get("/app/api/settings")
async def get_settings(u: dict = Depends(ANY)):
    c = await q1("SELECT * FROM clinics WHERE id=%s", u["clinic_id"])
    return c or {"id": u["clinic_id"], "name": S.clinic, "autopilot_name": "DentaCore Asistan", "default_lang": "tr", "slot_step_min": 15}


@router.post("/app/api/settings")
async def save_settings(b: SettingsIn, u: dict = Depends(OWNER)):
    cid = u["clinic_id"]
    rev_url = (b.google_review_url or "").strip()
    if rev_url and not re.match(r"^https?://", rev_url, re.IGNORECASE):
        raise HTTPException(400, "Google değerlendirme bağlantısı http:// veya https:// ile başlamalıdır")
    wh_str = b.working_hours_json or DEFAULT_WORKING_HOURS_JSON
    try:
        parsed_wh = json.loads(wh_str)
        if not isinstance(parsed_wh, dict):
            raise ValueError("dict değil")
    except Exception:
        raise HTTPException(400, "Geçersiz çalışma saatleri JSON formatı") from None
    cur_c = await q1("SELECT ai_custom_rules_json, wa_phone_id, ig_handle FROM clinics WHERE id=%s", cid) or {}
    ai_rules_str = b.ai_custom_rules_json if b.ai_custom_rules_json is not None else (cur_c.get("ai_custom_rules_json") or "{}")
    try:
        parsed_ai = json.loads(ai_rules_str)
        if not isinstance(parsed_ai, dict):
            raise ValueError("dict değil")
    except Exception:
        raise HTTPException(400, "Geçersiz yapay zeka cevap kuralları JSON formatı") from None
    wa_pid = b.wa_phone_id.strip() if b.wa_phone_id is not None else (cur_c.get("wa_phone_id") or "")
    ig_hdl = b.ig_handle.strip() if b.ig_handle is not None else (cur_c.get("ig_handle") or "")
    if wa_pid and await q1("SELECT id FROM clinics WHERE wa_phone_id=%s AND id<>%s", wa_pid, cid):
        raise HTTPException(409, "Bu WhatsApp telefon kimliği (wa_phone_id) başka bir şube tarafından kullanılıyor")
    if ig_hdl and await q1("SELECT id FROM clinics WHERE ig_handle=%s AND id<>%s", ig_hdl, cid):
        raise HTTPException(409, "Bu Instagram hesabı (ig_handle) başka bir şube tarafından kullanılıyor")
    await q("""UPDATE clinics SET name=%s, city=%s, address=%s, phone=%s, autopilot_name=%s, default_lang=%s,
               slot_step_min=%s, google_review_url=%s, working_hours_json=%s, buffer_min=%s, ai_custom_rules_json=%s,
               wa_phone_id=%s, ig_handle=%s WHERE id=%s""",
            b.name, b.city, b.address, b.phone, b.autopilot_name, b.default_lang, b.slot_step_min, rev_url, wh_str, b.buffer_min, ai_rules_str, wa_pid, ig_hdl, cid)
    await log(u, "settings.update", f"clinic:{cid}")
    return {"ok": True}


class AICustomRulesIn(BaseModel):
    tone: str = Field("resmi_samimi", max_length=40)
    coordinator_title: str = Field("Kıdemli Hasta Koordinatörü", max_length=80)
    greeting_style: str = Field("Merhabalar, {clinic} hasta danışma hattımıza hoş geldiniz.", max_length=300)
    price_policy: Literal["free_exam_invite", "starting_range", "direct_handoff"] = "free_exam_invite"
    exam_policy: str = Field("", max_length=400)
    cash_discount_note: str = Field("", max_length=400)
    payment_note: str = Field("", max_length=400)
    pain_comfort_note: str = Field("", max_length=400)
    kids_note: str = Field("", max_length=400)
    health_tourism_note: str = Field("", max_length=400)
    custom_extra_note: str = Field("", max_length=500)


@router.post("/app/api/settings/ai-rules")
async def save_ai_custom_rules(b: AICustomRulesIn, u: dict = Depends(OWNER)):
    rules_str = json.dumps(b.model_dump(), ensure_ascii=False)
    await q("UPDATE clinics SET ai_custom_rules_json=%s WHERE id=%s", rules_str, u["clinic_id"])
    await log(u, "settings.ai_rules_update", f"clinic:{u['clinic_id']}")
    return {"ok": True, "ai_custom_rules": b.model_dump()}


class AskIn(BaseModel):
    question: str = Field(min_length=1, max_length=300)


@router.post("/app/api/assistant")
async def panel_assistant(b: AskIn, u: dict = Depends(ANY)):
    if not await limiter.hit(f"asst:{u['id']}", 30, 60):
        raise HTTPException(429, "Çok fazla asistan sorgusu")
    from . import staff_bot
    txt = b.question.lower()
    if any(k in txt for k in ("bugün", "bugun")):
        return {"answer": await staff_bot.handle(u, "bugün"), "tokens": 0}
    if any(k in txt for k in ("yarın", "yarin", "randevu")):
        return {"answer": await staff_bot.handle(u, "yarın"), "tokens": 0}
    if any(k in txt for k in ("kasa", "tahsilat", "ciro", "gelir")):
        return {"answer": await staff_bot.handle(u, "kasa"), "tokens": 0}
    if any(k in txt for k in ("stok", "envanter", "malzeme")):
        return {"answer": await staff_bot.handle(u, "stok"), "tokens": 0}
    if any(k in txt for k in ("uyarı", "uyari", "alarm", "kırmızı", "kirmizi")):
        return {"answer": await staff_bot.handle(u, "uyarılar"), "tokens": 0}
    return {"answer": await staff_bot.handle(u, "özet"), "tokens": 0}


class SimIn(BaseModel):
    text: str = Field(min_length=1, max_length=1200)
    lang: str | None = Field(default=None, max_length=10)
    session_id: str | None = Field(default=None, max_length=80)
    patient_id: int | None = None
    context_previous_turn: str | None = Field(default=None, max_length=1200)


_SIM_ROUTER: TokenRouter | None = None


def _get_sim_router() -> TokenRouter:
    global _SIM_ROUTER
    if _SIM_ROUTER is None:
        _SIM_ROUTER = TokenRouter()
    return _SIM_ROUTER


@router.post("/app/api/conversations/simulate")
async def simulate_conversation(b: SimIn, u: dict = Depends(ANY)):
    sim_limit = 20 if u["role"] == "secretary" else (40 if u["role"] == "doctor" else 60)
    if not await limiter.hit(f"sim:{u['id']}", sim_limit, 60):
        raise HTTPException(429, "Çok fazla simülasyon isteği gönderildi; lütfen 1 dakika bekleyin")
    cid = u["clinic_id"]
    if b.patient_id is not None:
        if not await q1("SELECT id FROM patients WHERE id=%s AND clinic_id=%s", b.patient_id, cid):
            raise HTTPException(404, "hasta yok")
        await _enforce_doc_own_patient_pg(cid, b.patient_id, u)
        m_ref = re.search(r"\[?\bref\s*[:=-]\s*([a-zA-Z0-9_-]{2,64})\]?", b.text or "", re.IGNORECASE)
        cand_code = m_ref.group(1).strip() if m_ref else ""
        if cand_code:
            camp_sim = await q1(
                "SELECT * FROM campaigns WHERE clinic_id=%s AND (LOWER(code)=LOWER(%s) OR LOWER(utm_campaign)=LOWER(%s)) ORDER BY id DESC LIMIT 1",
                cid, cand_code, cand_code,
            )
            if camp_sim:
                det_s = detect_acquisition_source(
                    explicit_source=camp_sim.get("channel") or camp_sim.get("source"),
                    utm_source=camp_sim.get("utm_source") or "",
                    utm_medium=camp_sim.get("utm_medium") or "",
                    default_source="whatsapp",
                )
                cp_id_sim = int(camp_sim["id"])
                us_sim = (camp_sim.get("utm_source") or det_s)[:80]
                um_sim = (camp_sim.get("utm_medium") or "cpc")[:80]
                uc_sim = (camp_sim.get("utm_campaign") or camp_sim.get("code") or "")[:120]
                await q(
                    """UPDATE patients
                       SET last_source=%s, campaign_id=COALESCE(campaign_id, %s),
                           utm_source=CASE WHEN COALESCE(utm_source,'')='' AND %s<>'' THEN %s ELSE utm_source END,
                           utm_medium=CASE WHEN COALESCE(utm_medium,'')='' AND %s<>'' THEN %s ELSE utm_medium END,
                           utm_campaign=CASE WHEN COALESCE(utm_campaign,'')='' AND %s<>'' THEN %s ELSE utm_campaign END
                       WHERE id=%s AND clinic_id=%s""",
                    det_s, cp_id_sim, us_sim, us_sim, um_sim, um_sim, uc_sim, uc_sim, b.patient_id, cid,
                )
                has_ev_sim = await q1(
                    "SELECT 1 FROM campaign_events WHERE clinic_id=%s AND campaign_id=%s AND patient_id=%s AND event_type='patient_created' LIMIT 1",
                    cid, cp_id_sim, b.patient_id,
                )
                if not has_ev_sim:
                    await q(
                        """INSERT INTO campaign_events
                           (clinic_id,campaign_id,event_type,source,utm_source,utm_medium,utm_campaign,is_bot,is_unique,patient_id,created_at)
                           VALUES (%s,%s,'patient_created',%s,%s,%s,%s,0,1,%s,%s)""",
                        cid, cp_id_sim, det_s, us_sim, um_sim, uc_sim, b.patient_id, datetime.now(timezone.utc).isoformat(),
                    )
                    await q("UPDATE campaigns SET conversations = conversations + 1 WHERE id=%s AND clinic_id=%s", cp_id_sim, cid)
        sat_sim = await modules.handle_satisfaction_reply(b.patient_id, b.text, clinic_id=cid)
        if sat_sim:
            sat_ans, sat_intent = sat_sim
            await log_msg(b.patient_id, "in", None, "simulator", 0, 0, clinic_id=cid, body=b.text[:1200], delivery_status="received")
            await log_msg(b.patient_id, "out", "L1-memnuniyet", f"simulator:{sat_intent}", 0, 0, clinic_id=cid, body=sat_ans[:2000], delivery_status="dry_run")
            await log(u, "conversation.simulate", f"patient:{b.patient_id}", {"lang": b.lang or "tr", "layer": "L1-memnuniyet", "intent": sat_intent})
            return {
                "answer": sat_ans, "layer": "L1-memnuniyet", "intent": sat_intent, "lang": b.lang or "tr",
                "tokens_in": 0, "tokens_out": 0, "alert": None, "handoff": False, "meta": {"patient_id": b.patient_id},
            }
    c = await q1("SELECT name, address, phone, ai_custom_rules_json FROM clinics WHERE id=%s", cid)
    all_branches = await q("SELECT id, name, city, address, phone FROM clinics WHERE active")
    facts: dict = {
        "clinic": (c and c["name"]) or u.get("clinic_name") or S.clinic,
        "branches": all_branches,
    }
    if c and c.get("address"):
        facts["adres"] = c["address"]
    if c and c.get("phone"):
        facts["telefon"] = c["phone"]
    if c and c.get("ai_custom_rules_json"):
        facts["ai_custom_rules_json"] = c["ai_custom_rules_json"]
    allow_llm = (await has_consent(b.patient_id, "yurt_disi_aktarim")) if b.patient_id is not None else True
    rtr = _get_sim_router()
    try:
        res = await asyncio.wait_for(
            rtr.route(
                b.text,
                lang=b.lang,
                clinic_facts=facts,
                allow_llm=allow_llm,
                session_id=b.session_id,
                patient_id=b.patient_id,
                context_previous_turn=b.context_previous_turn,
            ),
            timeout=16.0,
        )
    except Exception:
        res = await rtr.route(
            b.text,
            lang=b.lang,
            clinic_facts=facts,
            allow_llm=False,
            session_id=b.session_id,
            patient_id=b.patient_id,
            context_previous_turn=b.context_previous_turn,
        )
    await log_msg(b.patient_id, "in", None, "simulator", 0, 0, clinic_id=cid, body=b.text[:1200], delivery_status="received")
    await log_msg(b.patient_id, "out", res.layer, f"simulator:{res.intent}", res.tokens_in, res.tokens_out, clinic_id=cid, body=res.answer[:2000], delivery_status="dry_run")
    await log(u, "conversation.simulate", f"clinic:{cid}", {"lang": res.lang, "layer": res.layer, "intent": res.intent})
    return {
        "answer": res.answer,
        "layer": res.layer,
        "intent": res.intent,
        "lang": res.lang,
        "tokens_in": res.tokens_in,
        "tokens_out": res.tokens_out,
        "alert": res.alert,
        "handoff": res.handoff,
        "meta": res.meta,
    }


async def _probe_http(url: str) -> bool:
    try:
        async with httpx.AsyncClient(timeout=0.18) as c:
            resp = await c.get(url)
            return resp.status_code < 500
    except Exception:
        return False


@router.get("/app/api/ecosystem-status")
async def ecosystem_status(u: dict = Depends(HQ_OWNER)):
    omni_url = env("LLM_BASE_URL", "http://127.0.0.1:20128/v1").rstrip("/")
    omni_base = omni_url[:-3] if omni_url.endswith("/v1") else omni_url
    headroom_url = env("HEADROOM_URL", "http://127.0.0.1:8787").rstrip("/")
    aioffice_url = env("AI_OFFICE_URL", "http://127.0.0.1:20140").rstrip("/")
    omni_ok, head_ok, aio_ok, voice_ok, seo_ok, op_ok, cal_ok, chat_ok = await asyncio.gather(
        _probe_http(f"{omni_base}/v1/models"),
        _probe_http(f"{headroom_url}/health"),
        _probe_http(f"{aioffice_url}/health"),
        _probe_http("http://127.0.0.1:3900/health"),
        _probe_http("http://127.0.0.1:3001/api/health"),
        _probe_http("http://127.0.0.1:8080/health_checks/default"),
        _probe_http("http://127.0.0.1:3002/api/version"),
        _probe_http("http://127.0.0.1:3000/api"),
    )
    local = os.environ.get("LOCALAPPDATA", "")
    apps = [
        {"id": "open-generative-ai", "name": "Open Generative AI", "ok": bool(local and (Path(local) / "Open Generative AI" / "Open Generative AI.exe").exists())},
        {"id": "voicestudio", "name": "VoiceStudio", "ok": voice_ok or bool(local and (Path(local) / "Programs" / "VoiceStudio" / "VoiceStudio.exe").exists())},
        {"id": "open-seo", "name": "OpenSEO", "ok": seo_ok},
        {"id": "appflowy", "name": "AppFlowy", "ok": bool(local and (Path(local) / "Programs" / "AppFlowy" / "AppFlowy" / "AppFlowy.exe").exists())},
        {"id": "openwhispr", "name": "OpenWhispr", "ok": bool(local and (Path(local) / "Programs" / "OpenWhispr" / "OpenWhispr.exe").exists())},
        {"id": "openproject", "name": "OpenProject CE", "ok": op_ok},
        {"id": "cal-diy", "name": "Cal.diy", "ok": cal_ok},
        {"id": "chatwoot", "name": "Chatwoot Community", "ok": chat_ok},
        {"id": "cap", "name": "Cap", "ok": bool(local and (Path(local) / "Cap" / "Cap.exe").exists())},
    ]
    return {
        "omniroute": {"ok": omni_ok, "url": omni_base},
        "headroom": {"ok": head_ok, "url": headroom_url},
        "ai_office": {"ok": aio_ok, "url": aioffice_url},
        "langs": 16,
        "security_headers": 12,
        "apps": apps,
    }


class RestoreTestIn(BaseModel):
    backup_path: str
    target_db_path: str


@router.post("/app/api/backup/create")
async def create_encrypted_backup(u: dict = Depends(HQ_OWNER)):
    if not await limiter.hit(f"bak_c:{u['id']}", 10, 60):
        raise HTTPException(429, "Çok fazla yedekleme isteği")
    await log(u, "backup.create", "postgres_backup")
    return {"ok": True, "mode": "postgres"}


@router.post("/app/api/backup/restore-test")
async def restore_encrypted_backup_test(b: RestoreTestIn, u: dict = Depends(HQ_OWNER)):
    if not await limiter.hit(f"bak_r:{u['id']}", 10, 60):
        raise HTTPException(429, "Çok fazla geri yükleme testi isteği")
    backups_dir = (Path(__file__).resolve().parents[2] / "backups").resolve()
    src_file = Path(b.backup_path).resolve()
    dst_file = Path(b.target_db_path).resolve()
    if (
        not src_file.is_relative_to(backups_dir)
        or not dst_file.is_relative_to(backups_dir)
        or dst_file.parent != backups_dir
        or not src_file.name.endswith(".db.gz.fernet")
        or not dst_file.name.endswith(".db")
    ):
        await log(u, "backup.restore_blocked", str(b.target_db_path)[:120])
        raise HTTPException(400, "Güvenlik engeli: Yedek ve hedef veritabanı yalnızca backups/ dizini içinde (.db) olabilir")
    await log(u, "backup.restore_test", dst_file.name)
    return {"ok": True}


@router.get("/app/api/audit")
async def audit_list(limit: int = 200, u: dict = Depends(OWNER)):
    return await q("SELECT id, ts, actor, action, target, meta, hash FROM audit_log WHERE clinic_id=%s ORDER BY id DESC LIMIT %s",
                   u["clinic_id"], min(max(limit, 1), 1000))


@router.get("/app/api/audit/verify")
async def audit_verify(u: dict = Depends(HQ_OWNER)):
    rows = await q("SELECT id, ts, actor, action, target, meta, prev_hash, hash FROM audit_log ORDER BY id")
    return sec.verify_chain(rows)


@router.get("/app/api/token-stats")
async def token_stats(days: int = 30, u: dict = Depends(ANY)):
    rows = await q("""SELECT m.layer, count(*) AS replies, coalesce(sum(m.tokens_in),0) AS tin, coalesce(sum(m.tokens_out),0) AS tout
                      FROM message_log m LEFT JOIN patients p ON p.id=m.patient_id
                      WHERE m.direction='out' AND m.created_at > now() - make_interval(days => %s)
                        AND COALESCE(p.clinic_id, m.clinic_id, 1)=%s
                      GROUP BY m.layer ORDER BY replies DESC""", min(max(days, 1), 365), u["clinic_id"])
    return rows


# ======================================================================== web sitesi demo talebi (herkese açık)
class LeadIn(BaseModel):
    clinic: str = Field(min_length=2, max_length=120)
    contact: str = Field(min_length=5, max_length=120)
    city: str | None = Field(default=None, max_length=40)
    chairs: int | None = Field(default=None, ge=1, le=200)
    source: str | None = Field(default=None, max_length=40)
    utm_source: str = Field("", max_length=80)
    utm_medium: str = Field("", max_length=80)
    utm_campaign: str = Field("", max_length=120)
    click_id: str = Field("", max_length=120)
    campaign_code: str = Field("", max_length=80)
    kvkk_aydinlatma: bool = False
    yurt_disi_riza: bool = False
    website: str | None = Field(default=None, max_length=200)   # bal küpü: insanlar boş bırakır


@router.post("/lead")
async def lead(b: LeadIn, request: Request):
    if b.website:
        return {"ok": True}
    if not b.kvkk_aydinlatma:
        raise HTTPException(400, "KVKK aydınlatma ve iletişim rızası onayı gereklidir")
    if not await limiter.hit(f"lead:{client_ip(request)}", 5, 3600):
        raise HTTPException(429, "Çok fazla talep")
    texts = sec.kvkk_texts("DentaCore")
    k_hash = sec.kvkk_sha256(texts["lead"])
    det_src = detect_acquisition_source(
        explicit_source=b.source,
        utm_source=b.utm_source,
        utm_medium=b.utm_medium,
        click_id=b.click_id,
        referrer=request.headers.get("referer", ""),
        default_source="website",
    )
    t_now = datetime.now(timezone.utc).isoformat()
    r = await q1(
        "INSERT INTO leads (clinic, contact_enc, city, chairs, kvkk_version, kvkk_sha256, yurt_disi_riza) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id",
        b.clinic, enc(b.contact), b.city, b.chairs, sec.KVKK_METIN_VER, k_hash, bool(b.yurt_disi_riza),
    )
    camp_code = b.campaign_code.strip() or b.utm_campaign.strip()
    camp_row = await q1("SELECT id, clinic_id FROM campaigns WHERE code=%s OR utm_campaign=%s LIMIT 1", camp_code, camp_code) if camp_code else None
    if camp_row:
        ua = request.headers.get("user-agent", "")
        bot_flag = 1 if is_bot_traffic(ua) else 0
        await q(
            """INSERT INTO campaign_events
               (clinic_id,campaign_id,event_type,source,utm_source,utm_medium,utm_campaign,click_id,is_bot,is_unique,user_agent_summary,created_at)
               VALUES (%s,%s,'form_submit',%s,%s,%s,%s,%s,%s,1,%s,%s)""",
            int(camp_row["clinic_id"]), int(camp_row["id"]), det_src, b.utm_source[:80], b.utm_medium[:80],
            b.utm_campaign[:120], b.click_id[:120], bot_flag, ua[:160], t_now,
        )
    await add_alert(None, "web_talep", f"Web sitesinden demo talebi ({PATIENT_SOURCE_LABELS.get(det_src, det_src)}): {b.clinic} ({b.city or '-'}, {b.chairs or '?'} koltuk)")
    return {"ok": True, "lead_id": r["id"] if r else None, "source": det_src}


@router.get("/app/api/leads")
async def list_leads_pg(u: dict = Depends(HQ_OWNER)):
    rows = await q("SELECT id, clinic, contact_enc, city, chairs, created_at FROM leads ORDER BY id DESC LIMIT 200")
    for r in rows:
        try:
            r["contact"] = dec(r.pop("contact_enc"))
        except Exception:
            r["contact"] = "***"
    return rows


@router.get("/app/api/patients/check-duplicate")
async def check_duplicate_patient_pg(phone: str = "", name: str = "", u: dict = Depends(require_perm("patient_view"))):
    cid = u["clinic_id"]
    matches = []
    if phone.strip():
        ph = phone_hmac(norm_phone(phone))
        p_row = await q1("SELECT id, display_name, first_source FROM patients WHERE clinic_id=%s AND phone_hmac=%s", cid, ph)
        if p_row:
            matches.append({"id": p_row["id"], "display_name": p_row["display_name"], "match_type": "exact_phone", "first_source": p_row.get("first_source")})
    if name.strip() and len(name.strip()) >= 3:
        n_rows = await q("SELECT id, display_name, first_source FROM patients WHERE clinic_id=%s AND lower(display_name)=lower(%s) LIMIT 5", cid, name.strip())
        for nr in n_rows:
            if not any(m["id"] == nr["id"] for m in matches):
                matches.append({"id": nr["id"], "display_name": nr["display_name"], "match_type": "similar_name", "first_source": nr.get("first_source")})
    return {"duplicate": len(matches) > 0, "matches": matches}


@router.post("/app/api/patients/{pid}/media")
async def upload_patient_media_pg(pid: int, request: Request, u: dict = Depends(require_perm("patient_edit"))):
    cid = u["clinic_id"]
    await _enforce_doc_own_patient_pg(cid, pid, u)
    p_row = await q1("SELECT id FROM patients WHERE id=%s AND clinic_id=%s", pid, cid)
    if not p_row:
        raise HTTPException(404, "hasta yok")
    data = await request.body()
    if not data or len(data) > 15 * 1024 * 1024:
        raise HTTPException(400, "Geçersiz dosya boyutu (en fazla 15 MB)")
    qp = request.query_params
    raw_base_fn = Path(str(qp.get("filename") or "upload.jpg").replace("\\", "/")).name
    safe_filename = re.sub(r"[^a-zA-Z0-9._-]", "_", raw_base_fn)[:120] or "upload.jpg"
    category = qp.get("category") if qp.get("category") in ("xray", "photo", "document") else "photo"
    stage = qp.get("stage") if qp.get("stage") in ("general", "before", "after") else "general"
    try:
        qc = media.assess_media_file(data, filename=safe_filename)
    except ValueError as ve:
        raise HTTPException(400, str(ve)) from None
    is_dcm = bool(qc.get("is_dicom") or qc.get("kind") == "dicom")
    eff_mime = str(qc.get("mime_type") or qc.get("mime") or "image/jpeg")
    enc_path = media.store_encrypted(pid, data, eff_mime)
    enc_name = Path(enc_path).name
    m_row = await q1(
        """INSERT INTO patient_media
           (clinic_id,patient_id,category,stage,original_filename,mime_type,file_size_bytes,
            sha256_hash,encrypted_path,is_dicom,width,height,sharpness,brightness,qc_verdict,uploaded_by,created_at)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
        cid, pid, "xray" if is_dcm else category, stage, safe_filename, eff_mime, len(data),
        qc.get("sha256", ""), enc_name, 1 if is_dcm else 0, int(qc.get("w") or 0), int(qc.get("h") or 0),
        float(qc.get("sharpness") or 0), float(qc.get("brightness") or 0), qc["verdict"], u["id"],
        datetime.now(timezone.utc).isoformat(),
    )
    mid = m_row["id"] if m_row else None
    await log(u, "patient.media_upload", f"patient:{pid}:media:{mid}", {"verdict": qc["verdict"]})
    return {**qc, "id": mid, "media_id": mid, "patient_id": pid, "filename": safe_filename, "encrypted_file": enc_name}


class PostopSchedPgIn(BaseModel):
    patient_id: int
    procedure: str = Field(min_length=2, max_length=120)


@router.post("/app/api/postop/schedule")
async def schedule_postop_pg(b: PostopSchedPgIn, u: dict = Depends(ANY)):
    if not await q1("SELECT id FROM patients WHERE id=%s AND clinic_id=%s", b.patient_id, u["clinic_id"]):
        raise HTTPException(404, "hasta yok")
    await modules.schedule_postop(b.patient_id, b.procedure, datetime.now(timezone.utc))
    return {"ok": True, "stages": ["2s", "24s", "72s"]}


class PostopReplyPgIn(BaseModel):
    patient_id: int
    stage: Literal["2s", "24s", "72s"] = "2s"
    pain_score: int = Field(ge=1, le=10)
    emergency: bool = False


@router.post("/app/api/postop/reply")
async def reply_postop_pg(b: PostopReplyPgIn, u: dict = Depends(ANY)):
    if not await q1("SELECT id FROM patients WHERE id=%s AND clinic_id=%s", b.patient_id, u["clinic_id"]):
        raise HTTPException(404, "hasta yok")
    alarm = bool(b.emergency or b.pain_score >= 8)
    await q("UPDATE postop_checks SET pain_score=%s, answered_at=now(), alarm=%s WHERE patient_id=%s AND stage=%s",
            b.pain_score, alarm, b.patient_id, b.stage)
    return {"ok": True, "alarm": alarm, "pain_score": b.pain_score}


@router.post("/app/api/appointments/{aid}/done")
async def appt_done_alias_pg(aid: int, u: dict = Depends(ANY)):
    return await appt_status(aid, StatusIn(status="done"), u)

