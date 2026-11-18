"""DentaCore API: WhatsApp webhook, yönetim uç noktaları, formlar."""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import re
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from pydantic import BaseModel, Field

from . import ig, media, modules, panel, staff_bot, wa
from .core import (S, add_alert, db_close, db_open, env, has_consent, log_msg, mask_phone, patient, phone_hmac, q, q1, run_migrations,
                   tx, upsert_identity, upsert_patient, verify_sig)
from .router import TokenRouter, normalize
from .security import SecurityHeadersMiddleware, WebhookDedupCache, audit as sec_audit

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("api")
state: dict = {}
_MEM_WEBHOOK_DEDUP = WebhookDedupCache(max_size=10_000, ttl_seconds=86_400)
HERE = Path(__file__).parent
WEB = HERE / "web"
MIGRATION = Path(env("MIGRATION_FILE", str(HERE / "migrations" / "002_platform.sql")))


@asynccontextmanager
async def lifespan(app: FastAPI):
    for k in ("DATA_ENCRYPTION_KEY", "PHONE_HMAC_KEY", "ADMIN_TOKEN", "DATABASE_URL"):
        if not env(k):
            raise RuntimeError(f"{k} tanımlı değil")
    await db_open()
    await run_migrations(str(MIGRATION))
    await panel.bootstrap_owner()
    redis = None
    if S.redis_url:
        import redis.asyncio as aioredis
        redis = aioredis.from_url(S.redis_url, decode_responses=True)
    state["redis"] = redis
    panel.limiter.redis = redis
    state["router"] = TokenRouter(redis=redis)
    task = asyncio.create_task(modules.scheduler_loop(redis))
    yield
    task.cancel()
    await db_close()


app = FastAPI(title="DentaCore", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SecurityHeadersMiddleware)
app.include_router(panel.router)


def require_admin(token: str | None):
    if not token or not hmac.compare_digest(token, S.admin_token):
        raise HTTPException(401, "yetkisiz")


@app.get("/health")
async def health():
    await q1("SELECT 1")
    return {"ok": True}


# ======================= Web sitesi ve panel (statik, dış kaynak yok) =======================
STATIC_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*\.(js|css|svg|png|webp|ico|json|webmanifest|woff2)$")


@app.get("/", include_in_schema=False)
async def landing():
    return FileResponse(WEB / "index.html")


@app.get("/app", include_in_schema=False)
async def app_shell():
    return FileResponse(WEB / "app.html")


@app.get("/app/", include_in_schema=False)
async def app_slash():
    return RedirectResponse("/app")


@app.get("/static/{name}", include_in_schema=False)
async def static(name: str):
    if not STATIC_RE.fullmatch(name) or ".." in name:
        raise HTTPException(404)
    p = (WEB / name).resolve()
    if p.parent != WEB.resolve() or not p.is_file():
        raise HTTPException(404)
    return FileResponse(p, headers={"cache-control": "public, max-age=3600"})


@app.get("/manifest.webmanifest", include_in_schema=False)
async def manifest():
    p = WEB / "manifest.webmanifest"
    if p.is_file():
        return FileResponse(p, media_type="application/manifest+json")
    return JSONResponse({
        "name": "DentaCore Klinik İşletim Sistemi",
        "short_name": "DentaCore",
        "start_url": "/app",
        "scope": "/",
        "display": "standalone",
        "background_color": "#0A2540",
        "theme_color": "#0D9488",
        "icons": [{"src": "/static/favicon.svg", "sizes": "any", "type": "image/svg+xml"}],
    }, media_type="application/manifest+json")


@app.get("/sw.js", include_in_schema=False)
async def service_worker():
    p = WEB / "sw.js"
    hdrs = {"Service-Worker-Allowed": "/", "cache-control": "no-cache"}
    if p.is_file():
        return FileResponse(p, media_type="application/javascript; charset=utf-8", headers=hdrs)
    return Response(
        "self.addEventListener('install', () => self.skipWaiting());\n"
        "self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));\n",
        media_type="application/javascript; charset=utf-8",
        headers=hdrs,
    )


@app.get("/sitemap.xml", include_in_schema=False)
async def sitemap(request: Request):
    base = str(request.base_url).rstrip("/")
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f'  <url><loc>{base}/</loc><changefreq>weekly</changefreq><priority>1.0</priority></url>\n'
        f'  <url><loc>{base}/app</loc><changefreq>monthly</changefreq><priority>0.8</priority></url>\n'
        '</urlset>\n'
    )
    return Response(xml, media_type="application/xml; charset=utf-8")


@app.get("/robots.txt", include_in_schema=False)
async def robots(request: Request):
    base = str(request.base_url).rstrip("/")
    return PlainTextResponse(
        "User-agent: *\nAllow: /$\nDisallow: /app\nDisallow: /calendar/\nDisallow: /form/\nDisallow: /view/\nDisallow: /admin/\n"
        f"Sitemap: {base}/sitemap.xml\n"
    )


# ======================= WhatsApp webhook =======================
@app.get("/webhook/whatsapp")
async def wa_verify(request: Request):
    p = request.query_params
    if p.get("hub.mode") == "subscribe" and hmac.compare_digest(p.get("hub.verify_token", ""), env("WA_VERIFY_TOKEN")):
        return PlainTextResponse(p.get("hub.challenge", ""))
    raise HTTPException(403)


async def _is_dup_webhook_msg(msg_id: str) -> bool:
    if not msg_id:
        return False
    r = state.get("redis")
    if r:
        return not await r.set(f"dc:seen:{msg_id}", "1", nx=True, ex=86400)
    return _MEM_WEBHOOK_DEDUP.seen_or_add(msg_id)


async def _resolve_webhook_clinic(channel: str, channel_id: str) -> int | None:
    if channel_id:
        col = "wa_phone_id" if channel == "wa" else "ig_handle"
        row = await q1(f"SELECT id FROM clinics WHERE {col}=%s AND active LIMIT 1", channel_id)  # nosec B608
        if row:
            return int(row["id"])
    log.error("Eşleşmeyen webhook kanalı: channel=%s id=%s", channel, channel_id or "<boş>")
    try:
        await sec_audit(None, f"{channel}_webhook", "webhook.unmapped_clinic", f"{channel}:{channel_id or 'missing'}",
                        meta={"channel": channel, "channel_id": channel_id[:80]}, clinic_id=1)
    except Exception:
        log.exception("webhook unmapped_clinic audit kaydı yazılamadı")
    return None


@app.post("/webhook/whatsapp")
async def wa_inbound(request: Request, x_hub_signature_256: str | None = Header(default=None)):
    raw = await request.body()
    if not wa.verify_signature(raw, x_hub_signature_256):
        raise HTTPException(401, "imza geçersiz")
    try:
        body = json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(400, "Geçersiz JSON gövdesi")
    processed, dedup, unmapped = 0, 0, 0
    for entry in body.get("entry", []):
        for ch in entry.get("changes", []):
            v = ch.get("value", {})
            phone_number_id = str((v.get("metadata") or {}).get("phone_number_id") or "").strip()
            clinic_id = await _resolve_webhook_clinic("wa", phone_number_id)
            if not clinic_id:
                unmapped += len(v.get("messages", [])) or 1
                continue
            names = {c.get("wa_id"): (c.get("profile") or {}).get("name") for c in v.get("contacts", [])}
            for m in v.get("messages", []):
                # Meta webhook'u yeniden deneyebilir: aynı mesajı iki kez işleme
                if await _is_dup_webhook_msg(str(m.get("id") or "")):
                    dedup += 1
                    continue
                try:
                    await handle_message(m, names.get(m.get("from")), clinic_id=clinic_id)
                    processed += 1
                except Exception:
                    log.exception("mesaj işlenemedi")
    return {"ok": True, "processed": processed, "dedup": dedup, "unmapped": unmapped}


# ======================= Instagram DM webhook =======================
@app.get("/webhook/instagram")
async def ig_verify(request: Request):
    p = request.query_params
    if p.get("hub.mode") == "subscribe" and hmac.compare_digest(p.get("hub.verify_token", ""), env("IG_VERIFY_TOKEN") or env("WA_VERIFY_TOKEN")):
        return PlainTextResponse(p.get("hub.challenge", ""))
    raise HTTPException(403)


@app.post("/webhook/instagram")
async def ig_inbound(request: Request, x_hub_signature_256: str | None = Header(default=None)):
    raw = await request.body()
    if not ig.verify_signature(raw, x_hub_signature_256):
        raise HTTPException(401, "imza geçersiz")
    try:
        body = json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(400, "Geçersiz JSON gövdesi")
    processed, dedup, unmapped = 0, 0, 0
    for entry in body.get("entry", []):
        entry_id = str(entry.get("id") or "").strip()
        for ev in entry.get("messaging", []):
            msg = ev.get("message") or {}
            if msg.get("is_echo") or not msg.get("text"):
                continue
            ig_target = str((ev.get("recipient") or {}).get("id") or entry_id).strip()
            clinic_id = await _resolve_webhook_clinic("ig", ig_target)
            if not clinic_id:
                unmapped += 1
                continue
            if await _is_dup_webhook_msg(str(msg.get("mid") or "")):
                dedup += 1
                continue
            try:
                await handle_message({"from": ev["sender"]["id"], "type": "text", "text": {"body": msg["text"]}},
                                     None, channel="ig", clinic_id=clinic_id)
                processed += 1
            except Exception:
                log.exception("IG mesajı işlenemedi")
    return {"ok": True, "processed": processed, "dedup": dedup, "unmapped": unmapped}


async def handle_message(m: dict, profile_name: str | None, channel: str = "wa", clinic_id: int = 1):
    sender = m["from"]
    mtype = m.get("type")
    text, payload = "", ""
    if mtype == "text":
        text = m["text"]["body"]
    elif mtype == "button":
        text, payload = m["button"].get("text", ""), m["button"].get("payload", "")
    elif mtype == "interactive":
        it = m["interactive"]
        rep = it.get("button_reply") or it.get("list_reply") or {}
        text, payload = rep.get("title", ""), rep.get("id", "")

    # Personel numarası: hasta akışına girmeden komut asistanı (0 token)
    if channel == "wa" and text:
        staff = await q1("SELECT id, clinic_id, role, full_name FROM staff_users WHERE phone_hmac=%s AND active", phone_hmac(sender))
        if staff:
            ans = await staff_bot.handle(staff, text)
            await wa.send_text(sender, ans or staff_bot.HELP)
            return

    router: TokenRouter = state["router"]
    from .router import detect_lang
    lang = detect_lang(text) if text else "tr"
    if channel == "ig":
        phone = f"ig:{sender}"
        pid = await upsert_identity(phone, "ig", lang=lang, name=profile_name, clinic_id=clinic_id)
    else:
        phone = sender
        pid = await upsert_patient(phone, lang=lang, name=profile_name, clinic_id=clinic_id)
    await log_msg(pid, "in", intent=f"{channel}:{mtype}", clinic_id=clinic_id, body=text or payload, delivery_status="received")

    async def reply(body: str, layer: str, intent: str, tin: int = 0, tout: int = 0):
        wa_res = await wa.send_text(phone, body)
        st = "dry_run" if (wa_res or {}).get("dry_run") else ("failed" if (wa_res or {}).get("error") else "sent")
        err = json.dumps(wa_res["error"], ensure_ascii=False)[:500] if (wa_res or {}).get("error") else None
        await log_msg(pid, "out", layer, intent, tin, tout, clinic_id=clinic_id, body=body, delivery_status=st, delivery_error=err)

    # 1) Görsel: önce açık rıza, sonra kalite denetimi (tanı yok)
    if mtype in ("image", "document") and (m.get(mtype) or {}).get("mime_type", "image/").startswith("image/"):
        if not await has_consent(pid, "saglik_verisi_acik_riza"):
            link = await modules.create_anamnesis_link(pid)
            return await reply("Görsel paylaşmadan önce sağlık verisi açık rıza formunu onaylamanız gerekir. "
                               f"Form (1 dk): {link} Onaydan sonra görseli tekrar gönderebilirsiniz.", "L1-onam", "gorsel")
        data, mime = await wa.download_media(m[mtype]["id"])
        result = media.assess_image(data)
        if result["verdict"] == "ok":
            path = media.store_encrypted(pid, data, mime)
            await add_alert(pid, "gorsel_alindi", f"Hasta #{pid} değerlendirmeye uygun görsel gönderdi ({result['w']}x{result['h']}). Dosya: {path}")
        return await reply(media.qc_reply(result, lang if lang in ("tr", "en") else "en"), "L1-gorsel-qc", "gorsel_" + result["verdict"])

    if not text:
        return

    # 2) Bağlamsal deterministik cevaplar (0 token)
    if re.fullmatch(r"\s*(10|[1-9])\s*", text):
        post = await modules.handle_postop_reply(pid, text, emergency=router.is_emergency(text))
        if post:
            return await reply(post, "L1-postop", "postop")
    else:
        norm_txt = normalize(text).strip()
        if payload.startswith("SLOT_") or (norm_txt in modules.YES and not payload):
            offer_id = int(payload.split("_")[1]) if payload.startswith("SLOT_") else None
            ans = await modules.claim_slot(pid, offer_id)
            if ans:
                return await reply(ans, "L1-koltuk", "bekleme_listesi")
        if payload.startswith("RMD_") or norm_txt in (modules._CONFIRM_WORDS | modules._CANCEL_WORDS):
            ans = await modules.handle_reminder_reply(pid, payload, text)
            if ans:
                return await reply(ans, "L1-hatirlatma", "teyit")

        post = await modules.handle_postop_reply(pid, text, emergency=router.is_emergency(text))
        if post:
            return await reply(post, "L1-postop", "postop")

    # 3) Token Router (SEC-03: yurt_disi_aktarim rızası yoksa yalnız yerel L1/L2)
    allow_llm = await has_consent(pid, "yurt_disi_aktarim")
    res = await router.route(text, lang, allow_llm=allow_llm, patient_id=pid)
    await reply(res.answer, res.layer, res.intent, res.tokens_in, res.tokens_out)
    if res.alert == "acil":
        p = await patient(pid)
        await modules.alert_doctor(S.doctor_on_call or S.doctor_owner,
                                   f"ACİL MESAJ: {p.get('display_name') or 'Hasta'} (#{pid}) acil belirti bildirdi. Geri arama: {mask_phone(p['phone'])}",
                                   pid, "acil")
    elif res.alert == "sikayet":
        await modules.alert_doctor(S.doctor_owner, f"ŞİKAYET: Hasta #{pid} memnuniyetsizlik bildirdi. Lütfen geri dönün.", pid, "sikayet")

    # 4) Yüksek değerli tedavi ilk temasında hekim sesi (varsa, hasta başına bir kez)
    r = state["redis"]
    if res.high_value and r and await r.set(f"dc:voice:{pid}", "1", nx=True, ex=180 * 86400):
        try:
            vn = await media.voice_note("yuksek_deger", lang)
            if vn:
                ogg, synthetic = vn
                mid = await wa.upload_media(ogg, "audio/ogg", "mesaj.ogg")
                if mid:
                    if synthetic:
                        await wa.send_text(phone, media.VOICE_DISCLOSURE.get(lang, media.VOICE_DISCLOSURE["en"]))
                    await wa.send_audio(phone, mid)
                    await log_msg(pid, "out", "L1-ses", "hekim_sesi")
        except Exception:
            log.exception("ses gönderilemedi")


_FORM_VALIDATE_JS = """document.addEventListener("DOMContentLoaded",function(){
  var f=document.querySelector("form[novalidate]");
  if(!f)return;
  var box=document.getElementById("form-err");
  function clearErr(){
    f.querySelectorAll(".f-err").forEach(function(n){n.remove();});
    f.querySelectorAll(".has-err").forEach(function(n){n.classList.remove("has-err");});
    if(box){box.style.display="none";box.textContent="";}
  }
  function addErr(host,msg){
    var p=document.createElement("p");
    p.className="f-err";
    p.textContent=msg;
    host.classList.add("has-err");
    host.appendChild(p);
  }
  f.addEventListener("change",function(ev){
    var fs=ev.target.closest("fieldset,label");
    if(fs){fs.classList.remove("has-err");fs.querySelectorAll(".f-err").forEach(function(n){n.remove();});}
  });
  f.addEventListener("input",function(ev){
    var p=ev.target.parentElement;
    if(p){p.classList.remove("has-err");p.querySelectorAll(".f-err").forEach(function(n){n.remove();});}
  });
  f.addEventListener("submit",function(e){
    clearErr();
    var first=null;
    f.querySelectorAll("fieldset").forEach(function(fs){
      var reqRadio=fs.querySelector("input[type=radio][required]");
      if(reqRadio && !fs.querySelector("input[type=radio]:checked")){
        addErr(fs,"Lütfen bu soruyu yanıtlayın.");
        if(!first)first=reqRadio;
      }
    });
    f.querySelectorAll("input[required]:not([type=radio]):not([type=checkbox]),textarea[required]").forEach(function(el){
      var v=(el.value||"").trim();
      var ml=parseInt(el.getAttribute("minlength")||"0",10);
      if(!v || (ml && v.length<ml)){
        var msg=el.name==="imza"?"Lütfen adınızı ve soyadınızı yazın (en az 2 karakter).":"Lütfen bu alanı doldurun.";
        addErr(el.parentElement,msg);
        if(!first)first=el;
      }
    });
    f.querySelectorAll("input[type=checkbox][required]").forEach(function(cb){
      if(!cb.checked){
        var lbl=cb.closest("label")||cb.parentElement;
        var p=document.createElement("p");
        p.className="f-err";
        p.textContent="Lütfen zorunlu onay kutusunu işaretleyin.";
        lbl.classList.add("has-err");
        lbl.insertAdjacentElement("afterend",p);
        if(!first)first=cb;
      }
    });
    if(first){
      e.preventDefault();
      if(box){box.textContent="Lütfen işaretlenen eksik alanları tamamlayın.";box.style.display="block";}
      first.scrollIntoView({behavior:"smooth",block:"center"});
      try{first.focus({preventScroll:true});}catch(_){}
    }
  });
});
"""


@app.get("/form/validate.js", include_in_schema=False)
async def form_validate_js():
    return Response(_FORM_VALIDATE_JS, media_type="application/javascript; charset=utf-8", headers={"cache-control": "no-store"})


# ======================= Formlar =======================
@app.get("/form/anamnez/{token}", response_class=HTMLResponse)
async def anamnez_form(token: str):
    return modules.anamnesis_form_html(token)


@app.post("/form/anamnez/{token}", response_class=HTMLResponse)
async def anamnez_submit(token: str, request: Request):
    form = dict(await request.form())
    ok, msg = await modules.submit_anamnesis(token, form)
    if not ok:
        return HTMLResponse(modules.anamnesis_form_html(token, msg), status_code=400)
    return HTMLResponse(f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'>"
                        f"<body style='font-family:system-ui;padding:24px;color:#0A2540'><h2>{msg}</h2></body>")


@app.get("/view/anamnez/{aid}", response_class=HTMLResponse)
async def anamnez_view(aid: int, exp: str = "", sig: str = ""):
    if not verify_sig(f"/view/anamnez/{aid}", exp, sig):
        raise HTTPException(403, "bağlantı geçersiz veya süresi dolmuş")
    return await modules.anamnesis_view_html(aid)


@app.get("/form/geri-bildirim", response_class=HTMLResponse)
async def feedback_form():
    import html as _html
    from .core import sign
    qs = sign("/form/geri-bildirim", ttl=3600).split("?", 1)[1]
    tok = _html.escape(qs, quote=True)
    return f"""<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Başhekimliğe ilet</title><style>.err,.f-err{{color:#b91c1c;font-size:13px;font-weight:600;margin:6px 0}}.err{{background:#FEF2F2;border:1px solid #FECACA;border-radius:8px;padding:10px}}.btn-back{{display:inline-block;padding:10px 16px;border-radius:8px;background:#0A2540;color:#fff;text-decoration:none;font-weight:600}}</style></head><body style="font-family:system-ui;background:#F8FAFC;color:#0A2540;padding:16px">
<main style="max-width:520px;margin:auto;background:#fff;border-radius:12px;padding:18px;border:1px solid #e2e8f0">
<h2 style="margin-top:0">{_html.escape(S.clinic)} - Başhekimliğe doğrudan ilet</h2>
<p>Görüşünüz doğrudan başhekime ulaşır. Google'da değerlendirme yapma hakkınız bundan bağımsızdır: <a href="{_html.escape(S.google_review_url or '#', quote=True)}">Google'da değerlendir</a></p>
<div id="form-err" class="err" role="alert" style="display:none"></div>
<form method="post" novalidate><input type="hidden" name="csrf_token" value="{tok}"><label for="mesaj" style="display:block;font-weight:600;margin-bottom:6px">Mesajınız</label><div><textarea id="mesaj" name="mesaj" rows="5" required maxlength="1500" style="width:100%;box-sizing:border-box;padding:10px;border-radius:8px;border:1px solid #cbd5e1"></textarea></div>
<input name="iletisim" placeholder="Size dönmemizi isterseniz telefon (isteğe bağlı)" maxlength="40" style="width:100%;box-sizing:border-box;padding:10px;margin-top:8px;border-radius:8px;border:1px solid #cbd5e1">
<button style="width:100%;margin-top:12px;background:#0F766E;color:#fff;border:0;border-radius:10px;padding:13px;font-weight:700">Gönder</button></form>
<script src="/form/validate.js" defer></script></main></body></html>"""


@app.post("/form/geri-bildirim", response_class=HTMLResponse)
async def feedback_submit(request: Request):
    from urllib.parse import parse_qs
    f = await request.form()
    tok_p = parse_qs(str(f.get("csrf_token", "")))
    if not verify_sig("/form/geri-bildirim", (tok_p.get("exp") or [""])[0], (tok_p.get("sig") or [""])[0]):
        raise HTTPException(403, "Form oturumu geçersiz veya süresi dolmuş")
    msg = str(f.get("mesaj", ""))[:1500]
    if not msg.strip():
        return HTMLResponse(
            "<meta charset=utf-8><body style='font-family:system-ui;padding:24px;color:#0A2540'>"
            "<h2>Lütfen mesajınızı yazın</h2><p><a href='/' style='display:inline-block;padding:10px 16px;border-radius:8px;background:#0A2540;color:#fff;text-decoration:none;font-weight:600'>Kliniğe / Ana Sayfaya Dön</a></p></body>",
            status_code=400,
        )
    await modules.alert_doctor(S.doctor_owner, f"Başhekimliğe geri bildirim: {msg[:600]} | İletişim: {str(f.get('iletisim', ''))[:40] or 'yok'}", None, "geri_bildirim")
    return HTMLResponse("<meta charset=utf-8><body style='font-family:system-ui;padding:24px'><h2>Teşekkür ederiz, mesajınız iletildi.</h2></body>")


# ======================= Yönetim (n8n / klinik yazılımı entegrasyonu) =======================
class ApptIn(BaseModel):
    phone: str
    name: str | None = None
    starts_at: datetime
    duration_min: int = Field(30, ge=5, le=480)
    treatment: str
    chair: str = "1"


class WaitIn(BaseModel):
    phone: str
    name: str | None = None
    treatment: str = "herhangi"
    earliest: datetime | None = None


class ProcIn(BaseModel):
    phone: str
    procedure: str
    done_at: datetime | None = None


class PlanIn(BaseModel):
    phone: str
    treatment: str
    contact_consent: bool = False


class PhoneIn(BaseModel):
    phone: str


@app.post("/admin/appointments")
async def admin_appt(a: ApptIn, x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    starts = a.starts_at if a.starts_at.tzinfo else a.starts_at.replace(tzinfo=timezone.utc)
    ends = starts + timedelta(minutes=a.duration_min)
    pid = await upsert_patient(a.phone, name=a.name)
    async with tx() as t:
        await t.q("SELECT pg_advisory_xact_lock(hashtext(%s))", f"chair:1:{a.chair}")
        clash = await t.q1(
            """SELECT id FROM appointments WHERE clinic_id=1 AND chair=%s AND status IN ('booked','confirmed')
               AND starts_at < %s AND starts_at + make_interval(mins => duration_min) > %s LIMIT 1""",
            a.chair, ends, starts,
        )
        if clash:
            raise HTTPException(409, f"Koltuk {a.chair} bu saatte dolu (randevu #{clash['id']})")
        r = await t.q1("INSERT INTO appointments (clinic_id, patient_id, starts_at, duration_min, treatment, chair) VALUES (1,%s,%s,%s,%s,%s) RETURNING id",
                       pid, starts, a.duration_min, a.treatment, a.chair)
    return {"id": r["id"], "patient_id": pid}


@app.post("/admin/appointments/{appt_id}/cancel")
async def admin_cancel(appt_id: int, x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    await modules.cancel_and_refill(appt_id)
    offers = await q1("SELECT count(*) AS n FROM slot_offers WHERE appointment_id=%s", appt_id)
    return {"ok": True, "teklif_gonderilen": offers["n"]}


@app.post("/admin/appointments/{appt_id}/done")
async def admin_done(appt_id: int, x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    a = await q1("UPDATE appointments SET status='done' WHERE id=%s RETURNING patient_id", appt_id)
    if a and a["patient_id"]:
        await modules.request_feedback(a["patient_id"])
    return {"ok": bool(a)}


@app.post("/admin/waitlist")
async def admin_wait(w: WaitIn, x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    pid = await upsert_patient(w.phone, name=w.name)
    r = await q1("INSERT INTO waitlist (patient_id, treatment, earliest) VALUES (%s,%s,COALESCE(%s, now())) RETURNING id",
                 pid, w.treatment, w.earliest)
    return {"id": r["id"]}


@app.post("/admin/procedure")
async def admin_proc(p: ProcIn, x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    pid = await upsert_patient(p.phone)
    await modules.schedule_postop(pid, p.procedure, p.done_at or datetime.now(timezone.utc))
    return {"ok": True, "kontroller": ["2s", "24s", "72s"]}


@app.post("/admin/plan")
async def admin_plan(p: PlanIn, x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    pid = await upsert_patient(p.phone)
    r = await q1("INSERT INTO treatment_plans (patient_id, treatment) VALUES (%s,%s) RETURNING id", pid, p.treatment)
    if p.contact_consent and not await has_consent(pid, "iletisim"):
        from .core import add_consent
        await add_consent(pid, "iletisim", "2026-11", "Tedavi planım hakkında WhatsApp ile hatırlatma almayı kabul ediyorum.", "klinik_sozlu_kayit")
    return {"id": r["id"]}


@app.post("/admin/anamnesis/send")
async def admin_anam(p: PhoneIn, x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    pid = await upsert_patient(p.phone)
    return {"link": await modules.send_anamnesis(pid)}


@app.post("/admin/brief")
async def admin_brief(x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    return {"ozet": await modules.morning_brief()}


@app.get("/admin/alerts")
async def admin_alerts(x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    return await q("SELECT id, patient_id, kind, detail, created_at FROM alerts WHERE acknowledged_at IS NULL ORDER BY created_at DESC LIMIT 100")


@app.get("/admin/token-stats")
async def admin_stats(days: int = 30, x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    rows = await q("""SELECT layer, count(*) AS cevap, coalesce(sum(tokens_in),0) AS tin, coalesce(sum(tokens_out),0) AS tout
                      FROM message_log WHERE direction='out' AND created_at > now() - make_interval(days => %s)
                      GROUP BY layer ORDER BY cevap DESC""", days)
    total = sum(r["cevap"] for r in rows)
    free = sum(r["cevap"] for r in rows if (r["layer"] or "").startswith("L1"))
    return {"gun": days, "toplam_cevap": total, "llm_siz_oran": round(free / total, 3) if total else None, "katmanlar": rows}


@app.post("/admin/route-test")
async def admin_route_test(request: Request, x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token)
    b = await request.json()
    res = await state["router"].route(b.get("text", ""), b.get("lang"))
    return JSONResponse(res.__dict__)
