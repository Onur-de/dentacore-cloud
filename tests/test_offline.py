"""Ağ ve veritabanı gerektirmeyen tam kapsamlı çevrimdışı testler:
1) 3 Katmanlı Token Router (14/14 çok dilli senaryo, 0 LLM çağrısı)
2) Türkiye 81 İl Klinik Puanlama Motoru (0-100)
3) Görsel Kalite Denetçisi (Pillow Laplacian keskinlik + pozlama)
4) Sıfır-Güven Güvenlik Katmanı (Scrypt parola, RFC 6238 TOTP + replay engeli, SHA-256 hash zinciri, 12 HTTP güvenlik başlığı)
5) Kriptografi, WhatsApp/Instagram HMAC imzaları, Kasa kuruş/maskeleme ve 61 FastAPI uç noktası
"""
import asyncio
import hashlib
import hmac
import io
import os
import sys
import types
from decimal import Decimal
from pathlib import Path

from cryptography.fernet import Fernet
from PIL import Image, ImageDraw, ImageFilter

# Host ortamında psycopg kurulu değilse bellekte stubla (veritabanı gerektirmeyen testler için)
if "psycopg" not in sys.modules:
    sys.modules["psycopg"] = types.ModuleType("psycopg")
    sys.modules["psycopg.rows"] = types.SimpleNamespace(dict_row=None)
    sys.modules["psycopg_pool"] = types.SimpleNamespace(AsyncConnectionPool=object)

os.environ["CLINIC_NAME"] = "Test Klinik"
os.environ["DATA_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ["PHONE_HMAC_KEY"] = "test-hmac-key-32-bytes-minimum-ok"
os.environ["ADMIN_TOKEN"] = "test-admin-token-32-bytes-minimum"
os.environ["WA_APP_SECRET"] = "wa-secret-test"
os.environ["IG_APP_SECRET"] = "ig-secret-test"

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
sys.path.insert(0, str(ROOT / "lead_hunter"))

from app import cal, core, ig, main, media, modules, panel, security as sec, staff_bot, wa  # noqa: E402
from app.router import LANGS, TokenRouter, detect_lang  # noqa: E402
from dental_lead_hunter_tr import score  # noqa: E402


def test_router():
    import asyncio
    asyncio.run(_test_router())


async def _test_router():
    r = TokenRouter(redis=None, offline=True)
    cases = [
        ("Merhaba", "tr", "L1-sss", "selam"),
        ("Adresiniz nerede?", "tr", "L1-sss", "konum"),
        ("Cumartesi kaçta açıksınız", "tr", "L1-sss", "saat"),
        ("Is there parking?", "en", "L1-sss", "otopark"),
        ("Wo ist Ihre Adresse?", "de", "L1-sss", "konum"),
        ("أين موقع العيادة", "ar", "L1-sss", "konum"),
        ("Какие у вас часы работы?", "ru", "L1-sss", "saat"),
        ("Dişimi çektirdim kanama durmuyor", "tr", "L1-acil", "acil"),
        ("my face is swollen and I can't swallow", "en", "L1-acil", "acil"),
        ("İmplant fiyatı ne kadar?", "tr", "L2-anahtar", "fiyat"),
        ("How much do zirconia crowns cost", "en", "L2-anahtar", "fiyat"),
        ("Yarın için randevu almak istiyorum", "tr", "L2-anahtar", "randevu"),
        ("Sekreterden çok şikayetçiyim rezalet", "tr", "L2-anahtar", "sikayet"),
        ("İmplant tedavisi kaç seans sürer?", "tr", "L2-yedek", "genel"),
    ]
    for text, lang, exp_layer, exp_intent in cases:
        res = await r.route(text)
        assert res.lang == lang, f"{text}: dil {res.lang} != {lang}"
        assert res.layer == exp_layer, f"{text}: katman {res.layer} != {exp_layer}"
        assert res.intent == exp_intent, f"{text}: niyet {res.intent} != {exp_intent}"
        assert res.tokens_in == 0 and res.tokens_out == 0
        print(f"OK  [{res.lang}/{res.layer}/{res.intent}] {text} -> {res.answer[:70]}")

    # 16 dil algilama ve offline yonlendirme testleri (her dilden en az 1 cumle)
    lang_samples = {
        "tr": ("Merhaba, implant fiyatı ne kadar?", "fiyat"),
        "en": ("Hello, how much do zirconia crowns cost?", "fiyat"),
        "de": ("Guten Tag, wo ist Ihre Adresse?", "konum"),
        "ar": ("مرحبا، أين موقع العيادة؟", "konum"),
        "ru": ("Здравствуйте, какая цена на имплант?", "fiyat"),
        "fr": ("Bonjour, quelle est votre adresse ?", "konum"),
        "nl": ("Hallo, wat zijn de openingstijden vandaag?", "saat"),
        "es": ("Hola, ¿cuál es el precio de la consulta?", "fiyat"),
        "it": ("Buongiorno, dove siete e quanto costa?", "konum"),
        "fa": ("سلام، آدرس کلینیک کجاست و قیمت چند است؟", "konum"),
        "az": ("Salam, ünvanınız haradadır və qiymət neçədir?", "konum"),
        "uk": ("Добрий день, яка ціна та де ваша адреса?", "konum"),
        "bg": ("Здравейте, какво е работното време и колко струва?", "fiyat"),
        "ro": ("Bună ziua, care este adresa și cât costă?", "konum"),
        "el": ("Γεια σας, ποια είναι η διεύθυνση και το ωράριο;", "konum"),
        "he": ("שלום, מה הכתובת ושעות הפעילות שלכם?", "konum"),
    }
    assert set(lang_samples.keys()) == set(LANGS)
    for exp_lang, (sentence, exp_int) in lang_samples.items():
        det = detect_lang(sentence)
        assert det == exp_lang, f"Dil algılama hatası: {sentence} -> {det} != {exp_lang}"
        sres = await r.route(sentence, clinic_facts={"clinic": "Ankara Test Diş", "adres": "Tunalı Cad. No:88"}, allow_llm=False)
        assert sres.lang == exp_lang, f"{exp_lang}: route lang {sres.lang} != {exp_lang}"
        assert sres.intent == exp_int, f"{exp_lang}: route intent {sres.intent} != {exp_int}"
        if exp_int == "konum":
            assert "Tunalı Cad. No:88" in sres.answer

    # Offline & circuit-breaker simülasyon testi (L2 veya L3 hatasında devre kesici açılır)
    r_cb = TokenRouter(redis=None, offline=False)
    r_cb.base_url = "http://127.0.0.1:59999/v1"
    r_cb.api_key = "test"
    r_cb.small = ""
    cb_res = await r_cb.route("Zirkonyum ömrü kaç yıldır?", lang="tr", clinic_facts={"clinic": "Ankara Klinik"}, allow_llm=True)
    assert cb_res.layer == "L2-yedek" and cb_res.handoff is True and cb_res.meta.get("failover") == "circuit-breaker"
    assert not r_cb.llm_ready, "Devre kesici açık olmalı"
    print(f"Router: {len(cases)}+{len(lang_samples)} (16 dil + circuit-breaker) doğru, LLM çağrısı: 0")


def test_lead_scorer():
    place = {
        "displayName": {"text": "Örnek Ağız ve Diş Sağlığı Polikliniği"},
        "rating": 4.1,
        "userRatingCount": 120,
        "nationalPhoneNumber": "0224 000 00 00",
        "websiteUri": "https://ornekdis.com",
        "reviews": [
            {"text": {"text": "Telefonlara ulaşılamıyor, randevu almak çok zor, 40 dakika bekledik."}},
            {"text": {"text": "Doktor iyi ama sekreter geri dönmedi."}},
        ],
    }
    html_body = "<h1>İmplant, Zirkonyum ve Gülüş Tasarımı</h1><p>Hemen bilgi alın</p>"
    lead = score(place, html_body, True, "Bursa")
    assert lead.skor == 85, lead
    print(f"Lead skoru: {lead.skor} | {' | '.join(lead.bulgular)}")


def test_image_qc():
    img = Image.new("RGB", (1200, 800), (140, 140, 140))
    d = ImageDraw.Draw(img)
    for x in range(0, 1200, 20):
        d.line([(x, 0), (x, 800)], fill=(20, 20, 20), width=2)
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    sharp = media.assess_image(buf.getvalue())
    assert sharp["verdict"] == "ok", sharp

    blurry = img.filter(ImageFilter.GaussianBlur(radius=12))
    buf2 = io.BytesIO()
    blurry.save(buf2, format="JPEG")
    bl = media.assess_image(buf2.getvalue())
    assert bl["verdict"] == "blur", bl
    print(f"Görsel QC: net -> {sharp['verdict']} {sharp['sharpness']} | bulanık -> {bl['verdict']} {bl['sharpness']}")


def test_security_and_platform():
    # 1. Scrypt parola özeti
    h = sec.hash_password("CokGucluParola2026!")
    assert sec.verify_password("CokGucluParola2026!", h) and not sec.verify_password("YanlisParola1234", h)

    # 2. TOTP RFC 6238 + replay koruması
    secret = sec.new_totp_secret()
    code = sec.totp_now(secret, at=1700000000)
    step1 = sec.totp_verify(secret, code, last_step=0, at=1700000000)
    step_replay = sec.totp_verify(secret, code, last_step=step1, at=1700000000)
    assert step1 is not None and step_replay is None

    # 3. SHA-256 Hash-zincirli denetim kaydı ve müdahale tespiti
    rows = []
    prev = sec.GENESIS
    for idx, (act, tgt) in enumerate([("auth.login", "user:1"), ("patient.view", "patient:42"), ("kasa.charge", "charge:9")], 1):
        ts = f"2026-11-17T22:00:0{idx}Z"
        dg = sec.audit_digest(prev, ts, "hekim@klinik.com", act, tgt, "{}")
        rows.append({"id": idx, "ts": ts, "actor": "hekim@klinik.com", "action": act, "target": tgt, "meta": "{}", "prev_hash": prev, "hash": dg})
        prev = dg
    assert sec.verify_chain(rows)["ok"] is True
    rows[1]["target"] = "patient:99"
    broken = sec.verify_chain(rows)
    assert broken["ok"] is False and broken["broken_at"] == 2

    # 4. ASGI Güvenlik Başlıkları Middleware (12 başlık + server/x-powered-by gizleme)
    sent = []

    async def dummy_app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": [(b"server", b"uvicorn"), (b"x-powered-by", b"fastapi")]})
        await send({"type": "http.response.body", "body": b"ok"})

    async def mock_send(m):
        sent.append(m)

    async def run_mw():
        mw = sec.SecurityHeadersMiddleware(dummy_app)
        await mw({"type": "http", "path": "/app/api/overview"}, None, mock_send)

    asyncio.run(run_mw())
    hdrs = dict(sent[0]["headers"])
    assert b"server" not in hdrs and b"x-powered-by" not in hdrs
    assert b"strict-transport-security" in hdrs and b"content-security-policy" in hdrs and hdrs[b"cache-control"] == b"no-store"
    assert b"manifest-src 'self'" in hdrs[b"content-security-policy"] and b"worker-src 'self'" in hdrs[b"content-security-policy"]
    assert len(hdrs) >= 12, f"12 güvenlik başlığı bekleniyor, bulunan: {len(hdrs)}"

    # 5. Fernet şifreleme, HMAC ve imzalı URL
    enc_val = core.enc("+905321112233")
    assert core.dec(enc_val) == "+905321112233"
    assert core.phone_hmac("0532 111 22 33") == core.phone_hmac("+905321112233")
    signed = core.sign("/view/anamnez/5", ttl=60)
    params = dict(x.split("=") for x in signed.split("?")[1].split("&"))
    assert core.verify_sig("/view/anamnez/5", params["exp"], params["sig"])

    # 6. WhatsApp & Instagram HMAC-SHA256 imza doğrulaması
    payload = b"webhook_event_body"
    wa_sig = "sha256=" + hmac.new(b"wa-secret-test", payload, hashlib.sha256).hexdigest()
    ig_sig = "sha256=" + hmac.new(b"ig-secret-test", payload, hashlib.sha256).hexdigest()
    assert wa.verify_signature(payload, wa_sig) and not wa.verify_signature(payload, "sha256=bad")
    assert ig.verify_signature(payload, ig_sig) and not ig.verify_signature(payload, "sha256=bad")

    # 7. Anamnez (11 soru), Kasa kuruş/maskeleme, Personel Botu ve 61 HTTP uç noktası
    html_form = modules.anamnesis_form_html("tok123")
    assert "Kan sulandırıcı" in html_form and len(modules.ANAMNEZ_SORULAR) == 11
    assert panel.kurus(Decimal("1250.50")) == 125050 and panel.tl(125050) == 1250.5
    assert panel.mask_phone("905321234567") == "+90 5** *** 45 67"
    assert "Personel komutları" in asyncio.run(staff_bot.handle({"role": "owner"}, "yardım"))
    total_routes = (len(main.app.routes) - 1) + len(panel.router.routes)
    assert total_routes >= 70, f"Beklenen en az 70 uç nokta, bulunan: {total_routes}"
    print(f"Güvenlik & Platform: Scrypt, TOTP+Replay, SHA-256 Zincir, {len(hdrs)} HTTP Başlık, {total_routes} Uç Nokta OK")


def test_calendar_and_multitenant():
    appt = {
        "id": 42,
        "starts_at": "2026-11-20T14:30:00+03:00",
        "duration_min": 45,
        "treatment": "İmplant Kontrol",
        "chair": "2",
        "patient": "Ahmet Yılmaz",
        "doctor": "Dt. Onur Aksoy",
        "red_flag": True,
        "status": "confirmed",
    }
    ics = cal.appointment_ics(appt, "Özel DentaCore Polikliniği", "Bağdat Cad. No:142, Kadıköy")
    assert "BEGIN:VCALENDAR" in ics and "BEGIN:VEVENT" in ics and "BEGIN:VALARM" in ics
    assert "TRIGGER:-PT60M" in ics and "TRIGGER:-PT15M" in ics and "DTSTART:20261120T113000Z" in ics

    feed = cal.feed_ics([appt], "Özel DentaCore Polikliniği", "Kadıköy")
    assert "REFRESH-INTERVAL;VALUE=DURATION:PT15M" in feed and "dentacore-42@dentacore.local" in feed

    gurl = cal.google_calendar_url(appt, "Özel DentaCore Polikliniği", "Kadıköy")
    assert gurl.startswith("https://calendar.google.com/calendar/render?action=TEMPLATE")
    assert "20261120T113000Z%2F20261120T121500Z" in gurl

    tok = cal.calendar_feed_token(7)
    assert cal.verify_feed_token(tok) == 7 and cal.verify_feed_token(tok + "tamper") is None
    print(f"iPhone/Android Takvim: RFC 5545 .ics + 2 VALARM + webcal/feed HMAC (clinic=7) + Google Cal URL OK")


if __name__ == "__main__":
    test_router()
    test_lead_scorer()
    test_image_qc()
    test_security_and_platform()
    test_calendar_and_multitenant()
    print("SONUÇ: TÜM TESTLER GEÇTİ")
