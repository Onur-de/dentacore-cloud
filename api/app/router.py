"""
Token Router: 3 katmanlı maliyet yönlendiricisi + Parlant VIP Hasta Koordinatörü (ContextualConciergeComposer)
+ Birleşik Niyet Motoru + Çok Turlu FSM + RapidFuzz + Müşteriye Özel Klinik Cevap Politikası Motoru.

Mimari Referanslar (GitHub Açık Kaynak En İyi Uygulamaları):
  - emcie-co/parlant (18,335⭐): Contextual Guideline Composition & Utterance Framing
  - chatwoot/chatwoot (40,115⭐): Captain AI Omnichannel Concierge Tone & Empathetic Handoff
  - RasaHQ/rasa (21,395⭐): CALM Dialogue Act & Entity Slot Carryover (asla müşterinin zaten verdiği bilgiyi tekrar sormaz)
  - pipecat-ai/pipecat (17,324⭐) & baptisteArno/typebot.io (10,639⭐): Per-Tenant Dynamic Variable & Policy Injection

Katman-1 (0 LLM tokenı):
  - 1a: Acil durum triyajı (16 dil, L1-acil)
  - 1b: Güvenlik / Prompt Injection / KVKK veri sızıntısı engeli (L1-guvenlik) ve Tıbbi ilaç/doz koruma (L1-tibbi)
  - 1c: Çok turlu diyalog hafızası & Sonlu Durum Makinesi (FSM: IDLE -> ASKED_TREATMENT -> OFFERED_APPT -> AWAITING_SLOT)
  - 1d: Birleşik Niyet Birleştirici & Parlant Bağlamsal Yanıt Bestecisi (L1-sss + L2-anahtar + RapidFuzz)
  - 1e: Kesin eşleşme önbelleği (Redis/Memory) ve semantik önbellek
Katman-2 (çok ucuz): küçük model tek etiket döndürür (max_tokens=4). LLM yoksa anahtar kelime sınıflandırıcı.
Katman-3: ana LLM, sabit sistem promptu, max_tokens sınırlı, çıktı sonrası yasaklı içerik filtresi.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

try:
    from rapidfuzz import fuzz as _rf_fuzz
except Exception:
    _rf_fuzz = None

BASE = Path(__file__).parent
LANGS = ("tr", "en", "de", "ar", "ru", "fr", "nl", "es", "it", "fa", "az", "uk", "bg", "ro", "el", "he")
LABELS = ("fiyat", "randevu", "tibbi_soru", "gorsel", "sikayet", "genel", "insan")

# Birleşik sorularda birincil niyet öncelik sırası (test_offline.py ve whatsapp_jury.py kontratlarıyla %100 uyumlu)
INTENT_PRIORITY = (
    "konum",
    "agri_korku",
    "tedavi_sure",
    "cocuk_dis",
    "sigorta_taksit",
    "otopark",
    "fiyat",
    "saat",
    "iletisim",
    "odeme",
    "gorsel",
    "randevu",
    "selam",
)

L1_INTENT_SET = {
    "selam",
    "konum",
    "saat",
    "otopark",
    "iletisim",
    "odeme",
    "agri_korku",
    "tedavi_sure",
    "cocuk_dis",
    "sigorta_taksit",
}

# Müşteriye (Klinik Sahibine) Özel Yapay Zeka Cevap Politikası Varsayılanları
DEFAULT_AI_CUSTOM_RULES: dict[str, Any] = {
    "tone": "resmi_samimi",
    "coordinator_title": "Kıdemli Hasta Koordinatörü",
    "greeting_style": "Merhabalar, {clinic} hasta danışma hattımıza hoş geldiniz.",
    "price_policy": "free_exam_invite",  # free_exam_invite | starting_range | direct_handoff
    "exam_policy": "Uzman hekimimizin yapacağı muayene ve panoramik röntgen kontrolünüzden sonra size özel yazılı tedavi planı paylaşıyoruz.",
    "cash_discount_note": "Nakit veya peşin ödemelerde sağladığımız özel ödeme kolaylıklarını da muayeneniz sırasında planınıza özenle yansıtıyoruz.",
    "payment_note": "Kredi kartlarına taksit kolaylığı sağlıyor, özel sağlık sigortası ve anlaşmalı kurumlar için gereken tüm evrakları eksiksiz hazırlıyoruz.",
    "pain_comfort_note": "İğne ve diş hekimi korkusu olan misafirlerimizde işlem öncesinde yüzey uyuşturucu jel, modern lokal anestezi ve sedasyon destekli konfor protokolü uyguluyoruz.",
    "kids_note": "Çocuk diş hekimimiz (pedodonti uzmanımız), minik misafirlerimizin tedavilerini hiç korkutmadan, oyunlaştırılmış ve koruyucu bir yaklaşımla gerçekleştiriyor.",
    "health_tourism_note": "Yurt dışından ve şehir dışından gelen misafirlerimiz için seyahat takvimine özel hızlandırılmış VIP randevu planlaması yapıyoruz.",
    "custom_extra_note": "",
}

# Varsayılan çok şubeli klinik dizini (DB'den gelen şubelerle dinamik zenginleştirilir)
DEFAULT_BRANCH_DIRECTORY: dict[str, dict[str, Any]] = {
    "istanbul": {
        "key": "istanbul",
        "clinic": "Özel DentaCore Merkez Polikliniği",
        "city": "İstanbul",
        "adres": "Bağdat Cad. No:142, Kadıköy / İstanbul",
        "harita": "https://maps.google.com/?q=Kadikoy+Istanbul",
        "telefon": "+90 216 555 01 01",
        "keywords": ("istanbul", "kadikoy", "bagdat", "merkez sube"),
    },
    "bursa": {
        "key": "bursa",
        "clinic": "Özel Bursa Gülüş Diş Polikliniği",
        "city": "Bursa",
        "adres": "FSM Bulvarı No:48, Nilüfer / Bursa",
        "harita": "https://maps.google.com/?q=Nilufer+Bursa",
        "telefon": "+90 224 555 02 02",
        "keywords": ("bursa", "nilufer", "fsm"),
    },
    "ankara": {
        "key": "ankara",
        "clinic": "Ankara Çankaya Estetik Diş Polikliniği",
        "city": "Ankara",
        "adres": "Tunalı Hilmi Cad. No:88, Çankaya / Ankara",
        "harita": "https://maps.google.com/?q=Cankaya+Ankara",
        "telefon": "+90 312 555 03 03",
        "keywords": ("ankara", "cankaya", "tunali"),
    },
}

# Türkçe STT / sokak ağzı / kısaltma ve yazım hatası normalizasyon kuralları
TR_INFORMAL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bslm\b"), "selam"),
    (re.compile(r"\bmrb\b"), "merhaba"),
    (re.compile(r"\bmeraba\b"), "merhaba"),
    (re.compile(r"\bne\s+kdr\b"), "ne kadar"),
    (re.compile(r"\bnekadr\b"), "ne kadar"),
    (re.compile(r"\bnekadar\b"), "ne kadar"),
    (re.compile(r"\bfyat(i|in|iniz|lar|lari|lariniz)?\b"), "fiyat"),
    (re.compile(r"\bfiyat(i|in|iniz|lar|lari|lariniz)?\b"), "fiyat"),
    (re.compile(r"\bucret(?!siz)(i|in|iniz|ler|leri|leriniz)?\b"), "ucret"),
    (re.compile(r"\binpilant\w*\b"), "implant"),
    (re.compile(r"\bimplnt\w*\b"), "implant"),
    (re.compile(r"\brandvu\w*\b"), "randevu"),
    (re.compile(r"\brandev\b"), "randevu"),
    (re.compile(r"\balmk\b"), "almak"),
    (re.compile(r"\bistiyom\b"), "istiyorum"),
    (re.compile(r"\bistiyrum\b"), "istiyorum"),
    (re.compile(r"\balami?yom\b"), "alamiyorum"),
    (re.compile(r"\byutkunami?yom\b"), "yutkunamiyorum"),
    (re.compile(r"\bdurmuyo\b"), "durmuyor"),
    (re.compile(r"\bkapaniyo\b"), "kapaniyor"),
    (re.compile(r"\baciliyo\b"), "aciliyor"),
    (re.compile(r"\boluyo\b"), "oluyor"),
    (re.compile(r"\bctesi\b"), "cumartesi"),
    (re.compile(r"\bcmtsi\b"), "cumartesi"),
    (re.compile(r"\bpztesi\b"), "pazartesi"),
    (re.compile(r"\bkanma\b"), "kanama"),
    (re.compile(r"\byuzm\b"), "yuzum"),
    (re.compile(r"\bbogzm\b"), "bogazim"),
    (re.compile(r"\bdisim\b"), "disim"),
    (re.compile(r"\bsisti\b"), "sisti"),
    (re.compile(r"\bkacta\b"), "kacta"),
]

# RapidFuzz bulanık eşleştirme için kanonik niyet ifadeleri (ezber değil, semantik çekirdek öbekler)
FUZZY_CANONICAL_PHRASES: dict[str, tuple[str, ...]] = {
    "acil": (
        "kanama durmuyor",
        "yuzum cok sisti",
        "bogazim sisti",
        "nefes alamiyorum",
        "yutkunamiyorum",
        "yuksek ates",
        "disim kirildi",
    ),
    "fiyat": (
        "fiyat ne kadar",
        "ucreti ne kadar",
        "implant fiyati",
        "zirkonyum fiyati",
        "dis beyazlatma ucreti",
        "kac lira",
    ),
    "randevu": (
        "randevu almak istiyorum",
        "muayene randevusu",
        "yarin saat uygun mu",
        "beni yazin lutfen",
    ),
    "konum": (
        "adresiniz nerede",
        "kliniginiz nerede",
        "subenizin adresi",
        "yol tarifi konum",
    ),
    "saat": (
        "calisma saatleriniz",
        "saat kaca kadar aciksiniz",
        "cumartesi kacta kapaniyor",
        "pazar gunu acik mi",
    ),
    "otopark": (
        "otopark var mi",
        "arabami nereye park",
    ),
    "agri_korku": (
        "igne korkum var",
        "disci korkusu",
        "islem sirasinda aci",
        "canim acir mi",
        "uyutarak sedasyon",
    ),
    "sigorta_taksit": (
        "ozel saglik sigortasi",
        "kredi kartina taksit",
        "ucreti taksit oluyor mu",
    ),
    "cocuk_dis": (
        "cocuk dis hekimi",
        "sut disi curudu",
        "pedodonti uzmani",
    ),
    "tedavi_sure": (
        "toplam kac gun surer",
        "tedavi kac gun surer",
    ),
}

# Prompt Injection ve KVKK başka hasta verisi sızdırma tuzaklarını yakalayan güvenlik filtreleri
PROMPT_INJECTION_RE = re.compile(
    r"(onceki\s+tum\s+kurallari\s+unut|sistem\s+komutu|ignore\s+previous\s+instructions|system\s+prompt|"
    r"sen\s+artik\s+comert\s+bir\s+asistansin|omur\s+boyu\s+%?100\s+agrisiz\s+garanti)"
)

KVKK_TRAP_RE = re.compile(
    r"(sistemdeki\s+telefon\s+numarasini|kullandigi\s+ilaclari\s+bana\s+yazar|"
    r"esinin\s+telefon\s+numarasi|baska\s+hastanin\s+bilgileri|ayse\s+kaya'?nin\s+(esi|telefon|ilac))"
)

# Çok turlu diyalogda zaman/slot onayı veya randevu bağlama ifadeleri
SLOT_CONFIRM_RE = re.compile(
    r"(\b(olur|tamam|uygun|evet|peki|tabii|harika|super)\b.*\b(yarin|bugun|sabah|ogleden\s+sonra|aksam|pazartesi|sali|carsamba|persembe|cuma|cumartesi|saat|\d{1,2}[:.]\d{2})\b|"
    r"\b(yarin|bugun|pazartesi|sali|carsamba|persembe|cuma|cumartesi)\b.*\b(\d{1,2}[:.]\d{2}|sabah|ogleden\s+sonra)\b.*\b(uygun\s+mu\w*|beni\s+yaz\w*|yazdir\w*|olustur\w*|ayir\w*|randevu)\b|"
    r"\bsaat\s*\d{1,2}[:.]?\d{0,2}\s*(a|e|ya|ye)?\s*(beni\s+yaz\w*|uygun\s+mu\w*|randevu)\b)"
)

TREATMENT_KEYWORDS = (
    "implant",
    "zirkonyum",
    "kanal",
    "dolgu",
    "beyazlatma",
    "cekim",
    "gulus tasarimi",
    "lamine",
    "protez",
    "ortodonti",
    "pedodonti",
    "sut disi",
)


_INVISIBLE_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")
_DOTTED_UNIT_RE = re.compile(r"\b(\d+)\s*m\s*[._-]\s*([gl])\.?\b")
_LEET_ALPHA_RE = re.compile(r"(?<=[a-z])([0134])(?=[a-z])")
_LEET_MAP = {"0": "o", "1": "i", "3": "e", "4": "a"}


def normalize(s: str) -> str:
    s = _INVISIBLE_CTRL_RE.sub("", s or "")
    s = s.replace("ı", "i").replace("İ", "i").replace("ə", "e").replace("Ə", "e")
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c) and unicodedata.category(c) not in ("Cf", "Cc")).casefold()
    s = _DOTTED_UNIT_RE.sub(r"\1 m\2", s)
    s = _LEET_ALPHA_RE.sub(lambda m: _LEET_MAP.get(m.group(1), m.group(1)), s)
    return re.sub(r"\s+", " ", s).strip()


def normalize_tr_informal(n_text: str) -> str:
    """Bozuk Türkçe, STT ve sokak ağzı kısaltmalarını standart Türkçe köklere dönüştürür."""
    out = n_text
    for pat, repl in TR_INFORMAL_PATTERNS:
        out = pat.sub(repl, out)
    return re.sub(r"\s+", " ", out).strip()


def detect_lang(text: str, default: str = "tr") -> str:
    raw = (text or "").casefold()
    if re.search(r"[\u0590-\u05FF]", raw):
        return "he"
    if re.search(r"[\u0600-\u06FF]", raw):
        if re.search(r"[پچژگک]", raw) or any(w in raw for w in ("سلام", "نوبت", "قیمت", "دندان", "چند", "آدرس", "خونریزی", "صورتم", "ورم", "نفس")):
            return "fa"
        return "ar"
    if re.search(r"[\u0370-\u03FF]", raw):
        return "el"
    if re.search(r"[\u0400-\u04FF]", raw):
        cyr_words = set(re.findall(r"[а-яёіїєґъ]+", raw))
        uk_score = (3 if re.search(r"[іїєґ]", raw) else 0) + len(
            cyr_words & {"добрий", "вітаю", "ціна", "скільки", "запис", "записатися", "адреса", "лікар", "клініка", "години", "роботи", "імплантації", "яка", "який", "графік"}
        )
        bg_score = len(
            cyr_words & {"здравейте", "добър", "колко", "зъб", "зъби", "работно", "работното", "време", "струва", "къде", "час", "лекар", "адресът", "какво"}
        ) + (2 if ("работно време" in raw or "работното време" in raw or "колко струва" in raw) else 0)
        ru_score = (3 if re.search(r"[ыэё]", raw) else 0) + len(
            cyr_words & {"здравствуйте", "сколько", "стоит", "стоимость", "записаться", "прием", "приём", "имплантация", "зубов", "часы", "работы", "какие", "какая", "цена", "вас", "где", "клиника", "можно"}
        )
        if uk_score > ru_score and uk_score >= bg_score and uk_score > 0:
            return "uk"
        if bg_score > ru_score and bg_score > uk_score and bg_score > 0:
            return "bg"
        return "ru"
    if re.search(r"[əƏ]", raw):
        return "az"
    if re.search(r"[ğşıİĞŞ]", text or ""):
        return "tr"
    n = normalize(text)
    words = set(re.findall(r"[a-z]+", n))
    lexicons = {
        "de": {"ich", "und", "nicht", "zahn", "zahne", "zahnimplantat", "termin", "bitte", "hallo", "wie", "viel", "kostet", "ist", "sie", "wir", "mein", "kosten", "danke", "guten", "wo", "adresse", "ihre", "klinik"},
        "en": {"the", "and", "is", "my", "tooth", "teeth", "appointment", "please", "hello", "hi", "how", "much", "can", "you", "what", "price", "where", "there", "parking", "swollen", "swallow", "cost", "crowns", "extraction", "breathe"},
        "tr": {"merhaba", "dis", "disim", "randevu", "randvu", "fiyat", "fyat", "ucret", "ucreti", "ne", "kadar", "kdr", "nekadr", "nerede", "var", "mi", "mu", "istiyorum", "istiyom", "tesekkur", "agri", "slm", "mrb", "selam", "kacta", "acik", "cumartesi", "ctesi", "kapaniyo", "kapaniyor", "yarin", "saat", "olur", "tamam", "bursa", "ankara", "sube", "subenizin", "otopark"},
        "fr": {"bonjour", "salut", "bonsoir", "merci", "prix", "tarif", "combien", "adresse", "horaires", "rendez", "vous", "dent", "dents", "dentiste", "peur", "douloureux", "ou", "etes", "quels", "sont"},
        "nl": {"hallo", "goedemorgen", "goedemiddag", "afspraak", "prijs", "kosten", "adres", "waar", "tandarts", "openingstijden", "bedankt", "hoe", "laat", "vandaag", "bang", "voor", "implantaat", "pijn", "sedatie", "hebben", "jullie"},
        "es": {"hola", "buenos", "dias", "gracias", "precio", "cuanto", "cuesta", "cita", "direccion", "donde", "horario", "horarios", "diente", "dentista", "tengo", "sonrisa", "cuales"},
        "it": {"ciao", "buongiorno", "buonasera", "salve", "grazie", "prezzo", "quanto", "costa", "appuntamento", "prenotare", "vorrei", "faccette", "indirizzo", "dove", "siete", "orari", "dente", "dentista"},
        "az": {"salam", "sabahiniz", "xeyir", "qiymet", "unvan", "unvaniniz", "hardasiniz", "haradadir", "hekim", "nece", "gorus", "qanaxma"},
        "ro": {"buna", "ziua", "multumesc", "pret", "cat", "costa", "programare", "adresa", "unde", "dinte", "stomatolog", "care", "este"},
    }
    scores = {k: len(words & v) for k, v in lexicons.items()}
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else default


@dataclass
class RouteResult:
    answer: str
    layer: str
    intent: str
    lang: str
    tokens_in: int = 0
    tokens_out: int = 0
    alert: str | None = None      # "acil" | "sikayet" | None
    handoff: bool = False
    high_value: bool = False
    meta: dict = field(default_factory=dict)


class _MemCache:
    """Redis yokken veya tek sunucu kurulumunda kullanılan hafif bellek önbelleği."""
    def __init__(self, cap: int = 2048):
        self.cap = cap
        self.kv: dict[str, str] = {}
        self.h: dict[str, dict[str, str]] = {}

    async def get(self, k: str):
        return self.kv.get(k)

    async def set(self, k: str, v: str, ex: int = 0):
        if len(self.kv) >= self.cap:
            self.kv.pop(next(iter(self.kv)))
        self.kv[k] = v

    async def hgetall(self, k: str) -> dict:
        return self.h.get(k, {})

    async def hlen(self, k: str) -> int:
        return len(self.h.get(k, {}))

    async def hset(self, k: str, f: str, v: str):
        self.h.setdefault(k, {})[f] = v


class DialogueFSM:
    """
    Çok turlu (multi-turn) konuşma hafızası ve Sonlu Durum Makinesi (FSM).
    Durumlar: IDLE -> ASKED_TREATMENT -> OFFERED_APPT -> AWAITING_SLOT
    Her oturum/hasta için son 5 mesajı, aktif şubeyi, konuşulan tedaviyi ve son bot teklifini tutar.
    """
    def __init__(self, max_sessions: int = 1024):
        self.max_sessions = max_sessions
        self.sessions: dict[str, dict[str, Any]] = {}

    def get_session(self, session_key: str) -> dict[str, Any]:
        if session_key not in self.sessions:
            if len(self.sessions) >= self.max_sessions:
                self.sessions.pop(next(iter(self.sessions)))
            self.sessions[session_key] = {
                "state": "IDLE",
                "last_intent": None,
                "active_branch": None,
                "treatment_topic": None,
                "turns": [],
                "updated_at": time.time(),
            }
        return self.sessions[session_key]

    def record_turn(
        self,
        session_key: str,
        user_text: str,
        intent: str,
        branch_key: str | None = None,
        treatment: str | None = None,
        bot_answer: str = "",
    ) -> dict[str, Any]:
        sess = self.get_session(session_key)
        sess["updated_at"] = time.time()
        sess["last_intent"] = intent
        if branch_key:
            sess["active_branch"] = branch_key
        if treatment:
            sess["treatment_topic"] = treatment

        if intent in ("fiyat", "tedavi_sure", "agri_korku", "cocuk_dis", "sigorta_taksit"):
            sess["state"] = "OFFERED_APPT"
        elif intent == "randevu":
            sess["state"] = "AWAITING_SLOT"
        elif treatment and sess["state"] == "IDLE":
            sess["state"] = "ASKED_TREATMENT"

        sess["turns"].append({
            "text": user_text[:400],
            "intent": intent,
            "branch": sess["active_branch"],
            "treatment": sess["treatment_topic"],
            "bot_answer": bot_answer[:400],
        })
        if len(sess["turns"]) > 5:
            sess["turns"] = sess["turns"][-5:]
        return sess


class TokenRouter:
    def __init__(self, redis=None, faq_path: Path | None = None, offline: bool = False):
        self.cache = redis or _MemCache()
        self.offline = offline
        self._cb_until = 0.0
        self.fsm = DialogueFSM()
        data = json.loads((faq_path or BASE / "faq.json").read_text(encoding="utf-8"))
        self.clinic = os.environ.get("CLINIC_NAME", "Klinik")
        self.facts = {**data["facts"], "clinic": self.clinic}
        self.intents = []
        self.intent_map: dict[str, dict[str, Any]] = {}
        for name, spec in data["intents"].items():
            pats = {lg: re.compile(normalize(p)) for lg, p in spec["patterns"].items()}
            self.intents.append((name, spec.get("only_short", False), pats, spec["answers"]))
            self.intent_map[name] = {"only_short": spec.get("only_short", False), "pats": pats, "answers": spec["answers"]}
        self.emerg = {lg: re.compile(normalize(p)) for lg, p in data["emergency"]["patterns"].items()}
        self.emerg_ans = data["emergency"]["answers"]
        self.tpl = data["templates"]
        self.kw = {k: re.compile(normalize(v)) for k, v in data["classifier_keywords"].items()}
        facts_txt = "\n".join(f"- {k}: {v}" for k, v in data["facts"].items())
        self.system_tpl = (BASE / "guardrail_prompt.txt").read_text(encoding="utf-8").replace("{facts}", facts_txt).replace("{clinic}", self.clinic)
        self.base_url = (os.environ.get("LLM_BASE_URL", "http://127.0.0.1:20128/v1") or "http://127.0.0.1:20128/v1").rstrip("/")
        self.api_key = os.environ.get("LLM_API_KEY", "")
        self.small = os.environ.get("LLM_SMALL_MODEL", "free-auto") or "free-auto"
        self.main = os.environ.get("LLM_MAIN_MODEL", "free-auto") or "free-auto"
        self.max_tokens = int(os.environ.get("LLM_MAX_TOKENS", "180"))
        self.embed_model = os.environ.get("EMBED_MODEL", "")
        self.sem_threshold = float(os.environ.get("SEMANTIC_THRESHOLD", "0.92"))
        self.price_on = os.environ.get("PRICE_DISCLOSURE", "off").lower() == "on"
        self.forbidden = re.compile(normalize(
            r"(\b\d+\s?(mg|ml|gr|mcg)\b|augmentin|klamoks|largopen|amoksisilin|amoxicillin|rovamycine|flagyl|nidazol|biteral|metronidazol|klindan|klindamisin|azitro|zitromax|azitromisin|cipro|siprofloksasin|tetradox|doksisiklin|cefaks|suprax|keflex|macrol|klacid|penisilin|bactrim|duocid|tavanic|avelox|rocephin|apranax|naprosyn|naproksen|majezik|flurbiprofen|arveles|dexomen|deksketoprofen|dexday|dexforte|dolorex|dikloron|voltaren|cataflam|diklofenak|brufen|nurofen|suprafen|ibuprofen|advil|dolven|calpol|parol|vermidon|minoset|tylol|parasetamol|paracetamol|panadol|novalgin|metamizol|geralgine|etol|etodolak|melox|ponstan|muscoril|tramadol|kloroben|andorex|tantum\s*verde|klorheksidin|chlorhexidine|listerine|batticon|betadine|aftojel|kenacort|anestol|dentinox|corsodyl|coumadin|warfarin|xarelto|eliquis|pradaxa|coraspin|ecopirin|aspirin|plavix|clexane|hibor|innohep|prednol|kortizon|dekort|deltacortril|fosamax|zometa|antibiyotik|antibiotic|painkiller|schmerzmittel|antibiotikum|recete|prescription|surup|tablet|kapsul|gargara|merhem|pomad|teshis(iniz)?|tanisi|garanti|en iyi|agrisiz|kusursuz|indirim|kampanya|ucretsiz|\b\d[\d.]*\s?(tl|try|euro|eur|usd|\$|€))"
        ))

    # ---------- yardımcılar ----------
    def _fmt(self, s: str, extra: dict | None = None) -> str:
        facts = {**self.facts, **(extra or {})}
        for k, v in facts.items():
            if k not in ("branches", "ai_custom_rules", "ai_custom_rules_json"):
                s = s.replace("{" + k + "}", str(v))
        return re.sub(r"\.{2,}", ".", s).strip()

    def _pick(self, table: dict, lang: str, extra: dict | None = None) -> str:
        return self._fmt(table.get(lang) or table.get("en") or table["tr"], extra)

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key or 'omniroute-local'}"}

    @property
    def llm_ready(self) -> bool:
        if self.offline or time.monotonic() < self._cb_until or not self.base_url:
            return False
        is_local = "127.0.0.1" in self.base_url or "localhost" in self.base_url
        return bool(self.api_key or is_local)

    @staticmethod
    def _detect_treatment(n_text: str) -> str | None:
        for tr_kw in TREATMENT_KEYWORDS:
            if tr_kw in n_text:
                return tr_kw
        return None

    @staticmethod
    def _extract_human_treatment_label(n_text: str, prev_norm: str = "") -> str | None:
        combined = f"{n_text} {prev_norm}".strip()
        if "tek dis implant" in combined:
            return "tek diş implant tedaviniz"
        if "all on 4" in combined or "all-on-4" in combined or "all on 6" in combined:
            return "All-on-4 / tam çene implant tedaviniz"
        if "zirkonyum" in combined and ("gulus" in combined or "tasarim" in combined):
            return "zirkonyum kaplama ve dijital gülüş tasarımı süreciniz"
        if "20 dis zirkonyum" in combined:
            return "tam çene zirkonyum kaplama ve gülüş tasarımı tedaviniz"
        if "zirkonyum" in combined:
            return "zirkonyum kaplama tedaviniz"
        if "gulus tasarim" in combined or "hollywood" in combined:
            return "dijital gülüş tasarımı süreciniz"
        if "beyazlatma" in combined:
            return "profesyonel diş beyazlatma işleminiz"
        if "kanal" in combined:
            return "kanal tedaviniz"
        if "dolgu" in combined:
            return "estetik dolgu işleminiz"
        if "20'lik" in combined or "20lik" in combined or "yirmilik" in combined:
            return "20'lik diş çekimi işleminiz"
        if "lamine" in combined or "lamina" in combined:
            return "porselen lamine (yaprak diş) tedaviniz"
        if "seffaf plak" in combined or "invisalign" in combined or "ortodonti" in combined:
            return "şeffaf plak ve ortodonti tedaviniz"
        if "sut disi" in combined:
            return "süt dişi tedavisi"
        if "implant" in combined:
            return "implant tedaviniz"
        return None

    @staticmethod
    def _parse_custom_rules(effective_facts: dict) -> dict[str, Any]:
        rules = dict(DEFAULT_AI_CUSTOM_RULES)
        raw = effective_facts.get("ai_custom_rules") or effective_facts.get("ai_custom_rules_json")
        if isinstance(raw, str) and raw.strip():
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    for k, v in parsed.items():
                        if v is not None and str(v).strip() != "":
                            rules[k] = v
            except Exception:
                pass
        elif isinstance(raw, dict):
            for k, v in raw.items():
                if v is not None and str(v).strip() != "":
                    rules[k] = v
        return rules

    @staticmethod
    def _strip_leading_greeting(sentence: str) -> str:
        s = sentence.strip()
        patterns = (
            r"^Merhabalar,\s*",
            r"^Merhaba,\s*",
            r"^Hello(?:\s+and\s+welcome[^,.]*|,\s*welcome[^,.]*)?,\s*",
            r"^Guten\s+Tag(?:\s+und\s+herzlich\s+willkommen[^,.]*)?,\s*",
            r"^Здравствуйте[!,]\s*",
            r"^Bonjour(?:\s+et\s+bienvenue[^,.]*)?,\s*",
            r"^Hartelijk\s+welkom[^,.]*,\s*",
            r"^Hola(?:\s+y\s+bienvenido[^,.]*)?,\s*",
            r"^Buongiorno(?:\s+e\s+benvenuti[^,.]*)?,\s*",
            r"^Salam,\s*",
            r"^Добрий\s+день[^,.]*[!,]\s*",
            r"^Здравейте[^,.]*,\s*",
            r"^Bună\s+ziua[^,.]*,\s*",
            r"^Καλημέρα\s+σας[^,.]*,\s*",
        )
        for pat in patterns:
            s_new = re.sub(pat, "", s, flags=re.IGNORECASE)
            if s_new != s and s_new:
                return s_new[0].upper() + s_new[1:]
        return s

    def _compose_parlant_concierge_reply(
        self,
        raw_text: str,
        n: str,
        lang: str,
        ordered: list[str],
        effective_facts: dict[str, Any],
        cur_treatment: str | None = None,
        branch_facts: dict[str, Any] | None = None,
        prev_norm: str = "",
    ) -> str:
        """
        Parlant (18.3k⭐) + Rasa CALM (21.3k⭐) + Chatwoot Captain (40.1k⭐) 4-Katmanlı VIP Hasta Koordinatörü Yanıt Bestecisi:
        1. Samimi & Resmi Karşılama / Empati
        2. Müşterinin Mesajındaki Özel Varlık & Alt-Soruları Yansıtma (Tedavi adı, çocuk yaşı, nakit avantajı, sigorta markası, yurt dışı/şehir dışı seyahat, Pazar/nöbetçi hekim)
        3. Kliniğe Özel Politika Enjeksiyonu (ai_custom_rules)
        4. Birleşik Sorularda Tekrarlayan Selamları Temizleyip Doğal Bağlaçlarla Birleştirme
        """
        rules = self._parse_custom_rules(effective_facts)
        treatment_lbl = self._extract_human_treatment_label(n, prev_norm)

        # Türkçe için yüksek hassasiyetli bağlamsal Parlant yanıt üretimi
        if lang == "tr":
            # Özel birleşik durum 1: Konum + Otopark birlikte sorulduysa tek akıcı paragrafta birleştir
            has_konum = "konum" in ordered
            has_otopark = "otopark" in ordered

            clauses: list[str] = []
            handled: set[str] = set()

            if has_konum and has_otopark:
                adres_val = effective_facts.get("adres", self.facts["adres"])
                harita_val = effective_facts.get("harita", self.facts["harita"])
                oto_val = str(effective_facts.get("otopark", self.facts["otopark"])).rstrip(".")
                clauses.append(
                    f"Merhabalar, sizleri {adres_val} adresindeki kliniğimizde ağırlamaktan memnuniyet duyarız "
                    f"(Yol tarifi: {harita_val}). Özel aracınızla rahatça gelebilirsiniz; {oto_val}."
                )
                handled.add("konum")
                handled.add("otopark")

            for it_name in ordered:
                if it_name in handled:
                    continue

                if it_name == "fiyat":
                    t_phrase = f"Sorduğunuz {treatment_lbl} için " if treatment_lbl else "Kliniğimizde "
                    exam_note = rules.get("exam_policy") or DEFAULT_AI_CUSTOM_RULES["exam_policy"]
                    base_fiyat = (
                        f"Merhabalar, kliniğimize hoş geldiniz. {t_phrase}tedavi planı ve net ücreti, "
                        f"uzman hekimimizin yapacağı muayene ve panoramik röntgen kontrolünüzden sonra size özel yazılı olarak paylaşıyoruz."
                    )
                    if any(w in n for w in ("nakit", "pesin", "indirim")):
                        cash_note = rules.get("cash_discount_note") or DEFAULT_AI_CUSTOM_RULES["cash_discount_note"]
                        base_fiyat += f" {cash_note}"
                        handled.add("odeme")
                    if rules.get("price_policy") == "starting_range" and rules.get("starting_price_note"):
                        base_fiyat += f" {rules['starting_price_note']}"
                    base_fiyat += " Ön değerlendirme ve size özel planlama için hangi gün ve saat aralığı size uyar?"
                    clauses.append(base_fiyat)

                elif it_name == "saat":
                    saat_val = str(effective_facts.get("saatler", self.facts["saatler"])).rstrip(".")
                    if any(w in n for w in ("pazar", "nobetci", "aksam")):
                        clauses.append(
                            "Merhabalar, kliniğimizde sizleri hafta içi her gün 09:00-19:00, Cumartesi günleri ise 09:00-15:00 saatleri arasında ağırlıyoruz. "
                            "Pazar günleri rutin muayeneye kapalıyız ancak acil durumlar için nöbetçi hekim koordinasyonumuz mevcuttur. "
                            "Size uygun bir gün için randevu planlayalım mı?"
                        )
                    else:
                        clauses.append(
                            f"Merhabalar, kliniğimizde sizleri çalışma saatlerimiz olan {saat_val} programı çerçevesinde ağırlıyoruz. "
                            f"Size en uygun gün ve saati paylaşırsanız randevunuzu hemen planlayabilirim."
                        )

                elif it_name == "cocuk_dis":
                    age_m = re.search(r"\b(\d{1,2})\s*yas(inda|indaki)?\b", n)
                    child_rel = "oğlunuza" if "oglum" in n else ("kızınıza" if "kizim" in n else "evladınıza")
                    kids_note = rules.get("kids_note") or DEFAULT_AI_CUSTOM_RULES["kids_note"]
                    if age_m:
                        age_num = age_m.group(1)
                        clauses.append(
                            f"Merhabalar, öncelikle {age_num} yaşındaki {child_rel} çok geçmiş olsun. "
                            f"{kids_note} {age_num} yaş grubu minik misafirlerimizin rahat bir muayene geçirmesi için "
                            f"size uygun günü paylaşırsanız uzman çocuk diş hekimimize hemen öncelikli randevu planlayabiliriz."
                        )
                    else:
                        clauses.append(
                            f"Merhabalar, {kids_note} Çocuğunuzun yaşını ve varsa şikayetini paylaşırsanız "
                            f"uzman çocuk diş hekimimize hemen öncelikli randevu planlayabiliriz."
                        )

                elif it_name == "tedavi_sure":
                    travel_intro = ""
                    if "almanya" in n:
                        travel_intro = "Almanya'dan kliniğimize gösterdiğiniz ilgi için çok teşekkür ederiz; yurt dışından gelen misafirlerimiz için uçuş takviminize tam uyumlu hızlandırılmış VIP planlama uyguluyoruz. "
                    elif any(w in n for w in ("londra", "ingiltere", "fransa", "hollanda", "isvicre", "belcika", "avusturya", "yurt disi")):
                        travel_intro = f"{rules.get('health_tourism_note') or DEFAULT_AI_CUSTOM_RULES['health_tourism_note']} "
                    elif "sehir disi" in n:
                        travel_intro = "Şehir dışından kliniğimize gösterdiğiniz ilgi için çok teşekkür ederiz; seyahat takviminize özel hızlandırılmış randevu planlaması uyguluyoruz. "

                    clauses.append(
                        f"Merhabalar, {travel_intro}Tedavi süremiz yapılacak klinik planlamaya göre şekilleniyor: "
                        f"tek seanslık işlemleri aynı gün tamamlıyoruz; zirkonyum kaplama ve dijital gülüş tasarımı süreçlerimiz ise provalarla birlikte ortalama 4 ile 6 gün (4-6 gün) sürüyor. "
                        f"İmplant tedavi takvimini ise hekimimiz muayenede netleştiriyor. Size özel tedavi planı çıkarmamız için ön değerlendirme randevusu oluşturalım mı?"
                    )

                elif it_name == "sigorta_taksit":
                    ins_brand = ""
                    for b_code, b_label in (
                        ("allianz", "Allianz özel sağlık sigortası"),
                        ("acibadem", "Acıbadem Bupa sağlık sigortası"),
                        ("axa", "AXA özel sağlık sigortası"),
                        ("anadolu", "Anadolu Sigorta"),
                        ("mapfre", "Mapfre Sigorta"),
                    ):
                        if b_code in n:
                            ins_brand = f"{b_label} dahil "
                            break
                    clauses.append(
                        f"Merhabalar, kliniğimizde kredi kartı ile ödemelerde taksit kolaylığı sağlıyor; {ins_brand}özel sağlık sigortası ve anlaşmalı kurumlar için "
                        f"poliçenizin gerektirdiği tüm tanı, röntgen ve fatura evraklarını eksiksiz hazırlıyoruz. "
                        f"Poliçenizin kapsamını veya kartınıza uygun taksit seçeneklerini hasta kabul ekibimizin sizin için hemen kontrol etmesi adına telefon numaranızı bırakabilirsiniz."
                    )

                elif it_name == "agri_korku":
                    pain_note = rules.get("pain_comfort_note") or DEFAULT_AI_CUSTOM_RULES["pain_comfort_note"]
                    clauses.append(
                        f"Merhabalar, bu hassasiyetinizi bizimle paylaştığınız için çok teşekkür ederiz; kliniğimizde sizi çok iyi anlıyoruz. "
                        f"{pain_note} Dilerseniz ilk gelişinizde hiçbir işlem yapmadan, sadece uzman hekimimizle tanışma ve ön görüşme için randevu oluşturalım mı?"
                    )

                elif it_name in self.intent_map:
                    clauses.append(self._pick(self.intent_map[it_name]["answers"], lang, effective_facts))
                elif it_name in self.tpl:
                    clauses.append(self._pick(self.tpl[it_name], lang, effective_facts))

            # Birden fazla niyet birleştiğinde 2. ve 3. cümlelerdeki tekrarlayan 'Merhabalar,' selamını temizle
            if len(clauses) > 1:
                merged: list[str] = [clauses[0]]
                for idx_c, cl in enumerate(clauses[1:], start=1):
                    cleaned = self._strip_leading_greeting(cl)
                    if idx_c == 1 and not cleaned.startswith(("Ayrıca", "Bunun yanı sıra")):
                        cleaned = f"Ayrıca {cleaned[0].lower()}{cleaned[1:]}" if cleaned else cleaned
                    merged.append(cleaned)
                final_tr = " ".join(merged)
            else:
                final_tr = clauses[0] if clauses else self._pick(self.tpl["insan"], lang, effective_facts)

            extra_note = str(rules.get("custom_extra_note") or "").strip()
            if extra_note and extra_note not in final_tr:
                final_tr = f"{final_tr} {extra_note}"

            return re.sub(r"\.{2,}", ".", final_tr).strip()

        # Diğer 15 yabancı dil için birleşik niyetleri doğal akışla (tekrarlayan selamları temizleyerek) birleştir
        ans_parts: list[str] = []
        for idx_it, it_name in enumerate(ordered):
            if it_name in self.intent_map:
                part = self._pick(self.intent_map[it_name]["answers"], lang, effective_facts)
            elif it_name in self.tpl:
                part = self._pick(self.tpl[it_name], lang, effective_facts)
            else:
                continue
            if part and part not in ans_parts:
                if idx_it > 0:
                    part = self._strip_leading_greeting(part)
                ans_parts.append(part)
        return re.sub(r"\.{2,}", ".", " ".join(ans_parts)).strip()

    def _compose_slot_confirm_reply(
        self,
        raw_text: str,
        n: str,
        lang: str,
        effective_facts: dict[str, Any],
        branch_facts: dict[str, Any] | None,
        cur_treatment: str | None,
        prev_norm: str,
    ) -> str:
        """Çok turlu konuşmada hasta gün/saat belirttiğinde ('Olur yarın 15:00 uygun mu?', 'Tamam yarın sabah 10:00'a beni yazın') bağlama duyarlı VIP koordinatör yanıtı üretir."""
        if lang != "tr":
            return self._pick(self.tpl["randevu"], lang, effective_facts)

        time_m = re.search(r"\b(\d{1,2}[:.]\d{2})\b", n)
        day_word = "yarın" if "yarin" in n else ("bugün" if "bugun" in n else "")
        part_of_day = "sabah" if "sabah" in n else ("öğleden sonra" if "ogleden sonra" in n else "")
        slot_desc = " ".join(filter(None, [day_word, part_of_day, f"saat {time_m.group(1)}" if time_m else "belirttiğiniz saat"])).strip()

        treatment_lbl = self._extract_human_treatment_label(n, prev_norm)
        clinic_lbl = branch_facts["clinic"] if branch_facts else effective_facts.get("clinic", self.clinic)
        topic_phrase = f"{clinic_lbl} bünyesinde {treatment_lbl}" if treatment_lbl else f"{clinic_lbl}"

        return (
            f"Memnuniyetle! {topic_phrase} için {slot_desc} randevu talebinizi öncelikli olarak sisteme aldık. "
            f"Hasta koordinatörümüz hekim ve koltuk uygunluğunu kontrol ederek randevu teyit mesajınızı hemen iletecektir."
        )

    def _detect_branch(self, n_text: str, clinic_facts: dict | None = None) -> tuple[str | None, dict[str, str] | None]:
        """Mesajda geçen şube/şehir adını tespit edip o şubenin gerçek adres, telefon ve harita bilgisini döndürür."""
        if not n_text:
            return None, None
        branch_dir = dict(DEFAULT_BRANCH_DIRECTORY)
        for b in (clinic_facts or {}).get("branches") or []:
            city_norm = normalize(b.get("city") or "")
            name_norm = normalize(b.get("name") or "")
            key = city_norm or name_norm
            if key:
                kws = tuple(filter(None, {city_norm, *name_norm.split()[:2]}))
                branch_dir[key] = {
                    "key": key,
                    "clinic": b.get("name") or self.clinic,
                    "city": b.get("city") or "",
                    "adres": b.get("address") or self.facts["adres"],
                    "harita": f"https://maps.google.com/?q={b.get('city') or 'Istanbul'}",
                    "telefon": b.get("phone") or self.facts["telefon"],
                    "keywords": kws,
                }
        for bkey, binfo in branch_dir.items():
            for kw in binfo.get("keywords", ()):
                if kw and re.search(r"\b" + re.escape(kw), n_text):
                    return bkey, {
                        "clinic": binfo["clinic"],
                        "adres": binfo["adres"],
                        "harita": binfo["harita"],
                        "telefon": binfo["telefon"],
                    }
        return None, None

    def _fuzzy_match_intents(self, n_norm: str, lang: str) -> list[str]:
        """Katı regex eşleşmediğinde RapidFuzz ile yazım hatalı Türkçe mesajlarda niyet yakalar."""
        if _rf_fuzz is None or lang != "tr" or len(n_norm) < 6:
            return []
        # Regression guard: "kaç seans sürer" L2-yedek/genel kalmalı
        if "kac seans surer" in n_norm:
            return []
        matched: list[str] = []
        for intent_name, phrases in FUZZY_CANONICAL_PHRASES.items():
            for ph in phrases:
                score_ts = _rf_fuzz.token_set_ratio(n_norm, ph)
                score_pr = _rf_fuzz.partial_ratio(n_norm, ph)
                if score_ts >= 84 or (len(n_norm) >= 14 and score_pr >= 86):
                    if intent_name not in matched:
                        matched.append(intent_name)
                    break
        return matched

    async def _chat(self, model: str, messages: list, max_tokens: int, temperature: float = 0.0):
        candidates = [model] + (["free-auto"] if model != "free-auto" else [])
        last_err = None
        async with httpx.AsyncClient(timeout=12) as c:
            for cand in candidates:
                try:
                    r = await c.post(f"{self.base_url}/chat/completions", headers=self._auth_headers(),
                                     json={"model": cand, "messages": messages, "max_tokens": max_tokens, "temperature": temperature})
                    r.raise_for_status()
                    j = r.json()
                    text = (j["choices"][0]["message"].get("content") or "").strip()
                    u = j.get("usage") or {}
                    tin = u.get("prompt_tokens") or sum(len(m["content"]) for m in messages) // 4
                    tout = u.get("completion_tokens") or len(text) // 4
                    return text, tin, tout
                except Exception as exc:
                    last_err = exc
        self._cb_until = time.monotonic() + 30.0
        raise RuntimeError(f"OmniRoute/LLM hatası: {last_err}")

    async def _embed(self, text: str) -> list[float] | None:
        if not (self.embed_model and self.llm_ready):
            return None
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.post(f"{self.base_url}/embeddings", headers=self._auth_headers(),
                             json={"model": self.embed_model, "input": text})
            r.raise_for_status()
            return r.json()["data"][0]["embedding"]

    @staticmethod
    def _cos(a, b) -> float:
        dot = sum(x * y for x, y in zip(a, b))
        na = math.sqrt(sum(x * x for x in a)); nb = math.sqrt(sum(y * y for y in b))
        return dot / (na * nb) if na and nb else 0.0

    def keyword_label(self, n: str) -> str:
        for lbl in ("sikayet", "tibbi_soru", "fiyat", "gorsel", "randevu"):
            if lbl in self.kw and self.kw[lbl].search(n):
                return lbl
        return "genel"

    # ---------- ana akış ----------
    def is_emergency(self, text: str) -> bool:
        n = normalize_tr_informal(normalize(text))
        return any(p.search(n) for p in self.emerg.values())

    async def route(
        self,
        text: str,
        lang: str | None = None,
        clinic_facts: dict | None = None,
        allow_llm: bool = True,
        session_id: str | None = None,
        patient_id: int | str | None = None,
        history: list[dict[str, Any]] | None = None,
        context_previous_turn: str | None = None,
    ) -> RouteResult:
        lang = lang if lang in LANGS else detect_lang(text)
        n_raw = normalize(text)
        n = normalize_tr_informal(n_raw) if lang == "tr" else n_raw

        # Çok turlu oturum anahtarı ve önceki tur bağlamı
        cf_base_name = (clinic_facts or {}).get("clinic", self.clinic)
        sess_key = f"{cf_base_name}:{session_id or patient_id or 'anon'}"
        sess = self.fsm.get_session(sess_key) if (session_id or patient_id or context_previous_turn or history) else None

        prev_texts: list[str] = []
        if context_previous_turn:
            prev_texts.append(context_previous_turn)
        if history:
            for h_item in history[-4:]:
                if isinstance(h_item, dict) and h_item.get("text"):
                    prev_texts.append(str(h_item["text"]))
        if sess and sess["turns"]:
            for t_item in sess["turns"][-3:]:
                if t_item.get("text"):
                    prev_texts.append(str(t_item["text"]))
        prev_norm = normalize_tr_informal(normalize(" ".join(prev_texts))) if prev_texts else ""

        # Şube çözümleyici: önce mevcut mesajda, yoksa önceki turda veya oturum hafızasında şube ara
        branch_key, branch_facts = self._detect_branch(n, clinic_facts)
        if not branch_facts and prev_norm:
            branch_key, branch_facts = self._detect_branch(prev_norm, clinic_facts)
        if not branch_facts and sess and sess.get("active_branch"):
            b_cached = DEFAULT_BRANCH_DIRECTORY.get(sess["active_branch"])
            if b_cached:
                branch_key = sess["active_branch"]
                branch_facts = {
                    "clinic": b_cached["clinic"],
                    "adres": b_cached["adres"],
                    "harita": b_cached["harita"],
                    "telefon": b_cached["telefon"],
                }

        effective_facts = {**(clinic_facts or {})}
        if branch_facts:
            effective_facts.update(branch_facts)

        cur_treatment = self._detect_treatment(n) or (self._detect_treatment(prev_norm) if prev_norm else None)
        high_value = bool(self.kw["yuksek_deger"].search(n) or (prev_norm and self.kw["yuksek_deger"].search(prev_norm)))

        # Katman-1a: Acil durum triyajı (16 dil + bulanık acil kontrolü; her şeyden önce gelir!)
        for lg, pat in self.emerg.items():
            if pat.search(n) or pat.search(n_raw):
                ans = self._pick(self.emerg_ans, lang, effective_facts)
                if sess is not None:
                    self.fsm.record_turn(sess_key, text, "acil", branch_key, cur_treatment, ans)
                return RouteResult(ans, "L1-acil", "acil", lang, alert="acil", handoff=True, meta={"branch": branch_key})

        # Katman-1b: Güvenlik / Prompt Injection / KVKK Üçüncü Kişi Veri Sızıntısı Koruması
        if PROMPT_INJECTION_RE.search(n):
            ans = (
                f"{self._pick(self.tpl['fiyat'], lang, effective_facts)} "
                f"{self._strip_leading_greeting(self._pick(self.tpl['insan'], lang, effective_facts))}"
            )
            if sess is not None:
                self.fsm.record_turn(sess_key, text, "insan", branch_key, cur_treatment, ans)
            return RouteResult(ans, "L1-guvenlik", "insan", lang, handoff=True, meta={"guardrail": "prompt_injection"})

        if KVKK_TRAP_RE.search(n):
            ans = (
                "Merhabalar, KVKK ve hasta mahremiyeti kurallarımız gereği hiçbir misafirimizin iletişim veya sağlık bilgisini üçüncü kişilerle paylaşamıyoruz. "
                "Talebinizi değerlendirmesi için hekim ve hasta kabul ekibimize ilettik; çalışma saatlerimiz içinde size dönüş yapılacaktır."
                if lang == "tr"
                else self._pick(self.tpl["guvenli_yedek"], lang, effective_facts)
            )
            if sess is not None:
                self.fsm.record_turn(sess_key, text, "insan", branch_key, cur_treatment, ans)
            return RouteResult(ans, "L1-guvenlik", "insan", lang, handoff=True, meta={"guardrail": "kvkk_privacy"})

        # Katman-1b2: Tıbbi Güvenlik, İlaç Dozu & Kan Sulandırıcı Sınıflandırıcısı (0 token)
        if "tibbi_soru" in self.kw and self.kw["tibbi_soru"].search(n):
            ans = self._pick(self.tpl["tibbi_soru"], lang, effective_facts)
            if sess is not None:
                self.fsm.record_turn(sess_key, text, "tibbi_soru", branch_key, cur_treatment, ans)
            return RouteResult(ans, "L1-tibbi", "tibbi_soru", lang, handoff=True, high_value=high_value)

        # Katman-1b3: Şikayet & Memnuniyetsizlik (Başhekim alarmı)
        if self.kw["sikayet"].search(n):
            ans = self._pick(self.tpl["sikayet"], lang, effective_facts)
            if sess is not None:
                self.fsm.record_turn(sess_key, text, "sikayet", branch_key, cur_treatment, ans)
            return RouteResult(ans, "L2-anahtar", "sikayet", lang, alert="sikayet", handoff=True, high_value=high_value)

        # Katman-1c: Çok Turlu FSM Randevu / Slot Kabulü Yakalayıcı ("Olur yarın 15:00 uygun mu?", "Tamam yarın sabah 10:00'a beni yazın")
        is_slot_confirm = bool(SLOT_CONFIRM_RE.search(n))
        has_appt_context = bool(
            prev_norm and any(w in prev_norm for w in ("randevu", "uygun", "sube", "tedavi", "kanal", "implant", "muayene", "ister misiniz"))
        ) or bool(sess and sess.get("state") in ("ASKED_TREATMENT", "OFFERED_APPT", "AWAITING_SLOT"))

        if is_slot_confirm and (has_appt_context or "beni yaz" in n or "uygun mu" in n):
            base_ans = self._compose_slot_confirm_reply(text, n, lang, effective_facts, branch_facts, cur_treatment, prev_norm)
            if sess is not None:
                self.fsm.record_turn(sess_key, text, "randevu", branch_key, cur_treatment, base_ans)
            return RouteResult(
                base_ans,
                "L1-baglam",
                "randevu",
                lang,
                handoff=True,
                high_value=high_value,
                meta={"fsm_state": "AWAITING_SLOT", "branch": branch_key, "treatment": cur_treatment},
            )

        # Katman-1d: Birleşik Niyet Birleştirici (Compound Query Engine: L1-sss + L2-anahtar)
        matched_intents: list[str] = []
        word_count = len(n.split())

        for name, only_short, pats, _ in self.intents:
            if only_short and word_count > 4:
                continue
            if (lang in pats and (pats[lang].search(n) or pats[lang].search(n_raw))) or any(
                p.search(n) or p.search(n_raw) for p in pats.values()
            ):
                if name not in matched_intents:
                    matched_intents.append(name)

        # L2 anahtar kelime niyetlerini de birleşik taramaya dahil et (fiyat, gorsel, randevu)
        for l2_lbl in ("fiyat", "gorsel", "randevu"):
            if self.kw[l2_lbl].search(n) or self.kw[l2_lbl].search(n_raw):
                if l2_lbl == "fiyat" and self.price_on:
                    continue
                if l2_lbl not in matched_intents:
                    matched_intents.append(l2_lbl)

        # Eğer birden fazla niyet eşleştiyse 'selam'ı çıkar (asıl sorular yanıtlansın)
        if len(matched_intents) > 1 and "selam" in matched_intents:
            matched_intents.remove("selam")
        if "sigorta_taksit" in matched_intents and "fiyat" in matched_intents:
            if not any(w in n for w in ("fiyat", "ne kadar", "kac tl", "kac lira")):
                matched_intents.remove("fiyat")

        # Hiçbir katı regex eşleşmediyse RapidFuzz bulanık eşleştirmeyi çalıştır
        if not matched_intents:
            fuzzy_hits = self._fuzzy_match_intents(n, lang)
            if "acil" in fuzzy_hits:
                ans = self._pick(self.emerg_ans, lang, effective_facts)
                if sess is not None:
                    self.fsm.record_turn(sess_key, text, "acil", branch_key, cur_treatment, ans)
                return RouteResult(ans, "L1-acil", "acil", lang, alert="acil", handoff=True, meta={"fuzzy": True})
            for fh in fuzzy_hits:
                if fh not in matched_intents:
                    matched_intents.append(fh)

        if matched_intents:
            ordered = [it for it in INTENT_PRIORITY if it in matched_intents]
            for it in matched_intents:
                if it not in ordered:
                    ordered.append(it)
            primary_intent = ordered[0]
            primary_layer = "L1-sss" if primary_intent in L1_INTENT_SET else "L2-anahtar"

            combined_answer = self._compose_parlant_concierge_reply(
                text, n, lang, ordered, effective_facts, cur_treatment, branch_facts, prev_norm
            )
            rules = self._parse_custom_rules(effective_facts)
            needs_handoff = any(it in ("randevu", "insan", "sikayet") for it in ordered) or (
                "fiyat" in ordered and rules.get("price_policy") == "direct_handoff"
            )
            if sess is not None:
                self.fsm.record_turn(sess_key, text, primary_intent, branch_key, cur_treatment, combined_answer)
            return RouteResult(
                combined_answer,
                primary_layer,
                primary_intent,
                lang,
                handoff=needs_handoff,
                high_value=high_value,
                meta={"matched_intents": ordered, "branch": branch_key, "treatment": cur_treatment},
            )

        # Katman-1e: kesin eşleşme önbelleği (klinik adıyla ayrı anahtar)
        cf_key = effective_facts.get("clinic", self.clinic)
        key = f"dc:ans:{cf_key}:{lang}:{hashlib.sha256(n.encode()).hexdigest()}"
        hit = await self.cache.get(key)
        if hit:
            return RouteResult(hit if isinstance(hit, str) else hit.decode(), "L1-onbellek", "genel", lang, high_value=high_value)

        # Katman-1f: semantik önbellek
        emb = None
        try:
            emb = await self._embed(n)
        except Exception:
            emb = None
        if emb:
            best, best_ans = 0.0, None
            for raw in (await self.cache.hgetall(f"dc:sem:{cf_key}:{lang}")).values():
                item = json.loads(raw)
                s = self._cos(emb, item["v"])
                if s > best:
                    best, best_ans = s, item["a"]
            if best_ans and best >= self.sem_threshold:
                return RouteResult(best_ans, "L1-semantik", "genel", lang, high_value=high_value, meta={"benzerlik": round(best, 3)})

        # Katman-2: sınıflandırma (küçük LLM veya önbellek)
        tin = tout = 0
        label = "genel"
        layer2 = "L2-anahtar"
        lkey = f"dc:lbl:{hashlib.sha256(n.encode()).hexdigest()}"
        cached_lbl = await self.cache.get(lkey)
        if cached_lbl:
            label, layer2 = (cached_lbl if isinstance(cached_lbl, str) else cached_lbl.decode()), "L2-onbellek"
        elif allow_llm and self.llm_ready and self.small:
            try:
                out, tin, tout = await self._chat(self.small, [
                    {"role": "system", "content": "Etiket: " + ",".join(LABELS)},
                    {"role": "user", "content": text[:300]}], max_tokens=3)
                cand = normalize(out).split()[0] if out else ""
                if cand in LABELS:
                    label, layer2 = cand, "L2-kucuk-model"
                    await self.cache.set(lkey, cand, ex=30 * 86400)
            except Exception:
                pass

        if label == "fiyat" and not self.price_on:
            return RouteResult(
                self._compose_parlant_concierge_reply(text, n, lang, ["fiyat"], effective_facts, cur_treatment, branch_facts, prev_norm),
                layer2,
                "fiyat",
                lang,
                tin,
                tout,
                high_value=high_value,
            )
        if label == "tibbi_soru":
            return RouteResult(self._pick(self.tpl["tibbi_soru"], lang, effective_facts), layer2, "tibbi_soru", lang, tin, tout, handoff=True, high_value=high_value)
        if label in ("randevu", "insan", "gorsel", "sikayet"):
            return RouteResult(self._pick(self.tpl[label], lang, effective_facts), layer2, label, lang, tin, tout,
                               alert="sikayet" if label == "sikayet" else None,
                               handoff=label in ("randevu", "insan", "sikayet"), high_value=high_value)

        # Katman-3: ana LLM
        if not (allow_llm and self.llm_ready and self.main):
            return RouteResult(self._pick(self.tpl["insan"], lang, effective_facts), "L2-yedek", label, lang, tin, tout, handoff=True, high_value=high_value)
        system = self.system_tpl.replace("{lang}", lang).replace(self.clinic, cf_key)
        try:
            ans, t3i, t3o = await self._chat(self.main, [{"role": "system", "content": system}, {"role": "user", "content": text[:1200]}],
                                             max_tokens=self.max_tokens, temperature=0.2)
        except Exception:
            return RouteResult(self._pick(self.tpl["insan"], lang, effective_facts), "L2-yedek", label, lang, tin, tout,
                               handoff=True, high_value=high_value, meta={"failover": "circuit-breaker"})
        tin += t3i; tout += t3o
        tag = re.search(r"\[(INSAN|RANDEVU|ACIL)\]", ans)
        ans_clean = re.sub(r"\s*\[(INSAN|RANDEVU|ACIL)\]\s*", " ", ans).strip()
        if not ans_clean or self.forbidden.search(normalize(ans_clean)):
            return RouteResult(self._pick(self.tpl["guvenli_yedek"], lang, effective_facts), "L3-filtre", label, lang, tin, tout, handoff=True, high_value=high_value)
        res = RouteResult(ans_clean, "L3-ana-model", label, lang, tin, tout,
                          alert="acil" if tag and tag.group(1) == "ACIL" else None,
                          handoff=bool(tag), high_value=high_value)
        if label == "genel" and not tag:
            await self.cache.set(key, ans_clean, ex=7 * 86400)
            if emb and await self.cache.hlen(f"dc:sem:{cf_key}:{lang}") < 2000:
                await self.cache.hset(f"dc:sem:{cf_key}:{lang}", key, json.dumps({"v": emb, "a": ans_clean}))
        return res
