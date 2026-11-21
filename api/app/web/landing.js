"use strict";
(() => {
  const $ = (id) => document.getElementById(id);
  const reducedMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const TL = (n) => Math.round(n).toLocaleString("tr-TR") + " TL";

  // Service worker kaydı (yalnız statik varlıklar önbelleğe alınır)
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/sw.js", { scope: "/" }).catch(() => {});
  }

  // Mobil menü aç/kapa
  const navToggle = $("nav-toggle");
  const mobileMenu = $("mobile-menu");
  if (navToggle && mobileMenu) {
    navToggle.addEventListener("click", () => {
      const open = mobileMenu.classList.toggle("hidden") === false;
      navToggle.setAttribute("aria-expanded", open ? "true" : "false");
      navToggle.setAttribute("aria-label", open ? "Menüyü kapat" : "Menüyü aç");
    });
    mobileMenu.querySelectorAll("a").forEach((a) => {
      a.addEventListener("click", () => {
        mobileMenu.classList.add("hidden");
        navToggle.setAttribute("aria-expanded", "false");
        navToggle.setAttribute("aria-label", "Menüyü aç");
      });
    });
  }

  // Sahneden panele doğrudan geçiş: /app (canlı) ya da panel.html (statik demo) adresine sekme bağlantısı eklenir
  document.querySelectorAll("a[data-panel-hash]").forEach((a) => {
    const base = a.getAttribute("href") || "/app";
    if (!base.includes("#")) a.setAttribute("href", base + a.dataset.panelHash);
  });

  // Canlı klinik sahnesi: üç vaka, adım adım oynar. HTML tek kaynaktır; betik yalnız sırayla gösterir.
  const caseTabs = Array.from(document.querySelectorAll("[data-case]"));
  const panels = Array.from(document.querySelectorAll(".stage-panel"));
  const replayBtn = $("replay");
  const STEP_MS = 950;
  let stageTimer = 0;
  let activeCase = "a";

  function panelFor(id) { return $("sc-" + id); }

  function resetReadout(panel) {
    panel.querySelectorAll("dd[data-key]").forEach((dd) => {
      if (!dd.dataset.final) dd.dataset.final = dd.textContent;
      dd.textContent = "Bekleniyor";
      dd.classList.add("is-pending");
    });
  }

  function fillReadout(panel, key) {
    panel.querySelectorAll('dd[data-key="' + key + '"]').forEach((dd) => {
      const live = dd.hasAttribute("data-live-ticket");
      if (!live && dd.dataset.final) dd.textContent = dd.dataset.final;
      dd.classList.remove("is-pending");
    });
  }

  function showCase(id, animate) {
    window.clearTimeout(stageTimer);
    activeCase = id;
    caseTabs.forEach((tab) => {
      const on = tab.dataset.case === id;
      tab.setAttribute("aria-selected", on ? "true" : "false");
      tab.tabIndex = on ? 0 : -1;
    });
    panels.forEach((p) => { p.hidden = p.id !== "sc-" + id; });
    const panel = panelFor(id);
    if (!panel) return;
    const steps = Array.from(panel.querySelectorAll(".step"));
    // Önceki oynatmanın izleri temizlenir
    steps.forEach((s) => { s.classList.remove("is-pending"); s.removeAttribute("aria-hidden"); });
    panel.querySelectorAll("dd[data-key]").forEach((dd) => {
      if (dd.dataset.final && !dd.hasAttribute("data-live-ticket")) dd.textContent = dd.dataset.final;
      dd.classList.remove("is-pending");
    });
    syncTicket();
    if (!animate || reducedMotion) return;

    steps.forEach((s) => { s.classList.add("is-pending"); s.setAttribute("aria-hidden", "true"); });
    resetReadout(panel);
    let i = 0;
    const next = () => {
      if (i >= steps.length) { panel.dataset.state = "done"; return; }
      const step = steps[i++];
      step.classList.remove("is-pending");
      step.removeAttribute("aria-hidden");
      if (step.dataset.key) fillReadout(panel, step.dataset.key);
      stageTimer = window.setTimeout(next, STEP_MS);
    };
    panel.dataset.state = "playing";
    next();
  }

  if (caseTabs.length) {
    // Betik varsa yalnız seçili vaka görünür; betik yoksa üçü de okunabilir kalır
    showCase("a", false);
    caseTabs.forEach((tab, idx) => {
      tab.addEventListener("click", () => showCase(tab.dataset.case, true));
      tab.addEventListener("keydown", (e) => {
        const keys = { ArrowDown: 1, ArrowRight: 1, ArrowUp: -1, ArrowLeft: -1 };
        let target = -1;
        if (e.key in keys) target = (idx + keys[e.key] + caseTabs.length) % caseTabs.length;
        else if (e.key === "Home") target = 0;
        else if (e.key === "End") target = caseTabs.length - 1;
        if (target < 0) return;
        e.preventDefault();
        caseTabs[target].focus();
        showCase(caseTabs[target].dataset.case, true);
      });
    });
  }
  if (replayBtn) replayBtn.addEventListener("click", () => showCase(activeCase, true));

  // 16 dil önizleme seçicisi (RTL destekli)
  const LANG_SAMPLES = {
    tr: { dir: "ltr", text: "Merhaba, Özel DentaCore Merkez Polikliniği hasta iletişim hattına hoş geldiniz. Randevu, adres veya çalışma saatleri için yazabilirsiniz." },
    en: { dir: "ltr", text: "Hello, welcome to DentaCore Dental Clinic. You can ask about appointments, our address or opening hours." },
    de: { dir: "ltr", text: "Hallo, willkommen bei DentaCore. Fragen Sie gern nach Terminen, unserer Adresse oder den Öffnungszeiten." },
    ar: { dir: "rtl", text: "مرحباً بكم في عيادة DentaCore. كيف يمكننا مساعدتكم؟ يمكنكم السؤال عن المواعيد أو العنوان أو ساعات العمل." },
    ru: { dir: "ltr", text: "Здравствуйте, добро пожаловать в клинику DentaCore. Спросите о записи, адресе или часах работы." },
    fr: { dir: "ltr", text: "Bonjour, bienvenue chez DentaCore. Comment pouvons-nous vous aider ? Vous pouvez demander un rendez-vous ou nos horaires." },
    nl: { dir: "ltr", text: "Hallo, welkom bij DentaCore. Waarmee kunnen wij u helpen? U kunt vragen naar afspraken, adres of openingstijden." },
    es: { dir: "ltr", text: "Hola, bienvenido a DentaCore. ¿En qué podemos ayudarle? Puede consultar por citas, dirección u horarios." },
    it: { dir: "ltr", text: "Buongiorno, benvenuti da DentaCore. Come possiamo aiutarvi? Potete chiedere appuntamenti, indirizzo o orari." },
    fa: { dir: "rtl", text: "سلام، به کلینیک DentaCore خوش آمدید. چگونه می‌توانیم کمکتان کنیم؟ می‌توانید درباره نوبت، آدرس یا ساعات کاری بپرسید." },
    az: { dir: "ltr", text: "Salam, DentaCore pasiyent xəttinə xoş gəlmisiniz. Görüş, ünvan və iş saatları barədə yaza bilərsiniz." },
    uk: { dir: "ltr", text: "Вітаємо у клініці DentaCore. Чим можемо допомогти? Запитайте про запис, адресу або години роботи." },
    bg: { dir: "ltr", text: "Здравейте, добре дошли в DentaCore. Можете да попитате за час, адрес или работно време." },
    ro: { dir: "ltr", text: "Bună ziua, bun venit la DentaCore. Puteți întreba despre programări, adresă sau program." },
    el: { dir: "ltr", text: "Γεια σας, καλώς ήρθατε στο DentaCore. Ρωτήστε για ραντεβού, διεύθυνση ή ωράριο λειτουργίας." },
    he: { dir: "rtl", text: "שלום, ברוכים הבאים למרפאת DentaCore. ניתן לשאול על תורים, כתובת או שעות פעילות." }
  };

  const langPreview = $("lang-preview");
  const lpCode = $("lp-code");
  const lpText = $("lp-text");
  document.querySelectorAll(".lang-chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      const lg = chip.dataset.lang;
      const sample = LANG_SAMPLES[lg];
      if (!sample || !langPreview) return;
      document.querySelectorAll(".lang-chip").forEach((c) => c.classList.toggle("active", c === chip));
      langPreview.setAttribute("dir", sample.dir);
      langPreview.setAttribute("lang", lg);
      lpCode.textContent = lg.toUpperCase() + (sample.dir === "rtl" ? " (sağdan sola)" : "");
      lpText.textContent = sample.text;
    });
  });

  // Kayıp hesaplayıcı: üç kırılım, yalnız tarayıcıda
  const CALC_FIELDS = {
    msg: (v) => String(v),
    off: (v) => "%" + v,
    for: (v) => "%" + v,
    conv: (v) => "%" + v,
    appt: (v) => String(v),
    ns: (v) => "%" + v,
    tic: (v) => TL(v),
    ftic: (v) => TL(v),
    min: (v) => v + " dk"
  };
  const WORK_DAYS = 26;
  const NUM = new Intl.NumberFormat("tr-TR", { maximumFractionDigits: 1 });

  function syncTicket() {
    const tic = $("i-tic");
    if (!tic) return;
    document.querySelectorAll("[data-live-ticket]").forEach((el) => { el.textContent = TL(Number(tic.value)); });
  }

  function calc() {
    const v = {};
    Object.keys(CALC_FIELDS).forEach((k) => {
      const inp = $("i-" + k);
      if (!inp) return;
      v[k] = Number(inp.value);
      const out = $("o-" + k);
      if (out) out.textContent = CALC_FIELDS[k](v[k]);
    });
    const offMonthly = v.msg * 30 * (v.off / 100);
    const offForeign = offMonthly * (v.for / 100);
    const offLocal = offMonthly - offForeign;
    const lostLocalPatients = offLocal * (v.conv / 100);
    const lostForeignPatients = offForeign * (v.conv / 100);
    const emptySeats = v.appt * (v.ns / 100);
    const seatLoss = emptySeats * v.tic;
    const localLoss = lostLocalPatients * v.tic;
    const foreignLoss = lostForeignPatients * v.ftic;
    const total = seatLoss + localLoss + foreignLoss;
    const hours = (v.min * WORK_DAYS) / 60;

    $("r-loss").textContent = TL(total);
    $("r-seat").textContent = TL(seatLoss);
    $("r-loc").textContent = TL(localLoss);
    $("r-for").textContent = TL(foreignLoss);
    $("r-seat-n").textContent = "ayda " + Math.round(emptySeats) + " boş koltuk";
    $("r-loc-n").textContent = "ayda " + Math.round(lostLocalPatients) + " hasta";
    $("r-for-n").textContent = "ayda " + Math.round(lostForeignPatients) + " hasta";
    $("r-hours").textContent = "ayda " + NUM.format(hours) + " saat";
    $("b-seat").style.setProperty("--v", String(Math.max(seatLoss, 0)));
    $("b-loc").style.setProperty("--v", String(Math.max(localLoss, 0)));
    $("b-for").style.setProperty("--v", String(Math.max(foreignLoss, 0)));
    syncTicket();
  }
  if ($("r-loss")) {
    Object.keys(CALC_FIELDS).forEach((k) => {
      const inp = $("i-" + k);
      if (inp) inp.addEventListener("input", calc);
    });
    calc();
  }

  // Kampanya ve UTM kaynak yakalama (Multi-Touch Attribution: dc_first_touch & dc_last_touch) + Demo formu (POST /lead)
  const urlParams = new URLSearchParams(window.location.search || "");
  const rawUtmSource = urlParams.get("utm_source") || "";
  const rawUtmMedium = urlParams.get("utm_medium") || "";
  const rawUtmCampaign = urlParams.get("utm_campaign") || "";
  const rawSource = urlParams.get("source") || "";
  const rawCampaignCode = urlParams.get("dc_code") || urlParams.get("campaign_code") || rawUtmCampaign || "";
  const rawClickId = urlParams.get("click_id")
    || (urlParams.get("gclid") ? "gclid:" + urlParams.get("gclid") : "")
    || (urlParams.get("fbclid") ? "fbclid:" + urlParams.get("fbclid") : "")
    || (urlParams.get("ttclid") ? "ttclid:" + urlParams.get("ttclid") : "");

  const hasUrlAttribution = Boolean(rawUtmSource || rawUtmMedium || rawUtmCampaign || rawCampaignCode || rawClickId || rawSource);
  const currentTouch = {
    source: rawSource || rawUtmSource || "website",
    utm_source: rawUtmSource,
    utm_medium: rawUtmMedium,
    utm_campaign: rawUtmCampaign,
    campaign_code: rawCampaignCode,
    click_id: rawClickId,
    ts: new Date().toISOString()
  };

  function safeParseJSON(raw) {
    if (!raw) return null;
    try { return JSON.parse(raw); } catch (_) { return null; }
  }

  let firstTouch = null;
  let lastTouch = null;
  try {
    firstTouch = safeParseJSON(window.localStorage.getItem("dc_first_touch"));
    lastTouch = safeParseJSON(window.sessionStorage.getItem("dc_last_touch"));
    if (hasUrlAttribution) {
      if (!firstTouch) {
        firstTouch = currentTouch;
        window.localStorage.setItem("dc_first_touch", JSON.stringify(firstTouch));
      }
      lastTouch = currentTouch;
      window.sessionStorage.setItem("dc_last_touch", JSON.stringify(lastTouch));
    }
  } catch (_) {}

  const effFirst = firstTouch || currentTouch;
  const effLast = lastTouch || firstTouch || currentTouch;
  const utmSource = effLast.utm_source || effFirst.utm_source || "";
  const utmMedium = effLast.utm_medium || effFirst.utm_medium || "";
  const utmCampaign = effLast.utm_campaign || effFirst.utm_campaign || "";
  const campaignCode = effLast.campaign_code || effFirst.campaign_code || utmCampaign || "";
  const clickId = effLast.click_id || effFirst.click_id || "";
  const firstSource = effFirst.source || effFirst.utm_source || "";

  // WhatsApp iletişim butonlarına aktif kampanya referansı ([Ref: KAMPANYA_KODU]) otomatik ekleme
  if (campaignCode) {
    const refTag = `[Ref: ${campaignCode}]`;
    document.querySelectorAll('a[href*="wa.me"], a[href*="whatsapp.com"], a[data-wa-link]').forEach((a) => {
      try {
        const u = new URL(a.href, window.location.origin);
        const curText = u.searchParams.get("text") || "Merhaba, DentaCore hakkında bilgi almak istiyorum.";
        if (!curText.includes("[Ref:")) {
          u.searchParams.set("text", `${curText} ${refTag}`.trim());
          a.href = u.toString();
        }
      } catch (_) {}
    });
  }

  const form = $("lead");
  const msg = $("lead-msg");
  const submitBtn = $("lead-submit");
  let formStartTracked = false;

  if (form && msg) {
    form.addEventListener("focusin", () => {
      if (formStartTracked || (!campaignCode && !utmSource && !clickId)) return;
      formStartTracked = true;
      fetch("/api/campaigns/track", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          event_type: "form_start",
          campaign_code: campaignCode,
          utm_source: utmSource,
          utm_medium: utmMedium,
          utm_campaign: utmCampaign,
          click_id: clickId
        })
      }).catch(() => {});
    });

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      msg.classList.remove("err");
      msg.textContent = "";
      const f = new FormData(form);
      const clinic = String(f.get("clinic") || "").trim();
      const contact = String(f.get("contact") || "").trim();
      const kvkkOk = Boolean(form.querySelector('[name="kvkk_aydinlatma"]')?.checked);
      const yurtDisiOk = Boolean(form.querySelector('[name="yurt_disi_riza"]')?.checked);
      if (clinic.length < 2 || contact.length < 5) {
        msg.classList.add("err");
        msg.textContent = "Lütfen klinik adını ve geçerli bir telefon veya e-posta girin.";
        return;
      }
      if (!kvkkOk) {
        msg.classList.add("err");
        msg.textContent = "Lütfen KVKK aydınlatma ve iletişim rızası kutusunu işaretleyin.";
        return;
      }
      const body = {
        clinic,
        contact,
        city: String(f.get("city") || "").trim() || null,
        chairs: f.get("chairs") ? Number(f.get("chairs")) : null,
        source: firstSource || effLast.source || null,
        utm_source: utmSource,
        utm_medium: utmMedium,
        utm_campaign: utmCampaign,
        click_id: clickId,
        campaign_code: campaignCode,
        kvkk_aydinlatma: kvkkOk,
        yurt_disi_riza: yurtDisiOk,
        website: f.get("website") || null
      };
      if (submitBtn) submitBtn.disabled = true;
      try {
        const r = await fetch("/lead", {
          method: "POST",
          headers: { "Content-Type": "application/json", "Accept": "application/json" },
          body: JSON.stringify(body)
        });
        if (!r.ok) {
          throw new Error("Sunucu yanıt vermedi veya statik önizleme ortamındasınız. Lütfen canlı sunucu üzerinden tekrar deneyin.");
        }
        form.reset();
        msg.textContent = "Talebiniz alındı. Ekibimiz en kısa sürede sizinle iletişime geçecek.";
      } catch (err) {
        msg.classList.add("err");
        msg.textContent = err && err.message ? err.message : "Gönderim sırasında sunucu bağlantısı kurulamadı.";
      } finally {
        if (submitBtn) submitBtn.disabled = false;
      }
    });
  }
})();
