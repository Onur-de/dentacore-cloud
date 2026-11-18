"use strict";
(() => {
  const $ = (id) => document.getElementById(id);

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
      });
    });
  }

  // Hero canlı ürün önizlemesi sekmeleri
  const tabChat = $("tab-chat");
  const tabSched = $("tab-schedule");
  const panelChat = $("panel-chat");
  const panelSched = $("panel-schedule");
  function switchPreviewTab(which) {
    const isChat = which === "chat";
    tabChat.classList.toggle("active", isChat);
    tabSched.classList.toggle("active", !isChat);
    tabChat.setAttribute("aria-selected", isChat ? "true" : "false");
    tabSched.setAttribute("aria-selected", !isChat ? "true" : "false");
    panelChat.classList.toggle("hidden", !isChat);
    panelSched.classList.toggle("hidden", isChat);
  }
  if (tabChat && tabSched) {
    tabChat.addEventListener("click", () => switchPreviewTab("chat"));
    tabSched.addEventListener("click", () => switchPreviewTab("schedule"));
  }

  // Hero senaryoları (TR, EN, AR RTL, DE — Parlant VIP Hasta Koordinatörü Üslubu)
  const SCENARIOS = {
    tr: {
      dir: "ltr",
      lang: "tr",
      msgs: [
        { cls: "msg-in", meta: "23:41 WhatsApp", text: "Yarın 14:30 randevuma yetişemeyeceğim, iptal edebilir misiniz?" },
        { cls: "msg-out", meta: "23:41 VIP Koordinatör AI", text: "Merhabalar, bilgi verdiğiniz için çok teşekkür ederiz; yarın 14:30 randevunuzu iptal ettik. Takviminize uygun yeni bir gün ve saat paylaşırsanız memnuniyetle hemen planlayabiliriz." },
        { cls: "msg-sys", meta: "", text: "Bekleme listesi dalga 1: 3 hastaya 14:30 teklifi gitti, Selin Arslan “EVET” dedi, koltuk 2 doldu." }
      ],
      layer: "L1 Parlant VIP + Bekleme Listesi",
      tokens: "yok",
      status: "Koltuk 2 yeniden doldu"
    },
    en: {
      dir: "ltr",
      lang: "en",
      msgs: [
        { cls: "msg-in", meta: "23:47 Instagram DM", text: "Hi, I'm in London. How much is a full set of zirconia crowns? Can I come next month?" },
        { cls: "msg-out", meta: "23:47 VIP Koordinatör AI", text: "Hello and a warm welcome from Istanbul! For guests traveling from London, our specialist dentist prepares a personalized written treatment and cost plan after reviewing your X-ray, and our 4-6 day VIP zirconia schedule is tailored to your flights. Which dates next month suit you best?" },
        { cls: "msg-sys", meta: "", text: "Yüksek değerli sağlık turizmi talebi: Görsel kalite kontrolü geçti, koordinatöre öncelikli düşürüldü." }
      ],
      layer: "L1 Parlant Bağlamsal Besteci",
      tokens: "yok",
      status: "Yüksek değerli VIP misafir"
    },
    ar: {
      dir: "rtl",
      lang: "ar",
      msgs: [
        { cls: "msg-in", meta: "01:12 WhatsApp", text: "لدي تورم في الوجه ونزيف لا يتوقف بعد الخلع، ماذا أفعل؟" },
        { cls: "msg-out", meta: "01:12 L1 Acil Triyaj", text: "نتمنى لكم السلامة؛ قد تحتاج حالتكم إلى رعاية طبية عاجلة. يرجى الاتصال بالرقم 112 فوراً أو التوجه لأقرب قسم طوارئ. تم إبلاغ طبيبنا المناوب فوراً." },
        { cls: "msg-sys", meta: "", text: "Acil durum alarmı tetiklendi: Nöbetçi hekim ve panel uyarı kutusu bilgilendirildi." }
      ],
      layer: "L1 Acil Durum Radarı",
      tokens: "yok",
      status: "Nöbetçi hekim alarmı"
    },
    de: {
      dir: "ltr",
      lang: "de",
      msgs: [
        { cls: "msg-in", meta: "08:05 WhatsApp", text: "Guten Morgen, wo ist Ihre Adresse und haben Sie Parkplätze?" },
        { cls: "msg-out", meta: "08:05 VIP Koordinatör AI", text: "Guten Morgen und herzlich willkommen! Wir begrüßen Sie gerne in unserer Klinik in der Bağdat Cad. No:142, Kadıköy / İstanbul. Sie können bequem mit dem Auto anreisen: Kostenlose Gästeparkplätze befinden sich direkt vor der Klinik." },
        { cls: "msg-sys", meta: "", text: "Konum + otopark birleşik VIP yanıtı 1 saniye altında gönderildi." }
      ],
      layer: "L1 Parlant Birleşik Niyet",
      tokens: "yok",
      status: "Otomatik yanıtlandı"
    }
  };

  const chatFeed = $("hero-chat-feed");
  const routerReadout = $("hero-router-readout");
  document.querySelectorAll(".sc-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const sc = SCENARIOS[btn.dataset.sc];
      if (!sc || !chatFeed || !routerReadout) return;
      document.querySelectorAll(".sc-btn").forEach((b) => b.classList.toggle("active", b === btn));
      chatFeed.setAttribute("dir", sc.dir);
      chatFeed.setAttribute("lang", sc.lang);
      chatFeed.replaceChildren(...sc.msgs.map((m) => {
        const box = document.createElement("div");
        box.className = "msg " + m.cls;
        if (m.cls === "msg-sys") box.setAttribute("dir", "ltr");
        if (m.meta) {
          const sp = document.createElement("span");
          sp.className = "msg-meta";
          sp.textContent = m.meta;
          box.appendChild(sp);
        }
        box.appendChild(document.createTextNode(m.text));
        return box;
      }));
      routerReadout.replaceChildren();
      [
        ["Katman:", sc.layer],
        ["Ek maliyet:", sc.tokens],
        ["Durum:", sc.status]
      ].forEach(([lbl, val]) => {
        const sp = document.createElement("span");
        const st = document.createElement("strong");
        st.textContent = lbl + " ";
        sp.appendChild(st);
        sp.appendChild(document.createTextNode(val));
        routerReadout.appendChild(sp);
      });
    });
  });

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
      lpCode.textContent = lg.toUpperCase() + (sample.dir === "rtl" ? " (RTL)" : "");
      lpText.textContent = sample.text;
    });
  });

  // Kayıp hesaplayıcı (yalnız tarayıcıda)
  const TL = new Intl.NumberFormat("tr-TR", { style: "currency", currency: "TRY", maximumFractionDigits: 0 });
  const ids = ["msg", "off", "conv", "appt", "ns", "tic"];
  function calc() {
    const v = {};
    ids.forEach((k) => {
      const inp = $(`i-${k}`);
      if (!inp) return;
      v[k] = Number(inp.value);
      $(`o-${k}`).textContent = k === "tic" ? v[k].toLocaleString("tr-TR") : String(v[k]);
    });
    const offLoss = Math.round(v.msg * 30 * (v.off / 100) * (v.conv / 100) * v.tic);
    const nsLoss = Math.round(v.appt * (v.ns / 100) * v.tic);
    $("r-off").textContent = TL.format(offLoss);
    $("r-ns").textContent = TL.format(nsLoss);
    $("r-loss").textContent = TL.format(offLoss + nsLoss);
  }
  ids.forEach((k) => {
    const inp = $(`i-${k}`);
    if (inp) inp.addEventListener("input", calc);
  });
  calc();

  // Demo formu (POST /lead)
  const form = $("lead");
  const msg = $("lead-msg");
  const submitBtn = $("lead-submit");
  if (form && msg) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      msg.classList.remove("err");
      msg.textContent = "";
      const f = new FormData(form);
      const clinic = String(f.get("clinic") || "").trim();
      const contact = String(f.get("contact") || "").trim();
      if (clinic.length < 2 || contact.length < 5) {
        msg.classList.add("err");
        msg.textContent = "Lütfen klinik adını ve geçerli bir telefon veya e-posta girin.";
        return;
      }
      const body = {
        clinic,
        contact,
        city: String(f.get("city") || "").trim() || null,
        chairs: f.get("chairs") ? Number(f.get("chairs")) : null,
        website: f.get("website") || null
      };
      if (submitBtn) submitBtn.disabled = true;
      try {
        const r = await fetch("/lead", {
          method: "POST",
          headers: { "Content-Type": "application/json", "Accept": "application/json" },
          body: JSON.stringify(body)
        });
        if (!r.ok) throw new Error("Lütfen bilgileri kontrol edip tekrar deneyin.");
        form.reset();
        msg.textContent = "Talebiniz alındı. Ekibimiz en kısa sürede sizinle iletişime geçecek.";
      } catch (err) {
        msg.classList.add("err");
        msg.textContent = err && err.message ? err.message : "Gönderim sırasında hata oluştu.";
      } finally {
        if (submitBtn) submitBtn.disabled = false;
      }
    });
  }
})();
