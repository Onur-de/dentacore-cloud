"use strict";
/* DentaCore v6 yönetim paneli. Dış kütüphane yok; tüm veriler textContent ile basılır (XSS'e kapalı). */
(() => {
  const S = {
    csrf: "",
    user: null,
    clinic: "",
    clinic_id: 1,
    home_clinic_id: 1,
    idle: 900,
    lastAct: Date.now(),
    day: sod(new Date()),
    calMode: lsGet("dc_cal_mode", "week"),
    counts: {},
    simResult: null,
  };
  const root = document.getElementById("root");
  const SVG = "http://www.w3.org/2000/svg";

  // Service worker kaydı (yalnız statik dosyalar)
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/sw.js", { scope: "/" }).catch(() => {});
  }

  // ------------------------------------------------------------------ güvenli localStorage & pano
  function lsGet(k, def) {
    try {
      const v = window.localStorage.getItem(k);
      return v === null ? def : v;
    } catch (e) {
      return def;
    }
  }
  function lsSet(k, v) {
    try {
      window.localStorage.setItem(k, String(v));
    } catch (e) { /* depolama kapalı */ }
  }
  async function copyText(txt, okMsg) {
    const str = String(txt || "");
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(str);
        toast(okMsg || "Kopyalandı");
        return true;
      }
    } catch (e) { /* yedek yöntem */ }
    try {
      const ta = document.createElement("textarea");
      ta.value = str;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.left = "-9999px";
      ta.style.top = "0";
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand("copy");
      ta.remove();
      if (ok) {
        toast(okMsg || "Kopyalandı");
        return true;
      }
    } catch (e2) { /* başarısız */ }
    toast("Otomatik kopyalanamadı, metni elle seçip kopyalayın.", true);
    return false;
  }

  // ------------------------------------------------------------------ DOM yardımcıları
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v === null || v === undefined || v === false) continue;
        if (k === "class") el.className = v;
        else if (k === "on") for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn);
        else if (k === "text") el.textContent = v;
        else if (k in el && k !== "list" && k !== "form") {
          try { el[k] = v; } catch (e) { el.setAttribute(k, v); }
        } else {
          el.setAttribute(k, v === true ? "" : v);
        }
      }
    }
    add(el, kids);
    return el;
  }
  function add(el, kids) {
    for (const c of kids.flat(Infinity)) {
      if (c === null || c === undefined || c === false) continue;
      el.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
    }
  }

  const ICONS = {
    home: "M3 11l9-8 9 8v9a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z",
    cal: "M4 6h16v14H4zM4 10h16M8 3v4M16 3v4",
    users: "M16 19v-1a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v1M9 10a3 3 0 1 0 0-6 3 3 0 0 0 0 6M22 19v-1a4 4 0 0 0-3-3.9M16 4.1a3 3 0 0 1 0 5.8",
    clock: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 7v5l3 2",
    bell: "M6 8a6 6 0 1 1 12 0c0 7 3 8 3 8H3s3-1 3-8M10 20a2 2 0 0 0 4 0",
    box: "M21 8l-9-5-9 5v8l9 5 9-5zM3 8l9 5 9-5M12 13v8",
    cash: "M3 6h18v12H3zM12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6M6 9v.01M18 15v.01",
    chip: "M7 7h10v10H7zM9 3v4M15 3v4M9 17v4M15 17v4M3 9h4M3 15h4M17 9h4M17 15h4",
    team: "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8M4 21v-1a6 6 0 0 1 6-6h4a6 6 0 0 1 6 6v1",
    shield: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6zM9 12l2 2 4-4",
    out: "M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4M10 17l5-5-5-5M15 12H3",
    plus: "M12 5v14M5 12h14",
    msg: "M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z",
    tpl: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M8 13h8M8 17h5",
    chart: "M3 3v18h18M7 14l4-4 4 3 5-6",
    cog: "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z",
    clinic: "M3 21h18M5 21V7l8-4v18M19 21V11l-6-4M9 9h1M9 13h1M9 17h1",
    menu: "M4 7h16M4 12h16M4 17h16",
    copy: "M9 9h11v11H9zM5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1",
  };
  function icon(n) {
    const s = document.createElementNS(SVG, "svg");
    s.setAttribute("viewBox", "0 0 24 24");
    s.setAttribute("class", "ico");
    s.setAttribute("aria-hidden", "true");
    const p = document.createElementNS(SVG, "path");
    p.setAttribute("d", ICONS[n] || "");
    s.appendChild(p);
    return s;
  }

  function sod(d) { const x = new Date(d); x.setHours(0, 0, 0, 0); return x; }
  function addDays(d, n) { const x = new Date(d); x.setDate(x.getDate() + n); return x; }
  function monday(d) { const x = sod(d); const w = (x.getDay() + 6) % 7; return addDays(x, -w); }
  const TL = new Intl.NumberFormat("tr-TR", { style: "currency", currency: "TRY", maximumFractionDigits: 2 });
  const fmtTL = (n) => TL.format(Number(n || 0));
  const fmtD = (s) => new Date(s).toLocaleDateString("tr-TR", { day: "2-digit", month: "short", year: "numeric" });
  const fmtT = (s) => new Date(s).toLocaleTimeString("tr-TR", { hour: "2-digit", minute: "2-digit" });
  const fmtDT = (s) => s ? `${fmtD(s)} ${fmtT(s)}` : "-";
  const ymd = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;

  const STATUS = {
    booked: ["Bekliyor", "yellow"],
    confirmed: ["Teyitli", "teal"],
    done: ["Geldi", "green"],
    noshow: ["Gelmedi", "red"],
    cancelled: ["İptal", ""],
    open: ["Açık", ""],
  };
  const ROLE = { owner: "Yönetici", doctor: "Hekim", secretary: "Sekreter" };
  const LANG_OPTIONS = [
    ["tr", "Türkçe (TR)"],
    ["en", "English (EN)"],
    ["de", "Deutsch (DE)"],
    ["ar", "العربية (AR · RTL)"],
    ["ru", "Русский (RU)"],
    ["fr", "Français (FR)"],
    ["nl", "Nederlands (NL)"],
    ["es", "Español (ES)"],
    ["it", "Italiano (IT)"],
    ["fa", "فارسی (FA · RTL)"],
    ["az", "Azərbaycanca (AZ)"],
    ["uk", "Українська (UK)"],
    ["bg", "Български (BG)"],
    ["ro", "Română (RO)"],
    ["el", "Ελληνικά (EL)"],
    ["he", "עברית (HE · RTL)"],
  ];
  const RTL_LANGS = new Set(["ar", "fa", "he"]);
  const DEMO_ACCOUNTS = [
    { label: "İstanbul Merkez (HQ)", note: "Zincir yönetimi", email: "yonetici@dentacore.com", pw: "DentaCore2026!" },
    { label: "Bursa Gülüş Diş", note: "İzole şube 2", email: "klinik@bursadis.com", pw: "BursaDis2026!" },
    { label: "Ankara Çankaya Estetik Diş", note: "İzole şube 3", email: "klinik@ankaradis.com", pw: "AnkaraDis2026!" },
  ];

  const isHQ = () => Boolean(S.user && (S.user.is_hq || (S.user.role === "owner" && S.home_clinic_id === 1)));
  const tag = (txt, cls) => h("span", { class: `tag ${cls || ""}` }, txt);
  const tblWrap = (table) => h("div", { class: "table-wrap" }, table);

  function toast(msg, bad) {
    document.querySelectorAll(".toast").forEach((t) => t.remove());
    const t = h("div", { class: "toast" + (bad ? " bad" : ""), role: "status", "aria-live": "polite", text: msg });
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 3400);
  }

  async function api(path, opts = {}) {
    const method = opts.method || "GET";
    const headers = { Accept: "application/json" };
    if (opts.body !== undefined) headers["Content-Type"] = "application/json";
    if (method !== "GET") headers["X-CSRF-Token"] = S.csrf;
    const r = await fetch(path, {
      method,
      headers,
      credentials: "same-origin",
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    });
    let data = null;
    try { data = await r.json(); } catch (e) { data = null; }
    if (r.status === 401 && path !== "/auth/login") {
      S.user = null;
      lsSet("dc_has_session", "");
      renderLogin("Oturumunuz sona erdi, lütfen tekrar giriş yapın.");
      throw new Error("oturum");
    }
    if (!r.ok) {
      let msg = "İşlem başarısız";
      if (data && typeof data.detail === "string") msg = data.detail;
      else if (data && Array.isArray(data.detail)) msg = data.detail.map((d) => d.msg).join(", ");
      throw new Error(msg);
    }
    return data;
  }

  const run = async (fn, okMsg) => {
    try {
      const r = await fn();
      if (okMsg) toast(okMsg);
      return r;
    } catch (e) {
      if (e.message !== "oturum") toast(e.message, true);
      return null;
    }
  };

  function modal(title, fields, onSubmit, submitText) {
    const prevFocus = document.activeElement;
    const err = h("div", { class: "err", role: "alert" });
    const btn = h("button", { class: "btn btn-cta", type: "submit" }, submitText || "Kaydet");
    const closeOv = () => {
      document.removeEventListener("keydown", onEsc);
      ov.remove();
      if (prevFocus && typeof prevFocus.focus === "function") prevFocus.focus();
    };
    const onEsc = (ev) => {
      if (ev.key !== "Escape") return;
      const modals = document.querySelectorAll(".modal");
      if (modals.length && modals[modals.length - 1] !== form) return;
      ev.stopImmediatePropagation();
      closeOv();
    };
    const titleId = "m-title-" + Math.random().toString(36).slice(2, 7);
    const form = h("form", {
      class: "modal",
      on: {
        submit: async (e) => {
          e.preventDefault();
          err.textContent = "";
          btn.disabled = true;
          try {
            const ok = await onSubmit(new FormData(form));
            if (ok !== false) closeOv();
          } catch (x) {
            if (x.message !== "oturum") err.textContent = x.message;
          } finally {
            btn.disabled = false;
          }
        },
      },
    },
      h("h2", { id: titleId, text: title }),
      fields,
      err,
      h("div", { class: "foot" },
        h("button", { class: "btn btn-ghost", type: "button", on: { click: closeOv } }, "Vazgeç"),
        btn
      )
    );
    const ov = h("div", {
      class: "overlay",
      role: "dialog",
      "aria-modal": "true",
      "aria-labelledby": titleId,
      on: { mousedown: (e) => { if (e.target === ov) closeOv(); } },
    }, form);
    document.addEventListener("keydown", onEsc);
    document.body.appendChild(ov);
    const first = form.querySelector("input,select,textarea,button");
    if (first) first.focus();
    return ov;
  }

  const fld = (label, input) => h("div", { class: "field" }, h("label", { text: label }), input);
  const inp = (name, attrs = {}) => h("input", { class: "input", name, ...attrs });
  const sel = (name, options, value) => h("select", { class: "input", name }, options.map(([v, t]) => h("option", { value: v, selected: v === value }, t)));

  // ------------------------------------------------------------------ hareketsizlik zaman aşımı
  ["mousemove", "keydown", "click", "touchstart", "scroll"].forEach((ev) =>
    addEventListener(ev, () => {
      S.lastAct = Date.now();
      const w = document.querySelector(".idle");
      if (w) w.remove();
    }, { passive: true })
  );
  setInterval(async () => {
    if (!S.user) return;
    const idle = (Date.now() - S.lastAct) / 1000;
    if (idle > S.idle - 5) {
      try { await api("/auth/logout", { method: "POST" }); } catch (e) { /* zaten düşmüş */ }
      S.user = null;
      renderLogin("Hareketsizlik nedeniyle oturum kapatıldı.");
    } else if (idle > S.idle - 60 && !document.querySelector(".idle")) {
      document.body.appendChild(h("div", { class: "idle", role: "status", text: "Hareketsizlik uyarısı: 1 dakika içinde oturum kapanacak." }));
    }
  }, 5000);

  // ------------------------------------------------------------------ giriş ekranı + 3 demo hesap
  // Demo hesap kutusu yalnız yerel bilgisayarda / aynı Wi-Fi ağında (veya ?demo adresinde) görünür.
  // Gerçek klinik alan adında (ör. panel.klinikadi.com) parolalar asla ekranda gösterilmez.
  const IS_DEMO_HOST = /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(location.hostname)
    || new URLSearchParams(location.search).has("demo");
  function renderLogin(msg) {
    S.simResult = null;
    S.simText = "";
    S.simLang = "";
    root.replaceChildren();
    const err = h("div", { class: "err", role: "alert", text: msg || "" });
    const demoStatus = h("div", { class: "sr-only", "aria-live": "polite", style: "position:absolute;left:-9999px" });
    const emailInput = inp("email", { type: "email", required: true, autocomplete: "username", placeholder: "klinik@ornek.com" });
    const pwInput = inp("password", { type: "password", required: true, autocomplete: "current-password", minLength: 12, placeholder: "En az 12 karakter" });
    const totpWrap = h("div", { class: "field hidden" },
      h("label", { text: "Doğrulama kodu (Authenticator)" }),
      inp("totp", { inputMode: "numeric", autocomplete: "one-time-code", maxLength: 6, pattern: "[0-9]{6}" })
    );
    const btn = h("button", { class: "btn btn-cta btn-block", type: "submit" }, "Giriş yap");

    const demoBox = h("div", { class: "demo-box" },
      h("div", { class: "demo-title", text: "Demo hesapları (tek tıkla doldur)" }),
      h("div", { class: "demo-grid" }, DEMO_ACCOUNTS.map((d) =>
        h("button", {
          class: "demo-btn",
          type: "button",
          "data-demo-email": d.email,
          on: {
            click: () => {
              emailInput.value = d.email;
              pwInput.value = d.pw;
              err.textContent = "";
              demoStatus.textContent = `${d.label} bilgileri dolduruldu.`;
              btn.focus();
            },
          },
        },
          h("div", null, h("strong", { text: d.label }), h("span", { text: d.email })),
          tag(d.note, d.email.includes("yonetici") ? "teal" : "")
        )
      )),
      demoStatus
    );

    const form = h("form", {
      class: "card-login",
      on: {
        submit: async (e) => {
          e.preventDefault();
          err.textContent = "";
          btn.disabled = true;
          const f = new FormData(form);
          try {
            const r = await api("/auth/login", {
              method: "POST",
              body: { email: f.get("email"), password: f.get("password"), totp: f.get("totp") || null },
            });
            if (r.need_totp) {
              totpWrap.classList.remove("hidden");
              totpWrap.querySelector("input").focus();
              err.textContent = "Hesabınızda iki adımlı doğrulama açık.";
              return;
            }
            lsSet("dc_has_session", "1");
            await boot(true);
          } catch (x) {
            err.textContent = x.message;
          } finally {
            btn.disabled = false;
          }
        },
      },
    },
      h("h2", { text: "Panele giriş" }),
      h("p", { class: "sub", text: "Klinik ekibine özel, şifreli bağlantı." }),
      IS_DEMO_HOST ? demoBox : null,
      fld("E-posta", emailInput),
      fld("Parola", pwInput),
      totpWrap,
      err,
      btn,
      h("div", { class: "lock-note" }, icon("shield"), "15 dk hareketsizlikte oturum kapanır. Tüm girişler denetim kaydına yazılır.")
    );

    root.appendChild(h("div", { class: "login", id: "panel-main" },
      h("section", { class: "login-art" },
        h("div", null, h("div", { class: "brand" }, h("img", { src: "/static/favicon.svg", alt: "" }), h("div", null, "DentaCore", h("small", { text: "Klinik İşletim Sistemi" })))),
        h("div", null,
          h("h1", { text: "Kaçan her mesaj, boş kalan her koltuk görünür olsun." }),
          h("p", { text: "Randevu, iPhone/Android takvim eşitleme, 16 dilde yapay zeka karşılama, dijital anamnez, kasa, envanter ve çok şubeli yönetim tek ekranda." }),
          h("div", { class: "badges" }, [
            "16 Dil + RTL Destek",
            "12/12 Güvenlik Başlığı",
            "Fernet Şifreli Veri",
            "TOTP İki Adımlı Giriş",
            "SHA-256 Denetim Zinciri",
          ].map((b) => h("span", { class: "badge", text: b })))
        ),
        h("small", { text: "© DentaCore · Kendi sunucunuzda tam kontrol" })
      ),
      h("section", { class: "login-form" }, form)
    ));
    emailInput.focus();
  }

  // ------------------------------------------------------------------ kabuk & mobil navigasyon
  const NAV = [
    ["overview", "Genel Bakış", "home"],
    ["calendar", "Takvim", "cal"],
    ["messages", "Mesajlar & Simülatör", "msg"],
    ["patients", "Hastalar", "users"],
    ["waitlist", "Bekleme Listesi", "clock"],
    ["alerts", "Uyarılar", "bell"],
    ["inventory", "Envanter", "box"],
    ["templates", "Şablonlar", "tpl"],
    ["kasa", "Kasa", "cash"],
    ["analytics", "İletişim Analizi", "chart"],
    ["sep"],
    ["costs", "Yapay Zeka Maliyeti", "chip"],
    ["team", "Ekip", "team"],
    ["clinics", "Zincir Klinikler", "clinic"],
    ["settings", "Ayarlar", "cog"],
    ["security", "Güvenlik", "shield"],
  ];

  let main;
  function visibleNavItems() {
    return NAV.filter(([k]) => k !== "clinics" || (S.user && S.user.role === "owner"));
  }

  function openMobileSheet() {
    document.querySelectorAll(".m-more-sheet").forEach((el) => el.remove());
    const curK = (location.hash.replace(/^#\//, "") || "overview").split("?")[0];
    const items = visibleNavItems().filter(([k]) => k !== "sep");
    const closeSheet = () => sheet.remove();
    const sheet = h("div", {
      class: "m-more-sheet",
      role: "dialog",
      "aria-modal": "true",
      "aria-label": "Tüm modüller",
      on: { mousedown: (e) => { if (e.target === sheet) closeSheet(); } },
    },
      h("div", { class: "m-more-panel" },
        h("div", { style: "display:flex;align-items:center;justify-content:space-between;gap:10px" },
          h("strong", { style: "font-size:17px;color:var(--navy)", text: S.clinic || "Modüller" }),
          h("button", { class: "btn btn-sm btn-ghost", type: "button", on: { click: closeSheet } }, "Kapat")
        ),
        h("div", { class: "m-more-grid" }, items.map(([k, t, ic]) =>
          h("a", {
            href: `#/${k}`,
            class: curK === k ? "active" : "",
            on: { click: closeSheet },
          }, icon(ic), h("span", { text: t }))
        ))
      )
    );
    document.body.appendChild(sheet);
  }

  function renderShell() {
    root.replaceChildren();
    const initials = (S.user.full_name || "?").split(" ").map((x) => x[0]).slice(0, 2).join("").toUpperCase();
    main = h("main", { class: "main", id: "panel-main", tabIndex: "-1" });
    const nav = h("nav", { class: "nav", "aria-label": "Ana navigasyon" }, visibleNavItems().map(([k, t, ic]) =>
      k === "sep"
        ? h("div", { class: "sep" })
        : h("a", { href: `#/${k}`, "data-k": k },
            icon(ic),
            t,
            k === "alerts" && S.counts.alerts ? h("span", { class: "count", text: S.counts.alerts }) : null
          )
    ));

    const logoutAction = async () => {
      await run(() => api("/auth/logout", { method: "POST" }));
      S.user = null;
      lsSet("dc_has_session", "");
      renderLogin("Çıkış yapıldı.");
    };

    const mTopbar = h("header", { class: "m-topbar" },
      h("div", { class: "m-topbar-brand" },
        h("img", { src: "/static/favicon.svg", alt: "" }),
        h("div", null, h("strong", { text: "DentaCore" }), h("small", { text: S.clinic }))
      ),
      h("div", { class: "m-topbar-actions" },
        h("button", { class: "btn btn-sm btn-teal", type: "button", on: { click: openAssistant } }, icon("chip"), "Asistan"),
        h("button", { class: "btn btn-sm btn-ghost", type: "button", "aria-label": "Çıkış yap", on: { click: logoutAction } }, icon("out"), "Çıkış")
      )
    );

    const mBottom = h("nav", { class: "m-bottom-nav", "aria-label": "Alt mobil navigasyon" },
      h("a", { href: "#/overview", "data-mk": "overview" }, icon("home"), "Genel"),
      h("a", { href: "#/calendar", "data-mk": "calendar" }, icon("cal"), "Takvim"),
      h("a", { href: "#/messages", "data-mk": "messages" }, icon("msg"), "Mesajlar"),
      h("a", { href: "#/patients", "data-mk": "patients" }, icon("users"), "Hastalar"),
      h("button", { type: "button", "data-mk": "more", on: { click: openMobileSheet } }, icon("menu"), "Diğer")
    );

    const sideAsst = h("button", { class: "btn side-asst", type: "button", on: { click: openAssistant } }, icon("chip"), "Klinik Asistanı (0 Token)");

    root.appendChild(mTopbar);
    root.appendChild(h("div", { class: "shell" },
      h("aside", { class: "side" },
        h("div", { class: "brand" },
          h("img", { src: "/static/favicon.svg", alt: "" }),
          h("div", null, "DentaCore", h("small", { text: S.clinic }))
        ),
        nav,
        sideAsst,
        h("div", { class: "me" },
          h("div", { class: "avatar", text: initials }),
          h("div", { class: "who" }, h("b", { text: S.user.full_name }), h("span", { text: ROLE[S.user.role] || S.user.role })),
          h("button", { type: "button", title: "Çıkış", "aria-label": "Çıkış yap", on: { click: logoutAction } }, icon("out"))
        )
      ),
      main
    ));
    root.appendChild(mBottom);
    route();
  }

  function openAssistant() {
    const out = h("div", { class: "asst-ans", text: "Örnek sorular: 'bugün', 'yarın kaç randevu var', 'kasa özeti', 'kritik stoklar', 'uyarılar'" });
    const qIn = inp("q", { placeholder: "Sorunuzu yazın..." });
    const ov = modal("Klinik Asistanı (0 LLM Token)", [
      h("p", { style: "color:var(--muted);margin-top:0", text: "Takvim, kırmızı bayraklar, stok ve tahsilat verilerini anlık okur." }),
      fld("Soru", qIn),
      out,
    ], async (f) => {
      const r = await api("/app/api/assistant", { method: "POST", body: { question: f.get("q") || "özet" } });
      out.textContent = r.answer || "Yanıt yok.";
      return false;
    }, "Sor");
    const cancelBtn = ov.querySelector(".btn-ghost");
    if (cancelBtn) cancelBtn.textContent = "Kapat";
  }

  function hqSwitchBanner() {
    if (!isHQ() || S.clinic_id === S.home_clinic_id) return null;
    return h("div", { class: "hq-banner", role: "status" },
      h("span", { text: `Merkez dışı şube görünümü aktif: ${S.clinic} (#${S.clinic_id})` }),
      h("button", { class: "btn btn-sm btn-primary", type: "button", on: { click: () => switchClinic(S.home_clinic_id) } }, "Merkeze dön")
    );
  }

  async function switchClinic(cid) {
    const r = await run(() => api(`/app/api/clinics/${cid}/switch`, { method: "POST" }), "Aktif şube değiştirildi");
    if (r && r.ok) await boot();
  }

  function header(title, sub, ...actions) {
    return h("div", { class: "top" },
      h("div", null, h("h1", { text: title }), sub ? h("p", { text: sub }) : null),
      h("div", { class: "actions" }, actions)
    );
  }

  let _activeRouteKey = "";
  function setMain(...nodes) {
    const curK = (location.hash.replace(/^#\//, "") || "overview").split("?")[0];
    if (_activeRouteKey && _activeRouteKey !== curK) return;
    const b = hqSwitchBanner();
    main.replaceChildren(...(b ? [b] : []), ...nodes.filter(Boolean));
  }

  async function route() {
    if (!S.user) return;
    const k = (location.hash.replace(/^#\//, "") || "overview").split("?")[0];
    _activeRouteKey = "";
    document.querySelectorAll(".nav a").forEach((a) => a.classList.toggle("active", a.dataset.k === k));
    document.querySelectorAll(".m-bottom-nav a").forEach((a) => a.classList.toggle("active", a.dataset.mk === k));
    setMain(h("div", { class: "skeleton", role: "status", "aria-label": "Yükleniyor" }), h("div", { class: "empty", text: "Veriler yükleniyor..." }));
    _activeRouteKey = k;
    const v = VIEWS[k] || VIEWS.overview;
    try {
      await v();
    } catch (e) {
      if (e.message !== "oturum") {
        setMain(h("div", { class: "error-card", role: "alert" },
          h("span", { text: `Yükleme hatası: ${e.message}` }),
          h("button", { class: "btn btn-sm btn-primary", type: "button", on: { click: route } }, "Tekrar dene")
        ));
      }
    }
  }
  addEventListener("hashchange", route);

  // ------------------------------------------------------------------ görünümler
  const VIEWS = {};

  VIEWS.overview = async () => {
    const o = await api("/app/api/overview");
    S.counts = o.counts || {};
    const c = S.counts;
    const kpi = (label, value, hint, cls) => h("div", { class: `card kpi ${cls || ""}` },
      h("div", { class: "label", text: label }),
      h("div", { class: "value", text: value }),
      hint ? h("div", { class: "hint", text: hint }) : null
    );
    const occ = h("div", { class: "card kpi" },
      h("div", { class: "label", text: "Bugünkü koltuk doluluğu" }),
      h("div", { class: "value", text: `%${o.today.occupancy}` }),
      h("div", { class: "hint", text: `${o.today.appointments} randevu, ${o.today.confirmed} teyitli` }),
      h("div", { class: "bar" }, h("i", { style: `width:${Math.min(100, o.today.occupancy)}%` }))
    );
    const nameParts = (S.user.full_name || "").trim().split(/\s+/);
    const greetName = nameParts[0] && nameParts[0].endsWith(".") && nameParts[1] ? `${nameParts[0]} ${nameParts[1]}` : (nameParts[0] || "Ekip");
    setMain(
      header(`Günaydın, ${greetName}`, new Date().toLocaleDateString("tr-TR", { weekday: "long", day: "numeric", month: "long" }),
        h("a", { class: "btn btn-cta", href: "#/calendar" }, icon("plus"), "Randevu oluştur")),
      h("div", { class: "grid g4" },
        occ,
        kpi("Son 30 gün gelmeme", `%${o.attendance_30d.noshow_rate}`, `${o.attendance_30d.noshow} gelmeyen / ${o.attendance_30d.done} gelen`),
        kpi("Gelmeyenlerden kayıp", fmtTL(o.loss.noshow_30d_try), `Ortalama işlem ${fmtTL(o.loss.avg_ticket_try)} üzerinden`, "loss"),
        kpi("LLM'siz cevap oranı", o.tokens_30d.llm_free_pct === null ? "-" : `%${o.tokens_30d.llm_free_pct}`, `${o.tokens_30d.replies} otomatik cevap, ${o.tokens_30d.tokens} token`, "good")
      ),
      h("div", { class: "grid g3", style: "margin-top:14px" },
        h("div", { class: "card span-2" },
          h("h3", null, "Son 14 gün: gelen mesaj ve açılan randevu",
            h("div", { class: "legend" },
              h("span", null, h("i", { style: "background:#0F766E" }), "Mesaj"),
              h("span", null, h("i", { style: "background:#0A2540" }), "Randevu")
            )
          ),
          chart(o.series || [])
        ),
        h("div", { class: "card" },
          h("h3", { text: "Bu ay kasa" }),
          h("div", { class: "kv" }, h("span", { text: "Hizmet" }), h("b", { text: fmtTL(o.month.billed_try) }), h("span", { text: "Tahsilat" }), h("b", { text: fmtTL(o.month.paid_try) })),
          h("div", { class: "section-t", text: "Dikkat isteyenler" }),
          h("div", { class: "kv" },
            h("span", { text: "Okunmamış uyarı" }), h("a", { href: "#/alerts", text: String(c.alerts || 0) }),
            h("span", { text: "Bekleme listesi" }), h("a", { href: "#/waitlist", text: String(c.waitlist || 0) }),
            h("span", { text: "Kritik stok" }), h("a", { href: "#/inventory", text: String(c.low_stock || 0) }),
            h("span", { text: "Post-op alarm (7g)" }), h("b", { text: String(c.postop_alarms || 0) }),
            h("span", { text: "Doldurulan koltuk (30g)" }), h("b", { text: String(c.refills || 0) })
          )
        )
      )
    );
    const alertNav = document.querySelector('.nav a[data-k="alerts"]');
    if (alertNav) {
      const badge = alertNav.querySelector(".count");
      if (badge) badge.textContent = c.alerts || "";
      else if (c.alerts) alertNav.appendChild(h("span", { class: "count", text: c.alerts }));
    }
  };

  function chart(series) {
    const W = 640, H = 175, pad = 22, n = series.length || 1;
    const max = Math.max(1, ...series.map((s) => Math.max(s.msgs, s.appts)));
    const svg = document.createElementNS(SVG, "svg");
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    svg.setAttribute("class", "chart");
    svg.setAttribute("preserveAspectRatio", "none");
    svg.setAttribute("aria-label", "Son 14 günlük mesaj ve randevu grafiği");
    const bw = (W - pad * 2) / n;
    const mk = (tagName, attrs) => {
      const e = document.createElementNS(SVG, tagName);
      for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
      svg.appendChild(e);
      return e;
    };
    for (let g = 0; g <= 4; g++) mk("line", { x1: pad, x2: W - pad, y1: pad + (H - pad * 2) * g / 4, y2: pad + (H - pad * 2) * g / 4, stroke: "#DCE4EE" });
    series.forEach((s, i) => {
      const x = pad + i * bw, hm = (H - pad * 2) * s.msgs / max, ha = (H - pad * 2) * s.appts / max;
      mk("rect", { x: x + bw * 0.14, y: H - pad - hm, width: bw * 0.34, height: Math.max(hm, 1), rx: 3, fill: "#0F766E" }).appendChild(titleNode(`${s.day}: ${s.msgs} mesaj`));
      mk("rect", { x: x + bw * 0.52, y: H - pad - ha, width: bw * 0.34, height: Math.max(ha, 1), rx: 3, fill: "#0A2540" }).appendChild(titleNode(`${s.day}: ${s.appts} randevu`));
      if (i % 2 === 0) {
        const t = mk("text", { x: x + bw / 2, y: H - 6, "text-anchor": "middle", "font-size": 10, fill: "#475569" });
        t.textContent = s.day;
      }
    });
    return svg;
  }
  function titleNode(t) { const e = document.createElementNS(SVG, "title"); e.textContent = t; return e; }

  // ---------------- takvim (haftalık + aylık + iPhone/Android/all.ics)
  VIEWS.calendar = async () => {
    const mode = S.calMode === "month" ? "month" : "week";
    let fetchStart, fetchEnd;
    if (mode === "month") {
      const mFirst = new Date(S.day.getFullYear(), S.day.getMonth(), 1);
      fetchStart = monday(mFirst);
      fetchEnd = addDays(fetchStart, 42);
    } else {
      fetchStart = monday(S.day);
      fetchEnd = addDays(fetchStart, 7);
    }
    const list = await api(`/app/api/appointments?start=${encodeURIComponent(fetchStart.toISOString())}&end=${encodeURIComponent(fetchEnd.toISOString())}`);
    const byDay = {};
    list.forEach((a) => {
      const k = ymd(new Date(a.starts_at));
      (byDay[k] = byDay[k] || []).push(a);
    });

    const setMode = (m) => {
      S.calMode = m;
      lsSet("dc_cal_mode", m);
      route();
    };

    let calGridView;
    if (mode === "month") {
      const monthLabel = S.day.toLocaleDateString("tr-TR", { month: "long", year: "numeric" });
      const curMonth = S.day.getMonth();
      const dows = ["Pzt", "Sal", "Çar", "Per", "Cum", "Cmt", "Paz"].map((d) => h("div", { class: "month-dow", text: d }));
      const cells = [...Array(42)].map((_, idx) => {
        const d = addDays(fetchStart, idx);
        const k = ymd(d);
        const dayAppts = (byDay[k] || []).filter((a) => a.status !== "cancelled");
        return h("button", {
          type: "button",
          class: "mcell" + (d.getMonth() !== curMonth ? " out" : "") + (k === ymd(S.day) ? " sel" : ""),
          on: { click: () => { S.day = d; route(); } },
        },
          h("div", { class: "mcell-head" },
            h("span", { text: d.getDate() }),
            dayAppts.length ? h("span", { class: "mcell-cnt", text: dayAppts.length }) : null
          ),
          dayAppts.slice(0, 2).map((a) => h("div", { class: "mcell-item", text: `${fmtT(a.starts_at)} ${a.patient || ""}` }))
        );
      });
      calGridView = h("div", { class: "month-wrap" },
        h("div", { class: "month-title" },
          h("h2", { text: monthLabel.charAt(0).toUpperCase() + monthLabel.slice(1) }),
          h("span", { style: "color:var(--muted);font-size:13px", text: "Günü seçerek randevuları aşağıda yönetin" })
        ),
        h("div", { class: "month-grid" }, dows, cells)
      );
    } else {
      const wk = monday(S.day);
      calGridView = h("div", { class: "week" }, [...Array(7)].map((_, i) => {
        const d = addDays(wk, i), k = ymd(d);
        const n = (byDay[k] || []).filter((a) => a.status !== "cancelled").length;
        return h("button", {
          type: "button",
          class: "day" + (k === ymd(S.day) ? " sel" : ""),
          on: { click: () => { S.day = d; route(); } },
        },
          n ? h("span", { class: "n", text: n }) : null,
          h("b", { text: d.toLocaleDateString("tr-TR", { day: "numeric", month: "short" }) }),
          h("span", { text: d.toLocaleDateString("tr-TR", { weekday: "long" }) })
        );
      }));
    }

    const today = (byDay[ymd(S.day)] || []);
    const act = (a, status, label, cls) => h("button", {
      type: "button",
      class: `btn btn-sm ${cls || "btn-ghost"}`,
      on: {
        click: async () => {
          if (status === "cancelled" && !confirm("Randevu iptal edilsin ve boş koltuk bekleme listesine teklif edilsin mi?")) return;
          const r = await run(() => api(`/app/api/appointments/${a.id}/status`, { method: "POST", body: { status } }), "Randevu durumu güncellendi");
          if (r && r.waitlist_offers !== undefined) toast(`Bekleme listesinden ${r.waitlist_offers} hastaya teklif gönderildi`);
          route();
        },
      },
    }, label);

    const shiftDate = (dir) => {
      if (mode === "month") S.day = new Date(S.day.getFullYear(), S.day.getMonth() + dir, 1);
      else S.day = addDays(S.day, dir * 7);
      route();
    };

    setMain(
      header("Takvim", "Koltuk çakışması sunucuda engellenir; randevular iPhone (Apple Takvim) ve Android (Google Takvim) ile senkronize olur.",
        h("button", { class: `btn ${mode === "week" ? "btn-primary" : "btn-ghost"}`, type: "button", on: { click: () => setMode("week") } }, "Hafta"),
        h("button", { class: `btn ${mode === "month" ? "btn-primary" : "btn-ghost"}`, type: "button", on: { click: () => setMode("month") } }, "Ay"),
        h("button", { class: "btn btn-ghost", type: "button", on: { click: () => shiftDate(-1) } }, mode === "month" ? "Önceki ay" : "Önceki hafta"),
        h("button", { class: "btn btn-ghost", type: "button", on: { click: () => { S.day = sod(new Date()); route(); } } }, "Bugün"),
        h("button", { class: "btn btn-ghost", type: "button", on: { click: () => shiftDate(1) } }, mode === "month" ? "Sonraki ay" : "Sonraki hafta"),
        h("button", { class: "btn btn-teal", type: "button", on: { click: showPhoneCalModal } }, "Telefon Takvimine Bağla"),
        h("a", { class: "btn btn-ghost", href: "/app/api/calendar/all.ics", download: "dentacore-takvim.ics" }, "Tümünü .ics İndir"),
        h("button", { class: "btn btn-cta", type: "button", on: { click: newAppt } }, icon("plus"), "Yeni randevu")
      ),
      calGridView,
      h("h2", { style: "font-size:17px;color:var(--navy);margin:0 0 10px", text: `${fmtD(S.day)} Randevuları (${today.length})` }),
      today.length ? h("div", null, today.map((a) => {
        const [st, cls] = STATUS[a.status] || [a.status, ""];
        const end = new Date(new Date(a.starts_at).getTime() + a.duration_min * 60000);
        const live = a.status === "booked" || a.status === "confirmed";
        return h("div", { class: `slot ${a.status}` },
          h("div", { class: "t" }, fmtT(a.starts_at), h("small", { text: `${fmtT(end)} · K${a.chair}` })),
          h("div", { class: "p" },
            h("b", { text: a.patient || "İsimsiz hasta" }), " ",
            a.red_flag ? tag("Kırmızı bayrak", "red") : null,
            h("div", { text: `${a.treatment}${a.doctor ? " · " + a.doctor : ""}${a.source !== "panel" ? " · " + a.source : ""}` })
          ),
          h("div", { class: "actions" },
            tag(st, cls),
            live && a.status === "booked" ? act(a, "confirmed", "Teyit") : null,
            live ? act(a, "done", "Geldi") : null,
            live ? act(a, "noshow", "Gelmedi", "btn-danger") : null,
            live ? act(a, "cancelled", "İptal", "btn-danger") : null,
            h("a", { class: "btn btn-sm btn-ghost", href: `/app/api/appointments/${a.id}/ics`, download: `randevu-${a.id}.ics` }, "+ iPhone (.ics)"),
            a.google_cal_url ? h("a", { class: "btn btn-sm btn-ghost", href: a.google_cal_url, target: "_blank", rel: "noopener noreferrer" }, "+ Android / Google") : null,
            a.patient_id ? h("button", { class: "btn btn-sm btn-ghost", type: "button", on: { click: () => openPatient(a.patient_id) } }, "Hasta") : null
          )
        );
      })) : h("div", { class: "card empty", text: "Bu gün için randevu yok. Yeni randevu düğmesiyle ekleyebilirsiniz." })
    );
  };

  async function showPhoneCalModal() {
    const lk = await run(() => api("/app/api/calendar-links"));
    if (!lk) return;
    const ov = modal("iPhone & Android Canlı Takvim Senkronizasyonu", [
      h("div", { class: "cal-box" },
        h("b", { text: "iPhone (Apple Takvim - Otomatik Abonelik)" }),
        h("p", { style: "margin:4px 0;font-size:13.5px;color:var(--ink-2)", text: lk.iphone_guide }),
        h("code", { text: lk.webcal_url }),
        h("div", { class: "actions" },
          h("a", { class: "btn btn-sm btn-primary", href: lk.webcal_url }, "iPhone'da Abone Ol"),
          h("button", { class: "btn btn-sm btn-ghost", type: "button", on: { click: () => copyText(lk.webcal_url, "iPhone webcal bağlantısı kopyalandı") } }, "webcal Kopyala")
        )
      ),
      h("div", { class: "cal-box" },
        h("b", { text: "Android / Google Takvim (Otomatik Abonelik)" }),
        h("p", { style: "margin:4px 0;font-size:13.5px;color:var(--ink-2)", text: lk.android_guide }),
        lk.google_subscribe_url ? h("code", { text: lk.google_subscribe_url }) : null,
        h("div", { class: "actions" },
          lk.google_subscribe_url ? h("a", { class: "btn btn-sm btn-cta", href: lk.google_subscribe_url, target: "_blank", rel: "noopener noreferrer" }, "Google Takvime Abone Ol") : null,
          lk.google_subscribe_url ? h("button", { class: "btn btn-sm btn-ghost", type: "button", on: { click: () => copyText(lk.google_subscribe_url, "Google Takvim bağlantısı kopyalandı") } }, "Google Link Kopyala") : null
        )
      ),
      h("div", { class: "cal-box" },
        h("b", { text: "Tüm Takvimi .ics Olarak İndir / Akış Adresi" }),
        h("code", { text: lk.ics_url }),
        h("div", { class: "actions" },
          h("a", { class: "btn btn-sm btn-teal", href: "/app/api/calendar/all.ics", download: "dentacore-takvim.ics" }, "Tümünü .ics İndir"),
          h("button", { class: "btn btn-sm btn-ghost", type: "button", on: { click: () => copyText(lk.ics_url, ".ics akış adresi kopyalandı") } }, ".ics Link Kopyala")
        )
      ),
    ], async () => true, "Tamam");
    const footCancel = ov.querySelector(".foot .btn-ghost");
    if (footCancel) footCancel.remove();
  }

  async function newAppt() {
    const patients = await api("/app/api/patients");
    const staff = await api("/app/api/staff");
    const doctors = staff.filter((s) => s.active && (s.role === "doctor" || s.role === "owner"));
    const newBox = h("div", { class: "row" }, fld("Telefon", inp("phone", { placeholder: "05xx xxx xx xx" })), fld("Ad Soyad", inp("name")));
    const pSel = sel("patient_id", [["", "+ Yeni hasta"], ...patients.map((p) => [String(p.id), p.display_name || `Hasta #${p.id}`])], patients[0] ? String(patients[0].id) : "");
    const toggle = () => newBox.classList.toggle("hidden", pSel.value !== "");
    pSel.addEventListener("change", toggle);
    toggle();
    modal("Yeni randevu", [
      fld("Hasta", pSel),
      newBox,
      h("div", { class: "row" }, fld("Tarih", inp("date", { type: "date", required: true, value: ymd(S.day) })), fld("Saat", inp("time", { type: "time", required: true, value: "10:00", step: 300 }))),
      h("div", { class: "row" }, fld("Süre (dk)", inp("duration", { type: "number", min: 5, max: 480, value: 30, required: true })), fld("Koltuk", inp("chair", { value: "1", required: true, maxLength: 10 }))),
      fld("İşlem", inp("treatment", { required: true, minLength: 2, maxLength: 80, placeholder: "Muayene, implant, dolgu..." })),
      fld("Hekim", sel("doctor_id", [["", "Seçilmedi"], ...doctors.map((d) => [String(d.id), d.full_name])], "")),
    ], async (f) => {
      const body = {
        starts_at: new Date(`${f.get("date")}T${f.get("time")}`).toISOString(),
        duration_min: Number(f.get("duration")),
        treatment: f.get("treatment"),
        chair: f.get("chair"),
        doctor_id: f.get("doctor_id") ? Number(f.get("doctor_id")) : null,
      };
      if (f.get("patient_id")) body.patient_id = Number(f.get("patient_id"));
      else { body.phone = f.get("phone"); body.name = f.get("name"); }
      await api("/app/api/appointments", { method: "POST", body });
      toast("Randevu oluşturuldu");
      S.day = sod(new Date(body.starts_at));
      route();
    }, "Randevu oluştur");
  }

  // ---------------- hastalar (16 dil)
  VIEWS.patients = async () => {
    const q = new URLSearchParams(location.hash.split("?")[1] || "").get("q") || "";
    const rows = await api(`/app/api/patients?search=${encodeURIComponent(q)}`);
    const search = inp("q", { class: "input search", placeholder: "Ad veya telefon ile ara", value: q, "aria-label": "Hasta ara" });
    const doSearch = () => { location.hash = `#/patients?q=${encodeURIComponent(search.value)}`; };
    search.addEventListener("keydown", (e) => { if (e.key === "Enter") doSearch(); });
    setMain(
      header("Hastalar", "Telefon numaraları şifreli saklanır; tam numarayı görmek denetim kaydına yazılır.",
        search,
        h("button", { class: "btn btn-ghost", type: "button", on: { click: doSearch } }, "Ara"),
        h("button", {
          class: "btn btn-cta",
          type: "button",
          on: {
            click: () => modal("Yeni hasta", [
              fld("Ad Soyad", inp("name", { required: true, minLength: 2 })),
              fld("Telefon", inp("phone", { required: true, placeholder: "05xx xxx xx xx" })),
              fld("İletişim dili (16 dil)", sel("lang", LANG_OPTIONS, "tr")),
            ], async (f) => {
              const r = await api("/app/api/patients", { method: "POST", body: { name: f.get("name"), phone: f.get("phone"), lang: f.get("lang") } });
              toast("Hasta kaydedildi");
              route();
              openPatient(r.id);
            }),
          },
        }, icon("plus"), "Hasta ekle")
      ),
      h("div", { class: "card card-flush" }, tblWrap(h("table", { class: "table" },
        h("thead", null, h("tr", null, ["Hasta", "Kanal", "Dil", "Son randevu", "Bakiye", ""].map((t, i) => h("th", { class: i === 4 ? "num" : "", text: t })))),
        h("tbody", null, rows.length ? rows.map((p) => h("tr", { class: "click", on: { click: () => openPatient(p.id) } },
          h("td", null, h("b", { text: p.display_name || `Hasta #${p.id}` }), " ", p.red_flag ? tag("Kırmızı bayrak", "red") : null),
          h("td", null, tag(p.channel === "ig" ? "Instagram" : "WhatsApp", p.channel === "ig" ? "amber" : "teal")),
          h("td", { text: (p.lang || "tr").toUpperCase() }),
          h("td", { text: p.last_appt ? fmtD(p.last_appt) : "-" }),
          h("td", { class: "num" }, p.balance > 0 ? h("b", { style: "color:var(--amber-hover)", text: fmtTL(p.balance) }) : fmtTL(p.balance)),
          h("td", null, h("button", { class: "btn btn-sm btn-ghost", type: "button", "aria-label": `${p.display_name || "Hasta"} kartını aç`, on: { click: (ev) => { ev.stopPropagation(); openPatient(p.id); } } }, "Aç"))
        )) : h("tr", null, h("td", { colSpan: 6, class: "empty", text: "Hasta kaydı bulunamadı." })))
      )))
    );
  };

  async function openPatient(pid, reveal) {
    document.querySelectorAll(".drawer-wrap").forEach((el) => el.remove());
    const [p, odo] = await Promise.all([
      run(() => api(`/app/api/patients/${pid}${reveal ? "?reveal=true" : ""}`)),
      api(`/app/api/patients/${pid}/odontogram`).catch(() => ({ records: [], summary: {} })),
    ]);
    if (!p) return;
    const onEsc = (ev) => {
      if (ev.key !== "Escape") return;
      if (document.querySelector(".modal")) return;
      close();
    };
    const close = () => { document.removeEventListener("keydown", onEsc); wrap.remove(); };
    document.addEventListener("keydown", onEsc);

    const consentNames = { kvkk_aydinlatma: "KVKK aydınlatma", saglik_verisi_acik_riza: "Sağlık verisi açık rıza", iletisim: "İletişim izni", yurt_disi_aktarim: "Yurt dışı aktarım" };
    const ledger = [...p.charges.map((c) => ({ ...c, t: "Hizmet", info: c.description })), ...p.payments.map((c) => ({ ...c, t: "Tahsilat", info: c.method }))]
      .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    const genIdem = (prefix) => `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;

    // --- FDI Odontogram (32 Daimi Diş 11-48 + 20 Süt Dişi 51-85, 5 Yüzey M/D/O/B/L) ---
    const ODO_STATUS_META = {
      healthy: ["Sağlıklı", "#0F766E"],
      caries: ["Çürük", "#B91C1C"],
      planned: ["Planlanan", "#C2410C"],
      treated: ["Tedavi Edildi", "#15803D"],
      implant: ["İmplant", "#0A2540"],
      crown: ["Zirkonyum / Kron", "#0D9488"],
      root_canal: ["Kanal Tedavisi", "#854D0E"],
      extraction: ["Çekim Planı", "#9A3412"],
      missing: ["Eksik Diş", "#64748B"],
    };
    const odoByTooth = {};
    (odo.records || []).forEach((r) => {
      (odoByTooth[r.tooth_fdi] = odoByTooth[r.tooth_fdi] || []).push(r);
    });

    function openToothModal(fdiNum, preSurface) {
      const existing = odoByTooth[fdiNum] || [];
      const idemKey = genIdem("odo");
      modal(`Diş #${fdiNum} (FDI) · Klinik İşlem & Yüzey Kaydı`, [
        existing.length ? h("div", { class: "cal-box" },
          h("b", { text: `Diş #${fdiNum} Mevcut Kayıtlar (${existing.length})` }),
          existing.map((er) => h("div", { style: "display:flex;justify-content:space-between;align-items:center;gap:8px;margin-top:6px;font-size:13px" },
            h("span", { text: `[${er.surface}] ${er.procedure_name} (${(ODO_STATUS_META[er.status] || [er.status])[0]}) · ${fmtTL(er.amount_try || 0)}` }),
            S.user.role !== "secretary" ? h("button", {
              class: "btn btn-sm btn-danger",
              type: "button",
              on: {
                click: async () => {
                  await run(() => api(`/app/api/patients/${pid}/odontogram/${er.id}`, { method: "DELETE" }), "Diş kaydı silindi");
                  document.querySelectorAll(".overlay .modal").forEach((m) => m.closest(".overlay")?.remove());
                  openPatient(pid, reveal);
                },
              },
            }, "Sil") : null
          ))
        ) : null,
        h("div", { class: "row" },
          fld("Diş Yüzeyi (5 Yüzey)", sel("surface", [
            ["FULL", "Tüm Diş (FULL)"],
            ["O", "Oklüzal / İnsizal (O)"],
            ["M", "Mezial (M)"],
            ["D", "Distal (D)"],
            ["B", "Bukkal / Vestibül (B)"],
            ["L", "Lingual / Palatinal (L)"],
          ], preSurface || "FULL")),
          fld("Klinik Durum", sel("status", Object.entries(ODO_STATUS_META).map(([k, [lbl]]) => [k, lbl]), "planned"))
        ),
        fld("İşlem / Tedavi Adı", inp("procedure_name", { required: true, minLength: 2, placeholder: "Kompozit Dolgu, İmplant, Zirkonyum Kron..." })),
        h("div", { class: "row" },
          fld("İşlem Kodu (Opsiyonel)", inp("procedure_code", { placeholder: "FDI-204" })),
          fld("Tutar (TL)", inp("amount", { type: "number", step: "0.01", min: "0", value: "0" }))
        ),
        fld("Klinik Not", inp("note", { placeholder: "Periapikal lezyon izlendi..." })),
        h("label", { class: "odo-check-row" },
          h("input", { type: "checkbox", name: "auto_charge", value: "1", checked: true }),
          h("span", { text: "Tutar > 0 ise kasaya otomatik hizmet borcu olarak aktar" })
        ),
      ], async (f) => {
        await api(`/app/api/patients/${pid}/odontogram`, {
          method: "POST",
          body: {
            tooth_fdi: fdiNum,
            surface: f.get("surface"),
            status: f.get("status"),
            procedure_code: f.get("procedure_code") || "",
            procedure_name: f.get("procedure_name"),
            amount: f.get("amount") || "0",
            note: f.get("note") || "",
            auto_charge: f.get("auto_charge") === "1",
            idempotency_key: idemKey,
          },
        });
        toast(`Diş #${fdiNum} işlemi kaydedildi`);
        openPatient(pid, reveal);
      }, "Kaydet");
    }

    function renderToothButton(fdiNum) {
      const recs = odoByTooth[fdiNum] || [];
      const topRec = recs[0];
      const stColor = topRec ? (ODO_STATUS_META[topRec.status] || ["", "#0F766E"])[1] : "#CBD5E1";
      const surfMap = {};
      recs.forEach((r) => { surfMap[r.surface] = (ODO_STATUS_META[r.status] || ["", "#0F766E"])[1]; });
      const fullCol = surfMap.FULL || "";

      const svg = document.createElementNS(SVG, "svg");
      svg.setAttribute("viewBox", "0 0 36 36");
      svg.setAttribute("class", "odo-svg");
      svg.setAttribute("aria-hidden", "true");

      const addSurf = (tagN, attrs, sCode) => {
        const el = document.createElementNS(SVG, tagN);
        for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
        el.setAttribute("fill", surfMap[sCode] || fullCol || "#F8FAFC");
        el.setAttribute("stroke", recs.length ? stColor : "#64748B");
        el.setAttribute("stroke-width", "1.4");
        svg.appendChild(el);
      };
      // 5 yüzey: Üst(B), Alt(L), Sol(M), Sağ(D), Merkez(O)
      addSurf("polygon", { points: "3,3 33,3 24,12 12,12" }, "B");
      addSurf("polygon", { points: "3,33 33,33 24,24 12,24" }, "L");
      addSurf("polygon", { points: "3,3 12,12 12,24 3,33" }, "M");
      addSurf("polygon", { points: "33,3 24,12 24,24 33,33" }, "D");
      addSurf("rect", { x: "12", y: "12", width: "12", height: "12", rx: "2" }, "O");

      return h("button", {
        type: "button",
        class: "odo-tooth" + (recs.length ? " has-rec" : ""),
        "data-tooth": String(fdiNum),
        title: recs.length ? `Diş #${fdiNum}: ${recs.map((x) => `${x.surface} ${x.procedure_name}`).join(", ")}` : `Diş #${fdiNum} işlem ekle`,
        on: { click: () => openToothModal(fdiNum, "FULL") },
      },
        svg,
        h("span", { class: "odo-num", text: String(fdiNum) })
      );
    }

    const permUpper = [18, 17, 16, 15, 14, 13, 12, 11, 21, 22, 23, 24, 25, 26, 27, 28];
    const permLower = [48, 47, 46, 45, 44, 43, 42, 41, 31, 32, 33, 34, 35, 36, 37, 38];
    const pedoUpper = [55, 54, 53, 52, 51, 61, 62, 63, 64, 65];
    const pedoLower = [85, 84, 83, 82, 81, 71, 72, 73, 74, 75];

    const permGrid = h("div", { class: "odo-arch-wrap" },
      h("div", { class: "odo-row" }, permUpper.map(renderToothButton)),
      h("div", { class: "odo-row" }, permLower.map(renderToothButton))
    );
    const pedoGrid = h("div", { class: "odo-arch-wrap hidden" },
      h("div", { class: "odo-row odo-pedo" }, pedoUpper.map(renderToothButton)),
      h("div", { class: "odo-row odo-pedo" }, pedoLower.map(renderToothButton))
    );

    const btnPerm = h("button", {
      type: "button",
      class: "btn btn-sm btn-primary",
      on: {
        click: () => {
          permGrid.classList.remove("hidden");
          pedoGrid.classList.add("hidden");
          btnPerm.className = "btn btn-sm btn-primary";
          btnPedo.className = "btn btn-sm btn-ghost";
        },
      },
    }, "Erişkin (11–48)");
    const btnPedo = h("button", {
      type: "button",
      class: "btn btn-sm btn-ghost",
      on: {
        click: () => {
          pedoGrid.classList.remove("hidden");
          permGrid.classList.add("hidden");
          btnPedo.className = "btn btn-sm btn-primary";
          btnPerm.className = "btn btn-sm btn-ghost";
        },
      },
    }, "Süt Dişi / Pedodonti (51–85)");

    const odoSection = h("div", { class: "odo-box", id: "patient-odontogram" },
      h("div", { class: "odo-head" },
        h("div", null,
          h("strong", { text: "FDI İnteraktif Odontogram (5 Yüzey M/D/O/B/L)" }),
          h("small", { text: `Toplam ${odo.summary?.total_records || 0} diş kaydı · Dişe tıklayarak yüzey ve işlem girin` })
        ),
        h("div", { class: "actions" }, btnPerm, btnPedo)
      ),
      permGrid,
      pedoGrid
    );

    const drawer = h("div", { class: "drawer", role: "dialog", "aria-modal": "true", "aria-label": p.name || `Hasta #${p.id}` },
      h("div", { class: "top" },
        h("div", null,
          h("h2", { text: p.name || `Hasta #${p.id}` }),
          h("p", { text: `#${p.id} · ${p.channel === "ig" ? "Instagram" : "WhatsApp"} · ${(p.lang || "tr").toUpperCase()}${p.active === false ? " · ARŞİVLİ" : ""}` })
        ),
        h("div", { class: "actions" },
          S.user.role !== "secretary" ? h("button", {
            class: "btn btn-sm btn-ghost",
            type: "button",
            on: {
              click: async () => {
                const ep = p.active === false ? "unarchive" : "archive";
                await run(() => api(`/app/api/patients/${pid}/${ep}`, { method: "POST" }), p.active === false ? "Hasta aktifleştirildi" : "Hasta arşivlendi");
                close();
                route();
              },
            },
          }, p.active === false ? "Aktifleştir" : "Arşivle") : null,
          h("button", { class: "btn btn-ghost btn-sm", type: "button", on: { click: close } }, "Kapat")
        )
      ),
      h("div", { class: "kv" },
        h("span", { text: "Telefon" }),
        h("div", null, h("b", { class: "mono", text: p.phone }), " ", !reveal && p.channel !== "ig" ? h("button", { class: "btn btn-sm btn-ghost", type: "button", on: { click: () => openPatient(pid, true) } }, "Göster") : null),
        h("span", { text: "Bakiye" }),
        h("b", { style: p.balance > 0 ? "color:var(--amber-hover)" : "", text: fmtTL(p.balance) })
      ),
      h("div", { class: "actions" },
        h("button", {
          class: "btn btn-sm btn-primary",
          type: "button",
          on: {
            click: () => {
              const chgIdem = genIdem("chg");
              modal("Hizmet ekle", [
                fld("Açıklama", inp("description", { required: true, minLength: 2, placeholder: "Zirkonyum kron x2" })),
                fld("Tutar (TL)", inp("amount", { type: "number", step: "0.01", min: "0.01", required: true })),
              ], async (f) => {
                await api("/app/api/charges", {
                  method: "POST",
                  body: { patient_id: pid, description: f.get("description"), amount: f.get("amount"), idempotency_key: chgIdem },
                });
                toast("Hizmet eklendi");
                openPatient(pid, reveal);
              });
            },
          },
        }, "Hizmet ekle"),
        h("button", {
          class: "btn btn-sm btn-cta",
          type: "button",
          on: {
            click: () => {
              const payIdem = genIdem("pay");
              const amtIn = inp("amount", { type: "number", step: "0.01", min: "0.01", required: true, value: p.balance > 0 ? p.balance : "" });
              const advCheck = h("input", { type: "checkbox", name: "allow_advance", value: "1", checked: p.balance <= 0 });
              const advBox = h("label", { class: "odo-check-row" },
                advCheck,
                h("span", { text: `Bakiye üstü / Avans (Ön Ödeme) tahsilatı olarak onayla (Açık bakiye: ${fmtTL(Math.max(0, p.balance))})` })
              );
              modal("Tahsilat al", [
                fld("Tutar (TL)", amtIn),
                fld("Yöntem", sel("method", [["kart", "Kart"], ["nakit", "Nakit"], ["havale", "Havale/EFT"], ["diger", "Diğer"]], "kart")),
                advBox,
              ], async (f) => {
                await api("/app/api/payments", {
                  method: "POST",
                  body: {
                    patient_id: pid,
                    amount: f.get("amount"),
                    method: f.get("method"),
                    idempotency_key: payIdem,
                    allow_advance: f.get("allow_advance") === "1",
                  },
                });
                toast("Tahsilat kaydedildi");
                openPatient(pid, reveal);
              });
            },
          },
        }, "Tahsilat al"),
        h("button", {
          class: "btn btn-sm btn-ghost",
          type: "button",
          on: {
            click: async () => {
              const r = await run(() => api(`/app/api/patients/${pid}/anamnesis`, { method: "POST" }), "Anamnez formu oluşturuldu");
              if (r) openPatient(pid, reveal);
            },
          },
        }, "Anamnez gönder"),
        h("button", {
          class: "btn btn-sm btn-ghost",
          type: "button",
          on: {
            click: () => modal("Bekleme listesine ekle", [fld("İşlem", inp("treatment", { value: "herhangi", required: true }))], async (f) => {
              await api("/app/api/waitlist", { method: "POST", body: { patient_id: pid, treatment: f.get("treatment") } });
              toast("Bekleme listesine eklendi");
            }),
          },
        }, "Bekleme listesi")
      ),
      odoSection,
      h("div", { class: "section-t", text: "Anamnez" }),
      p.anamnesis.length ? p.anamnesis.map((a) => h("div", { class: "alert-item" },
        h("div", { class: "k" }, a.red_flags.length ? tag(`${a.red_flags.length} kırmızı bayrak`, "red") : tag("Temiz", "green")),
        h("div", { class: "d" }, a.red_flags.join(", ") || "Risk işareti yok", h("small", { text: fmtDT(a.signed_at) })),
        p.anamnesis_links && p.anamnesis_links[a.id] ? h("a", { class: "btn btn-sm btn-ghost", href: p.anamnesis_links[a.id], target: "_blank", rel: "noopener noreferrer" }, "Aç") : null
      )) : h("div", { class: "empty", text: "Henüz anamnez yok." }),
      h("div", { class: "section-t", text: "Onamlar (KVKK)" }),
      p.consents.length ? p.consents.map((c) => h("div", { class: "alert-item" },
        h("div", { class: "d" }, consentNames[c.kind] || c.kind, h("small", { text: `Sürüm ${c.text_version} · ${fmtDT(c.granted_at)}` })),
        c.revoked_at ? tag("Geri alındı", "red") : tag("Geçerli", "green")
      )) : h("div", { class: "empty", text: "Onam kaydı yok." }),
      h("div", { class: "section-t", text: "Randevular" }),
      p.appointments.length ? tblWrap(h("table", { class: "table" }, h("tbody", null, p.appointments.map((a) =>
        h("tr", null, h("td", { text: fmtDT(a.starts_at) }), h("td", { text: a.treatment }), h("td", null, tag(...(STATUS[a.status] || [a.status, ""]))))
      )))) : h("div", { class: "empty", text: "Randevu yok." }),
      h("div", { class: "section-t", text: "Hesap hareketleri" }),
      ledger.length ? tblWrap(h("table", { class: "table" }, h("tbody", null, ledger.map((e) =>
        h("tr", { style: e.voided_at ? "opacity:.45;text-decoration:line-through" : "" },
          h("td", { text: fmtD(e.created_at) }),
          h("td", { text: `${e.t}: ${e.info}` }),
          h("td", { class: "num", text: (e.t === "Tahsilat" ? "-" : "") + fmtTL(e.amount) })
        )
      )))) : h("div", { class: "empty", text: "Hareket yok." })
    );
    const wrap = h("div", { class: "drawer-wrap" },
      h("div", { class: "overlay", on: { click: close } }),
      drawer
    );
    document.body.appendChild(wrap);
    const closeBtn = drawer.querySelector("button");
    if (closeBtn) closeBtn.focus();
  }

  // ---------------- bekleme listesi
  VIEWS.waitlist = async () => {
    const rows = await api("/app/api/waitlist");
    setMain(
      header("Bekleme Listesi", "Randevu iptal edildiğinde listedeki hastalara 3 dakikalık dalgalarla teklif gider; ilk onay veren koltuğu alır."),
      h("div", { class: "card card-flush" }, tblWrap(h("table", { class: "table" },
        h("thead", null, h("tr", null, ["Sıra", "Hasta", "İşlem", "Eklenme", ""].map((t) => h("th", { text: t })))),
        h("tbody", null, rows.length ? rows.map((w, i) => h("tr", null,
          h("td", { text: i + 1 }),
          h("td", null, h("a", { href: "#", on: { click: (e) => { e.preventDefault(); openPatient(w.patient_id); } }, text: w.patient || `Hasta #${w.patient_id}` })),
          h("td", { text: w.treatment }),
          h("td", { text: fmtDT(w.created_at) }),
          h("td", null, h("button", { class: "btn btn-sm btn-danger", type: "button", on: { click: async () => { await run(() => api(`/app/api/waitlist/${w.id}/remove`, { method: "POST" }), "Listeden çıkarıldı"); route(); } } }, "Çıkar"))
        )) : h("tr", null, h("td", { colSpan: 5, class: "empty", text: "Bekleme listesi boş. Hasta kartından ekleyebilirsiniz." })))
      )))
    );
  };

  // ---------------- uyarılar
  const ALERT = {
    acil: ["Acil", "red"],
    postop_alarm: ["Post-op alarm", "red"],
    anamnez_kirmizi: ["Kırmızı bayrak", "red"],
    sikayet: ["Şikayet", "amber"],
    geri_bildirim: ["Geri bildirim", "amber"],
    koltuk_dolduruldu: ["Koltuk dolduruldu", "green"],
    gorsel_alindi: ["Görsel", "teal"],
    stok_kritik: ["Stok", "yellow"],
    web_talep: ["Web talebi", "teal"],
  };
  VIEWS.alerts = async () => {
    const rows = await api("/app/api/alerts");
    setMain(
      header("Uyarılar", "Acil durumlar, kırmızı bayraklı anamnezler, işlem sonrası alarmlar ve sistem olayları."),
      h("div", { class: "card" }, rows.length ? rows.map((a) => {
        const [t, c] = ALERT[a.kind] || [a.kind, ""];
        return h("div", { class: "alert-item" },
          h("div", { class: "k" }, tag(t, c)),
          h("div", { class: "d" }, a.detail, h("small", { text: fmtDT(a.created_at) })),
          a.patient_id ? h("button", { class: "btn btn-sm btn-ghost", type: "button", on: { click: () => openPatient(a.patient_id) } }, "Hasta") : null,
          h("button", { class: "btn btn-sm btn-primary", type: "button", on: { click: async () => { await run(() => api(`/app/api/alerts/${a.id}/ack`, { method: "POST" })); route(); } } }, "Okundu")
        );
      }) : h("div", { class: "empty", text: "Okunmamış uyarı yok." }))
    );
  };

  // ---------------- envanter
  VIEWS.inventory = async () => {
    const rows = await api("/app/api/inventory");
    const total = rows.reduce((s, r) => s + Number(r.value || 0), 0);
    setMain(
      header("Envanter", `Stok değeri: ${fmtTL(total)} · Kritik seviyeye inen ürün için otomatik uyarı oluşur.`,
        h("button", {
          class: "btn btn-cta",
          type: "button",
          on: {
            click: () => modal("Ürün ekle", [
              fld("Ürün adı", inp("name", { required: true, minLength: 2, placeholder: "Kompozit A2" })),
              h("div", { class: "row" }, fld("Stok kodu", inp("sku")), fld("Birim", inp("unit", { value: "adet" }))),
              h("div", { class: "row" }, fld("Mevcut miktar", inp("qty", { type: "number", step: "0.01", min: 0, value: 0 })), fld("Alt sınır", inp("min_qty", { type: "number", step: "0.01", min: 0, value: 0 }))),
              fld("Birim maliyet (TL)", inp("unit_cost", { type: "number", step: "0.01", min: 0, value: 0 })),
            ], async (f) => {
              await api("/app/api/inventory", { method: "POST", body: Object.fromEntries(f) });
              toast("Ürün eklendi");
              route();
            }),
          },
        }, icon("plus"), "Ürün ekle")
      ),
      h("div", { class: "card card-flush" }, tblWrap(h("table", { class: "table" },
        h("thead", null, h("tr", null, ["Ürün", "Stok", "Alt sınır", "Birim maliyet", "Değer", ""].map((t, i) => h("th", { class: i && i < 5 ? "num" : "", text: t })))),
        h("tbody", null, rows.length ? rows.map((r) => h("tr", null,
          h("td", null, h("b", { text: r.name }), r.sku ? h("span", { class: "mono", style: "color:var(--muted)", text: `  ${r.sku}` }) : null, " ", r.low ? tag("Kritik", "red") : null),
          h("td", { class: "num", text: `${Number(r.qty)} ${r.unit}` }),
          h("td", { class: "num", text: Number(r.min_qty) }),
          h("td", { class: "num", text: fmtTL(r.unit_cost) }),
          h("td", { class: "num", text: fmtTL(r.value) }),
          h("td", null, h("div", { class: "actions" },
            h("button", { class: "btn btn-sm btn-ghost", type: "button", on: { click: () => moveItem(r, 1) } }, "Giriş"),
            h("button", { class: "btn btn-sm btn-ghost", type: "button", on: { click: () => moveItem(r, -1) } }, "Çıkış"),
            h("button", { class: "btn btn-sm btn-ghost", type: "button", on: { click: () => itemHistory(r) } }, "Geçmiş")
          ))
        )) : h("tr", null, h("td", { colSpan: 6, class: "empty", text: "Henüz ürün yok." })))
      )))
    );
  };

  function moveItem(r, sign) {
    modal(`${r.name}: stok ${sign > 0 ? "girişi" : "çıkışı"}`, [
      fld(`Miktar (${r.unit})`, inp("qty", { type: "number", step: "0.01", min: "0.01", required: true })),
      fld("Açıklama", inp("reason", { required: true, minLength: 2, value: sign > 0 ? "Satın alma" : "Kullanım" })),
    ], async (f) => {
      await api(`/app/api/inventory/${r.id}/move`, { method: "POST", body: { delta: String(sign * Number(f.get("qty"))), reason: f.get("reason") } });
      toast("Stok güncellendi");
      route();
    });
  }

  async function itemHistory(r) {
    const rows = await run(() => api(`/app/api/inventory/${r.id}/moves`));
    if (!rows) return;
    const ov = modal(`${r.name}: hareket geçmişi`, [tblWrap(h("table", { class: "table" },
      h("tbody", null, rows.length ? rows.map((m) => h("tr", null,
        h("td", { text: fmtDT(m.created_at) }),
        h("td", { class: "num", style: `color:${Number(m.delta) < 0 ? "var(--red)" : "var(--green)"}`, text: (Number(m.delta) > 0 ? "+" : "") + Number(m.delta) }),
        h("td", { class: "num", text: Number(m.qty_after) }),
        h("td", { text: `${m.reason}${m.actor ? " · " + m.actor : ""}` })
      )) : h("tr", null, h("td", { class: "empty", text: "Hareket yok." })))
    ))], async () => true, "Kapat");
    ov.querySelector(".foot .btn-ghost").remove();
  }

  // ---------------- kasa
  const RANGES = { bugun: "Bugün", hafta: "Bu hafta", ay: "Bu ay", gecen: "Geçen ay" };
  function range(k) {
    const t = sod(new Date());
    if (k === "bugun") return [t, addDays(t, 1)];
    if (k === "hafta") return [monday(t), addDays(monday(t), 7)];
    const m0 = new Date(t.getFullYear(), t.getMonth(), 1);
    if (k === "ay") return [m0, new Date(t.getFullYear(), t.getMonth() + 1, 1)];
    return [new Date(t.getFullYear(), t.getMonth() - 1, 1), m0];
  }
  VIEWS.kasa = async () => {
    const k = new URLSearchParams(location.hash.split("?")[1] || "").get("r") || "ay";
    const [s, e] = range(k);
    const d = await api(`/app/api/kasa?start=${encodeURIComponent(s.toISOString())}&end=${encodeURIComponent(e.toISOString())}`);
    const canVoid = S.user.role !== "secretary";
    const voidBtn = (en) => h("button", {
      class: "btn btn-sm btn-danger",
      type: "button",
      on: {
        click: () => modal("Kaydı iptal et", [
          h("p", { text: "Kayıt silinmez; iptal olarak işaretlenir ve denetim kaydına yazılır." }),
          fld("Gerekçe", inp("reason", { required: true, minLength: 3 })),
        ], async (f) => {
          await api(`/app/api/${en.type === "hizmet" ? "charges" : "payments"}/${en.id}/void`, { method: "POST", body: { reason: f.get("reason") } });
          toast("İptal edildi");
          route();
        }, "İptal et"),
      },
    }, "İptal");
    setMain(
      header("Kasa", "Tutarlar kuruş hassasiyetinde tutulur; kayıt silinmez, gerekçeli iptal edilir.",
        Object.entries(RANGES).map(([rk, t]) => h("a", { class: `btn ${rk === k ? "btn-primary" : "btn-ghost"}`, href: `#/kasa?r=${rk}`, text: t }))
      ),
      h("div", { class: "grid g3" },
        h("div", { class: "card kpi" }, h("div", { class: "label", text: "Toplam hizmet" }), h("div", { class: "value", text: fmtTL(d.billed) })),
        h("div", { class: "card kpi good" }, h("div", { class: "label", text: "Toplam tahsilat" }), h("div", { class: "value", text: fmtTL(d.paid) }),
          h("div", { class: "hint", text: d.methods.map((m) => `${m.method}: ${fmtTL(m.amount)}`).join(" · ") || "Tahsilat yok" })),
        h("div", { class: "card kpi loss" }, h("div", { class: "label", text: "Kalan alacak (tüm zamanlar)" }), h("div", { class: "value", text: fmtTL(d.receivable) }))
      ),
      d.shares && d.shares.length ? h("div", { class: "card", style: "margin-top:14px" },
        h("h3", { text: "Hekim payları" }),
        tblWrap(h("table", { class: "table" },
          h("thead", null, h("tr", null, ["Hekim", "Pay oranı", "Hizmet", "Hak ediş"].map((t, i) => h("th", { class: i ? "num" : "", text: t })))),
          h("tbody", null, d.shares.map((x) => h("tr", null,
            h("td", { text: x.full_name }),
            h("td", { class: "num", text: `%${Number(x.share_pct)}` }),
            h("td", { class: "num", text: fmtTL(x.billed) }),
            h("td", { class: "num", text: fmtTL(x.share_try) })
          )))
        ))
      ) : null,
      h("div", { class: "card card-flush", style: "margin-top:14px" }, tblWrap(h("table", { class: "table" },
        h("thead", null, h("tr", null, ["Tarih", "Tür", "Hasta", "Açıklama", "Tutar", ""].map((t, i) => h("th", { class: i === 4 ? "num" : "", text: t })))),
        h("tbody", null, d.entries.length ? d.entries.map((en) => h("tr", { style: en.voided_at ? "opacity:.45;text-decoration:line-through" : "" },
          h("td", { text: fmtDT(en.created_at) }),
          h("td", null, tag(en.type === "hizmet" ? "Hizmet" : "Tahsilat", en.type === "hizmet" ? "" : "green")),
          h("td", { text: en.patient || "-" }),
          h("td", { text: en.info }),
          h("td", { class: "num", text: fmtTL(en.amount) }),
          h("td", null, canVoid && !en.voided_at ? voidBtn(en) : null)
        )) : h("tr", null, h("td", { colSpan: 6, class: "empty", text: "Bu aralıkta kayıt yok. Hizmet ve tahsilat hasta kartından girilir." })))
      )))
    );
  };

  // ---------------- maliyet
  VIEWS.costs = async () => {
    const rows = await api("/app/api/token-stats?days=30");
    const total = rows.reduce((s, r) => s + r.replies, 0);
    const free = rows.filter((r) => (r.layer || "").startsWith("L1")).reduce((s, r) => s + r.replies, 0);
    const LAYER = { L1: "Katman 1: kural ve önbellek (0 token)", L2: "Katman 2: küçük sınıflandırıcı", L3: "Katman 3: ana model" };
    setMain(
      header("Yapay Zeka Maliyeti", "Mesajların çoğu kural tabanlı katmanda token harcamadan yanıtlanır. Ana model yalnız gerektiğinde, 180 token sınırıyla çalışır."),
      h("div", { class: "grid g3" },
        h("div", { class: "card kpi good" }, h("div", { class: "label", text: "LLM'siz cevap" }), h("div", { class: "value", text: total ? `%${Math.round(100 * free / total)}` : "-" }), h("div", { class: "hint", text: `${free} / ${total} cevap (30 gün)` })),
        h("div", { class: "card kpi" }, h("div", { class: "label", text: "Girdi token" }), h("div", { class: "value", text: rows.reduce((s, r) => s + Number(r.tin), 0).toLocaleString("tr-TR") })),
        h("div", { class: "card kpi" }, h("div", { class: "label", text: "Çıktı token" }), h("div", { class: "value", text: rows.reduce((s, r) => s + Number(r.tout), 0).toLocaleString("tr-TR") }))
      ),
      h("div", { class: "card card-flush", style: "margin-top:14px" }, tblWrap(h("table", { class: "table" },
        h("thead", null, h("tr", null, ["Katman", "Cevap", "Girdi", "Çıktı"].map((t, i) => h("th", { class: i ? "num" : "", text: t })))),
        h("tbody", null, rows.length ? rows.map((r) => h("tr", null,
          h("td", null, h("b", { text: r.layer || "-" }), h("div", { style: "color:var(--muted);font-size:13px", text: LAYER[(r.layer || "").slice(0, 2)] || "" })),
          h("td", { class: "num", text: r.replies }),
          h("td", { class: "num", text: r.tin }),
          h("td", { class: "num", text: r.tout })
        )) : h("tr", null, h("td", { colSpan: 4, class: "empty", text: "Henüz otomatik cevap yok." })))
      )))
    );
  };

  // ---------------- ekip
  VIEWS.team = async () => {
    const rows = await api("/app/api/staff");
    const owner = S.user.role === "owner";
    setMain(
      header("Ekip", "Kullanıcı ve hekim sayısı sınırsız. WhatsApp numarası tanımlı personel 'bugün', 'yarın', 'özet', 'stok', 'kasa' yazarak paneli telefondan kullanır.",
        owner ? h("button", {
          class: "btn btn-cta",
          type: "button",
          on: {
            click: () => modal("Ekip üyesi ekle", [
              fld("Ad Soyad", inp("full_name", { required: true, minLength: 2 })),
              fld("E-posta", inp("email", { type: "email", required: true })),
              h("div", { class: "row" },
                fld("Rol", sel("role", [["secretary", "Sekreter"], ["doctor", "Hekim"], ["owner", "Yönetici"]], "secretary")),
                fld("Hekim pay oranı (%)", inp("share_pct", { type: "number", min: 0, max: 100, step: "0.5", value: 0 }))
              ),
              fld("WhatsApp numarası (personel asistanı, isteğe bağlı)", inp("phone", { placeholder: "05xx xxx xx xx" })),
              fld("Geçici parola (en az 12 karakter)", inp("password", { type: "password", required: true, minLength: 12, autocomplete: "new-password" })),
            ], async (f) => {
              const b = Object.fromEntries(f);
              if (!b.phone) delete b.phone;
              await api("/app/api/staff", { method: "POST", body: b });
              toast("Ekip üyesi eklendi");
              route();
            }),
          },
        }, icon("plus"), "Üye ekle") : null
      ),
      h("div", { class: "card card-flush" }, tblWrap(h("table", { class: "table" },
        h("thead", null, h("tr", null, ["Ad", "Rol", owner ? "E-posta" : null, "2FA", "WhatsApp", "Durum", owner ? "" : null].filter(Boolean).map((t) => h("th", { text: t })))),
        h("tbody", null, rows.map((s) => h("tr", null,
          h("td", null, h("b", { text: s.full_name })),
          h("td", null, tag(ROLE[s.role] || s.role, s.role === "owner" ? "teal" : "")),
          owner ? h("td", { text: s.email }) : null,
          h("td", null, s.totp_enabled ? tag("Açık", "green") : tag("Kapalı", "yellow")),
          h("td", null, s.whatsapp ? tag("Bağlı", "teal") : "-"),
          h("td", null, s.active ? tag("Aktif", "green") : tag("Pasif", "")),
          owner ? h("td", null, s.id !== S.user.id ? h("button", {
            class: `btn btn-sm ${s.active ? "btn-danger" : "btn-ghost"}`,
            type: "button",
            on: { click: async () => { await run(() => api(`/app/api/staff/${s.id}/active`, { method: "POST", body: { active: !s.active } }), "Güncellendi"); route(); } },
          }, s.active ? "Pasifleştir" : "Aktifleştir") : null) : null
        )))
      )))
    );
  };

  // ---------------- güvenlik
  VIEWS.security = async () => {
    const owner = S.user.role === "owner";
    const box2fa = h("div", { class: "card" },
      h("h3", null, "İki adımlı doğrulama (TOTP)", S.user.totp_enabled ? tag("Açık", "green") : tag("Kapalı", "yellow")),
      h("p", { style: "color:var(--muted);margin-top:0", text: "Google Authenticator, Microsoft Authenticator veya 1Password ile 30 saniyelik kod. Kullanılan kod tekrar oynatılamaz." }),
      h("button", {
        class: "btn btn-primary",
        type: "button",
        on: {
          click: () => modal("İki adımlı doğrulamayı kur", [
            h("p", { text: "Güvenlik için parolanızı tekrar girin." }),
            fld("Parola", inp("password", { type: "password", required: true, autocomplete: "current-password" })),
          ], async (f) => {
            const r = await api("/auth/totp/setup", { method: "POST", body: { password: f.get("password") } });
            setTimeout(() => modal("Kodu doğrulayın", [
              h("p", { text: "Authenticator uygulamasında 'Kurulum anahtarı gir' seçeneğine bu anahtarı yazın:" }),
              h("div", { class: "secret", text: r.secret.replace(/(.{4})/g, "$1 ").trim() }),
              h("p", null, h("a", { href: r.uri, text: "Bu cihazda uygulamada aç" })),
              fld("Uygulamadaki 6 haneli kod", inp("code", { inputMode: "numeric", maxLength: 6, required: true, pattern: "[0-9]{6}" })),
            ], async (g) => {
              await api("/auth/totp/enable", { method: "POST", body: { code: g.get("code") } });
              S.user.totp_enabled = true;
              toast("İki adımlı doğrulama açıldı");
              route();
            }, "Etkinleştir"), 50);
          }, "Devam"),
        },
      }, S.user.totp_enabled ? "Yeniden kur" : "Şimdi kur")
    );
    const boxPw = h("div", { class: "card" },
      h("h3", { text: "Parola ve oturumlar" }),
      h("div", { class: "actions" },
        h("button", {
          class: "btn btn-ghost",
          type: "button",
          on: {
            click: () => modal("Parola değiştir", [
              fld("Mevcut parola", inp("current", { type: "password", required: true, autocomplete: "current-password" })),
              fld("Yeni parola (en az 12 karakter)", inp("new", { type: "password", required: true, minLength: 12, autocomplete: "new-password" })),
            ], async (f) => {
              await api("/auth/password", { method: "POST", body: { current: f.get("current"), new: f.get("new") } });
              toast("Parola değişti, diğer cihazlardaki oturumlar kapatıldı");
            }),
          },
        }, "Parola değiştir"),
        h("button", {
          class: "btn btn-danger",
          type: "button",
          on: {
            click: async () => {
              if (!confirm("Tüm cihazlardaki oturumlar kapatılsın mı?")) return;
              await run(() => api("/auth/sessions/revoke-all", { method: "POST" }));
              S.user = null;
              renderLogin("Tüm oturumlar kapatıldı.");
            },
          },
        }, "Tüm cihazlardan çıkış")
      ),
      h("div", { class: "section-t", text: "Bu sistemde etkin korumalar" }),
      h("ul", { style: "margin:0;padding-left:18px;color:var(--ink-2)" }, [
        "Parolalar scrypt (bellek-yoğun) ile özetlenir; 10 hatalı denemede hesap 15 dk kilitlenir",
        "Oturum çerezi: __Host-, HttpOnly, Secure, SameSite=Strict; sunucuda yalnızca özeti tutulur",
        "Her değişiklik isteğinde CSRF jetonu ve köken (Origin) kontrolü",
        "CSP, HSTS, COOP/COEP/CORP, Permissions-Policy ve no-store dahil 12 HTTP güvenlik başlığı",
        "Hasta telefonu, anamnez, TOTP anahtarı uygulama katmanında şifreli (Fernet)",
        "Denetim kaydı SHA-256 hash zinciriyle bağlı ve veritabanında değiştirilemez",
      ].map((t) => h("li", { text: t })))
    );

    const nodes = [header("Güvenlik", "Hesap güvenliği, oturum kontrolü ve klinik denetim kaydı."), h("div", { class: "grid g2" }, box2fa, boxPw)];
    if (owner) {
      const res = h("span", { role: "status" });
      const rows = await api("/app/api/audit?limit=150");
      nodes.push(h("div", { class: "card card-flush", style: "margin-top:14px" },
        h("div", { style: "padding:16px 18px 8px" }, h("h3", null, "Denetim kaydı", h("div", { class: "actions" }, res,
          h("button", {
            class: "btn btn-sm btn-primary",
            type: "button",
            on: {
              click: async () => {
                const v = await run(() => api("/app/api/audit/verify"));
                if (!v) return;
                res.className = v.ok ? "chain-ok" : "chain-bad";
                res.textContent = v.ok ? `Zincir sağlam: ${v.checked} kayıt doğrulandı` : `ZİNCİR KIRIK: kayıt #${v.broken_at}`;
              },
            },
          }, "Bütünlüğü doğrula")
        ))),
        tblWrap(h("table", { class: "table" },
          h("thead", null, h("tr", null, ["#", "Zaman", "Kim", "İşlem", "Hedef", "Özet"].map((t) => h("th", { text: t })))),
          h("tbody", null, rows.map((r) => h("tr", null,
            h("td", { text: r.id }),
            h("td", { text: fmtDT(r.ts) }),
            h("td", { text: r.actor }),
            h("td", null, tag(r.action, r.action.includes("fail") ? "red" : "")),
            h("td", { class: "mono", text: r.target }),
            h("td", { class: "mono", style: "color:var(--muted)", text: (r.hash || "").slice(0, 12) })
          )))
        ))
      ));
    }
    setMain(...nodes);
  };

  // ---------------- mesajlar + Canlı AI Mesaj Simülatörü (16 dil, RTL)
  const SIM_PRESETS = [
    { label: "TR Konum", lang: "", text: "Adresiniz nerede ve otopark var mı?" },
    { label: "TR Acil Kanama", lang: "tr", text: "Dişimi çektirdim kanama durmuyor ve yüzüm şişti" },
    { label: "EN Zirkonyum Fiyat", lang: "en", text: "How much do zirconia crowns cost?" },
    { label: "AR Randevu (RTL)", lang: "ar", text: "مرحباً، أريد حجز موعد في العيادة" },
    { label: "FA Fiyat (RTL)", lang: "fa", text: "سلام قیمت ایمپلنت چقدر است؟" },
    { label: "HE Adres (RTL)", lang: "he", text: "שלום איפה הכתובת שלכם?" },
    { label: "RU Saatler", lang: "ru", text: "Какие у вас часы работы в субботу?" },
    { label: "DE İmplant", lang: "de", text: "Wie viel kostet ein Zahnimplantat?" },
  ];

  VIEWS.messages = async () => {
    const rows = await api("/app/api/conversations");

    const simLang = sel("lang", [["", "Otomatik algıla (16 dil)"], ...LANG_OPTIONS], S.simLang || "");
    const simInput = inp("text", { required: true, placeholder: "Hastanın mesajını yazın (ör. Arapça, İngilizce, Türkçe)...", value: S.simText || "" });
    const simBtn = h("button", { class: "btn btn-cta", type: "submit" }, "Simüle Et");
    const simOut = h("div", { class: "sim-reply" + (S.simResult ? "" : " hidden"), role: "region", "aria-live": "polite" });

    function renderSimResult(r) {
      if (!r) return;
      const isRtl = RTL_LANGS.has(r.lang);
      simOut.classList.remove("hidden");
      simOut.replaceChildren(
        h("div", { class: "sim-reply-head" },
          tag(`Katman: ${r.layer}`, (r.layer || "").startsWith("L1") ? "green" : "teal"),
          tag(`Niyet: ${r.intent}`, ""),
          tag(`Dil: ${(r.lang || "tr").toUpperCase()}${isRtl ? " (RTL)" : ""}`, "teal"),
          tag(`Token: ${r.tokens_in} girdi / ${r.tokens_out} çıktı`, (r.tokens_in + r.tokens_out) === 0 ? "green" : "amber"),
          r.alert ? tag(`Uyarı: ${r.alert}`, "red") : null,
          r.handoff ? tag("Ekibe aktarım", "yellow") : null
        ),
        h("p", {
          class: "sim-reply-text",
          dir: isRtl ? "rtl" : "ltr",
          lang: r.lang || "tr",
          text: r.answer,
        })
      );
    }
    if (S.simResult) renderSimResult(S.simResult);

    let simReqId = 0;
    async function runSim(text, lang) {
      const myReq = ++simReqId;
      S.simText = text;
      S.simLang = lang || "";
      simBtn.disabled = true;
      simBtn.textContent = "Yanıtlanıyor...";
      simForm.querySelectorAll(".sim-presets button").forEach((b) => { b.disabled = true; });
      try {
        const body = lang ? { text, lang } : { text };
        const res = await api("/app/api/conversations/simulate", { method: "POST", body });
        if (myReq !== simReqId) return;
        S.simResult = res;
        renderSimResult(res);
        const freshRows = await api("/app/api/conversations");
        if (myReq === simReqId) tbody.replaceChildren(...buildConvRows(freshRows));
      } catch (e) {
        if (myReq === simReqId && e.message !== "oturum") toast(e.message, true);
      } finally {
        if (myReq === simReqId) {
          simBtn.disabled = false;
          simBtn.textContent = "Simüle Et";
          simForm.querySelectorAll(".sim-presets button").forEach((b) => { b.disabled = false; });
        }
      }
    }

    const simForm = h("form", {
      class: "sim-card",
      on: {
        submit: (e) => {
          e.preventDefault();
          const t = simInput.value.trim();
          if (!t) return;
          runSim(t, simLang.value);
        },
      },
    },
      h("h3", { text: "Canlı AI Mesaj Simülatörü (16 Dil + 3 Katmanlı Yönlendirici)" }),
      h("p", { style: "color:var(--muted);margin:0 0 12px;font-size:14px", text: "Seçili kliniğin bilgileriyle hastaya verilecek yanıtı, token katmanını ve RTL yönünü gerçek zamanlı test edin." }),
      h("div", { class: "sim-presets" }, SIM_PRESETS.map((p) =>
        h("button", {
          class: "btn btn-sm btn-ghost",
          type: "button",
          on: {
            click: () => {
              simInput.value = p.text;
              simLang.value = p.lang;
              runSim(p.text, p.lang);
            },
          },
        }, p.label)
      )),
      h("div", { class: "sim-form-row" },
        fld("Dil", simLang),
        fld("Hasta mesajı", simInput),
        simBtn
      ),
      simOut
    );

    const buildConvRows = (list) => list.length ? list.map((r) => h("tr", null,
      h("td", null, h("b", { text: r.display_name || `Hasta #${r.id}` })),
      h("td", null, tag(r.channel === "ig" ? "Instagram" : r.channel === "simulator" ? "Simülatör" : "WhatsApp", r.channel === "ig" ? "amber" : "teal")),
      h("td", { text: (r.lang || "tr").toUpperCase() }),
      h("td", null, tag(r.last_layer || "yeni", (r.last_layer || "").startsWith("L1") ? "green" : "")),
      h("td", { text: r.last_intent || "-" }),
      h("td", { text: r.msg_count || 0 }),
      h("td", { text: r.last_at ? fmtDT(r.last_at) : "-" }),
      h("td", null, h("div", { class: "actions" },
        h("button", {
          class: "btn btn-sm btn-primary",
          type: "button",
          on: {
            click: () => modal(`${r.display_name || "Hasta #" + r.id} · Otopilotu Devral`, [
              fld("Doğrudan Mesaj", h("textarea", { class: "input", name: "text", rows: 3, required: true, placeholder: "Hastaya iletilecek mesaj..." })),
            ], async (f) => {
              await api(`/app/api/conversations/${r.id}/send`, { method: "POST", body: { text: f.get("text") } });
              toast("Mesaj gönderildi");
              route();
            }, "Gönder"),
          },
        }, "Yanıtla"),
        h("button", { class: "btn btn-sm btn-ghost", type: "button", on: { click: () => openPatient(r.id) } }, "Kart")
      ))
    )) : [h("tr", null, h("td", { colSpan: 8, class: "empty", text: "Henüz mesaj kaydı yok." }))];

    const tbody = h("tbody", null, buildConvRows(rows));

    setMain(
      header("Mesajlar", "WhatsApp ve Instagram DM görüşmeleri ile 16 dilli canlı yapay zeka simülatörü."),
      simForm,
      h("div", { class: "card card-flush" }, tblWrap(h("table", { class: "table" },
        h("thead", null, h("tr", null, ["Hasta", "Kanal", "Dil", "Son Katman", "Niyet", "Mesaj", "Son Temas", ""].map((t) => h("th", { text: t })))),
        tbody
      )))
    );
  };

  // ---------------- şablonlar
  VIEWS.templates = async () => {
    const rows = await api("/app/api/templates");
    setMain(
      header("Mesaj Şablonları", "Meta WhatsApp Cloud API ve Instagram için onaylı mesaj şablonları.",
        h("button", {
          class: "btn btn-cta",
          type: "button",
          on: {
            click: () => modal("Yeni şablon", [
              fld("Şablon kodu (küçük harf)", inp("name", { required: true, placeholder: "implant_kontrol" })),
              h("div", { class: "row" },
                fld("Kanal", sel("channel", [["whatsapp", "WhatsApp"], ["instagram", "Instagram"]], "whatsapp")),
                fld("Kategori", sel("category", [["UTILITY", "Hizmet / Teyit"], ["MARKETING", "Kampanya"], ["AUTHENTICATION", "Doğrulama"]], "UTILITY"))
              ),
              fld("Metin ({{1}}, {{2}} değişkenleri desteklenir)", h("textarea", { class: "input", name: "body", rows: 3, required: true })),
            ], async (f) => {
              await api("/app/api/templates", { method: "POST", body: Object.fromEntries(f) });
              toast("Şablon eklendi");
              route();
            }),
          },
        }, icon("plus"), "Şablon oluştur")
      ),
      h("div", { class: "card card-flush" }, tblWrap(h("table", { class: "table" },
        h("thead", null, h("tr", null, ["Ad", "Kanal", "Kategori", "Durum", "İçerik"].map((t) => h("th", { text: t })))),
        h("tbody", null, rows.length ? rows.map((t) => h("tr", null,
          h("td", { class: "mono", text: t.name }),
          h("td", null, tag(t.channel, "teal")),
          h("td", { text: t.category }),
          h("td", null, tag(t.status, "green")),
          h("td", { text: t.body })
        )) : h("tr", null, h("td", { colSpan: 5, class: "empty", text: "Şablon yok." })))
      )))
    );
  };

  // ---------------- iletişim ve reklam analizi
  VIEWS.analytics = async () => {
    const d = await api("/app/api/analytics");
    setMain(
      header("İletişim & Reklam Analizi", "Mesai dışı yakalanan randevular ve Meta/Google reklam kampanyalarının kasa dönüşümü.",
        h("button", {
          class: "btn btn-cta",
          type: "button",
          on: {
            click: () => modal("Reklam kampanyası ekle", [
              fld("Kampanya adı", inp("name", { required: true, placeholder: "İstanbul İmplant Meta Eylül" })),
              h("div", { class: "row" },
                fld("Kaynak", sel("source", [["meta_ads", "Meta / Instagram Ads"], ["google_ads", "Google Ads"], ["organik", "Organik"]], "meta_ads")),
                fld("Tıklama", inp("clicks", { type: "number", value: 120 }))
              ),
              h("div", { class: "row" },
                fld("Konuşma", inp("conversations", { type: "number", value: 24 })),
                fld("Randevu", inp("appointments_booked", { type: "number", value: 9 }))
              ),
              fld("Gerçekleşen Ciro (TL)", inp("revenue_try", { type: "number", step: "0.01", value: 38000 })),
            ], async (f) => {
              const b = Object.fromEntries(f);
              b.clicks = Number(b.clicks || 0);
              b.conversations = Number(b.conversations || 0);
              b.appointments_booked = Number(b.appointments_booked || 0);
              await api("/app/api/campaigns", { method: "POST", body: b });
              toast("Kampanya eklendi");
              route();
            }),
          },
        }, icon("plus"), "Kampanya ekle")
      ),
      h("div", { class: "grid g3" },
        h("div", { class: "card kpi" }, h("div", { class: "label", text: "Son 30 gün randevu" }), h("div", { class: "value", text: String(d.total_appts_30d) })),
        h("div", { class: "card kpi good" }, h("div", { class: "label", text: "Mesai dışı / Pazar bağlanan" }), h("div", { class: "value", text: `%${d.off_hours_pct}` }), h("div", { class: "hint", text: `${d.off_hours_appts} randevu klinik kapalıyken` })),
        h("div", { class: "card kpi" }, h("div", { class: "label", text: "Aktif kampanya" }), h("div", { class: "value", text: String(d.campaigns.length) }))
      ),
      h("div", { class: "card card-flush", style: "margin-top:14px" }, tblWrap(h("table", { class: "table" },
        h("thead", null, h("tr", null, ["Kampanya", "Kaynak", "Tıklama", "Konuşma", "Randevu", "Kasa Cirosu"].map((t, i) => h("th", { class: i > 1 ? "num" : "", text: t })))),
        h("tbody", null, d.campaigns.length ? d.campaigns.map((c) => h("tr", null,
          h("td", null, h("b", { text: c.name })),
          h("td", null, tag(c.source, "teal")),
          h("td", { class: "num", text: c.clicks }),
          h("td", { class: "num", text: c.conversations }),
          h("td", { class: "num", text: c.appointments_booked }),
          h("td", { class: "num", text: fmtTL(c.revenue_try) })
        )) : h("tr", null, h("td", { colSpan: 6, class: "empty", text: "Henüz kampanya kaydı yok." })))
      )))
    );
  };

  // ---------------- zincir klinikler + teslim kartı + şube geçişi
  function showDeliveryCardModal(info) {
    const loginUrl = info.login_url || `${location.origin}/app`;
    const gUrl = info.google_subscribe_url || (info.webcal_url ? `https://calendar.google.com/calendar/r?cid=${encodeURIComponent(info.webcal_url)}` : "");
    const lines = [
      `Merhaba ${info.clinic_name || "Ekibimiz"}, DentaCore klinik paneliniz hazır.`,
      ``,
      `Panel Girişi: ${loginUrl}`,
      `E-posta: ${info.email || info.owner_email || "-"}`,
      info.password ? `Geçici Parola: ${info.password} (İlk giriş sonrası Ayarlar/Güvenlikten değiştirin)` : null,
      ``,
      `iPhone Takvim (webcal): ${info.webcal_url || "-"}`,
      `Android / Google Takvim: ${gUrl || "-"}`,
      `Tüm Takvim (.ics): ${info.ics_url || "-"}`,
    ].filter((x) => x !== null).join("\n");

    const ov = modal("WhatsApp Giriş + Takvim Teslim Kartı", [
      h("p", { style: "color:var(--muted);margin-top:0", text: "Bu kartı tek tıkla kopyalayıp yeni kliniğin yöneticisine WhatsApp'tan gönderebilirsiniz." }),
      h("div", { class: "handoff-box" }, h("pre", { text: lines })),
      h("div", { class: "actions" },
        h("button", { class: "btn btn-cta", type: "button", on: { click: () => copyText(lines, "WhatsApp teslim kartı kopyalandı") } }, icon("copy"), "WhatsApp Mesajını Kopyala"),
        info.webcal_url ? h("button", { class: "btn btn-ghost", type: "button", on: { click: () => copyText(info.webcal_url, "iPhone webcal linki kopyalandı") } }, "webcal Kopyala") : null,
        gUrl ? h("button", { class: "btn btn-ghost", type: "button", on: { click: () => copyText(gUrl, "Google Takvim linki kopyalandı") } }, "Google Link Kopyala") : null
      ),
    ], async () => true, "Kapat");
    const cancelBtn = ov.querySelector(".foot .btn-ghost");
    if (cancelBtn) cancelBtn.remove();
  }

  VIEWS.clinics = async () => {
    const rows = await api("/app/api/clinics");
    const hq = isHQ();
    setMain(
      header("Zincir Klinikler (Çoklu Müşteri Yönetimi)",
        hq ? "Her şube izole çalışır. Tek tıkla başka şubeye geçebilir veya yeni şubeye WhatsApp teslim kartı oluşturabilirsiniz." : "Şubenizin izolasyon özeti.",
        hq ? h("button", {
          class: "btn btn-cta",
          type: "button",
          on: {
            click: () => modal("Yeni Klinik Hesabı Aç", [
              fld("Klinik Adı", inp("clinic_name", { required: true, minLength: 2, placeholder: "Özel Ataşehir Diş Polikliniği" })),
              h("div", { class: "row" },
                fld("Şehir", inp("city", { value: "İstanbul", required: true })),
                fld("Koltuk Sayısı", inp("chairs", { type: "number", min: 1, max: 200, value: 3 }))
              ),
              fld("Adres", inp("address", { placeholder: "Mahalle, Cadde, İlçe" })),
              fld("Klinik Telefonu", inp("phone", { placeholder: "+90 5xx xxx xx xx" })),
              fld("Yetkili Hekim / Yönetici Adı", inp("owner_name", { required: true, placeholder: "Dt. Ahmet Demir" })),
              fld("Giriş E-postası", inp("owner_email", { type: "email", required: true, placeholder: "klinik@atasehirdis.com" })),
              fld("Giriş Parolası (En az 12 karakter)", inp("owner_password", { type: "password", required: true, minLength: 12 })),
            ], async (f) => {
              const payload = Object.fromEntries(f);
              payload.chairs = Number(payload.chairs || 2);
              const pwPlain = payload.owner_password;
              const r = await api("/app/api/clinics", { method: "POST", body: payload });
              toast(`Klinik #${r.clinic_id} (${r.email}) oluşturuldu`);
              route();
              setTimeout(() => showDeliveryCardModal({ ...r, clinic_name: payload.clinic_name, password: pwPlain }), 80);
            }, "Kliniği Oluştur"),
          },
        }, icon("plus"), "Yeni Klinik Ekle") : null
      ),
      h("div", { class: "card card-flush" }, tblWrap(h("table", { class: "table" },
        h("thead", null, h("tr", null, ["ID", "Klinik Adı", "Giriş E-postası", "Şehir", "Koltuk", "Hasta", "Randevu", "Ciro", "Durum", "İşlemler"].map((t, i) => h("th", { class: i === 7 ? "num" : "", text: t })))),
        h("tbody", null, rows.map((c) => {
          const isCurrent = c.id === S.clinic_id;
          const isHome = c.id === S.home_clinic_id;
          return h("tr", null,
            h("td", { text: `#${c.id}` }),
            h("td", null, h("b", { text: c.name }), h("div", { class: "mono", style: "color:var(--muted)", text: c.slug })),
            h("td", { class: "mono", text: c.owner_email || "-" }),
            h("td", { text: c.city }),
            h("td", { text: c.chairs }),
            h("td", { text: c.patient_count }),
            h("td", { text: c.active_appts }),
            h("td", { class: "num", text: fmtTL(c.paid_try || 0) }),
            h("td", null, isCurrent ? tag("Aktif Oturum", "teal") : (c.active ? tag("Aktif", "green") : tag("Pasif", ""))),
            h("td", null, h("div", { class: "actions" },
              hq && !isCurrent ? h("button", { class: "btn btn-sm btn-primary", type: "button", on: { click: () => switchClinic(c.id) } }, "Bu kliniğe geç") : null,
              hq && isCurrent && !isHome ? h("button", { class: "btn btn-sm btn-cta", type: "button", on: { click: () => switchClinic(S.home_clinic_id) } }, "Merkeze dön") : null,
              h("button", {
                class: "btn btn-sm btn-ghost",
                type: "button",
                on: { click: () => showDeliveryCardModal({ clinic_name: c.name, email: c.owner_email, webcal_url: c.webcal_url, ics_url: c.ics_url }) },
              }, "Teslim Kartı")
            ))
          );
        }))
      )))
    );
  };

  // ---------------- ayarlar (16 dil + Ekosistem Durum Kartı)
  VIEWS.settings = async () => {
    const [s, eco] = await Promise.all([
      api("/app/api/settings"),
      api("/app/api/ecosystem-status").catch(() => null),
    ]);
    const owner = S.user.role === "owner";

    const form = h("form", {
      class: "card",
      on: {
        submit: async (e) => {
          e.preventDefault();
          if (!owner) return toast("Yalnızca yönetici kaydedebilir", true);
          const f = Object.fromEntries(new FormData(form));
          f.slot_step_min = Number(f.slot_step_min || 15);
          f.buffer_min = Number(f.buffer_min || 0);
          await run(() => api("/app/api/settings", { method: "POST", body: f }), "Klinik ayarları kaydedildi");
          S.clinic = f.name;
          document.querySelectorAll(".brand small, .m-topbar-brand small").forEach((el) => { el.textContent = S.clinic; });
        },
      },
    },
      h("h3", { text: "Klinik ve Otopilot Ayarları" }),
      h("div", { class: "row" },
        fld("Klinik Adı", inp("name", { value: s.name || S.clinic, required: true })),
        fld("Otopilot Asistan Adı", inp("autopilot_name", { value: s.autopilot_name || "DentaCore Asistan" }))
      ),
      h("div", { class: "row" },
        fld("Şehir", inp("city", { value: s.city || "İstanbul" })),
        fld("Telefon", inp("phone", { value: s.phone || "" }))
      ),
      fld("Klinik Adresi (iPhone / Android Takvim konumunda görünür)", inp("address", { value: s.address || "" })),
      h("div", { class: "row" },
        fld("Varsayılan Dil (16 Dil)", sel("default_lang", LANG_OPTIONS, s.default_lang || "tr")),
        fld("Randevu Slot Aralığı (dk)", sel("slot_step_min", [["5", "5 dakika"], ["10", "10 dakika"], ["15", "15 dakika (varsayılan)"], ["20", "20 dakika"], ["30", "30 dakika"], ["60", "60 dakika"]], String(s.slot_step_min || 15)))
      ),
      h("div", { class: "row" },
        fld("Çalışma Saatleri Kuralı (JSON)", inp("working_hours_json", { value: s.working_hours_json || '{"mon_fri":["09:00","19:00"],"sat":["09:00","15:00"],"sun":null}' })),
        fld("İşlem Arası Sterilizasyon Payı (buffer dk)", inp("buffer_min", { type: "number", min: 0, max: 120, value: s.buffer_min || 0 }))
      ),
      fld("Google Haritalar Yorum Bağlantısı", inp("google_review_url", { value: s.google_review_url || "", placeholder: "https://search.google.com/local/writereview?placeid=..." })),
      owner ? h("button", { class: "btn btn-cta", type: "submit" }, "Ayarları Kaydet") : null
    );

    const ecoServices = eco ? [
      ["OmniRoute LLM Gateway", eco.omniroute],
      ["Headroom Token Sıkıştırma", eco.headroom],
      ["AI Office Orkestratör", eco.ai_office],
    ] : [];

    const ecoCard = h("div", { class: "card", style: "margin-top:14px" },
      h("h3", null,
        "Ekosistem ve Altyapı Durum Kartı",
        h("div", { class: "actions" },
          eco ? tag(`${eco.langs || 16} Dil Aktif`, "teal") : null,
          eco ? tag(`${eco.security_headers || 12}/12 Güvenlik Başlığı`, "green") : null,
          h("button", { class: "btn btn-sm btn-ghost", type: "button", on: { click: route } }, "Durumu Yenile")
        )
      ),
      eco ? [
        h("div", { class: "eco-grid" }, ecoServices.map(([name, st]) =>
          h("div", { class: "eco-item" },
            h("div", { style: "display:flex;justify-content:space-between;align-items:center;gap:6px" },
              h("strong", { text: name }),
              tag(st && st.ok ? "Çalışıyor" : "Kapalı", st && st.ok ? "green" : "yellow")
            ),
            h("small", { text: (st && st.url) || "-" })
          )
        )),
        eco.apps && eco.apps.length ? [
          h("div", { class: "section-t", text: "Bağlı Açık Kaynak Uygulama Ekosistemi" }),
          h("div", { class: "actions", style: "gap:8px" }, eco.apps.map((ap) =>
            tag(`${ap.name}: ${ap.ok ? "Hazır" : "Beklemede"}`, ap.ok ? "teal" : "")
          )),
        ] : null,
      ] : h("div", { class: "empty", text: "Ekosistem durum servisi şu an yanıt vermedi." })
    );

    let aiRulesObj = {};
    try {
      aiRulesObj = s.ai_custom_rules_json ? JSON.parse(s.ai_custom_rules_json) : {};
    } catch (e) { aiRulesObj = {}; }

    const aiRulesForm = h("form", {
      class: "card",
      style: "margin-top:14px",
      on: {
        submit: async (e) => {
          e.preventDefault();
          if (!owner) return toast("Yalnızca yönetici kaydedebilir", true);
          const f = Object.fromEntries(new FormData(aiRulesForm));
          await run(() => api("/app/api/settings/ai-rules", { method: "POST", body: f }), "Müşteriye özel WhatsApp yapay zeka cevap politikası kaydedildi");
        },
      },
    },
      h("h3", null,
        "Müşteriye / Kliniğe Özel WhatsApp Yapay Zeka Cevap Politikası (Parlant VIP Koordinatör Motoru)",
        tag("Resmi & Samimi İnsan Üslubu", "teal")
      ),
      h("p", { style: "color:var(--muted);margin:0 0 12px;font-size:13.5px", text: "Kliniğinizin fiyat, ilk muayene, nakit avantajı, çocuk diş, iğne korkusu ve yurt dışı hasta politikalarını buradan özelleştirin; WhatsApp ve Instagram asistanı hastanın mesajındaki isteğe göre bu kurallarla yanıt verir." }),
      h("div", { class: "row" },
        fld("Konuşma Üslubu & Tonu", sel("tone", [
          ["resmi_samimi", "Resmi, Samimi ve Değer Hissettiren VIP Hasta Koordinatörü (Önerilen)"],
          ["kurumsal_akademik", "Kurumsal ve Akademik Poliklinik Üslubu"],
          ["sicak_butik", "Sıcak ve Butik Aile Diş Kliniği Üslubu"],
        ], aiRulesObj.tone || "resmi_samimi")),
        fld("Fiyat Sorusu Politikası", sel("price_policy", [
          ["free_exam_invite", "Seçenek A (Önerilen): Fiyat verilmesin, muayene & röntgen sonrası yazılı plan densin"],
          ["starting_range", "Seçenek B: Özel not eklensin ve muayeneye davet edilsin"],
          ["direct_handoff", "Seçenek C: Fiyat soran hastalar öncelikle koordinatöre devredilsin"],
        ], aiRulesObj.price_policy || "free_exam_invite"))
      ),
      h("div", { class: "row" },
        fld("Nakit / Peşin Ödeme Avantajı Cevabı", inp("cash_discount_note", {
          value: aiRulesObj.cash_discount_note || "Nakit veya peşin ödemelerde sağladığımız özel ödeme kolaylıklarını da muayeneniz sırasında planınıza özenle yansıtıyoruz.",
        })),
        fld("Taksit ve Özel Sigorta Cevabı", inp("payment_note", {
          value: aiRulesObj.payment_note || "Kredi kartlarına taksit kolaylığı sağlıyor, özel sağlık sigortası ve anlaşmalı kurumlar için gereken tüm evrakları eksiksiz hazırlıyoruz.",
        }))
      ),
      h("div", { class: "row" },
        fld("İğne Korkusu & Sedasyon Konfor Cevabı", inp("pain_comfort_note", {
          value: aiRulesObj.pain_comfort_note || "İğne ve diş hekimi korkusu olan misafirlerimizde işlem öncesinde yüzey uyuşturucu jel, modern lokal anestezi ve sedasyon destekli konfor protokolü uyguluyoruz.",
        })),
        fld("Çocuk Diş (Pedodonti) Yaklaşımı Cevabı", inp("kids_note", {
          value: aiRulesObj.kids_note || "Çocuk diş hekimimiz (pedodonti uzmanımız), minik misafirlerimizin tedavilerini hiç korkutmadan, oyunlaştırılmış ve koruyucu bir yaklaşımla gerçekleştiriyor.",
        }))
      ),
      h("div", { class: "row" },
        fld("Yurt Dışı / Şehir Dışı Misafir VIP Karşılama Notu", inp("health_tourism_note", {
          value: aiRulesObj.health_tourism_note || "Yurt dışından ve şehir dışından gelen misafirlerimiz için seyahat takvimine özel hızlandırılmış VIP randevu planlaması yapıyoruz.",
        })),
        fld("Kliniğe Özel Ekstra Bilgi / Kampanya / Vale Notu", inp("custom_extra_note", {
          value: aiRulesObj.custom_extra_note || "",
          placeholder: "Örn: Ücretsiz vale ve havalimanı VIP transfer desteğimiz mevcuttur.",
        }))
      ),
      owner ? h("button", { class: "btn btn-primary", type: "submit" }, "WhatsApp AI Cevap Kurallarını Kaydet") : null
    );

    setMain(
      header("Ayarlar", "Otopilot kimliği, müşteriye özel WhatsApp yapay zeka cevap politikası, 16 dil seçimi ve ekosistem durumu."),
      form,
      aiRulesForm,
      ecoCard
    );
  };

  // ------------------------------------------------------------------ açılış
  async function boot(forceCheck) {
    if (!forceCheck && lsGet("dc_has_session", "") !== "1" && !location.hash.startsWith("#/")) {
      return renderLogin();
    }
    try {
      const me = await fetch("/auth/me", { credentials: "same-origin", headers: { Accept: "application/json" } });
      if (!me.ok) {
        lsSet("dc_has_session", "");
        return renderLogin();
      }
      const d = await me.json();
      lsSet("dc_has_session", "1");
      Object.assign(S, {
        csrf: d.csrf,
        user: d.user,
        clinic: d.clinic,
        clinic_id: d.clinic_id || (d.user && d.user.clinic_id) || 1,
        home_clinic_id: d.home_clinic_id || (d.user && d.user.clinic_id) || 1,
        idle: d.idle_seconds || 900,
        lastAct: Date.now(),
      });
      renderShell();
    } catch (e) {
      renderLogin("Sunucuya ulaşılamadı.");
    }
  }
  boot(false);
})();
