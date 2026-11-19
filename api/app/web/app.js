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

  let _uid = 0;
  const nextId = (p = "dc") => `${p}-${++_uid}`;
  const isHQ = () => Boolean(S.user && (S.user.is_hq || (S.user.role === "owner" && S.home_clinic_id === 1)));
  const tag = (txt, cls) => h("span", { class: `tag ${cls || ""}` }, txt);
  const tblWrap = (table, label = "Veri tablosu") => h("div", { class: "table-wrap", tabIndex: 0, role: "region", "aria-label": label }, table);

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

  function focusablesIn(el) {
    return [...el.querySelectorAll('a[href],button:not([disabled]),input:not([disabled]):not([type="hidden"]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])')]
      .filter((n) => !n.closest(".hidden") && (n.offsetParent !== null || n.getClientRects().length > 0));
  }
  function handleTabTrap(ev, container) {
    if (ev.key !== "Tab") return;
    const list = focusablesIn(container);
    if (!list.length) { ev.preventDefault(); return; }
    const first = list[0], last = list[list.length - 1];
    if (ev.shiftKey && (document.activeElement === first || !container.contains(document.activeElement))) {
      ev.preventDefault();
      last.focus();
    } else if (!ev.shiftKey && (document.activeElement === last || !container.contains(document.activeElement))) {
      ev.preventDefault();
      first.focus();
    }
  }

  function validateFormTr(form) {
    const controls = [...form.querySelectorAll("input,select,textarea")];
    controls.forEach((c) => {
      c.classList.remove("input-err");
      c.removeAttribute("aria-invalid");
    });
    for (const el of controls) {
      if (el.disabled || el.type === "hidden" || el.closest(".hidden")) continue;
      if (el.checkValidity()) continue;
      el.classList.add("input-err");
      el.setAttribute("aria-invalid", "true");
      const clear = () => {
        el.classList.remove("input-err");
        el.removeAttribute("aria-invalid");
      };
      el.addEventListener("input", clear, { once: true });
      el.addEventListener("change", clear, { once: true });
      let lbl = "";
      if (el.id) {
        const l = form.querySelector(`label[for="${CSS.escape(el.id)}"]`);
        if (l) lbl = l.textContent.trim();
      }
      if (!lbl) {
        const wrapLbl = el.closest(".field")?.querySelector("label");
        lbl = (wrapLbl && wrapLbl.textContent.trim()) || el.getAttribute("aria-label") || el.name || "Bu alan";
      }
      const v = el.validity;
      let msg = `${lbl} alanını kontrol edin.`;
      if (v.valueMissing) msg = `${lbl} alanı zorunludur.`;
      else if (v.typeMismatch) msg = `${lbl} için geçerli bir değer girin.`;
      else if (v.tooShort) msg = `${lbl} en az ${el.minLength} karakter olmalıdır.`;
      else if (v.tooLong) msg = `${lbl} en fazla ${el.maxLength} karakter olmalıdır.`;
      else if (v.rangeUnderflow) msg = `${lbl} en az ${el.min} olmalıdır.`;
      else if (v.rangeOverflow) msg = `${lbl} en fazla ${el.max} olmalıdır.`;
      else if (v.stepMismatch) msg = `${lbl} için geçerli bir değer aralığı girin.`;
      else if (v.patternMismatch) msg = `${lbl} beklenen biçimde değil.`;
      el.focus();
      return msg;
    }
    return "";
  }

  function modal(title, fields, onSubmit, submitText) {
    const prevFocus = document.activeElement;
    const err = h("div", { class: "err", role: "alert" });
    const btn = h("button", { class: "btn btn-cta", type: "submit" }, submitText || "Kaydet");
    const closeOv = () => {
      document.removeEventListener("keydown", onKey);
      ov.remove();
      if (prevFocus && typeof prevFocus.focus === "function") prevFocus.focus();
    };
    const onKey = (ev) => {
      const modals = document.querySelectorAll(".modal");
      if (modals.length && modals[modals.length - 1] !== form) return;
      if (ev.key === "Escape") {
        ev.stopImmediatePropagation();
        closeOv();
      } else if (ev.key === "Tab") {
        handleTabTrap(ev, form);
      }
    };
    const titleId = nextId("m-title");
    const form = h("form", {
      class: "modal",
      autocomplete: "off",
      noValidate: true,
      on: {
        submit: async (e) => {
          e.preventDefault();
          err.textContent = "";
          const vErr = validateFormTr(form);
          if (vErr) { err.textContent = vErr; return; }
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
    document.addEventListener("keydown", onKey);
    document.body.appendChild(ov);
    const first = focusablesIn(form)[0];
    if (first) first.focus();
    return ov;
  }

  function confirmModal(title, message, onConfirm, confirmText = "Onayla", danger = true) {
    const ov = modal(title, [
      h("p", { style: "margin:0;color:var(--ink-2)", text: message }),
    ], async () => {
      await onConfirm();
    }, confirmText);
    if (danger) {
      const sub = ov.querySelector('button[type="submit"]');
      if (sub) sub.className = "btn btn-danger";
    }
    const cancel = ov.querySelector('.foot .btn-ghost');
    if (cancel) cancel.focus();
    return ov;
  }

  const fld = (label, input) => {
    const target = input && input.matches && input.matches("input,select,textarea")
      ? input
      : (input && input.querySelector ? input.querySelector("input,select,textarea") : null);
    let fid = target ? target.id : "";
    if (target && !fid) {
      fid = nextId("dc-fld");
      target.id = fid;
    }
    return h("div", { class: "field" }, h("label", fid ? { for: fid, text: label } : { text: label }), input);
  };
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
    const totpId = nextId("dc-totp");
    const totpWrap = h("div", { class: "field hidden" },
      h("label", { for: totpId, text: "Doğrulama kodu (Authenticator)" }),
      inp("totp", { id: totpId, inputMode: "numeric", autocomplete: "one-time-code", maxLength: 6, pattern: "[0-9]{6}" })
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
      noValidate: true,
      on: {
        submit: async (e) => {
          e.preventDefault();
          err.textContent = "";
          const vErr = validateFormTr(form);
          if (vErr) { err.textContent = vErr; return; }
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
    const role = S.user && S.user.role;
    return NAV.filter(([k]) => {
      if (k === "clinics") return role === "owner";
      if (k === "kasa") return role !== "secretary";
      return true;
    });
  }

  function openMobileSheet() {
    document.querySelectorAll(".m-more-sheet").forEach((el) => el.remove());
    const prevFocus = document.activeElement;
    const curK = (location.hash.replace(/^#\//, "") || "overview").split("?")[0];
    const items = visibleNavItems().filter(([k]) => k !== "sep");
    const closeSheet = () => {
      document.removeEventListener("keydown", onKey);
      sheet.remove();
      if (prevFocus && typeof prevFocus.focus === "function") prevFocus.focus();
    };
    const onKey = (ev) => {
      if (ev.key === "Escape") {
        ev.stopImmediatePropagation();
        closeSheet();
      } else if (ev.key === "Tab") {
        handleTabTrap(ev, panel);
      }
    };
    const panel = h("div", { class: "m-more-panel" },
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
    );
    const sheet = h("div", {
      class: "m-more-sheet",
      role: "dialog",
      "aria-modal": "true",
      "aria-label": "Tüm modüller",
      on: { mousedown: (e) => { if (e.target === sheet) closeSheet(); } },
    }, panel);
    document.addEventListener("keydown", onKey);
    document.body.appendChild(sheet);
    const first = focusablesIn(panel)[0];
    if (first) first.focus();
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

  function setMain(...nodes) {
    const b = hqSwitchBanner();
    main.replaceChildren(...(b ? [b] : []), ...nodes.filter(Boolean));
  }

  async function route() {
    if (!S.user) return;
    if (activeDrawerCleanup) activeDrawerCleanup(false);
    const k = (location.hash.replace(/^#\//, "") || "overview").split("?")[0];
    document.querySelectorAll(".nav a").forEach((a) => a.classList.toggle("active", a.dataset.k === k));
    document.querySelectorAll(".m-bottom-nav a").forEach((a) => a.classList.toggle("active", a.dataset.mk === k));
    setMain(h("div", { class: "skeleton", role: "status", "aria-label": "Yükleniyor" }), h("div", { class: "empty", text: "Veriler yükleniyor..." }));
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
        kpi("Gelmeyenlerden kayıp", o.loss ? fmtTL(o.loss.noshow_30d_try) : "-", o.loss ? `Ortalama işlem ${fmtTL(o.loss.avg_ticket_try)} üzerinden` : "Finans yetkisi gerektirir", "loss"),
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
          h("div", { class: "kv" }, h("span", { text: "Hizmet" }), h("b", { text: o.month ? fmtTL(o.month.billed_try) : "-" }), h("span", { text: "Tahsilat" }), h("b", { text: o.month ? fmtTL(o.month.paid_try) : "-" })),
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
          const doUpdate = async () => {
            const r = await api(`/app/api/appointments/${a.id}/status`, { method: "POST", body: { status } });
            toast("Randevu durumu güncellendi");
            if (r && r.waitlist_offers !== undefined) toast(`Bekleme listesinden ${r.waitlist_offers} hastaya teklif gönderildi`);
            route();
          };
          if (status === "cancelled") {
            confirmModal(
              "Randevuyu iptal et",
              `${a.patient || "Hasta"} randevusu iptal edilsin ve boş koltuk bekleme listesine teklif edilsin mi?`,
              doUpdate,
              "İptal et"
            );
            return;
          }
          await run(doUpdate);
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
            live ? h("button", { class: "btn btn-sm btn-primary", type: "button", on: { click: () => editAppt(a) } }, "Saat Değiştir") : null,
            live && a.status === "booked" ? act(a, "confirmed", "Teyit") : null,
            live ? act(a, "done", "Geldi") : null,
            live ? act(a, "noshow", "Gelmedi", "btn-danger") : null,
            live ? act(a, "cancelled", "İptal", "btn-danger") : null,
            a.status === "cancelled" && new Date(a.starts_at) > new Date() ? act(a, "booked", "Geri al") : null,
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

  function createSlotPicker(dateIn, durIn, timeIn, chairIn) {
    const note = h("span", { class: "slot-picker-note", text: "Uygun saatler yükleniyor..." });
    const chips = h("div", { class: "slot-chips" });
    const wrap = h("div", { class: "slot-picker" },
      h("div", { class: "slot-picker-head" }, h("span", { text: "Uygun boş saatler" }), note),
      chips
    );
    let reqSeq = 0;
    const syncActive = () => {
      chips.querySelectorAll(".slot-chip").forEach((b) => {
        b.classList.toggle("active", b.dataset.time === timeIn.value);
      });
    };
    const refresh = async () => {
      const seq = ++reqSeq;
      const dateVal = dateIn.value;
      const durVal = Math.max(5, Math.min(480, Number(durIn.value || 30)));
      if (!dateVal) {
        note.textContent = "Önce tarih seçin";
        chips.replaceChildren();
        return;
      }
      note.textContent = "Yükleniyor...";
      try {
        const res = await api(`/app/api/appointments/available?date=${encodeURIComponent(dateVal)}&duration=${encodeURIComponent(durVal)}`);
        if (seq !== reqSeq) return;
        if (res.closed) {
          note.textContent = "Bu tarihte klinik kapalı.";
          chips.replaceChildren();
          return;
        }
        const slots = res.slots || [];
        if (!slots.length) {
          note.textContent = "Bu tarih ve süre için uygun boş saat yok.";
          chips.replaceChildren();
          return;
        }
        const wh = res.working_hours ? `Mesai: ${res.working_hours[0]}–${res.working_hours[1]} · ` : "";
        note.textContent = `${wh}${slots.length} uygun saat`;
        chips.replaceChildren(...slots.map((sl) => h("button", {
          type: "button",
          class: "slot-chip" + (timeIn.value === sl.time ? " active" : ""),
          "data-time": sl.time,
          title: `${sl.time}–${sl.end_time} · Boş koltuk: ${(sl.available_chairs || []).join(", ")}`,
          "aria-label": `Saat ${sl.time}, boş koltuk ${(sl.available_chairs || []).join(", ")}`,
          on: {
            click: () => {
              timeIn.value = sl.time;
              if (chairIn && sl.available_chairs && sl.available_chairs.length && !sl.available_chairs.includes(String(chairIn.value).trim())) {
                chairIn.value = sl.available_chairs[0];
              }
              syncActive();
            },
          },
        }, sl.time)));
      } catch (e) {
        if (seq === reqSeq) {
          note.textContent = e.message || "Uygun saatler alınamadı.";
          chips.replaceChildren();
        }
      }
    };
    dateIn.addEventListener("change", refresh);
    durIn.addEventListener("change", refresh);
    timeIn.addEventListener("input", syncActive);
    refresh();
    return wrap;
  }

  async function editAppt(a) {
    const staff = await run(() => api("/app/api/staff"));
    if (!staff) return;
    const doctors = staff.filter((s) => s.active && (s.role === "doctor" || s.role === "owner"));
    const dt = new Date(a.starts_at);
    const initTime = `${String(dt.getHours()).padStart(2, "0")}:${String(dt.getMinutes()).padStart(2, "0")}`;
    const dateIn = inp("date", { type: "date", required: true, value: ymd(dt) });
    const timeIn = inp("time", { type: "time", required: true, value: initTime, step: 300 });
    const durIn = inp("duration", { type: "number", min: 5, max: 480, value: a.duration_min || 30, required: true });
    const chairIn = inp("chair", { value: String(a.chair || "1"), required: true, maxLength: 10 });
    const slotPicker = createSlotPicker(dateIn, durIn, timeIn, chairIn);
    modal("Randevu Saatini / Bilgilerini Değiştir", [
      h("p", { style: "margin:0 0 12px;color:var(--ink-2);font-size:13.5px", text: `Hasta: ${a.patient || "İsimsiz hasta"}` }),
      h("div", { class: "row" }, fld("Tarih", dateIn), fld("Saat", timeIn)),
      slotPicker,
      h("div", { class: "row" }, fld("Süre (dk)", durIn), fld("Koltuk", chairIn)),
      fld("İşlem", inp("treatment", { required: true, minLength: 2, maxLength: 80, value: a.treatment || "" })),
      fld("Hekim", sel("doctor_id", [["", "Seçilmedi"], ...doctors.map((d) => [String(d.id), d.full_name])], a.doctor_id ? String(a.doctor_id) : "")),
    ], async (f) => {
      const body = {
        starts_at: new Date(`${f.get("date")}T${f.get("time")}`).toISOString(),
        duration_min: Number(f.get("duration")),
        chair: String(f.get("chair")),
        treatment: f.get("treatment"),
        doctor_id: f.get("doctor_id") ? Number(f.get("doctor_id")) : null,
      };
      await api(`/app/api/appointments/${a.id}`, { method: "PATCH", body });
      toast("Randevu güncellendi");
      S.day = sod(new Date(body.starts_at));
      route();
    }, "Değişikliği Kaydet");
  }

  const PATIENT_SOURCES = [
    ["instagram", "Instagram"],
    ["instagram_dm", "Instagram DM"],
    ["facebook", "Facebook"],
    ["tiktok", "TikTok"],
    ["google", "Google Arama"],
    ["google_ads", "Google Ads"],
    ["whatsapp", "WhatsApp"],
    ["whatsapp_direct", "WhatsApp Direkt"],
    ["website", "Web Sitesi"],
    ["campaign_form", "Kampanya Formu"],
    ["phone", "Telefon"],
    ["referral", "Referans / Tavsiye"],
    ["patient_referral", "Hasta Yönlendirmesi"],
    ["doctor_referral", "Hekim Yönlendirmesi"],
    ["walk_in", "Klinik Önünden Geçerken"],
    ["returning", "Eski / Tekrar Gelen Hasta"],
    ["corporate", "Kurumsal Anlaşma"],
    ["qr", "QR / Form"],
    ["other", "Diğer"],
  ];

  async function newAppt(preselectedPatientId) {
    const [patients, staff] = await Promise.all([
      api("/app/api/patients"),
      api("/app/api/staff"),
    ]);
    const doctors = staff.filter((s) => s.active && (s.role === "doctor" || s.role === "owner"));
    const newBox = h("div", null,
      h("div", { class: "row" },
        fld("Ad Soyad", inp("name", { placeholder: "Hasta adını giriniz", autocomplete: "off" })),
        fld("Telefon", inp("phone", { placeholder: "05xx xxx xx xx", autocomplete: "off" }))
      ),
      fld("Geliş Kaynağı", sel("source", PATIENT_SOURCES, "phone"))
    );
    const defaultPid = preselectedPatientId
      ? String(preselectedPatientId)
      : (patients[0] ? String(patients[0].id) : "");
    const pSel = sel("patient_id", [["", "+ Yeni hasta oluştur ve randevu bağla"], ...patients.map((p) => [String(p.id), p.display_name || `Hasta #${p.id}`])], defaultPid);
    const toggle = () => newBox.classList.toggle("hidden", pSel.value !== "");
    pSel.addEventListener("change", toggle);
    toggle();
    const dateIn = inp("date", { type: "date", required: true, value: ymd(S.day) });
    const timeIn = inp("time", { type: "time", required: true, value: "10:00", step: 300 });
    const durIn = inp("duration", { type: "number", min: 5, max: 480, value: 30, required: true });
    const chairIn = inp("chair", { value: "1", required: true, maxLength: 10 });
    const slotPicker = createSlotPicker(dateIn, durIn, timeIn, chairIn);
    modal("Yeni randevu", [
      fld("Hasta", pSel),
      newBox,
      h("div", { class: "row" }, fld("Tarih", dateIn), fld("Saat", timeIn)),
      slotPicker,
      h("div", { class: "row" }, fld("Süre (dk)", durIn), fld("Koltuk", chairIn)),
      fld("İşlem", inp("treatment", { required: true, minLength: 2, maxLength: 80, placeholder: "Muayene, implant, dolgu..." })),
      h("div", { class: "row" },
        fld("Hekim", sel("doctor_id", [["", "Seçilmedi"], ...doctors.map((d) => [String(d.id), d.full_name])], "")),
        fld("Tekrarlama (Seri Seans)", sel("repeat_freq", [
          ["none", "Tek Seferlik"],
          ["weekly", "Haftalık (3 Seans)"],
          ["biweekly", "2 Haftada Bir (3 Seans)"],
          ["monthly", "Aylık Kontrol (3 Seans)"],
        ], "none"))
      ),
    ], async (f) => {
      const startsIso = new Date(`${f.get("date")}T${f.get("time")}`).toISOString();
      const freq = f.get("repeat_freq") || "none";
      if (freq !== "none" && f.get("patient_id")) {
        const recRes = await api("/app/api/appointments/recurring", {
          method: "POST",
          body: {
            patient_id: Number(f.get("patient_id")),
            starts_at: startsIso,
            duration_min: Number(f.get("duration")),
            treatment: f.get("treatment"),
            chair: String(f.get("chair") || "1"),
            doctor_id: f.get("doctor_id") ? Number(f.get("doctor_id")) : null,
            frequency: freq,
            occurrences: 3,
          },
        });
        toast(`${recRes.created_count} seanslık tekrarlayan randevu serisi oluşturuldu`);
        S.day = sod(new Date(startsIso));
        route();
        return;
      }
      const body = {
        starts_at: startsIso,
        duration_min: Number(f.get("duration")),
        treatment: f.get("treatment"),
        chair: f.get("chair"),
        doctor_id: f.get("doctor_id") ? Number(f.get("doctor_id")) : null,
      };
      if (f.get("patient_id")) {
        body.patient_id = Number(f.get("patient_id"));
      } else {
        body.phone = f.get("phone");
        body.name = f.get("name");
        body.source = f.get("source") || "phone";
      }
      await api("/app/api/appointments", { method: "POST", body });
      toast("Randevu oluşturuldu");
      S.day = sod(new Date(body.starts_at));
      route();
    }, "Randevu oluştur");
  }

  // ---------------- hastalar (13 geliş kaynağı, hızlı sekreter kaydı, grup filtresi, CSV içe/dışa aktarım)
  VIEWS.patients = async () => {
    const params = new URLSearchParams(location.hash.split("?")[1] || "");
    const q = params.get("q") || "";
    const gid = params.get("group_id") || "";
    const src = params.get("source") || "";
    const qs = new URLSearchParams();
    if (q) qs.set("search", q);
    if (gid) qs.set("group_id", gid);
    if (src) qs.set("source", src);
    const [rows, groups, staff, banks] = await Promise.all([
      api(`/app/api/patients?${qs.toString()}`),
      api("/app/api/patient-groups").catch(() => []),
      api("/app/api/staff").catch(() => []),
      api("/app/api/bank-agreements").catch(() => []),
    ]);
    const doctors = staff.filter((s) => s.active && (s.role === "doctor" || s.role === "owner"));
    const search = inp("q", { class: "input search", placeholder: "Ad veya telefon ile ara", value: q, "aria-label": "Hasta ara" });
    const grpSel = sel("group_id", [["", "Tüm Gruplar"], ...groups.map((g) => [String(g.id), g.name])], gid);
    const srcSel = sel("source", [["", "Tüm Geliş Kaynakları"], ...PATIENT_SOURCES], src);
    const doSearch = () => {
      const nq = new URLSearchParams();
      if (search.value.trim()) nq.set("q", search.value.trim());
      if (grpSel.value) nq.set("group_id", grpSel.value);
      if (srcSel.value) nq.set("source", srcSel.value);
      location.hash = `#/patients${nq.toString() ? "?" + nq.toString() : ""}`;
    };
    search.addEventListener("keydown", (e) => { if (e.key === "Enter") doSearch(); });
    grpSel.addEventListener("change", doSearch);
    srcSel.addEventListener("change", doSearch);

    function openFastCreatePatientModal() {
      const nameIn = inp("name", { required: true, minLength: 2, placeholder: "Hasta adını giriniz", value: "", autocomplete: "off" });
      const phoneIn = inp("phone", { required: true, placeholder: "Telefon numarası giriniz (05xx xxx xx xx)", value: "", autocomplete: "off" });
      const dupBanner = h("div", { class: "cal-box hidden", role: "status", style: "border-color:var(--amber);background:#FFFBEB" });
      let dupTimer = null;
      phoneIn.addEventListener("input", () => {
        clearTimeout(dupTimer);
        const raw = phoneIn.value.trim();
        if (raw.replace(/\D/g, "").length < 10) {
          dupBanner.classList.add("hidden");
          dupBanner.replaceChildren();
          return;
        }
        dupTimer = setTimeout(async () => {
          try {
            const res = await api(`/app/api/patients/check-duplicate?phone=${encodeURIComponent(raw)}`);
            if (res && res.duplicate && res.patient) {
              dupBanner.classList.remove("hidden");
              dupBanner.replaceChildren(
                h("strong", { text: `Mükerrer Kayıt Uyarısı: Bu numara ${res.patient.display_name} (#${res.patient.id}) adına kayıtlı.` }),
                h("div", { class: "actions", style: "margin-top:6px" },
                  h("button", {
                    type: "button",
                    class: "btn btn-sm btn-primary",
                    on: {
                      click: () => {
                        document.querySelectorAll(".overlay .modal").forEach((m) => m.closest(".overlay")?.remove());
                        openPatient(res.patient.id);
                      },
                    },
                  }, "Mevcut Hasta Kartını Aç")
                )
              );
            } else {
              dupBanner.classList.add("hidden");
              dupBanner.replaceChildren();
            }
          } catch (_) { /* sessiz */ }
        }, 250);
      });

      let openApptAfterSave = false;
      const ov = modal("Hızlı Hasta Kaydı (Sekreter & Klinik Akışı)", [
        h("p", { style: "margin:0 0 8px;font-size:13px;color:var(--muted)", text: "Zorunlu alanlar: Ad Soyad, Telefon ve Geliş Kaynağı. Diğer detayları şimdi veya daha sonra hasta kartından ekleyebilirsiniz." }),
        h("div", { class: "row" },
          fld("Ad Soyad *", nameIn),
          fld("Telefon *", phoneIn)
        ),
        dupBanner,
        h("div", { class: "row" },
          fld("İlk Geliş Kaynağı *", sel("first_source", PATIENT_SOURCES, "phone")),
          fld("Sorumlu Doktor (Opsiyonel)", sel("primary_doctor_id", [["", "Seçilmedi"], ...doctors.map((d) => [String(d.id), d.full_name])], ""))
        ),
        h("div", { class: "row" },
          fld("Banka / Kurum Anlaşması (Opsiyonel)", sel("bank_agreement_id", [["", "Yok"], ...banks.filter((b) => b.active).map((b) => [String(b.id), `${b.bank_name} (%${b.discount_pct})`])], "")),
          fld("İletişim Dili (16 Dil)", sel("lang", LANG_OPTIONS, "tr"))
        ),
        h("div", { class: "row" },
          fld("Hasta Grubu / Etiket (Opsiyonel)", sel("group_id", [["", "Seçilmedi"], ...groups.map((g) => [String(g.id), `${g.name}${g.is_restricted ? " (Gerekçe zorunlu)" : ""}`])], "")),
          fld("Grup Gerekçesi / Kısa Not", inp("group_reason", { placeholder: "Özel takip veya etiket nedeni giriniz", value: "", autocomplete: "off" }))
        ),
        fld("Klinik Notu (Opsiyonel)", inp("notes", { placeholder: "Ek hasta bilgisi giriniz", value: "", autocomplete: "off" })),
      ], async (f) => {
        const body = {
          name: f.get("name"),
          phone: f.get("phone"),
          first_source: f.get("first_source") || "phone",
          lang: f.get("lang") || "tr",
          primary_doctor_id: f.get("primary_doctor_id") ? Number(f.get("primary_doctor_id")) : null,
          bank_agreement_id: f.get("bank_agreement_id") ? Number(f.get("bank_agreement_id")) : null,
          group_id: f.get("group_id") ? Number(f.get("group_id")) : null,
          group_reason: f.get("group_reason") || "",
          notes: f.get("notes") || "",
        };
        const r = await api("/app/api/patients", { method: "POST", body });
        if (r.duplicate) {
          toast(`Telefon numarası zaten kayıtlı (${r.existing_name || "#" + r.id}); mevcut hasta kartı açılıyor.`);
        } else {
          toast("Hasta kaydedildi");
        }
        await route();
        if (openApptAfterSave) {
          newAppt(r.id);
        } else {
          openPatient(r.id);
        }
      }, "Kaydet");

      const foot = ov.querySelector(".foot");
      if (foot) {
        const saveAndBookBtn = h("button", {
          type: "button",
          class: "btn btn-teal",
          on: {
            click: () => {
              openApptAfterSave = true;
              ov.querySelector("form")?.requestSubmit();
            },
          },
        }, "Kaydet ve Randevu Oluştur");
        foot.insertBefore(saveAndBookBtn, foot.lastElementChild);
      }
    }

    function openCsvImportModal() {
      const csvArea = h("textarea", {
        class: "input",
        name: "csv_text",
        rows: 6,
        required: true,
        placeholder: "ad,telefon,kaynak,dil\nAyşe Demir,05321112233,instagram,tr\nMehmet Kaya,05334445566,referral,tr",
      });
      modal("CSV ile Toplu Hasta İçe Aktar", [
        h("p", { style: "margin:0 0 8px;font-size:13px;color:var(--muted)", text: "Başlık satırı (ad,telefon,kaynak,dil) içeren CSV metnini yapıştırın. Mükerrer telefon numaraları otomatik atlanır." }),
        fld("CSV Verisi", csvArea),
      ], async (f) => {
        const res = await api("/app/api/patients/import-csv", {
          method: "POST",
          body: { csv_text: f.get("csv_text"), default_source: "other" },
        });
        toast(`İçe aktarma tamamlandı: ${res.imported} yeni, ${res.duplicates} mükerrer, ${res.errors_count || 0} hatalı`);
        route();
      }, "İçe Aktar");
    }

    setMain(
      header("Hastalar", "13 geliş kanalı, değiştirilemez ilk kaynak, sorumlu doktor, özel hasta grupları ve 10 kalem finans takibi.",
        search,
        grpSel,
        srcSel,
        h("button", { class: "btn btn-ghost", type: "button", on: { click: doSearch } }, "Filtrele"),
        h("button", { class: "btn btn-ghost", type: "button", on: { click: openCsvImportModal } }, "CSV İçe Aktar"),
        h("a", { class: "btn btn-ghost", href: "/app/api/export/patients.csv", download: "dentacore-hastalar.csv" }, "CSV İndir"),
        h("button", { class: "btn btn-cta", type: "button", on: { click: openFastCreatePatientModal } }, icon("plus"), "Hasta ekle")
      ),
      h("div", { class: "card card-flush" }, tblWrap(h("table", { class: "table" },
        h("thead", null, h("tr", null, ["Hasta & Gruplar", "İlk / Son Kaynak", "Sorumlu Doktor", "Dil", "Son randevu", "Kalan Borç / Bakiye", "İşlemler"].map((t, i) => h("th", { class: i === 5 ? "num" : "", text: t })))),
        h("tbody", null, rows.length ? rows.map((p) => h("tr", { class: "click", on: { click: () => openPatient(p.id) } },
          h("td", null,
            h("b", { text: p.display_name || `Hasta #${p.id}` }), " ",
            p.red_flag ? tag("Kırmızı bayrak", "red") : null,
            (p.groups || []).map((g) => tag(g.name, g.color || "teal"))
          ),
          h("td", null,
            tag(p.first_source_label || p.first_source || "WhatsApp", p.first_source === "instagram" ? "amber" : "teal"),
            p.last_source && p.last_source !== p.first_source ? h("small", { style: "display:block;color:var(--muted)", text: `Son: ${p.last_source_label || p.last_source}` }) : null
          ),
          h("td", { text: p.primary_doctor_name || "-" }),
          h("td", { text: (p.lang || "tr").toUpperCase() }),
          h("td", { text: p.last_appt ? fmtD(p.last_appt) : "-" }),
          h("td", { class: "num" },
            p.balance > 0 ? h("b", { style: "color:var(--amber-hover)", text: fmtTL(p.balance) }) : fmtTL(p.balance),
            p.planned_total > 0 ? h("small", { style: "display:block;color:var(--muted)", text: `Plan: ${fmtTL(p.planned_total)}` }) : null
          ),
          h("td", null, h("button", { class: "btn btn-sm btn-ghost", type: "button", "aria-label": `${p.display_name || "Hasta"} kartını aç`, on: { click: (ev) => { ev.stopPropagation(); openPatient(p.id); } } }, "Aç"))
        )) : h("tr", null, h("td", { colSpan: 7, class: "empty", text: "Hasta kaydı bulunamadı." })))
      ), "Hastalar tablosu"))
    );
  };

  let activeDrawerCleanup = null;
  let activeDrawerOpener = null;

  async function openPatient(pid, reveal) {
    if (!activeDrawerCleanup) activeDrawerOpener = document.activeElement;
    else activeDrawerCleanup(false);
    document.querySelectorAll(".drawer-wrap").forEach((el) => el.remove());
    const [p, odo, staffList, bankList, groupList, catalogList] = await Promise.all([
      run(() => api(`/app/api/patients/${pid}${reveal ? "?reveal=true" : ""}`)),
      api(`/app/api/patients/${pid}/odontogram`).catch(() => ({ records: [], summary: {} })),
      api("/app/api/staff").catch(() => []),
      api("/app/api/bank-agreements").catch(() => []),
      api("/app/api/patient-groups").catch(() => []),
      api("/app/api/treatment-catalog").catch(() => []),
    ]);
    if (!p) return;
    if (activeDrawerCleanup) activeDrawerCleanup(false);
    const doctors = staffList.filter((s) => s.active && (s.role === "doctor" || s.role === "owner"));
    const fin = p.finance_summary || {
      planned_total: 0, completed_gross: 0, discount_total: 0, completed_net_debt: 0,
      collected_paid: 0, pending_payment: 0, failed_payment: 0, refunded_total: 0,
      available_advance: 0, net_remaining_debt: Math.max(0, p.balance || 0),
    };

    const onKey = (ev) => {
      if (document.querySelector(".modal")) return;
      if (ev.key === "Escape") {
        ev.stopImmediatePropagation();
        close(true);
      } else if (ev.key === "Tab") {
        handleTabTrap(ev, drawer);
      }
    };
    const close = (restoreFocus = true) => {
      document.removeEventListener("keydown", onKey);
      wrap.remove();
      if (activeDrawerCleanup === close) activeDrawerCleanup = null;
      if (restoreFocus !== false) {
        const target = activeDrawerOpener;
        activeDrawerOpener = null;
        if (target && typeof target.focus === "function" && document.body.contains(target)) target.focus();
      }
    };
    activeDrawerCleanup = close;
    document.addEventListener("keydown", onKey);

    const consentNames = { kvkk_aydinlatma: "KVKK aydınlatma", saglik_verisi_acik_riza: "Sağlık verisi açık rıza", iletisim: "İletişim izni", yurt_disi_aktarim: "Yurt dışı aktarım" };
    const ledger = [
      ...p.charges.map((c) => ({ ...c, t: "Hizmet", info: `${c.description}${c.doctor_name ? " (" + c.doctor_name + ")" : ""}${c.discount > 0 ? " [İndirim: " + fmtTL(c.discount) + "]" : ""}` })),
      ...p.payments.map((c) => ({ ...c, t: c.status === "refunded" ? "İade" : "Tahsilat", info: `${c.method} (${c.status || "completed"})${c.is_advance ? " · Avans" : ""}` })),
    ].sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    const genIdem = (prefix) => `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;

    // --- FDI 52 Diş Anatomik Odontogram (32 Daimi 11-48 + 20 Süt 51-85, 5 Yüzey + Kuron/Kök Silüeti) ---
    const ODO_STATUS_META = {
      healthy: ["Sağlıklı", "#0F766E"],
      caries: ["Çürük", "#B91C1C"],
      planned: ["Planlanan Tedavi", "#C2410C"],
      treated: ["Tamamlandı", "#15803D"],
      filling: ["Dolgu (Tamamlandı)", "#0284C7"],
      implant: ["İmplant", "#0A2540"],
      crown: ["Zirkonyum / Kron", "#0D9488"],
      bridge: ["Köprü Restorasyonu", "#7C3AED"],
      root_canal: ["Kanal Tedavisi", "#854D0E"],
      extraction: ["Çekim Planı", "#9A3412"],
      missing: ["Eksik Diş", "#64748B"],
      postponed: ["Ertelendi", "#475569"],
      cancelled: ["İptal Edildi", "#94A3B8"],
    };
    const odoByTooth = {};
    (odo.records || []).forEach((r) => {
      (odoByTooth[r.tooth_fdi] = odoByTooth[r.tooth_fdi] || []).push(r);
    });

    function openToothModal(fdiNum, preSurface) {
      const existing = odoByTooth[fdiNum] || [];
      const idemKey = genIdem("odo");
      const procIn = inp("procedure_name", { required: true, minLength: 2, placeholder: "İşlem adını giriniz (örn. Kompozit Dolgu, İmplant, Köprü)", value: "" });
      const codeIn = inp("procedure_code", { placeholder: "İşlem kodu (örn. DOL-101)", value: "" });
      const amtIn = inp("amount", { type: "number", step: "0.01", min: "0", placeholder: "Brüt tutar giriniz (örn. 3000)", value: "" });
      const discIn = inp("discount", { type: "number", step: "0.01", min: "0", placeholder: "Özel indirim (TL)", value: "" });
      const statusSel = sel("status", Object.entries(ODO_STATUS_META).map(([k, [lbl]]) => [k, lbl]), "planned");
      const activeBanks = bankList.filter((b) => b.active);
      const bankSel = sel("bank_agreement_id", [["", "Anlaşma yok"], ...activeBanks.map((b) => [String(b.id), `${b.bank_name} (%${b.discount_pct})`])], p.bank_agreement_id ? String(p.bank_agreement_id) : "");
      const catSel = sel("catalog_pick", [["", "Katalogdan hazır tedavi seçin..."], ...catalogList.map((c) => [c.code, `${c.name} (${fmtTL(c.default_price)})`])], "");
      catSel.addEventListener("change", () => {
        const found = catalogList.find((c) => c.code === catSel.value);
        if (found) {
          procIn.value = found.name;
          codeIn.value = found.code;
          amtIn.value = String(found.default_price || 0);
          if (found.default_status && ODO_STATUS_META[found.default_status]) statusSel.value = found.default_status;
        }
      });

      modal(`Diş #${fdiNum} (FDI) · Adım Adım Tedavi, Hekim ve Fiyat Kaydı`, [
        p.primary_doctor_name ? h("p", { style: "margin:0 0 8px;font-size:12.5px;color:var(--teal)", text: `Hastanın Sorumlu Doktoru: ${p.primary_doctor_name} (Bu işlemde farklı bir 'Tedaviyi Yapan Doktor' seçseniz bile sorumlu doktor değişmez.)` }) : null,
        existing.length ? h("div", { class: "cal-box" },
          h("b", { text: `Diş #${fdiNum} Mevcut Kayıtlar (${existing.length})` }),
          existing.map((er) => h("div", { style: "display:flex;justify-content:space-between;align-items:center;gap:8px;margin-top:6px;font-size:13px;flex-wrap:wrap" },
            h("span", { text: `[${er.surface}] ${er.procedure_name} (${(ODO_STATUS_META[er.status] || [er.status])[0]}) · Hekim: ${er.doctor_name || "-"} · Brüt: ${fmtTL(er.gross_amount_try || er.amount_try || 0)}${er.discount_try > 0 ? " / İndirim: " + fmtTL(er.discount_try) : ""} · Net: ${fmtTL(er.amount_try || 0)}` }),
            S.user.role !== "secretary" ? h("div", { class: "actions" },
              er.status === "planned" ? h("button", {
                class: "btn btn-sm btn-teal",
                type: "button",
                on: {
                  click: async () => {
                    await api(`/app/api/patients/${pid}/odontogram/${er.id}`, { method: "PATCH", body: { status: "treated" } });
                    toast("Tedavi tamamlandı olarak güncellendi ve hasta borcuna işlendi");
                    document.querySelectorAll(".overlay .modal").forEach((m) => m.closest(".overlay")?.remove());
                    openPatient(pid, reveal);
                  },
                },
              }, "Tamamlandı Yap") : null,
              h("button", {
                class: "btn btn-sm btn-danger",
                type: "button",
                "aria-label": `Diş #${fdiNum} ${er.procedure_name} kaydını sil`,
                on: {
                  click: () => {
                    confirmModal(
                      "Diş kaydını sil",
                      `Diş #${fdiNum} (${er.surface} · ${er.procedure_name}) kaydı silinsin mi? Bu kayda bağlı hizmet borcu varsa silinmez, gerekçesiyle iptal edilir.`,
                      async () => {
                        await api(`/app/api/patients/${pid}/odontogram/${er.id}`, { method: "DELETE" });
                        toast("Diş kaydı silindi");
                        document.querySelectorAll(".overlay .modal").forEach((m) => m.closest(".overlay")?.remove());
                        openPatient(pid, reveal);
                      },
                      "Sil"
                    );
                  },
                },
              }, "Sil")
            ) : null
          ))
        ) : null,
        fld("Hazır Tedavi Kataloğu (Hızlı Seçim)", catSel),
        h("div", { class: "row" },
          fld("1. Diş Yüzeyi (5 Yüzey)", sel("surface", [
            ["FULL", "Tüm Diş (FULL)"],
            ["O", "Oklüzal / İnsizal (O)"],
            ["M", "Mezial (M)"],
            ["D", "Distal (D)"],
            ["B", "Bukkal / Vestibül (B)"],
            ["L", "Lingual / Palatinal (L)"],
          ], preSurface || "FULL")),
          fld("2. Klinik Durum", statusSel)
        ),
        h("div", { class: "row" },
          fld("3. İşlem / Tedavi Adı *", procIn),
          fld("4. Tedaviyi Yapan Doktor", sel("doctor_id", doctors.map((d) => [String(d.id), d.full_name]), String(S.user.id)))
        ),
        activeBanks.length ? h("div", { class: "row" },
          fld("Brüt Tutar (TL)", amtIn),
          fld("Kurum / Banka İndirimi", bankSel)
        ) : null,
        h("div", { class: "row" },
          !activeBanks.length ? fld("Brüt Tutar (TL)", amtIn) : null,
          fld("Özel İndirim (TL)", discIn),
          fld("İşlem Kodu", codeIn)
        ),
        fld("Klinik Not", inp("note", { placeholder: "Tedavi notu giriniz...", value: "" })),
        h("label", { class: "odo-check-row" },
          h("input", { type: "checkbox", name: "auto_charge", value: "1", checked: true }),
          h("span", { text: "Gerçekleşen (Tamamlandı/Dolgu/İmplant/Kron/Köprü/Kanal) işlemleri net tutarıyla hasta borcuna yaz. Planlanan/Ertelenen/İptal kayıtları borç oluşturmaz." })
        ),
      ], async (f) => {
        const odoRes = await api(`/app/api/patients/${pid}/odontogram`, {
          method: "POST",
          body: {
            tooth_fdi: fdiNum,
            surface: f.get("surface"),
            status: f.get("status"),
            procedure_code: f.get("procedure_code") || "",
            procedure_name: f.get("procedure_name"),
            amount: f.get("amount") || "0",
            discount: f.get("discount") || "0",
            bank_agreement_id: f.get("bank_agreement_id") ? Number(f.get("bank_agreement_id")) : null,
            use_patient_bank_agreement: Boolean(f.get("bank_agreement_id")),
            doctor_id: f.get("doctor_id") ? Number(f.get("doctor_id")) : null,
            note: f.get("note") || "",
            auto_charge: f.get("auto_charge") === "1",
            idempotency_key: idemKey,
          },
        });
        toast(odoRes && odoRes.charge_skipped ? `Diş #${fdiNum} tedavi planına eklendi (borç yazılmadı)` : `Diş #${fdiNum} işlemi kaydedildi (Net: ${fmtTL(odoRes.net_amount || 0)})`);
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
      const isUpper = Math.floor(fdiNum / 10) in { 1: 1, 2: 1, 5: 1, 6: 1 };

      const svg = document.createElementNS(SVG, "svg");
      svg.setAttribute("viewBox", "0 0 36 46");
      svg.setAttribute("class", "odo-svg");
      svg.setAttribute("aria-hidden", "true");

      // Anatomik kök silüeti
      const rootPath = document.createElementNS(SVG, "path");
      rootPath.setAttribute("d", isUpper ? "M11,10 L14,1 L18,7 L22,1 L25,10 Z" : "M11,36 L14,45 L18,39 L22,45 L25,36 Z");
      rootPath.setAttribute("fill", topRec && ["implant", "root_canal"].includes(topRec.status) ? stColor : "#E2E8F0");
      rootPath.setAttribute("stroke", recs.length ? stColor : "#94A3B8");
      rootPath.setAttribute("stroke-width", "1.1");
      svg.appendChild(rootPath);

      const yOff = isUpper ? 9 : 1;
      const addSurf = (tagN, attrs, sCode) => {
        const el = document.createElementNS(SVG, tagN);
        for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
        el.setAttribute("fill", surfMap[sCode] || fullCol || "#F8FAFC");
        el.setAttribute("stroke", recs.length ? stColor : "#64748B");
        el.setAttribute("stroke-width", "1.4");
        if (topRec && topRec.status === "planned") el.setAttribute("stroke-dasharray", "2,1");
        svg.appendChild(el);
      };
      addSurf("polygon", { points: `3,${3 + yOff} 33,${3 + yOff} 24,${12 + yOff} 12,${12 + yOff}` }, "B");
      addSurf("polygon", { points: `3,${33 + yOff} 33,${33 + yOff} 24,${24 + yOff} 12,${24 + yOff}` }, "L");
      addSurf("polygon", { points: `3,${3 + yOff} 12,${12 + yOff} 12,${24 + yOff} 3,${33 + yOff}` }, "M");
      addSurf("polygon", { points: `33,${3 + yOff} 24,${12 + yOff} 24,${24 + yOff} 33,${33 + yOff}` }, "D");
      addSurf("rect", { x: "12", y: String(12 + yOff), width: "12", height: "12", rx: "2" }, "O");

      const toothLabel = recs.length
        ? `Diş #${fdiNum}: ${recs.map((x) => `${x.surface} ${x.procedure_name} (${x.status})`).join(", ")}`
        : `Diş #${fdiNum} işlem ekle`;
      return h("button", {
        type: "button",
        class: "odo-tooth" + (recs.length ? " has-rec" : ""),
        "data-tooth": String(fdiNum),
        title: toothLabel,
        "aria-label": toothLabel,
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
          h("strong", { text: "ISO 3950 FDI 52 Diş Anatomik Odontogram (Kuron + Kök & 5 Yüzey M/D/O/B/L)" }),
          h("small", { text: `Tamamlanan: ${odo.summary?.treated_count || 0} · Planlanan: ${odo.summary?.planned_count || 0} · Ertelenen: ${odo.summary?.postponed_count || 0}` })
        ),
        h("div", { class: "actions" }, btnPerm, btnPedo)
      ),
      permGrid,
      pedoGrid
    );

    // Dosya / Röntgen / DICOM / Fotoğraf (Öncesi-Sonrası) / PDF yükleme modalı (XHR ilerleme çubuğu + iptal + tekrar dene)
    function openMediaUploadModal() {
      const fileIn = h("input", { class: "input", type: "file", name: "file", required: true, accept: ".jpg,.jpeg,.png,.webp,.pdf,.dcm,image/*,application/pdf,application/dicom" });
      const progBar = h("i", { style: "width:0%;display:block;height:8px;background:var(--teal);border-radius:4px" });
      const progWrap = h("div", { class: "bar hidden", style: "margin:8px 0" }, progBar);
      const progText = h("div", { style: "font-size:12.5px;color:var(--muted)" });
      let activeXhr = null;
      const cancelUploadBtn = h("button", {
        type: "button",
        class: "btn btn-sm btn-danger hidden",
        on: {
          click: () => {
            if (activeXhr) {
              activeXhr.abort();
              activeXhr = null;
              progText.textContent = "Yükleme kullanıcı tarafından iptal edildi. Tekrar deneyebilirsiniz.";
              cancelUploadBtn.classList.add("hidden");
            }
          },
        },
      }, "Yüklemeyi İptal Et");

      modal("Röntgen / DICOM / Fotoğraf (Öncesi-Sonrası) / PDF Yükle", [
        h("p", { style: "margin:0 0 8px;font-size:12.5px;color:var(--muted)", text: "Desteklenen türler: JPEG, PNG, WebP, PDF ve DICOM (.dcm). Maksimum boyut: 15 MB. Otomatik kalite kontrolü tıbbi teşhis koymaz; yalnızca teknik netlik/parlaklık ölçer." }),
        fld("Dosya Seçin *", fileIn),
        h("div", { class: "row" },
          fld("Kategori", sel("category", [["xray", "Röntgen / Panoramik / DICOM"], ["photo", "Ağız İçi / Klinik Fotoğraf"], ["document", "PDF / Onam / Belge"]], "xray")),
          fld("Aşama (Öncesi / Sonrası)", sel("stage", [["general", "Genel"], ["before", "Tedavi Öncesi (Before)"], ["after", "Tedavi Sonrası (After)"]], "general"))
        ),
        fld("Açıklama / Not", inp("note", { placeholder: "Dosya notu giriniz...", value: "" })),
        progWrap,
        progText,
        cancelUploadBtn,
      ], async (f) => {
        const fileObj = fileIn.files && fileIn.files[0];
        if (!fileObj) throw new Error("Lütfen yüklenecek dosyayı seçin.");
        if (fileObj.size > 15 * 1024 * 1024) throw new Error("Dosya boyutu 15 MB sınırını aşıyor.");
        const fd = new FormData();
        fd.append("file", fileObj);
        fd.append("category", f.get("category") || "xray");
        fd.append("stage", f.get("stage") || "general");
        fd.append("note", f.get("note") || "");
        progWrap.classList.remove("hidden");
        cancelUploadBtn.classList.remove("hidden");
        progBar.style.width = "5%";
        progText.textContent = "Yükleniyor (%0)...";

        await new Promise((resolve, reject) => {
          const xhr = new XMLHttpRequest();
          activeXhr = xhr;
          xhr.open("POST", `/app/api/patients/${pid}/media`);
          xhr.setRequestHeader("X-CSRF-Token", S.csrf);
          xhr.upload.onprogress = (ev) => {
            if (ev.lengthComputable) {
              const pct = Math.round((ev.loaded / ev.total) * 100);
              progBar.style.width = `${pct}%`;
              progText.textContent = `Yükleniyor (%${pct})...`;
            }
          };
          xhr.onload = () => {
            activeXhr = null;
            cancelUploadBtn.classList.add("hidden");
            if (xhr.status >= 200 && xhr.status < 300) {
              resolve(JSON.parse(xhr.responseText || "{}"));
            } else {
              let errMsg = "Dosya yüklenemedi";
              try { errMsg = JSON.parse(xhr.responseText).detail || errMsg; } catch (_) {}
              reject(new Error(errMsg));
            }
          };
          xhr.onerror = () => {
            activeXhr = null;
            cancelUploadBtn.classList.add("hidden");
            reject(new Error("Ağ hatası oluştu; lütfen tekrar deneyin."));
          };
          xhr.onabort = () => {
            activeXhr = null;
            reject(new Error("Yükleme iptal edildi."));
          };
          xhr.send(fd);
        });
        toast("Dosya şifrelenerek hasta kartına kaydedildi");
        openPatient(pid, reveal);
      }, "Yükle");
    }

    // Hasta Bilgisi / Sorumlu Doktor / İlk Kaynak Düzenleme Modalı
    const activeBanksForPatient = bankList.filter((b) => b.active);
    function openEditPatientModal() {
      const manualChk = h("input", { type: "checkbox", name: "manual_first_source_change", value: "1" });
      modal("Hasta Bilgileri, Sorumlu Doktor & İlk Kaynak Düzenle", [
        h("div", { class: "row" },
          fld("Ad Soyad", inp("name", { required: true, minLength: 2, value: p.display_name || p.name || "" })),
          fld("İletişim Dili", sel("lang", LANG_OPTIONS, p.lang || "tr"))
        ),
        h("div", { class: "row" },
          fld("Sorumlu Doktor (Hasta Sahibi Hekim)", sel("primary_doctor_id", [["", "Seçilmedi"], ...doctors.map((d) => [String(d.id), d.full_name])], p.primary_doctor_id ? String(p.primary_doctor_id) : "")),
          activeBanksForPatient.length ? fld("Kurum / Banka Anlaşması", sel("bank_agreement_id", [["", "Yok"], ...activeBanksForPatient.map((b) => [String(b.id), `${b.bank_name} (%${b.discount_pct})`])], p.bank_agreement_id ? String(p.bank_agreement_id) : "")) : null
        ),
        h("div", { class: "row" },
          fld("Son Temas Kaynağı", sel("last_source", PATIENT_SOURCES, p.last_source || p.first_source || "whatsapp")),
          fld("İlk Geliş Kaynağı (Değiştirilemez / Loglu)", sel("first_source", PATIENT_SOURCES, p.first_source || "whatsapp"))
        ),
        h("label", { class: "odo-check-row" },
          manualChk,
          h("span", { text: "İlk geliş kaynağını manuel olarak değiştirmeyi onayla (eski değer, yeni değer ve kullanıcı denetim izine kaydedilir)" })
        ),
        fld("İlk Kaynak Değişiklik Gerekçesi", inp("first_source_reason", { placeholder: "Yalnız ilk kaynak değiştiriliyorsa gerekçe giriniz", value: "" })),
        fld("Notlar", inp("notes", { value: p.notes || "", placeholder: "Hasta notu giriniz" })),
      ], async (f) => {
        await api(`/app/api/patients/${pid}`, {
          method: "PATCH",
          body: {
            name: f.get("name"),
            lang: f.get("lang"),
            primary_doctor_id: f.get("primary_doctor_id") ? Number(f.get("primary_doctor_id")) : null,
            clear_primary_doctor: !f.get("primary_doctor_id"),
            bank_agreement_id: f.get("bank_agreement_id") ? Number(f.get("bank_agreement_id")) : null,
            clear_bank_agreement: !f.get("bank_agreement_id"),
            last_source: f.get("last_source"),
            first_source: f.get("first_source"),
            manual_first_source_change: f.get("manual_first_source_change") === "1",
            first_source_reason: f.get("first_source_reason") || "",
            notes: f.get("notes") || "",
          },
        });
        toast("Hasta bilgileri güncellendi");
        route();
        openPatient(pid, reveal);
      }, "Güncelle");
    }

    function openAddGroupModal() {
      modal("Hastaya Grup / Özel Takip Etiketi Ekle", [
        h("p", { style: "margin:0 0 8px;font-size:12.5px;color:var(--muted)", text: "Etik kural: Küçük düşürücü veya ayrımcı ifadeler sistem tarafından engellenir. Özel dikkat / ödeme takibi gruplarında nesnel gerekçe zorunludur." }),
        fld("Grup Seçin", sel("group_id", groupList.map((g) => [String(g.id), `${g.name}${g.is_restricted ? " (Gerekçe zorunlu)" : ""}`]), groupList[0] ? String(groupList[0].id) : "")),
        fld("Atama Gerekçesi / Açıklama", inp("reason", { required: true, minLength: 3, placeholder: "Örn: 2 kez habersiz randevuya gelmedi, randevu öncesi teyit alınmalı", value: "" })),
      ], async (f) => {
        await api(`/app/api/patients/${pid}/groups`, {
          method: "POST",
          body: { group_id: Number(f.get("group_id")), reason: f.get("reason") || "" },
        });
        toast("Hasta grubu eklendi");
        openPatient(pid, reveal);
      }, "Gruba Ekle");
    }

    const drawer = h("div", { class: "drawer", role: "dialog", "aria-modal": "true", "aria-label": p.name || `Hasta #${p.id}` },
      h("div", { class: "top" },
        h("div", null,
          h("h2", { text: p.name || `Hasta #${p.id}` }),
          h("p", { text: `#${p.id} · İlk Kaynak: ${p.first_source_label || p.first_source || "WhatsApp"} · Son Kaynak: ${p.last_source_label || p.last_source || "-"} · ${(p.lang || "tr").toUpperCase()}${p.active === false ? " · ARŞİVLİ" : ""}` })
        ),
        h("div", { class: "actions" },
          h("button", { class: "btn btn-sm btn-ghost", type: "button", on: { click: openEditPatientModal } }, "Bilgileri Düzenle"),
          S.user.role !== "secretary" ? h("button", {
            class: `btn btn-sm ${p.active === false ? "btn-ghost" : "btn-danger"}`,
            type: "button",
            on: {
              click: async () => {
                if (p.active === false) {
                  const r = await run(() => api(`/app/api/patients/${pid}/unarchive`, { method: "POST" }), "Hasta aktifleştirildi");
                  if (r !== null) { close(); route(); }
                  return;
                }
                confirmModal(
                  "Hastayı arşivle",
                  `${p.name || `Hasta #${p.id}`} arşivlensin mi? Arşivlenen hastalar varsayılan listeden gizlenir.`,
                  async () => {
                    await api(`/app/api/patients/${pid}/archive`, { method: "POST" });
                    toast("Hasta arşivlendi");
                    close();
                    route();
                  },
                  "Arşivle"
                );
              },
            },
          }, p.active === false ? "Aktifleştir" : "Arşivle") : null,
          h("button", { class: "btn btn-ghost btn-sm", type: "button", on: { click: close } }, "Kapat")
        )
      ),
      h("div", { class: "kv" },
        h("span", { text: "Telefon" }),
        h("div", { style: "display:flex;align-items:center;gap:6px;flex-wrap:wrap" },
          h("b", { class: "mono", text: p.phone }),
          !reveal && p.channel !== "ig" ? h("button", { class: "btn btn-sm btn-ghost", type: "button", on: { click: () => openPatient(pid, true) } }, "Göster") : null,
          p.tel_href ? h("a", { class: "btn btn-sm btn-teal", href: p.tel_href }, "Telefonla Ara") : null
        ),
        h("span", { text: "Sorumlu Doktor" }),
        h("b", { text: p.primary_doctor_name || "Atanmadı" }),
        p.bank_agreement_name || activeBanksForPatient.length ? h("span", { text: "Kurum / Banka Anlaşması" }) : null,
        p.bank_agreement_name || activeBanksForPatient.length ? h("b", { text: p.bank_agreement_name ? `${p.bank_agreement_name} (%${p.bank_discount_pct || 0})` : "Yok" }) : null,
        h("span", { text: "Kayıt Tarihi / Kaydeden" }),
        h("span", { text: `${p.created_at ? fmtDT(p.created_at) : "-"} · ${p.created_by_name || "Sistem"}` }),
        h("span", { text: "Gruplar & Özel Etiketler" }),
        h("div", { style: "display:flex;align-items:center;gap:6px;flex-wrap:wrap" },
          (p.groups || []).length ? (p.groups || []).map((g) => tag(`${g.name}${g.reason ? ": " + g.reason : ""}`, g.color || "teal")) : h("span", { style: "color:var(--muted)", text: "Grup yok" }),
          h("button", { class: "btn btn-sm btn-ghost", type: "button", on: { click: openAddGroupModal } }, "+ Grup Ekle")
        )
      ),
      // 10 Kalemlik Finansal Özet Kutusu (Bölüm 11)
      h("div", { class: "cal-box", style: "margin:10px 0" },
        h("div", { style: "display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px;margin-bottom:6px" },
          h("b", { text: "10 Kalem Hasta Finans & Muhasebe Özeti (Kuruş Kesinliğinde)" }),
          fin.available_advance > 0 && fin.net_remaining_debt > 0 ? h("button", {
            class: "btn btn-sm btn-teal",
            type: "button",
            on: {
              click: async () => {
                const r = await run(() => api(`/app/api/patients/${pid}/settle-advance`, { method: "POST", body: {} }), "Avans açık borca mahsup edildi");
                if (r) openPatient(pid, reveal);
              },
            },
          }, "Avansı Borca Mahsup Et") : null
        ),
        h("div", { class: "kv", style: "font-size:13px" },
          h("span", { text: "1. Planlanan Tedavi (Borç Oluşturmaz)" }), h("b", { text: fmtTL(fin.planned_total) }),
          h("span", { text: "2. Gerçekleşen Brüt Hizmet" }), h("b", { text: fmtTL(fin.completed_gross) }),
          h("span", { text: "3. Toplam İndirim" }), h("b", { text: fmtTL(fin.discount_total) }),
          h("span", { text: "4. Gerçekleşen Net Hizmet Borcu" }), h("b", { text: fmtTL(fin.completed_net_debt) }),
          h("span", { text: "5. Başarılı Tahsilat" }), h("b", { style: "color:var(--green)", text: fmtTL(fin.collected_paid) }),
          h("span", { text: "6. Bekleyen Ödeme (Borçtan Düşülmez)" }), h("span", { text: fmtTL(fin.pending_payment) }),
          h("span", { text: "7. Başarısız Ödeme (Borçtan Düşülmez)" }), h("span", { text: fmtTL(fin.failed_payment) }),
          h("span", { text: "8. İade Toplamı" }), h("span", { text: fmtTL(fin.refunded_total) }),
          h("span", { text: "9. Kullanılabilir Avans" }), h("b", { style: "color:var(--teal)", text: fmtTL(fin.available_advance) }),
          h("span", { text: "10. Net Kalan Borç" }), h("b", { style: fin.net_remaining_debt > 0 ? "color:var(--amber-hover)" : "", text: fmtTL(fin.net_remaining_debt) })
        )
      ),
      h("div", { class: "actions", style: "flex-wrap:wrap" },
        h("button", {
          class: "btn btn-sm btn-primary",
          type: "button",
          on: {
            click: () => {
              const chgIdem = genIdem("chg");
              modal("Hizmet ekle", [
                fld("Açıklama", inp("description", { required: true, minLength: 2, placeholder: "Zirkonyum kron x2", value: "" })),
                h("div", { class: "row" },
                  fld("Brüt Tutar (TL)", inp("amount", { type: "number", step: "0.01", min: "0.01", required: true, placeholder: "Örn. 10000", value: "" })),
                  fld("Tedaviyi Yapan Doktor", sel("doctor_id", [["", "Seçilmedi"], ...doctors.map((d) => [String(d.id), d.full_name])], String(S.user.id)))
                ),
                h("div", { class: "row" },
                  activeBanksForPatient.length ? fld("Kurum / Banka Anlaşması", sel("bank_agreement_id", [["", "Yok"], ...activeBanksForPatient.map((b) => [String(b.id), `${b.bank_name} (%${b.discount_pct})`])], p.bank_agreement_id ? String(p.bank_agreement_id) : "")) : null,
                  fld("Özel İndirim (TL)", inp("discount", { type: "number", step: "0.01", min: "0", placeholder: "0", value: "" }))
                ),
              ], async (f) => {
                await api("/app/api/charges", {
                  method: "POST",
                  body: {
                    patient_id: pid,
                    description: f.get("description"),
                    amount: f.get("amount"),
                    discount: f.get("discount") || "0",
                    bank_agreement_id: f.get("bank_agreement_id") ? Number(f.get("bank_agreement_id")) : null,
                    doctor_id: f.get("doctor_id") ? Number(f.get("doctor_id")) : null,
                    idempotency_key: chgIdem,
                  },
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
              const remDebt = Number(fin.net_remaining_debt || Math.max(0, p.balance || 0));
              const amtIn = inp("amount", { type: "number", step: "0.01", min: "0.01", required: true, value: remDebt > 0 ? remDebt : "", placeholder: "Tahsilat tutarı giriniz" });
              const advCheck = h("input", { type: "checkbox", name: "allow_advance", value: "1", checked: remDebt <= 0 });
              const advBox = h("label", { class: "odo-check-row" },
                advCheck,
                h("span", { text: `Bakiye üstü / Avans (Ön Ödeme) tahsilatı olarak onayla (Net Kalan Borç: ${fmtTL(remDebt)})` })
              );
              modal("Tahsilat al", [
                fld("Tutar (TL)", amtIn),
                h("div", { class: "row" },
                  fld("Yöntem", sel("method", [
                    ["kart", "Kart"],
                    ["kredi_karti", "Kredi Kartı"],
                    ["banka_karti", "Banka Kartı"],
                    ["nakit", "Nakit"],
                    ["havale", "Havale / EFT"],
                    ["taksitli", "Taksitli Ödeme"],
                    ["diger", "Diğer"],
                  ], "kart")),
                  fld("Ödeme Durumu", sel("status", [
                    ["completed", "Tamamlandı (Borçtan Düşer)"],
                    ["pending", "Bekleyen (Borçtan Düşülmez)"],
                    ["failed", "Başarısız (Borçtan Düşülmez)"],
                  ], "completed"))
                ),
                advBox,
              ], async (f) => {
                await api("/app/api/payments", {
                  method: "POST",
                  body: {
                    patient_id: pid,
                    amount: f.get("amount"),
                    method: f.get("method"),
                    status: f.get("status") || "completed",
                    idempotency_key: payIdem,
                    allow_advance: f.get("allow_advance") === "1",
                  },
                });
                toast("Ödeme kaydı işlendi");
                openPatient(pid, reveal);
              });
            },
          },
        }, "Tahsilat al"),
        h("button", { class: "btn btn-sm btn-teal", type: "button", on: { click: openMediaUploadModal } }, "Röntgen / Görsel Yükle"),
        h("button", {
          class: "btn btn-sm btn-ghost",
          type: "button",
          on: {
            click: async () => {
              const r = await run(() => api(`/app/api/patients/${pid}/treatment-consents`, { method: "POST", body: {} }), "Dijital tedavi planı onam bağlantısı oluşturuldu");
              if (r && r.url) {
                openPatient(pid, reveal);
                modal("Dijital Tedavi Planı Onayı Bağlantısı", [
                  h("p", { style: "margin:0 0 8px;font-size:13px;color:var(--muted)", text: r.legal_notice_tr || "Bu onay 5070 sayılı Nitelikli Elektronik İmza değildir; zaman damgalı dijital form onayıdır." }),
                  h("code", { style: "display:block;word-break:break-all;padding:10px;background:#f1f5f9;border-radius:8px;margin-bottom:10px", text: r.url }),
                  h("div", { class: "actions" },
                    h("button", { class: "btn btn-sm btn-primary", type: "button", on: { click: () => copyText(r.url, "Tedavi onam bağlantısı kopyalandı") } }, icon("copy"), "Kopyala"),
                    h("a", { class: "btn btn-sm btn-ghost", href: r.url, target: "_blank", rel: "noopener noreferrer" }, "Onam Sayfasını Aç")
                  ),
                ], async () => true, "Tamam");
              }
            },
          },
        }, "Tedavi Onamı Oluştur"),
        h("button", {
          class: "btn btn-sm btn-ghost",
          type: "button",
          on: {
            click: async () => {
              const r = await run(() => api(`/app/api/patients/${pid}/anamnesis`, { method: "POST" }), "Anamnez formu oluşturuldu");
              if (r) {
                openPatient(pid, reveal);
                if (r.link) {
                  const delivNote = r.dry_run
                    ? "Kuru çalıştırma (dry_run): Mesaj konuşma kaydına işlendi. Bağlantıyı kopyalayıp hastaya iletebilirsiniz."
                    : r.delivery === "sent"
                      ? "Bağlantı hastaya WhatsApp ile iletildi."
                      : `Gönderim durumu: ${r.delivery || "kaydedildi"}${r.error ? " (" + r.error + ")" : ""}`;
                  const ov = modal("Anamnez Formu Bağlantısı", [
                    h("p", { style: "margin:0 0 8px;color:var(--muted);font-size:13.5px", text: delivNote }),
                    h("code", { style: "display:block;word-break:break-all;padding:10px;background:#f1f5f9;border-radius:8px;margin-bottom:10px", text: r.link }),
                    h("div", { class: "actions" },
                      h("button", { class: "btn btn-sm btn-primary", type: "button", on: { click: () => copyText(r.link, "Anamnez bağlantısı kopyalandı") } }, icon("copy"), "Kopyala"),
                      h("a", { class: "btn btn-sm btn-ghost", href: r.link, target: "_blank", rel: "noopener noreferrer" }, "Formu Aç")
                    ),
                  ], async () => true, "Tamam");
                  const fc = ov.querySelector(".foot .btn-ghost");
                  if (fc) fc.remove();
                }
              }
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
        }, "Bekleme listesi"),
        h("button", {
          class: "btn btn-sm btn-ghost",
          type: "button",
          on: {
            click: () => modal("Periodontal Ölçüm Kaydı (6 Nokta PD / BOP)", [
              h("div", { class: "row" },
                fld("Diş Numarası (FDI)", inp("fdi", { type: "number", min: 11, max: 85, value: "16", required: true })),
                fld("Cep Derinlikleri (6 nokta mm, virgülle)", inp("pd", { value: "3,4,3,3,5,4", required: true }))
              ),
              h("div", { class: "row" },
                fld("Diş Eti Çekilmesi (6 nokta mm)", inp("gm", { value: "0,1,0,0,1,0", required: true })),
                fld("Mobilite (0-3) / Furkasyon (0-3)", inp("mob_furc", { value: "1,0", required: true }))
              ),
              fld("Kanamalı Nokta Sayısı (0-6)", inp("bop_cnt", { type: "number", min: 0, max: 6, value: "2", required: true })),
              fld("Hekim Klinik Notu", inp("doctor_note", { placeholder: "Bölgesel derin cep ve BOP gözlendi", value: "" })),
            ], async (f) => {
              const fdi = String(f.get("fdi") || "16").trim();
              const pdArr = String(f.get("pd") || "2,2,2,2,2,2").split(",").map((x) => Number(x.trim()) || 2).slice(0, 6);
              while (pdArr.length < 6) pdArr.push(2);
              const gmArr = String(f.get("gm") || "0,0,0,0,0,0").split(",").map((x) => Number(x.trim()) || 0).slice(0, 6);
              while (gmArr.length < 6) gmArr.push(0);
              const [mob, furc] = String(f.get("mob_furc") || "0,0").split(",").map((x) => Number(x.trim()) || 0);
              const bopCnt = Math.min(6, Math.max(0, Number(f.get("bop_cnt") || 0)));
              const bopArr = [0, 1, 2, 3, 4, 5].map((i) => i < bopCnt);
              await api(`/app/api/patients/${pid}/periodontal`, {
                method: "POST",
                body: {
                  teeth: { [fdi]: { pd: pdArr, gm: gmArr, bop: bopArr, plaque: bopArr, mobility: mob || 0, furcation: furc || 0 } },
                  doctor_approved: true,
                  doctor_note: f.get("doctor_note") || "",
                },
              });
              toast("Periodontal ölçüm kaydedildi");
              openPatient(pid, reveal);
            }, "Kaydet"),
          },
        }, "Periodontal Ölçüm"),
        h("button", {
          class: "btn btn-sm btn-ghost",
          type: "button",
          on: {
            click: () => modal("Laboratuvar İş Emri Oluştur", [
              h("div", { class: "row" },
                fld("Laboratuvar Adı *", inp("lab_name", { required: true, minLength: 2, placeholder: "Ege Dental Lab", value: "" })),
                fld("İşlem / Protez Türü *", inp("procedure_type", { required: true, minLength: 2, placeholder: "Zirkonyum Üst Yapı", value: "" }))
              ),
              h("div", { class: "row" },
                fld("Diş (FDI)", inp("tooth_fdi", { type: "number", min: 11, max: 85, value: "26" })),
                fld("Renk (Vita)", inp("shade_color", { value: "A2" }))
              ),
              h("div", { class: "row" },
                fld("Teslim Tarihi *", inp("due_date", { type: "date", required: true, value: new Date(Date.now() + 5 * 86400000).toISOString().slice(0, 10) })),
                fld("Lab Maliyeti (TL)", inp("cost", { type: "number", step: "0.01", min: "0", value: "0" }))
              ),
              fld("Not", inp("note", { placeholder: "Oklüzal temas kontrolü", value: "" })),
            ], async (f) => {
              await api("/app/api/lab-orders", {
                method: "POST",
                body: {
                  patient_id: pid,
                  tooth_fdi: f.get("tooth_fdi") ? Number(f.get("tooth_fdi")) : null,
                  lab_name: f.get("lab_name"),
                  procedure_type: f.get("procedure_type"),
                  shade_color: f.get("shade_color") || "A2",
                  due_date: f.get("due_date"),
                  cost: f.get("cost") || "0",
                  note: f.get("note") || "",
                },
              });
              toast("Laboratuvar iş emri oluşturuldu");
              openPatient(pid, reveal);
            }, "Oluştur"),
          },
        }, "Lab Emri"),
        h("button", {
          class: "btn btn-sm btn-ghost",
          type: "button",
          on: {
            click: () => modal("İmplant & Lot / Barkod Kaydı", [
              h("div", { class: "row" },
                fld("Diş (FDI) *", inp("tooth_fdi", { type: "number", min: 11, max: 85, value: "36", required: true })),
                fld("Marka *", inp("brand", { required: true, placeholder: "Straumann / Nobel / Osstem", value: "" }))
              ),
              h("div", { class: "row" },
                fld("Model *", inp("model", { required: true, placeholder: "BLT SLA", value: "" })),
                fld("Çap × Boy (mm)", inp("dims", { value: "4.1x10", required: true }))
              ),
              h("div", { class: "row" },
                fld("Lot Numarası *", inp("lot_number", { required: true, placeholder: "LOT-2026-991", value: "" })),
                fld("Seri / ÜTS Barkod", inp("uts_barcode", { placeholder: "869...", value: "" }))
              ),
              h("div", { class: "row" },
                fld("SKT", inp("expiry_date", { type: "date", value: "" })),
                fld("Tedarikçi", inp("supplier", { placeholder: "Yetkili Distribütör", value: "" }))
              ),
            ], async (f) => {
              const [dmm, lmm] = String(f.get("dims") || "4.1x10").toLowerCase().split("x").map((x) => Number(x.trim()) || 4.1);
              await api("/app/api/implants", {
                method: "POST",
                body: {
                  patient_id: pid,
                  tooth_fdi: Number(f.get("tooth_fdi") || 36),
                  brand: f.get("brand"),
                  model: f.get("model"),
                  diameter_mm: dmm || 4.1,
                  length_mm: lmm || 10.0,
                  lot_number: f.get("lot_number"),
                  uts_barcode: f.get("uts_barcode") || "",
                  expiry_date: f.get("expiry_date") || "",
                  supplier: f.get("supplier") || "",
                },
              });
              toast("İmplant ve Lot kaydı eklendi");
              openPatient(pid, reveal);
            }, "Kaydet"),
          },
        }, "İmplant / Lot")
      ),
      odoSection,
      (p.periodontal_exams || []).length || (p.lab_orders || []).length || (p.implant_records || []).length ? h("div", { class: "cal-box", style: "margin:10px 0" },
        (p.periodontal_exams || []).length ? [
          h("div", { class: "section-t", style: "margin-top:0", text: `Periodontal Muayeneler (${p.periodontal_exams.length})` }),
          ...p.periodontal_exams.map((pe) => h("div", { style: "font-size:13px;margin-bottom:4px" },
            `Tarih: ${pe.exam_date} · Ort. Cep (PD): ${pe.mean_pd} mm · Maks PD: ${pe.max_pd} mm · BOP: %${pe.bleeding_index_pct} · Plak: %${pe.plaque_index_pct}${pe.note ? " · " + pe.note : ""}`
          )),
        ] : null,
        (p.lab_orders || []).length ? [
          h("div", { class: "section-t", text: `Laboratuvar İş Emirleri (${p.lab_orders.length})` }),
          ...p.lab_orders.map((lo) => h("div", { style: "font-size:13px;margin-bottom:4px" },
            `#${lo.id} ${lo.lab_name} · ${lo.work_type} (Diş #${lo.tooth_fdi || "-"}, Renk ${lo.shade || "A2"}) · Teslim: ${lo.due_date} · Durum: ${lo.status}`
          )),
        ] : null,
        (p.implant_records || []).length ? [
          h("div", { class: "section-t", text: `İmplant & Lot Pasaportu (${p.implant_records.length})` }),
          ...p.implant_records.map((ir) => h("div", { style: "font-size:13px;margin-bottom:4px" },
            `Diş #${ir.tooth_fdi} · ${ir.brand} ${ir.model} (${ir.diameter_mm}×${ir.length_mm}mm) · Lot: ${ir.lot_number}${ir.barcode_udi ? " · Barkod: " + ir.barcode_udi : ""} (ÜTS Hazır - Canlı Bağlı Değil)`
          )),
        ] : null
      ) : null,
      h("div", { class: "section-t", text: `Röntgen, DICOM, Fotoğraf (Öncesi/Sonrası) & Belgeler (${(p.media_files || []).length})` }),
      (p.media_files || []).length ? tblWrap(h("table", { class: "table" },
        h("thead", null, h("tr", null, ["Tür / Aşama", "Dosya", "Kalite Kontrol (Teşhissiz)", "Tarih", "İşlem"].map((t) => h("th", { text: t })))),
        h("tbody", null, (p.media_files || []).map((mf) => h("tr", null,
          h("td", null, tag(`${mf.category} · ${mf.stage}`, mf.category === "xray" ? "teal" : "green")),
          h("td", { text: `${mf.filename} (${Math.round((mf.size_bytes || 0) / 1024)} KB)` }),
          h("td", null, tag(mf.qc_verdict === "ok" ? "Teknik Kalite Uygun" : mf.qc_verdict, mf.qc_verdict === "ok" ? "green" : "amber")),
          h("td", { text: fmtDT(mf.created_at) }),
          h("td", null, h("button", {
            class: "btn btn-sm btn-danger",
            type: "button",
            on: {
              click: async () => {
                await run(() => api(`/app/api/patients/${pid}/media/${mf.id}`, { method: "DELETE" }), "Dosya silindi");
                openPatient(pid, reveal);
              },
            },
          }, "Sil"))
        )))
      ), "Hasta dosyaları tablosu") : h("div", { class: "empty", text: "Henüz yüklenmiş röntgen veya fotoğraf yok." }),
      h("div", { class: "section-t", text: "Anamnez" }),
      p.anamnesis.length ? p.anamnesis.map((a) => h("div", { class: "alert-item" },
        h("div", { class: "k" }, a.red_flags.length ? tag(`${a.red_flags.length} kırmızı bayrak`, "red") : tag("Temiz", "green")),
        h("div", { class: "d" }, a.red_flags.join(", ") || "Risk işareti yok", h("small", { text: fmtDT(a.signed_at) })),
        p.anamnesis_links && p.anamnesis_links[a.id] ? h("a", { class: "btn btn-sm btn-ghost", href: p.anamnesis_links[a.id], target: "_blank", rel: "noopener noreferrer" }, "Aç") : null
      )) : h("div", { class: "empty", text: "Henüz anamnez yok." }),
      h("div", { class: "section-t", text: "Onamlar (KVKK & Dijital Tedavi Planı)" }),
      p.consents.length || (p.treatment_consents || []).length ? [
        ...p.consents.map((c) => h("div", { class: "alert-item" },
          h("div", { class: "d" }, consentNames[c.kind] || c.kind, h("small", { text: `Sürüm ${c.text_version} · ${fmtDT(c.granted_at)}` })),
          c.revoked_at ? tag("Geri alındı", "red") : tag("Geçerli", "green")
        )),
        ...(p.treatment_consents || []).map((tc) => h("div", { class: "alert-item" },
          h("div", { class: "d" }, `Dijital Tedavi Planı Onamı (${tc.document_version})`, h("small", { text: tc.signed_at ? `Onaylayan: ${tc.signer_name} · ${fmtDT(tc.signed_at)}` : "Hasta onayı bekleniyor" })),
          tag(tc.status === "signed" ? "İmzalandı" : "Bekliyor", tc.status === "signed" ? "green" : "yellow")
        )),
      ] : h("div", { class: "empty", text: "Onam kaydı yok." }),
      h("div", { class: "section-t", text: "Randevular" }),
      p.appointments.length ? tblWrap(h("table", { class: "table" }, h("tbody", null, p.appointments.map((a) =>
        h("tr", null, h("td", { text: fmtDT(a.starts_at) }), h("td", { text: `${a.treatment}${a.doctor_name ? " · " + a.doctor_name : ""}` }), h("td", null, tag(...(STATUS[a.status] || [a.status, ""]))))
      ))), "Hasta randevuları tablosu") : h("div", { class: "empty", text: "Randevu yok." }),
      h("div", { class: "section-t", text: "Hesap hareketleri" }),
      ledger.length ? tblWrap(h("table", { class: "table" }, h("tbody", null, ledger.map((e) =>
        h("tr", { style: e.voided_at ? "opacity:.45;text-decoration:line-through" : "" },
          h("td", { text: fmtD(e.created_at) }),
          h("td", { text: `${e.t}: ${e.info}` }),
          h("td", { class: "num", text: (e.t === "Tahsilat" ? "-" : "") + fmtTL(e.amount) }),
          h("td", null, e.t === "Tahsilat" && !e.voided_at && e.status === "completed" && S.user.role !== "secretary" ? h("button", {
            class: "btn btn-sm btn-ghost",
            type: "button",
            on: {
              click: () => modal("Tahsilat İadesi", [
                fld("İade Tutarı (TL)", inp("amount", { type: "number", step: "0.01", min: "0.01", max: String(e.amount), value: String(e.amount), required: true })),
                fld("İade Gerekçesi *", inp("reason", { required: true, minLength: 3, placeholder: "İade nedenini giriniz", value: "" })),
              ], async (f) => {
                await api(`/app/api/payments/${e.id}/refund`, {
                  method: "POST",
                  body: { amount: f.get("amount"), reason: f.get("reason") },
                });
                toast("İade işlemi denetim kaydıyla tamamlandı");
                openPatient(pid, reveal);
              }, "İade Et"),
            },
          }, "İade") : null)
        )
      ))), "Hasta hesap hareketleri tablosu") : h("div", { class: "empty", text: "Hareket yok." }),
      h("div", { class: "section-t", text: `Kronolojik Hasta Zaman Çizelgesi (${(p.timeline || []).length})` }),
      (p.timeline || []).length ? h("div", null, (p.timeline || []).slice(0, 25).map((tlItem) => h("div", { class: "alert-item" },
        h("div", { class: "d" }, h("strong", { text: tlItem.title }), " — ", tlItem.detail, h("small", { text: fmtDT(tlItem.ts) }))
      ))) : h("div", { class: "empty", text: "Zaman çizelgesi kaydı yok." })
    );
    const wrap = h("div", { class: "drawer-wrap" },
      h("div", { class: "overlay", on: { click: () => close(true) } }),
      drawer
    );
    document.body.appendChild(wrap);
    if (!document.querySelector(".modal")) {
      const closeBtn = drawer.querySelector("button");
      if (closeBtn) closeBtn.focus();
    }
  }

  // ---------------- bekleme listesi
  VIEWS.waitlist = async () => {
    const [rows, offers] = await Promise.all([
      api("/app/api/waitlist"),
      api("/app/api/waitlist/offers"),
    ]);
    const OFFER_ST = { sent: ["Bekliyor", "yellow"], won: ["Kazanıldı", "green"], lost: ["Kaybedildi", ""], expired: ["Süresi doldu", ""] };
    setMain(
      header("Bekleme Listesi", "Randevu iptal edildiğinde listedeki hastalara 3 dakikalık dalgalarla teklif gider; ilk onay veren koltuğu alır."),
      h("div", { class: "card card-flush" }, tblWrap(h("table", { class: "table" },
        h("thead", null, h("tr", null, ["Sıra", "Hasta", "İşlem", "Eklenme", "İşlemler"].map((t) => h("th", { text: t })))),
        h("tbody", null, rows.length ? rows.map((w, i) => h("tr", null,
          h("td", { text: i + 1 }),
          h("td", null, h("a", { href: "#", on: { click: (e) => { e.preventDefault(); openPatient(w.patient_id); } }, text: w.patient || `Hasta #${w.patient_id}` })),
          h("td", { text: w.treatment }),
          h("td", { text: fmtDT(w.created_at) }),
          h("td", null, h("button", {
            class: "btn btn-sm btn-danger",
            type: "button",
            on: {
              click: () => {
                confirmModal(
                  "Bekleme listesinden çıkar",
                  `${w.patient || `Hasta #${w.patient_id}`} bekleme listesinden çıkarılsın mı?`,
                  async () => {
                    await api(`/app/api/waitlist/${w.id}/remove`, { method: "POST" });
                    toast("Listeden çıkarıldı");
                    route();
                  },
                  "Çıkar"
                );
              },
            },
          }, "Çıkar"))
        )) : h("tr", null, h("td", { colSpan: 5, class: "empty", text: "Bekleme listesi boş. Hasta kartından ekleyebilirsiniz." })))
      ), "Bekleme listesi tablosu")),
      h("div", { class: "section-t", style: "margin-top:20px", text: `Aktif ve Son Slot Teklifleri (${offers.length})` }),
      h("div", { class: "card card-flush" }, tblWrap(h("table", { class: "table" },
        h("thead", null, h("tr", null, ["Teklif", "Hasta", "Açılan Koltuk", "Dalga", "Durum", "Gönderim", "İşlemler"].map((t) => h("th", { text: t })))),
        h("tbody", null, offers.length ? offers.map((o) => {
          const [ost, ocls] = OFFER_ST[o.status] || [o.status, ""];
          return h("tr", null,
            h("td", { text: `#${o.id}` }),
            h("td", null, h("a", { href: "#", on: { click: (e) => { e.preventDefault(); openPatient(o.patient_id); } }, text: o.patient || `Hasta #${o.patient_id}` })),
            h("td", { text: `${fmtDT(o.starts_at)} · ${o.treatment} (K${o.chair})` }),
            h("td", { text: `Dalga ${o.wave}` }),
            h("td", null, tag(ost, ocls)),
            h("td", { text: fmtDT(o.sent_at) }),
            h("td", null, o.status === "sent" ? h("div", { class: "actions" },
              h("button", {
                class: "btn btn-sm btn-primary",
                type: "button",
                on: {
                  click: async () => {
                    const res = await run(() => api(`/app/api/waitlist/offers/${o.id}/respond`, { method: "POST", body: { action: "accept" } }), "Koltuk hastaya atandı");
                    if (res) route();
                  },
                },
              }, "Koltuk Ver"),
              h("button", {
                class: "btn btn-sm btn-ghost",
                type: "button",
                on: {
                  click: async () => {
                    const res = await run(() => api(`/app/api/waitlist/offers/${o.id}/respond`, { method: "POST", body: { action: "reject" } }), "Teklif reddedildi");
                    if (res) route();
                  },
                },
              }, "Reddet")
            ) : h("span", { style: "color:var(--muted)", text: "-" }))
          );
        }) : h("tr", null, h("td", { colSpan: 7, class: "empty", text: "Henüz slot teklifi oluşturulmadı." })))
      ), "Slot teklifleri tablosu"))
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

  // ---------------- envanter (Bölüm 14: 13 Alan + Lot + SKT + Depo + CSV)
  VIEWS.inventory = async () => {
    const rows = await api("/app/api/inventory");
    const total = rows.reduce((s, r) => s + Number(r.value || 0), 0);
    setMain(
      header("Envanter & Sarf Takibi", `Stok değeri: ${fmtTL(total)} · Kritik seviye ve son kullanma tarihi (SKT) için otomatik uyarı oluşur.`,
        h("a", { class: "btn btn-ghost", href: "/app/api/export/inventory.csv", download: "dentacore-envanter.csv" }, "CSV İndir"),
        h("button", {
          class: "btn btn-cta",
          type: "button",
          on: {
            click: () => modal("Ürün ekle", [
              fld("Ürün adı *", inp("name", { required: true, minLength: 2, placeholder: "Kompozit A2", value: "" })),
              h("div", { class: "row" },
                fld("Kategori", sel("category", [
                  ["Sarf Malzeme", "Sarf Malzeme"],
                  ["İmplant & Cerrahi", "İmplant & Cerrahi"],
                  ["Endodonti", "Endodonti"],
                  ["Protez & Ölçü", "Protez & Ölçü"],
                  ["Sterilizasyon", "Sterilizasyon"],
                ], "Sarf Malzeme")),
                fld("Depo / Konum", inp("warehouse", { value: "Ana Depo" }))
              ),
              h("div", { class: "row" }, fld("Stok kodu", inp("sku", { value: "" })), fld("Birim", inp("unit", { value: "adet" }))),
              h("div", { class: "row" }, fld("Mevcut miktar", inp("qty", { type: "number", step: "0.01", min: 0, value: "" })), fld("Alt sınır", inp("min_qty", { type: "number", step: "0.01", min: 0, value: "" }))),
              h("div", { class: "row" },
                fld("Birim maliyet (TL)", inp("unit_cost", { type: "number", step: "0.01", min: 0, value: "" })),
                fld("Tedarikçi", inp("supplier", { placeholder: "Dental Medikal A.Ş.", value: "" }))
              ),
              h("div", { class: "row" },
                fld("Lot / Parti No", inp("lot_number", { placeholder: "LOT-2026", value: "" })),
                fld("Son Kullanma Tarihi (SKT)", inp("expiry_date", { type: "date", value: "" }))
              ),
            ], async (f) => {
              const body = Object.fromEntries(f);
              body.qty = body.qty || "0";
              body.min_qty = body.min_qty || "0";
              body.unit_cost = body.unit_cost || "0";
              await api("/app/api/inventory", { method: "POST", body });
              toast("Ürün eklendi");
              route();
            }),
          },
        }, icon("plus"), "Ürün ekle")
      ),
      h("div", { class: "card card-flush" }, tblWrap(h("table", { class: "table" },
        h("thead", null, h("tr", null, ["Ürün / Kategori", "Lot / SKT / Depo", "Stok", "Alt sınır", "Birim maliyet", "Değer", "İşlemler"].map((t, i) => h("th", { class: i >= 2 && i < 6 ? "num" : "", text: t })))),
        h("tbody", null, rows.length ? rows.map((r) => h("tr", null,
          h("td", null,
            h("b", { text: r.name }),
            r.sku ? h("span", { class: "mono", style: "color:var(--muted)", text: `  ${r.sku}` }) : null,
            " ",
            r.category ? tag(r.category, "teal") : null,
            " ",
            r.low ? tag("Kritik", "red") : null,
            r.expired ? tag("SKT Geçmiş", "red") : (r.expiring_soon ? tag("SKT Yaklaşıyor", "amber") : null)
          ),
          h("td", { style: "font-size:12.5px;color:var(--ink-2)" },
            `${r.warehouse || "Ana Depo"}${r.lot_number ? " · Lot: " + r.lot_number : ""}${r.expiry_date ? " · SKT: " + r.expiry_date : ""}${r.supplier ? " · " + r.supplier : ""}`
          ),
          h("td", { class: "num", text: `${Number(r.qty)} ${r.unit}` }),
          h("td", { class: "num", text: Number(r.min_qty) }),
          h("td", { class: "num", text: fmtTL(r.unit_cost) }),
          h("td", { class: "num", text: fmtTL(r.value) }),
          h("td", null, h("div", { class: "actions" },
            h("button", { class: "btn btn-sm btn-ghost", type: "button", on: { click: () => moveItem(r, 1) } }, "Giriş"),
            h("button", { class: "btn btn-sm btn-ghost", type: "button", on: { click: () => moveItem(r, -1) } }, "Çıkış"),
            h("button", { class: "btn btn-sm btn-ghost", type: "button", on: { click: () => itemHistory(r) } }, "Geçmiş")
          ))
        )) : h("tr", null, h("td", { colSpan: 7, class: "empty", text: "Henüz ürün yok." })))
      ), "Envanter tablosu"))
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
    ), "Stok hareket geçmişi tablosu")], async () => true, "Kapat");
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
    if (S.user && S.user.role === "secretary") {
      setMain(
        header("Kasa", "Yetki bilgilendirmesi"),
        h("div", { class: "card", role: "status" },
          h("h3", { text: "Bu ekran klinik yöneticisine özeldir" }),
          h("p", { style: "color:var(--ink-2);margin:0 0 12px", text: "Bu ekran klinik yöneticisine özeldir; hasta tahsilatını Hasta Kartı içinden girebilirsiniz." }),
          h("a", { class: "btn btn-primary", href: "#/patients" }, "Hastalara git")
        )
      );
      return;
    }
    const k = new URLSearchParams(location.hash.split("?")[1] || "").get("r") || "ay";
    const [s, e] = range(k);
    const [d, banks, exps] = await Promise.all([
      api(`/app/api/kasa?start=${encodeURIComponent(s.toISOString())}&end=${encodeURIComponent(e.toISOString())}`),
      api("/app/api/bank-agreements").catch(() => []),
      api("/app/api/expenses").catch(() => []),
    ]);
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
      header("Kasa & Kurumsal Muhasebe", "Tutarlar kuruş hassasiyetinde (Decimal) tutulur; planlanan işlem borç oluşturmaz, bekleyen/başarısız ödeme borçtan düşülmez.",
        ...Object.entries(RANGES).map(([rk, t]) => h("a", { class: `btn ${rk === k ? "btn-primary" : "btn-ghost"}`, href: `#/kasa?r=${rk}`, text: t })),
        h("a", { class: "btn btn-ghost", href: "/app/api/export/kasa.csv", download: "dentacore-kasa.csv" }, "CSV İndir"),
        h("button", {
          class: "btn btn-ghost",
          type: "button",
          on: {
            click: () => modal("Klinik Gideri Kaydet", [
              h("div", { class: "row" },
                fld("Kategori", sel("category", [
                  ["malzeme", "Sarf & Malzeme"],
                  ["laboratuvar", "Laboratuvar"],
                  ["kira", "Kira"],
                  ["maas", "Personel / Maaş"],
                  ["fatura", "Fatura / Vergi"],
                  ["diger", "Diğer"],
                ], "malzeme")),
                fld("Ödeme Yöntemi", sel("method", [
                  ["havale", "Havale / EFT"],
                  ["kredi_karti", "Kredi Kartı"],
                  ["nakit", "Nakit"],
                ], "havale"))
              ),
              fld("Açıklama *", inp("description", { required: true, minLength: 2, placeholder: "Aylık sarf malzeme ödemesi", value: "" })),
              fld("Tutar (TL) *", inp("amount", { type: "number", step: "0.01", min: "0.01", required: true, placeholder: "Örn. 4500", value: "" })),
            ], async (f) => {
              await api("/app/api/expenses", { method: "POST", body: Object.fromEntries(f) });
              toast("Gider kaydedildi");
              route();
            }, "Kaydet"),
          },
        }, "+ Gider Ekle"),
        h("button", {
          class: "btn btn-cta",
          type: "button",
          on: {
            click: () => modal("Günlük Kasa Kapanışı", [
              fld("Açılış Bakiyesi (TL)", inp("opening_balance", { type: "number", step: "0.01", min: "0", value: "0" })),
              fld("Sayılan Fiziksel Kasa / POS Toplamı (TL) *", inp("physical_counted", { type: "number", step: "0.01", min: "0", required: true, value: String(d.net_cash_flow || d.paid || 0) })),
              fld("Kapanış Notu", inp("note", { placeholder: "Gün sonu mutabakatı tam", value: "" })),
            ], async (f) => {
              const res = await api("/app/api/kasa/closings", { method: "POST", body: Object.fromEntries(f) });
              toast(`Gün sonu kasa kapanışı tamamlandı (Fark: ${fmtTL(res.diff)})`);
              route();
            }, "Kapanışı Onayla"),
          },
        }, "Gün Sonu Kapanış")
      ),
      h("div", { class: "grid g3" },
        h("div", { class: "card kpi" }, h("div", { class: "label", text: "Gerçekleşen Net Hizmet" }), h("div", { class: "value", text: fmtTL(d.billed) }),
          h("div", { class: "hint", text: `Brüt: ${fmtTL(d.gross_billed || d.billed)} · İndirim: ${fmtTL(d.discount_total || 0)} · Planlanan: ${fmtTL(d.planned_total || 0)}` })),
        h("div", { class: "card kpi good" }, h("div", { class: "label", text: "Başarılı Tahsilat" }), h("div", { class: "value", text: fmtTL(d.paid) }),
          h("div", { class: "hint", text: (d.methods.map((m) => `${m.method}: ${fmtTL(m.amount)}`).join(" · ") || "Tahsilat yok") + (d.refunded_total ? ` · İade: ${fmtTL(d.refunded_total)}` : "") })),
        h("div", { class: "card kpi loss" }, h("div", { class: "label", text: "Kalan Alacak (Tüm Zamanlar)" }), h("div", { class: "value", text: fmtTL(d.receivable) }),
          h("div", { class: "hint", text: `Giderler: ${fmtTL(d.expenses_total || 0)} · Net Nakit Akışı: ${fmtTL(d.net_cash_flow !== undefined ? d.net_cash_flow : d.paid)}` }))
      ),
      banks.length ? h("div", { class: "cal-box", style: "margin-top:12px" },
        h("b", { text: "Aktif Kurum / Banka İndirim Anlaşmaları: " }),
        banks.map((b) => `${b.bank_name} (%${b.discount_pct}${b.max_discount ? ", üst sınır " + fmtTL(b.max_discount) : ""})`).join(" · ")
      ) : h("div", { class: "cal-box", style: "margin-top:12px;font-size:12.5px;color:var(--muted)" },
        "Şirket Ünvanı, Kurum/Banka Anlaşmaları ve Sanal POS şu an Taslak Modundadır. Bilgileriniz 3_BENIM_DOSYALARIM klasöründeki forma girildiğinde otomatik aktifleşir."
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
        ), "Hekim payları tablosu")
      ) : null,
      h("div", { class: "card card-flush", style: "margin-top:14px" }, tblWrap(h("table", { class: "table" },
        h("thead", null, h("tr", null, ["Tarih", "Tür", "Hasta", "Açıklama", "Tutar", "İşlemler"].map((t, i) => h("th", { class: i === 4 ? "num" : "", text: t })))),
        h("tbody", null, d.entries.length ? d.entries.map((en) => h("tr", { style: en.voided_at ? "opacity:.45;text-decoration:line-through" : "" },
          h("td", { text: fmtDT(en.created_at) }),
          h("td", null, tag(en.type === "hizmet" ? "Hizmet" : "Tahsilat", en.type === "hizmet" ? "" : "green")),
          h("td", { text: en.patient || "-" }),
          h("td", { text: en.info }),
          h("td", { class: "num", text: fmtTL(en.amount) }),
          h("td", null, canVoid && !en.voided_at ? voidBtn(en) : null)
        )) : h("tr", null, h("td", { colSpan: 6, class: "empty", text: "Bu aralıkta kayıt yok. Hizmet ve tahsilat hasta kartından girilir." })))
      ), "Kasa hareketleri tablosu"))
    );
  };
  VIEWS.billing = VIEWS.kasa;

  // ---------------- maliyet (Bölüm 13: 3.500 TL SaaS Brüt Kâr Analizi & Kota)
  VIEWS.costs = async () => {
    const [rows, aiRep] = await Promise.all([
      api("/app/api/token-stats?days=30"),
      api("/app/api/ai-costs?days=30").catch(() => null),
    ]);
    const total = rows.reduce((s, r) => s + r.replies, 0);
    const free = rows.filter((r) => (r.layer || "").startsWith("L1")).reduce((s, r) => s + r.replies, 0);
    const LAYER = { L1: "Katman 1: kural ve önbellek (0 token)", L2: "Katman 2: küçük sınıflandırıcı", L3: "Katman 3: ana model" };
    setMain(
      header("Yapay Zeka Maliyeti & 3.500 TL Abonelik Kârlılık Analizi", "Mesajların büyük çoğunluğu Katman-1 deterministik kurallarla 0 token ile yanıtlanır; aylık kota ve maliyet freni aktiftir.",
        S.user.role === "owner" && aiRep ? h("button", {
          class: "btn btn-ghost",
          type: "button",
          on: {
            click: () => modal("Aylık AI Token & Bütçe Kotası", [
              fld("Aylık Token Limiti", inp("monthly_token_limit", { type: "number", min: 10000, max: 50000000, value: String(aiRep.monthly_token_limit || 1500000), required: true })),
              fld("Aylık AI Bütçe Tavanı (TL)", inp("monthly_budget_try", { type: "number", step: "1", min: 10, max: 50000, value: String(aiRep.monthly_budget_try || 250), required: true })),
            ], async (f) => {
              await api("/app/api/ai-costs/quota", {
                method: "POST",
                body: {
                  monthly_token_limit: Number(f.get("monthly_token_limit") || 1500000),
                  monthly_budget_try: Number(f.get("monthly_budget_try") || 250),
                  hard_stop: true,
                },
              });
              toast("Aylık yapay zeka kotası güncellendi");
              route();
            }, "Kaydet"),
          },
        }, "Kota Ayarla") : null
      ),
      h("div", { class: "grid g3" },
        h("div", { class: "card kpi good" }, h("div", { class: "label", text: "0 Token (LLM'siz) Cevap Oranı" }), h("div", { class: "value", text: total ? `%${Math.round(100 * free / total)}` : "%100" }), h("div", { class: "hint", text: `${free} / ${total} cevap (30 gün)` })),
        h("div", { class: "card kpi" }, h("div", { class: "label", text: "Tahmini 30 Günlük AI Maliyeti" }), h("div", { class: "value", text: aiRep ? fmtTL(aiRep.estimated_cost_try) : "0,00 TL" }),
          h("div", { class: "hint", text: aiRep ? `Toplam Token: ${Number(aiRep.total_tokens || 0).toLocaleString("tr-TR")} / ${Number(aiRep.monthly_token_limit || 1500000).toLocaleString("tr-TR")}` : "" })),
        h("div", { class: "card kpi good" }, h("div", { class: "label", text: "3.500 TL Pakette Brüt Kâr Marjı" }), h("div", { class: "value", text: aiRep ? `%${aiRep.gross_margin_after_ai_pct}` : "%100" }),
          h("div", { class: "hint", text: aiRep ? `AI Sonrası Kalan: ${fmtTL(aiRep.gross_profit_after_ai_try)} / 3.500 TL` : "3.500 TL + KDV / ay" }))
      ),
      h("div", { class: "card card-flush", style: "margin-top:14px" }, tblWrap(h("table", { class: "table" },
        h("thead", null, h("tr", null, ["Katman", "Cevap", "Girdi Token", "Çıktı Token"].map((t, i) => h("th", { class: i ? "num" : "", text: t })))),
        h("tbody", null, rows.length ? rows.map((r) => h("tr", null,
          h("td", null, h("b", { text: r.layer || "-" }), h("div", { style: "color:var(--muted);font-size:13px", text: LAYER[(r.layer || "").slice(0, 2)] || "" })),
          h("td", { class: "num", text: r.replies }),
          h("td", { class: "num", text: r.tin }),
          h("td", { class: "num", text: r.tout })
        )) : h("tr", null, h("td", { colSpan: 4, class: "empty", text: "Henüz otomatik cevap yok." })))
      ), "Yapay zeka maliyet tablosu"))
    );
  };

  // ---------------- ekip (Bölüm 17: 14 Meslek & 15 Granüler RBAC Yetkisi)
  VIEWS.team = async () => {
    const [rows, profCat] = await Promise.all([
      api("/app/api/staff"),
      api("/app/api/staff/professions-catalog").catch(() => null),
    ]);
    const owner = S.user.role === "owner";
    const profEntries = profCat && profCat.professions
      ? Object.entries(profCat.professions).map(([k, v]) => [k, v.label || k])
      : [
        ["dentist", "Diş Hekimi"],
        ["specialist_dentist", "Uzman Diş Hekimi"],
        ["orthodontist", "Ortodontist"],
        ["oral_surgeon", "Ağız, Diş ve Çene Cerrahı"],
        ["endodontist", "Endodontist"],
        ["periodontist", "Periodontist"],
        ["pedodontist", "Pedodontist (Çocuk Diş Hekimi)"],
        ["prosthodontist", "Protetik Diş Tedavisi Uzmanı"],
        ["dental_assistant", "Diş Hekimi Asistanı"],
        ["secretary", "Sekreter / Ön Büro"],
        ["patient_coordinator", "Hasta Koordinatörü"],
        ["clinic_manager", "Klinik Yöneticisi"],
        ["accountant", "Muhasebe Sorumlusu"],
        ["lab_technician", "Laboratuvar / Protez Teknisyeni"],
      ];
    const permLabels = (profCat && profCat.permission_labels) || {};
    const roleOpts = [
      ["secretary", "Sekreter / Ön Büro"],
      ["doctor", "Hekim"],
      ["owner", "Yönetici"],
      ["accounting", "Muhasebe"],
      ["clinical_support", "Klinik Destek / Asistan"],
      ["lab_tech", "Laboratuvar Teknisyeni"],
      ["warehouse", "Depo / Envanter"],
      ["no_access", "Sisteme Giriş Yok"],
    ];
    setMain(
      header("Ekip & 15 Granüler Yetki (RBAC)", "14 klinik meslek grubu ve 15 granüler yetki anahtarı ile rol bazlı erişim kontrolü. Hekim hakediş raporunu CSV indirebilirsiniz.",
        h("a", { class: "btn btn-ghost", href: "/app/api/export/doctor_shares.csv", download: "dentacore-hekim-hakedis.csv" }, "Hakediş CSV"),
        owner ? h("button", {
          class: "btn btn-cta",
          type: "button",
          on: {
            click: () => modal("Ekip üyesi ekle", [
              fld("Ad Soyad *", inp("full_name", { required: true, minLength: 2, value: "" })),
              fld("E-posta *", inp("email", { type: "email", required: true, value: "" })),
              h("div", { class: "row" },
                fld("Meslek / Uzmanlık (14 Meslek)", sel("job_title", profEntries, "dentist")),
                fld("Sistem Rolü", sel("role", roleOpts, "doctor"))
              ),
              h("div", { class: "row" },
                fld("Hekim pay oranı (%)", inp("share_pct", { type: "number", min: 0, max: 100, step: "0.5", value: "" })),
                fld("WhatsApp numarası (isteğe bağlı)", inp("phone", { placeholder: "05xx xxx xx xx", value: "" }))
              ),
              fld("Geçici parola (en az 12 karakter) *", inp("password", { type: "password", required: true, minLength: 12, autocomplete: "new-password", value: "" })),
            ], async (f) => {
              const b = Object.fromEntries(f);
              b.share_pct = b.share_pct || "0";
              if (!b.phone) delete b.phone;
              await api("/app/api/staff", { method: "POST", body: b });
              toast("Ekip üyesi eklendi");
              route();
            }),
          },
        }, icon("plus"), "Üye ekle") : null
      ),
      h("div", { class: "card card-flush" }, tblWrap(h("table", { class: "table" },
        h("thead", null, h("tr", null, ["Ad", "Meslek / Rol", owner ? "E-posta" : null, "Pay", "2FA", "WhatsApp", "Durum", owner ? "İşlemler" : null].filter((x) => x !== null).map((t) => h("th", { text: t })))),
        h("tbody", null, rows.map((s) => h("tr", null,
          h("td", null, h("b", { text: s.full_name })),
          h("td", null,
            tag(s.job_title_label || ROLE[s.role] || s.role, s.role === "owner" ? "teal" : "green"),
            " ",
            tag(ROLE[s.role] || s.role, "")
          ),
          owner ? h("td", { text: s.email }) : null,
          h("td", { text: `%${Number(s.share_pct || 0)}` }),
          h("td", null, s.totp_enabled ? tag("Açık", "green") : tag("Kapalı", "yellow")),
          h("td", null, s.whatsapp ? tag("Bağlı", "teal") : "-"),
          h("td", null, s.active ? tag("Aktif", "green") : tag("Pasif", "")),
          owner ? h("td", null, h("div", { class: "actions" },
            h("button", {
              class: "btn btn-sm btn-ghost",
              type: "button",
              on: {
                click: () => {
                  const curPerms = s.permissions || {};
                  const permBoxes = Object.entries(permLabels).map(([pk, plbl]) =>
                    h("label", { class: "odo-check-row" },
                      h("input", { type: "checkbox", name: `perm_${pk}`, value: "1", checked: Boolean(curPerms[pk]) }),
                      h("span", { text: `${plbl} (${pk})` })
                    )
                  );
                  modal(`${s.full_name} · Meslek & 15 Yetki Düzenle`, [
                    h("div", { class: "row" },
                      fld("Meslek (14 Grup)", sel("job_title", profEntries, s.job_title || "secretary")),
                      fld("Rol", sel("role", roleOpts, s.role || "secretary"))
                    ),
                    fld("Hekim Pay Oranı (%)", inp("share_pct", { type: "number", min: 0, max: 100, step: "0.5", value: String(s.share_pct || 0) })),
                    h("div", { class: "section-t", text: "15 Granüler Yetki Anahtarı" }),
                    h("div", { style: "max-height:240px;overflow-y:auto;border:1px solid var(--line);border-radius:8px;padding:8px" }, ...permBoxes),
                  ], async (f) => {
                    const permissions = {};
                    Object.keys(permLabels).forEach((pk) => {
                      permissions[pk] = f.get(`perm_${pk}`) === "1";
                    });
                    await api(`/app/api/staff/${s.id}/permissions`, {
                      method: "PATCH",
                      body: {
                        job_title: f.get("job_title"),
                        role: f.get("role"),
                        share_pct: f.get("share_pct") || "0",
                        permissions,
                      },
                    });
                    toast("Personel meslek ve yetkileri güncellendi");
                    route();
                  }, "Kaydet");
                },
              },
            }, "Yetkiler"),
            s.id !== S.user.id ? h("button", {
              class: `btn btn-sm ${s.active ? "btn-danger" : "btn-ghost"}`,
              type: "button",
              on: {
                click: async () => {
                  if (!s.active) {
                    const r = await run(() => api(`/app/api/staff/${s.id}/active`, { method: "POST", body: { active: true } }), "Ekip üyesi aktifleştirildi");
                    if (r !== null) route();
                    return;
                  }
                  confirmModal(
                    "Ekip üyesini pasifleştir",
                    `${s.full_name} hesabı pasifleştirilsin mi? Pasif kullanıcı panele giriş yapamaz.`,
                    async () => {
                      await api(`/app/api/staff/${s.id}/active`, { method: "POST", body: { active: false } });
                      toast("Ekip üyesi pasifleştirildi");
                      route();
                    },
                    "Pasifleştir"
                  );
                },
              },
            }, s.active ? "Pasifleştir" : "Aktifleştir") : null
          )) : null
        )))
      ), "Ekip üyeleri tablosu"))
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
            click: () => {
              confirmModal(
                "Tüm cihazlardan çıkış",
                "Tüm cihazlardaki aktif oturumlar kapatılsın mı? Mevcut oturumunuz da sonlanacaktır.",
                async () => {
                  await api("/auth/sessions/revoke-all", { method: "POST" });
                  S.user = null;
                  lsSet("dc_has_session", "");
                  toast("Tüm oturumlar kapatıldı");
                  renderLogin("Tüm oturumlar kapatıldı.");
                },
                "Oturumları kapat"
              );
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
        ), "Denetim kaydı tablosu")
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
      noValidate: true,
      on: {
        submit: (e) => {
          e.preventDefault();
          const vErr = validateFormTr(simForm);
          if (vErr) { toast(vErr, true); return; }
          const t = simInput.value.trim();
          if (!t) { simInput.focus(); return toast("Hasta mesajı alanı zorunludur.", true); }
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

    async function openReplyModal(r) {
      const msgs = await run(() => api(`/app/api/conversations/${r.id}/messages`));
      if (!msgs) return;
      const ordered = [...msgs].reverse().slice(-30);
      const thread = h("div", { class: "conv-thread", role: "region", "aria-label": "Konuşma geçmişi" },
        ordered.length ? ordered.map((m) => {
          const isOut = m.direction === "out";
          const ds = m.delivery_status || "";
          const dsCls = ds === "sent" ? "green" : ds === "failed" ? "red" : "yellow";
          return h("div", { class: "conv-msg" + (isOut ? " out" : "") },
            h("div", { class: "conv-msg-body", dir: "auto", text: m.body || "(Mesaj içeriği yok)" }),
            h("div", { class: "conv-msg-meta" },
              h("strong", { text: isOut ? "Klinik" : "Hasta" }),
              h("span", { text: fmtDT(m.created_at) }),
              m.layer ? tag(m.layer, (m.layer || "").startsWith("L1") ? "green" : "") : null,
              isOut && ds ? tag(ds, dsCls) : null
            )
          );
        }) : h("div", { class: "empty", style: "padding:12px", text: "Henüz kayıtlı mesaj geçmişi yok." })
      );
      modal(`${r.display_name || "Hasta #" + r.id} · Otopilotu Devral`, [
        thread,
        fld("Doğrudan Mesaj", h("textarea", { class: "input", name: "text", rows: 3, required: true, placeholder: "Hastaya iletilecek mesaj..." })),
      ], async (f) => {
        const res = await api(`/app/api/conversations/${r.id}/send`, { method: "POST", body: { text: f.get("text") } });
        if (res.status === "failed") toast(`Mesaj iletilemedi: ${res.error || "API hatası"}`, true);
        else if (res.dry_run) toast("Mesaj kuru çalıştırma (dry_run) modunda kaydedildi");
        else toast("Mesaj gönderildi");
        route();
      }, "Gönder");
      requestAnimationFrame(() => { thread.scrollTop = thread.scrollHeight; });
    }

    const buildConvRows = (list) => list.length ? list.map((r) => {
      const lastBody = (r.last_body || "").trim();
      const previewText = lastBody ? (lastBody.length > 64 ? `${lastBody.slice(0, 64)}…` : lastBody) : "—";
      return h("tr", null,
        h("td", null, h("b", { text: r.display_name || `Hasta #${r.id}` })),
        h("td", null, tag(r.channel === "ig" ? "Instagram" : r.channel === "simulator" ? "Simülatör" : "WhatsApp", r.channel === "ig" ? "amber" : "teal")),
        h("td", { text: (r.lang || "tr").toUpperCase() }),
        h("td", null, h("div", { class: "msg-preview", title: lastBody || "", text: previewText })),
        h("td", null, tag(r.last_layer || "yeni", (r.last_layer || "").startsWith("L1") ? "green" : "")),
        h("td", { text: r.last_intent || "-" }),
        h("td", { text: r.msg_count || 0 }),
        h("td", { text: r.last_at ? fmtDT(r.last_at) : "-" }),
        h("td", null, h("div", { class: "actions" },
          h("button", {
            class: "btn btn-sm btn-primary",
            type: "button",
            on: { click: () => openReplyModal(r) },
          }, "Yanıtla"),
          h("button", { class: "btn btn-sm btn-ghost", type: "button", on: { click: () => openPatient(r.id) } }, "Kart")
        ))
      );
    }) : [h("tr", null, h("td", { colSpan: 9, class: "empty", text: "Henüz mesaj kaydı yok." }))];

    const tbody = h("tbody", null, buildConvRows(rows));

    setMain(
      header("Mesajlar", "WhatsApp ve Instagram DM görüşmeleri ile 16 dilli canlı yapay zeka simülatörü."),
      simForm,
      h("div", { class: "card card-flush" }, tblWrap(h("table", { class: "table" },
        h("thead", null, h("tr", null, ["Hasta", "Kanal", "Dil", "Son Mesaj", "Son Katman", "Niyet", "Mesaj", "Son Temas", "İşlemler"].map((t) => h("th", { text: t })))),
        tbody
      ), "Konuşmalar tablosu"))
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
      ), "Mesaj şablonları tablosu"))
    );
  };

  // ---------------- iletişim ve reklam analizi (Bölüm 5: Gerçek Takip Hunisi & Kanal Dağılımı)
  VIEWS.analytics = async () => {
    const [d, rep] = await Promise.all([
      api("/app/api/analytics"),
      api("/app/api/campaigns/report?include_samples=false").catch(() => null),
    ]);
    const campRows = (rep && rep.campaigns) ? rep.campaigns : (d.campaigns || []);
    setMain(
      header("İletişim & Gerçek Kampanya Dönüşüm Analizi", "Tıklama takip bağlantısı (/c/kod), bot filtreleme, tekil ziyaretçi, hasta kaydı, randevu ve kasa tahsilatı uçtan uca bağlanır.",
        h("a", { class: "btn btn-ghost", href: "/app/api/export/campaigns.csv", download: "dentacore-kampanyalar.csv" }, "CSV İndir"),
        h("button", {
          class: "btn btn-cta",
          type: "button",
          on: {
            click: () => modal("Reklam Kampanyası ve Takip Bağlantısı Oluştur", [
              fld("Kampanya Adı *", inp("name", { required: true, placeholder: "İstanbul İmplant Meta Kasım", value: "" })),
              h("div", { class: "row" },
                fld("Kanal", sel("channel", PATIENT_SOURCES, "instagram")),
                fld("Takip Kodu (URL /c/kod)", inp("code", { placeholder: "kasim-implant", value: "" }))
              ),
              h("div", { class: "row" },
                fld("UTM Source", inp("utm_source", { value: "instagram" })),
                fld("UTM Medium", inp("utm_medium", { value: "cpc" }))
              ),
              fld("UTM Campaign", inp("utm_campaign", { placeholder: "implant_2026_11", value: "" })),
            ], async (f) => {
              const b = Object.fromEntries(f);
              b.source = b.channel || "instagram";
              b.clicks = 0;
              b.conversations = 0;
              b.appointments_booked = 0;
              b.revenue_try = "0";
              await api("/app/api/campaigns", { method: "POST", body: b });
              toast("Kampanya ve takip bağlantısı oluşturuldu");
              route();
            }),
          },
        }, icon("plus"), "Kampanya ekle")
      ),
      h("div", { class: "grid g3" },
        h("div", { class: "card kpi" }, h("div", { class: "label", text: "Son 30 gün randevu" }), h("div", { class: "value", text: String(d.total_appts_30d) })),
        h("div", { class: "card kpi good" }, h("div", { class: "label", text: "Mesai dışı / Pazar bağlanan" }), h("div", { class: "value", text: `%${d.off_hours_pct}` }), h("div", { class: "hint", text: `${d.off_hours_appts} randevu klinik kapalıyken` })),
        h("div", { class: "card kpi" }, h("div", { class: "label", text: "Aktif Gerçek Kampanya" }), h("div", { class: "value", text: String(campRows.length) }))
      ),
      h("div", { class: "cal-box", role: "note", style: "margin-top:14px" },
        h("b", { text: "Ölçüm Dürüstlük Notu: " }),
        (rep && rep.measurement_honesty_notice_tr) || "Sunucu tarafı gerçek tıklama, bot filtresi ve kasa tahsilatı eşleştirmesi aktiftir; iOS gizlilik ve reklam engelleyiciler nedeniyle %100 reklam tıklama garantisi verilemez."
      ),
      h("div", { class: "card card-flush", style: "margin-top:14px" }, tblWrap(h("table", { class: "table" },
        h("thead", null, h("tr", null, ["Kampanya & Takip Linki", "Kanal", "Tekil Tık (Bot Hariç)", "Form", "Hasta", "Randevu", "Gerçek Kasa Tahsilatı"].map((t, i) => h("th", { class: i > 1 ? "num" : "", text: t })))),
        h("tbody", null, campRows.length ? campRows.map((c) => h("tr", null,
          h("td", null,
            h("b", { text: c.name }),
            c.tracking_url ? h("div", { style: "font-size:12px;color:var(--teal);margin-top:2px" },
              h("code", { text: `/c/${c.code}` }),
              " ",
              h("button", { class: "btn btn-sm btn-ghost", type: "button", on: { click: () => copyText(c.tracking_url, "Kampanya takip linki kopyalandı") } }, "Linki Kopyala")
            ) : null
          ),
          h("td", null, tag(PATIENT_SOURCE_MAP[c.channel || c.source] || c.channel || c.source, "teal")),
          h("td", { class: "num", text: `${c.unique_clicks !== undefined ? c.unique_clicks : c.clicks}${c.bot_clicks ? " (+" + c.bot_clicks + " bot)" : ""}` }),
          h("td", { class: "num", text: c.form_submits !== undefined ? `${c.form_submits}/${c.form_starts || 0}` : "-" }),
          h("td", { class: "num", text: c.patients_created !== undefined ? c.patients_created : (c.conversations || 0) }),
          h("td", { class: "num", text: c.appointments_booked || 0 }),
          h("td", { class: "num", text: fmtTL(c.collected_revenue_try !== undefined ? c.collected_revenue_try : c.revenue_try) })
        )) : h("tr", null, h("td", { colSpan: 7, class: "empty", text: "Henüz kampanya kaydı yok." })))
      ), "Reklam kampanyaları tablosu"))
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
    if (S.user && S.user.role !== "owner") {
      setMain(
        header("Zincir Klinikler", "Yetki bilgilendirmesi"),
        h("div", { class: "card", role: "status" },
          h("h3", { text: "Bu ekran klinik yöneticisine özeldir" }),
          h("p", { style: "color:var(--ink-2);margin:0 0 12px", text: "Şube yönetimi ve yeni klinik açma işlemleri yalnızca yönetici hesabıyla yapılabilir." }),
          h("a", { class: "btn btn-primary", href: "#/overview" }, "Genel Bakışa dön")
        )
      );
      return;
    }
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
      ), "Zincir klinikler tablosu"))
    );
  };

  // ---------------- ayarlar (16 dil + Ekosistem Durum Kartı)
  VIEWS.settings = async () => {
    const [s, eco] = await Promise.all([
      api("/app/api/settings"),
      api("/app/api/ecosystem-status").catch(() => null),
    ]);
    const owner = S.user.role === "owner";

    const WH_DAYS = [
      ["mon", "Pazartesi"],
      ["tue", "Salı"],
      ["wed", "Çarşamba"],
      ["thu", "Perşembe"],
      ["fri", "Cuma"],
      ["sat", "Cumartesi"],
      ["sun", "Pazar"],
    ];
    let whInit = {};
    try {
      const parsed = s.working_hours_json ? JSON.parse(s.working_hours_json) : null;
      if (parsed && typeof parsed === "object") whInit = parsed;
    } catch (e) { whInit = {}; }

    const getInitDay = (dk) => {
      if (Object.prototype.hasOwnProperty.call(whInit, dk)) return whInit[dk];
      if (dk === "sat") return whInit.sat !== undefined ? whInit.sat : ["09:00", "15:00"];
      if (dk === "sun") return whInit.sun !== undefined ? whInit.sun : null;
      return whInit.mon_fri !== undefined ? whInit.mon_fri : ["09:00", "19:00"];
    };

    const whLblId = nextId("wh-lbl");
    const whState = {};
    const whGrid = h("div", { class: "wh-grid", role: "group", "aria-labelledby": whLblId }, WH_DAYS.map(([dk, dLabel]) => {
      const cur = getInitDay(dk);
      const isOpen = Array.isArray(cur) && cur.length >= 2 && cur[0] && cur[1];
      const chkId = nextId(`wh-on-${dk}`);
      const sId = nextId(`wh-s-${dk}`);
      const eId = nextId(`wh-e-${dk}`);
      const chk = h("input", { type: "checkbox", id: chkId, checked: isOpen });
      const sIn = h("input", { class: "input", type: "time", id: sId, value: isOpen ? cur[0] : "09:00", disabled: !isOpen, "aria-label": `${dLabel} başlangıç saati` });
      const eIn = h("input", { class: "input", type: "time", id: eId, value: isOpen ? cur[1] : (dk === "sat" ? "15:00" : "19:00"), disabled: !isOpen, "aria-label": `${dLabel} bitiş saati` });
      const closedLbl = h("span", { class: "wh-closed" + (isOpen ? " hidden" : ""), text: "Kapalı" });
      const timesWrap = h("div", { class: "wh-times" + (isOpen ? "" : " hidden") }, sIn, h("span", { class: "wh-sep", "aria-hidden": "true", text: "–" }), eIn);
      chk.addEventListener("change", () => {
        const on = chk.checked;
        sIn.disabled = !on;
        eIn.disabled = !on;
        timesWrap.classList.toggle("hidden", !on);
        closedLbl.classList.toggle("hidden", on);
      });
      whState[dk] = { label: dLabel, chk, sIn, eIn };
      return h("div", { class: "wh-row" },
        h("label", { class: "wh-day", for: chkId }, chk, h("span", { text: dLabel })),
        h("div", null, timesWrap, closedLbl)
      );
    }));

    function buildWorkingHoursJson() {
      const days = {};
      for (const [dk] of WH_DAYS) {
        const st = whState[dk];
        if (!st.chk.checked) {
          days[dk] = null;
          continue;
        }
        const a = st.sIn.value, b = st.eIn.value;
        if (!a || !b || a >= b) {
          toast(`${st.label}: başlangıç saati bitiş saatinden önce olmalıdır`, true);
          (a ? st.eIn : st.sIn).focus();
          return null;
        }
        days[dk] = [a, b];
      }
      const sameWeekdays = ["tue", "wed", "thu", "fri"].every((dk) => JSON.stringify(days[dk]) === JSON.stringify(days.mon));
      if (sameWeekdays) {
        return JSON.stringify({ mon_fri: days.mon, sat: days.sat, sun: days.sun });
      }
      return JSON.stringify(days);
    }

    const form = h("form", {
      class: "card",
      noValidate: true,
      on: {
        submit: async (e) => {
          e.preventDefault();
          if (!owner) return toast("Yalnızca yönetici kaydedebilir", true);
          const vErr = validateFormTr(form);
          if (vErr) return toast(vErr, true);
          const whJson = buildWorkingHoursJson();
          if (!whJson) return;
          const f = Object.fromEntries(new FormData(form));
          f.slot_step_min = Number(f.slot_step_min || 15);
          f.buffer_min = Number(f.buffer_min || 0);
          f.working_hours_json = whJson;
          const saved = await run(() => api("/app/api/settings", { method: "POST", body: f }), "Klinik ayarları kaydedildi");
          if (saved) {
            S.clinic = f.name;
            document.querySelectorAll(".brand small, .m-topbar-brand small").forEach((el) => { el.textContent = S.clinic; });
          }
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
        fld("İşlem Arası Sterilizasyon Payı (buffer dk)", inp("buffer_min", { type: "number", min: 0, max: 120, value: s.buffer_min || 0 })),
        fld("Google Haritalar Yorum Bağlantısı", inp("google_review_url", { value: s.google_review_url || "", placeholder: "https://search.google.com/local/writereview?placeid=..." }))
      ),
      h("div", { class: "field" },
        h("span", { id: whLblId, style: "font-size:13.5px;font-weight:650;color:var(--navy)", text: "Çalışma Saatleri" }),
        whGrid
      ),
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
