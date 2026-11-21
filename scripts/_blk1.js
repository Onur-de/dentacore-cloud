  // ------------------------------------------------------------------ kokpit katmanı: ortak yardımcılar
  const trNorm = (s) => String(s || "").toLocaleLowerCase("tr-TR").replace(/ı/g, "i").normalize("NFD").replace(/[\u0300-\u036f]/g, "");
  const genKey = (prefix) => `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
  const resolvedKey = () => `dc_resolved_${S.clinic_id}`;
  function getResolved() {
    try { return JSON.parse(lsGet(resolvedKey(), "{}")) || {}; } catch (e) { return {}; }
  }
  function markResolved(pid, stamp) {
    const m = getResolved();
    m[pid] = stamp || "1";
    lsSet(resolvedKey(), JSON.stringify(m));
  }
  const isUnanswered = (r) => r.last_dir === "in" && Number(r.msg_count || 0) > 0 && getResolved()[r.id] !== (r.last_at || "1");

  function downloadText(filename, text) {
    const blob = new Blob(["\ufeff" + text], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = h("a", { href: url, download: filename });
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  const csvCell = (v) => {
    let s = String(v === null || v === undefined ? "" : v);
    if (/^[=+\-@]/.test(s)) s = `'${s}`;
    return `"${s.replace(/"/g, '""')}"`;
  };

  // ------------------------------------------------------------------ canlı rozetler ve anlık tazeleme
  function setNavBadge(link, n) {
    if (!link) return;
    let b = link.querySelector(".count");
    if (!n) {
      if (b) b.remove();
      return;
    }
    if (!b) {
      b = h("span", { class: "count" });
      link.appendChild(b);
    }
    b.textContent = n > 99 ? "99+" : String(n);
  }

  async function refreshNavBadges() {
    if (!S.user) return;
    const [o, convs] = await Promise.all([
      api("/app/api/overview").catch(() => null),
      api("/app/api/conversations").catch(() => null),
    ]);
    if (!S.user) return;
    if (o && o.counts) S.counts = o.counts;
    if (Array.isArray(convs)) S.convs = convs;
    S.unread = (S.convs || []).filter(isUnanswered).length;
    const c = S.counts || {};
    const map = { messages: S.unread, waitlist: c.waitlist || 0, alerts: c.alerts || 0, inventory: c.low_stock || 0 };
    Object.entries(map).forEach(([k, n]) => {
      setNavBadge(document.querySelector(`.nav a[data-k="${k}"]`), n);
      if (k === "messages") setNavBadge(document.querySelector('.m-bottom-nav a[data-mk="messages"]'), n);
    });
  }

  // Her kayıt/yanıt/çözüm sonrası: aktif görünümü, açık çekmeceyi ve sol menü rozetlerini sayfa yenilemeden tazeler.
  async function afterChange(pid) {
    const d = S.drawer;
    const reopen = Boolean(d && activeDrawerCleanup && (pid === undefined || pid === null || Number(pid) === Number(d.pid)));
    await route(true);
    refreshNavBadges();
    if (reopen) await openPatient360(d.pid, d.tab, d.reveal);
  }

  // ------------------------------------------------------------------ hızlı eylemler (üst bar, komut paleti, kokpit ve çekmece ortak kullanır)
  async function openQuickPayment(preselectedPid) {
    const patients = await run(() => api("/app/api/patients"));
    if (!patients) return;
    if (!patients.length) { toast("Tahsilat için önce bir hasta kaydı gerekir.", true); return; }
    const byId = new Map(patients.map((p) => [String(p.id), p]));
    const startPid = preselectedPid ? String(preselectedPid) : String(patients[0].id);
    const pSel = sel("patient_id", patients.map((p) => [String(p.id), `${p.display_name || `Hasta #${p.id}`}${p.balance > 0 ? ` · Borç ${fmtTL(p.balance)}` : ""}`]), startPid);
    const amtIn = inp("amount", { type: "number", step: "0.01", min: "0.01", required: true, placeholder: "Tahsilat tutarı" });
    const advCheck = h("input", { type: "checkbox", name: "allow_advance", value: "1" });
    const advInfo = h("span", { text: "" });
    const sync = () => {
      const bal = Number((byId.get(pSel.value) || {}).balance || 0);
      amtIn.value = bal > 0 ? String(bal) : "";
      advCheck.checked = bal <= 0;
      advInfo.textContent = bal > 0 ? `Açık borç: ${fmtTL(bal)}. Bakiye üstü tutar için avans onayı verin.` : "Açık borç yok; tutar avans (ön ödeme) olarak işlenir.";
    };
    pSel.addEventListener("change", sync);
    const idem = genKey("pay");
    modal("Hızlı tahsilat", [
      fld("Hasta", pSel),
      fld("Tutar (TL)", amtIn),
      fld("Yöntem", sel("method", [
        ["kart", "Kart"],
        ["nakit", "Nakit"],
        ["havale", "Havale / EFT"],
        ["taksitli", "Taksitli ödeme"],
        ["diger", "Diğer"],
      ], "kart")),
      h("label", { class: "odo-check-row" }, advCheck, advInfo),
    ], async (f) => {
      const pid = Number(f.get("patient_id"));
      await api("/app/api/payments", {
        method: "POST",
        body: { patient_id: pid, amount: f.get("amount"), method: f.get("method"), status: "completed", idempotency_key: idem, allow_advance: f.get("allow_advance") === "1" },
      });
      toast(`Tahsilat kaydedildi: ${fmtTL(f.get("amount"))}`);
      afterChange(pid);
    }, "Tahsilatı kaydet");
    sync();
  }

  async function openQuickExpense() {
    const suppliers = await api("/app/api/suppliers").catch(() => []);
    modal("Hızlı gider kaydı", [
      h("div", { class: "row" },
        fld("Kategori", sel("category", [
          ["malzeme", "Sarf & Malzeme"],
          ["laboratuvar", "Laboratuvar"],
          ["kira", "Kira"],
          ["maas", "Personel / Maaş"],
          ["fatura", "Fatura / Vergi"],
          ["diger", "Diğer"],
        ], "malzeme")),
        fld("Ödeme yöntemi", sel("method", [["havale", "Havale / EFT"], ["kredi_karti", "Kredi Kartı"], ["nakit", "Nakit"]], "nakit"))
      ),
      Array.isArray(suppliers) && suppliers.length ? fld("Tedarikçi (isteğe bağlı)", sel("supplier_id", [["", "Seçilmedi"], ...suppliers.map((sp) => [String(sp.id), sp.name])], "")) : null,
      fld("Açıklama", inp("description", { required: true, minLength: 2, placeholder: "Aylık sarf malzeme ödemesi", value: "" })),
      fld("Tutar (TL)", inp("amount", { type: "number", step: "0.01", min: "0.01", required: true, placeholder: "Örn. 4500", value: "" })),
    ], async (f) => {
      const payload = Object.fromEntries(f);
      if (payload.supplier_id) payload.supplier_id = Number(payload.supplier_id);
      else delete payload.supplier_id;
      await api("/app/api/expenses", { method: "POST", body: payload });
      toast(`Gider kaydedildi: ${fmtTL(payload.amount)}`);
      afterChange();
    }, "Gideri kaydet");
  }

  // Sipariş listesi cihazda (localStorage) tutulur; sunucuda sipariş ucu yoktur. CSV/pano ile tedarikçiye iletilir.
  const orderKey = () => `dc_order_list_${S.clinic_id}`;
  function getOrders() {
    try {
      const v = JSON.parse(lsGet(orderKey(), "[]"));
      return Array.isArray(v) ? v : [];
    } catch (e) { return []; }
  }
  const setOrders = (list) => lsSet(orderKey(), JSON.stringify(list));
  const suggestQty = (r) => Math.max(1, Math.ceil(Number(r.min_qty || 0) * 2 - Number(r.qty || 0)));

  async function openStockOrderModal() {
    const rows = await run(() => api("/app/api/inventory"));
    if (!rows) return;
    const low = rows.filter((r) => r.low);
    const box = h("div");
    const render = () => {
      const orders = getOrders();
      const listed = new Set(orders.map((o) => o.id));
      box.replaceChildren(
        h("div", { class: "section-t", text: `Kritik seviyenin altındaki kalemler (${low.length})` }),
        low.length ? h("div", { class: "sec-desk-list" }, low.map((r) => {
          const q = inp(`q-${r.id}`, { type: "number", min: "1", step: "1", value: String(suggestQty(r)), "aria-label": `${r.name} sipariş miktarı` });
          return h("div", { class: "sec-desk-row" },
            h("div", { class: "sec-desk-meta" },
              h("strong", { text: r.name }),
              tag(`Stok ${Number(r.qty)} / alt sınır ${Number(r.min_qty)} ${r.unit || ""}`, "red")
            ),
            h("div", { class: "actions" },
              q,
              listed.has(r.id) ? tag("Listede", "green") : h("button", {
                class: "btn btn-sm btn-teal",
                type: "button",
                on: {
                  click: () => {
                    const list = getOrders();
                    list.push({ id: r.id, name: r.name, unit: r.unit || "", qty: Math.max(1, Number(q.value) || 1), supplier: r.supplier || "", added_at: new Date().toISOString() });
                    setOrders(list);
                    toast(`${r.name} sipariş listesine eklendi`);
                    render();
                  },
                },
              }, "Siparişe ekle")
            )
          );
        })) : h("div", { class: "empty", text: "Kritik seviyenin altında stok kalemi yok." }),
        h("div", { class: "section-t", text: `Sipariş listesi (${orders.length})` }),
        orders.length ? h("div", { class: "sec-desk-list" }, orders.map((o, i) => h("div", { class: "sec-desk-row" },
          h("div", { class: "sec-desk-meta" }, h("strong", { text: o.name }), tag(`${o.qty} ${o.unit}`, "teal"), o.supplier ? h("span", { class: "muted-s", text: o.supplier }) : null),
          h("button", {
            class: "btn btn-sm btn-ghost",
            type: "button",
            on: { click: () => { const list = getOrders(); list.splice(i, 1); setOrders(list); render(); } },
          }, "Listeden çıkar")
        ))) : h("div", { class: "empty", text: "Sipariş listesi boş." }),
        orders.length ? h("div", { class: "actions" },
          h("button", {
            class: "btn btn-sm btn-primary",
            type: "button",
            on: { click: () => copyText(orders.map((o) => `${o.name}: ${o.qty} ${o.unit}${o.supplier ? ` (${o.supplier})` : ""}`).join("\n"), "Sipariş listesi kopyalandı") },
          }, "Listeyi kopyala"),
          h("button", {
            class: "btn btn-sm btn-ghost",
            type: "button",
            on: {
              click: () => {
                downloadText("dentacore-siparis-listesi.csv", ["Ürün;Miktar;Birim;Tedarikçi", ...orders.map((o) => [o.name, o.qty, o.unit, o.supplier].map(csvCell).join(";"))].join("\r\n"));
                toast("Sipariş listesi CSV olarak indirildi");
              },
            },
          }, "CSV indir"),
          h("button", {
            class: "btn btn-sm btn-danger",
            type: "button",
            on: { click: () => { setOrders([]); toast("Sipariş listesi temizlendi"); render(); } },
          }, "Listeyi temizle")
        ) : null
      );
    };
    modal("Kritik stok ve sipariş listesi", [box], async () => true, "Kapat");
    render();
  }

  async function openBranchSwitcher() {
    if (!S.user || S.user.role !== "owner") { toast("Şube değiştirme yalnızca yönetici hesaplarında kullanılabilir.", true); return; }
    const rows = await run(() => api("/app/api/clinics"));
    if (!rows) return;
    const ov = modal("Şube değiştir", [
      h("div", { class: "sec-desk-list" }, rows.map((c) => h("div", { class: "sec-desk-row" },
        h("div", { class: "sec-desk-meta" },
          h("strong", { text: c.name || `Şube #${c.id}` }),
          Number(c.id) === Number(S.clinic_id) ? tag("Aktif şube", "green") : null,
          h("span", { class: "muted-s", text: `${c.patient_count || 0} hasta` })
        ),
        Number(c.id) === Number(S.clinic_id) || c.active === false ? null : h("button", {
          class: "btn btn-sm btn-primary",
          type: "button",
          on: { click: async () => { ov.querySelector(".foot .btn-ghost").click(); await switchClinic(c.id); } },
        }, "Bu şubeye geç")
      ))),
    ], async () => true, "Kapat");
  }

  function openSimulatorModal() {
    const lang = sel("lang", [["", "Otomatik algıla (16 dil)"], ...LANG_OPTIONS], S.simLang || "");
    const txt = inp("text", { required: true, placeholder: "Hastanın mesajını yazın...", value: S.simText || "" });
    const out = h("div", { class: "sim-reply hidden", role: "region", "aria-live": "polite" });
    const show = (r) => {
      if (!r) return;
      const isRtl = RTL_LANGS.has(r.lang);
      out.classList.remove("hidden");
      out.replaceChildren(
        h("div", { class: "sim-reply-head" },
          tag(`Katman: ${r.layer}`, (r.layer || "").startsWith("L1") ? "green" : "teal"),
          tag(`Niyet: ${r.intent}`, ""),
          tag(`Dil: ${(r.lang || "tr").toUpperCase()}${isRtl ? " (RTL)" : ""}`, "teal"),
          tag(`Token: ${r.tokens_in} girdi / ${r.tokens_out} çıktı`, (r.tokens_in + r.tokens_out) === 0 ? "green" : "amber"),
          r.alert ? tag(`Uyarı: ${r.alert}`, "red") : null,
          r.handoff ? tag("Ekibe aktarım", "yellow") : null
        ),
        h("p", { class: "sim-reply-text", dir: isRtl ? "rtl" : "ltr", lang: r.lang || "tr", text: r.answer })
      );
    };
    const simulate = async (text, lg) => {
      const r = await api("/app/api/conversations/simulate", { method: "POST", body: lg ? { text, lang: lg } : { text } });
      S.simResult = r;
      S.simText = text;
      S.simLang = lg || "";
      show(r);
      refreshNavBadges();
    };
    modal("Mesaj simülatörü (0 token)", [
      h("div", { class: "sim-presets" }, SIM_PRESETS.map((p) => h("button", {
        class: "btn btn-sm btn-ghost",
        type: "button",
        on: { click: async () => { txt.value = p.text; lang.value = p.lang; await run(() => simulate(p.text, p.lang)); } },
      }, p.label))),
      h("div", { class: "row" }, fld("Dil", lang), fld("Hasta mesajı", txt)),
      out,
    ], async (f) => {
      await simulate(String(f.get("text") || "").trim(), f.get("lang"));
      return false;
    }, "Simüle et");
    if (S.simResult) show(S.simResult);
  }

  // Konuşma geçmişi + doğrudan mesaj: kokpit "Hızlı Yanıtla", Hasta 360 WhatsApp sekmesi ve modal ortak kullanır.
  function convThreadNode(msgs) {
    const ordered = [...msgs].sort((a, b) => (a.id || 0) - (b.id || 0)).slice(-30);
    const node = h("div", { class: "conv-thread", role: "region", "aria-label": "Konuşma geçmişi" },
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
      }) : h("div", { class: "empty", text: "Henüz kayıtlı mesaj geçmişi yok." })
    );
    requestAnimationFrame(() => { node.scrollTop = node.scrollHeight; });
    return node;
  }

  async function sendConv(pid, text) {
    const res = await api(`/app/api/conversations/${pid}/send`, { method: "POST", body: { text } });
    if (res.status === "failed") throw new Error(`Mesaj iletilemedi: ${res.error || "API hatası"}`);
    toast(res.dry_run ? "Mesaj kuru çalıştırma (dry_run) modunda kaydedildi" : "Mesaj gönderildi");
    return res;
  }

  function templatePicker(tpls, ta, patientName) {
    if (!tpls || !tpls.length) return null;
    const pick = sel("tpl", [["", "Şablon seç (isteğe bağlı)"], ...tpls.slice(0, 40).map((t) => [String(t.id), t.name])], "");
    pick.addEventListener("change", () => {
      const t = tpls.find((x) => String(x.id) === pick.value);
      if (t) ta.value = String(t.body || "").replace(/\{\{1\}\}/g, patientName || "").replace(/\{\{\d+\}\}/g, "");
    });
    return fld("Şablondan doldur", pick);
  }

  async function openConversationModal(pid, name) {
    const [msgs, tpls] = await Promise.all([
      run(() => api(`/app/api/conversations/${pid}/messages`)),
      api("/app/api/templates").catch(() => []),
    ]);
    if (!msgs) return;
    const ta = h("textarea", { class: "input", name: "text", rows: 3, required: true, placeholder: "Hastaya iletilecek mesaj..." });
    modal(`${name || `Hasta #${pid}`} · Hızlı yanıt`, [
      convThreadNode(msgs),
      templatePicker(tpls, ta, name),
      fld("Doğrudan mesaj", ta),
    ], async (f) => {
      await sendConv(pid, f.get("text"));
      afterChange(pid);
    }, "Gönder");
  }

  // ------------------------------------------------------------------ Ctrl+K komut paleti: hasta + eylem + görünüm
  function paletteCommands() {
    const perms = (S.user && S.user.permissions) || null;
    const role = S.user && S.user.role;
    const can = (p, fallback) => (perms ? Boolean(perms[p]) : fallback);
    const cmds = [
      { label: "Yeni randevu oluştur", hint: "randevu saat muayene takvim", run: () => newAppt("") },
      { label: "Yeni hasta kaydet", hint: "hasta ekle kayıt yeni", run: openFastCreatePatientModal },
      { label: "Hızlı tahsilat al", hint: "tahsilat ödeme para kasa", run: () => openQuickPayment(), ok: can("finance_edit", true) },
      { label: "Gider kaydet", hint: "gider masraf fatura", run: openQuickExpense, ok: can("finance_view", role !== "secretary") },
      { label: "Kritik stok ve sipariş listesi", hint: "stok envanter sipariş sarf", run: openStockOrderModal, ok: can("inventory_manage", role !== "secretary") },
      { label: "Şube değiştir", hint: "şube klinik zincir", run: openBranchSwitcher, ok: role === "owner" },
      { label: "Mesaj simülatörünü aç", hint: "mesaj simülatör whatsapp yapay zeka", run: openSimulatorModal },
      { label: "Klinik asistanına sor", hint: "asistan soru özet", run: openAssistant },
    ].filter((c) => c.ok !== false);
    const nav = visibleNavItems().map(([k, t]) => ({ label: `Git: ${t}`, hint: `${k} sayfa görünüm`, run: () => { location.hash = `#/${k}`; }, isNav: true }));
    return { actions: cmds, nav };
  }

  async function openQuickSearch() {
    if (!S.user) return;
    const qIn = inp("q", { placeholder: "Hasta adı veya telefon yazın; ya da randevu, tahsilat, stok, şube...", autocomplete: "off", "aria-label": "Hasta ara veya komut çalıştır" });
    const listBox = h("div", { class: "sec-desk-list palette-list" }, h("div", { class: "empty", text: "Yükleniyor..." }));
    let firstAct = null;
    const ov = modal("Arama ve komut paleti (Ctrl+K)", [
      h("p", { class: "muted-s", text: "Hasta adı ya da telefonu yazınca kartı açılır; \"randevu\", \"tahsilat\", \"stok\", \"şube\" yazınca ilgili işlem çalışır. Enter ilk sonucu açar." }),
      fld("Ara veya komut ver", qIn),
      listBox,
    ], async () => {
      if (firstAct) setTimeout(firstAct, 0);
      return true;
    }, "İlk sonucu aç");
    const closePalette = () => ov.querySelector(".foot .btn-ghost").click();
    const go = (fn) => () => { closePalette(); setTimeout(fn, 0); };
    const cmdRow = (c) => h("div", { class: "sec-desk-row" },
      h("div", { class: "sec-desk-meta" }, h("strong", { text: c.label }), tag(c.isNav ? "Sayfa" : "Eylem", c.isNav ? "" : "teal")),
      h("button", { type: "button", class: "btn btn-sm btn-primary", on: { click: go(c.run) } }, c.isNav ? "Git" : "Çalıştır")
    );
    const patRow = (p) => h("div", { class: "sec-desk-row" },
      h("div", { class: "sec-desk-meta" },
        h("strong", { text: p.display_name || `Hasta #${p.id}` }),
        tag(p.first_source_label || p.first_source || "WhatsApp", "teal"),
        p.primary_doctor_name ? h("span", { class: "muted-s", text: `Dr: ${p.primary_doctor_name}` }) : null,
        p.balance > 0 ? tag(`Borç: ${fmtTL(p.balance)}`, "amber") : null
      ),
      h("div", { class: "actions" },
        h("button", { type: "button", class: "btn btn-sm btn-primary", on: { click: go(() => openPatient360(p.id)) } }, "Hasta 360"),
        h("button", { type: "button", class: "btn btn-sm btn-teal", on: { click: go(() => newAppt(p.id)) } }, "+ Randevu")
      )
    );

    let timer = null;
    let seq = 0;
    const search = async (term) => {
      const mine = ++seq;
      const t = trNorm(term);
      const { actions, nav } = paletteCommands();
      const match = (c) => !t || trNorm(`${c.label} ${c.hint}`).includes(t);
      const cmdHits = t ? [...actions.filter(match), ...nav.filter(match)].slice(0, 6) : actions.slice(0, 6);
      let pats = [];
      try {
        pats = await api(`/app/api/patients${term ? "?search=" + encodeURIComponent(term) : ""}`);
      } catch (e) {
        pats = [];
      }
      if (mine !== seq) return;
      const shown = pats.slice(0, 10);
      firstAct = t && cmdHits.length ? cmdHits[0].run : (shown[0] ? () => openPatient360(shown[0].id) : (cmdHits[0] ? cmdHits[0].run : null));
      listBox.replaceChildren(
        cmdHits.length ? h("div", { class: "section-t", text: t ? "Eşleşen eylemler" : "Hızlı eylemler" }) : null,
        ...cmdHits.map(cmdRow),
        h("div", { class: "section-t", text: t ? `Eşleşen hastalar (${shown.length})` : "Son hastalar" }),
        ...(shown.length ? shown.map(patRow) : [h("div", { class: "empty" },
          "Eşleşen hasta bulunamadı. ",
          h("button", { type: "button", class: "btn btn-sm btn-cta", on: { click: go(() => newAppt("")) } }, "+ Yeni hasta ve randevu oluştur")
        )])
      );
    };
    qIn.addEventListener("input", () => {
      clearTimeout(timer);
      timer = setTimeout(() => search(qIn.value.trim()), 200);
    });
    search("");
  }

  // Stabil API: her ekrandan hasta adına/telefonuna tıklayınca açılan birleşik çekmece.
  function openPatient360(pid, tab, reveal) {
    return openPatient(pid, reveal, tab);
  }

