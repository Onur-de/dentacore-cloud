# DentaCore v6.2 — Kurumsal Klinik Otomasyon Sistemi (GitHub & Kalıcı Bulut Paketi)

Bu depo hem **Ömür Boyu Ücretsiz GitHub Pages / Vercel / Netlify Statik Bulut Sürümünü** (`docs/`) hem de **7/24 Ortak Veritabanlı Canlı Python FastAPI Sunucusunu** (`run_cloud.py`) içerir.

## 1. Ömür Boyu Ücretsiz Link (GitHub Pages / Vercel / Netlify)
- **GitHub Pages:** Depo ayarlarından `Settings -> Pages -> Source: GitHub Actions` seçildiğinde `.github/workflows/deploy-pages.yml` tekil olarak yayına alır:
  - Tam Sistem & Yönetim Paneli (3 Şube): `https://<kullanici-adi>.github.io/<depo-adi>/`
  - Tanıtım Sitesi: `https://<kullanici-adi>.github.io/<depo-adi>/tanitim.html`
- **Vercel / Netlify:** Depoyu bağladığınız anda otomatik olarak `vercel.json` / `netlify.toml` ile yayına girer.

## 2. Gerçek Klinik 7/24 Ortak Veritabanlı Sunucu (Render / Railway / Docker)
- **Render.com:** `New -> Blueprint` veya `New -> Web Service` seçip bu GitHub deposunu bağlayın (`render.yaml` tüm ayarları otomatik yapar).
- **Railway.app:** `New Project -> Deploy from GitHub repo` seçin (`railway.json` otomatik başlatır).
