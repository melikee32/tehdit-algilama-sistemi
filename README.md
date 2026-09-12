# Tehdit Algılama Sistemi

Ağ trafiği ve log verilerinden saldırı tespiti yapan, kural tabanlı motor ile
makine öğrenmesi tabanlı anomali tespitini bir korelasyon motorunda birleştirip
alarmları canlı bir web panelinde gösteren sistem.

## Mimari

```
collector      -> ham paket/log toplama, saldırı simülasyon scriptleri
rules-engine   -> imza/kural tabanlı tespit (port taraması, brute-force, SYN flood, CVE eşleştirme)
ml-engine      -> denetimsiz anomali tespiti (Elliptic Envelope / Isolation Forest)
shared         -> ortak Pydantic şemaları (rules-engine, dashboard için)
app            -> FastAPI backend: /events, /alarms, /health, /ws (korelasyon motoru burada)
frontend       -> React tabanlı SOC dashboard (canlı alarm akışı, PDF rapor)
```

Veri akışı: `collector` → `rules-engine` / `ml-engine` → `POST /events` →
`app/correlation.py` (kural + ML skorlarını birleştirir) → `/alarms` ve
WebSocket (`/ws`) üzerinden `frontend`.

## Kurulum

Python tarafı için tüm modüllerin bağımlılıklarını tek seferde kurmak üzere
kökte birleşik bir `requirements.txt` var:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Sadece tek bir modülle çalışacaksanız o modülün kendi `requirements.txt`
dosyasını kurmanız yeterli (örn. `pip install -r app/requirements.txt`).

Frontend için:

```bash
cd frontend
npm install
```

## Çalıştırma

**Backend (FastAPI):**

```bash
uvicorn app.main:app --reload --port 8000
```

`http://localhost:8000/docs` adresinden tüm endpoint'leri interaktif test
edebilirsiniz.

**Frontend (dashboard):**

```bash
cd frontend
npm run dev
```

**Rules-engine / collector / ml-engine:** her modülün kendi `src`/kök
dizinindeki script'ler ilgili tespit sürecini (paket yakalama, kural
motoru, model eğitimi/skorlama) çalıştırır ve sonuçları `POST /events`
ile backend'e gönderir. Model eğitimi için:

```bash
python ml-engine/src/train_model.py
```

## Test

```bash
pytest collector/tests rules-engine/tests shared/schema/tests
```
