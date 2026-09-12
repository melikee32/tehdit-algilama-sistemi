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

## Veri Seti (ML Engine)

ML modelini yeniden eğitmek için CICIDS2017 veri setine ihtiyaç vardır.

**İndirme:**
1. https://www.unb.ca/cic/datasets/ids-2017.html adresine git
2. **MachineLearningCVE** sürümünü indir (işlenmiş CSV'ler, ~900 MB)
3. Dosyaları `data/raw/MachineLearningCVE/` klasörüne koy

Beklenen klasör yapısı:
```
data/
└── raw/
    └── MachineLearningCVE/
        ├── Monday-WorkingHours.pcap_ISCX.csv        ← eğitim (sadece BENIGN)
        ├── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
        └── ... (diğer günler)
```

> **Not:** `ml-engine/models/anomaly_model.joblib` zaten repoda mevcut —
> sadece paneli çalıştırmak için veri setine gerek yoktur.
> Modeli yeniden eğitmek veya değerlendirmek istiyorsanız indirmeniz gerekir.

## Kurulum

Python tarafı için tüm modüllerin bağımlılıklarını tek seferde kurmak üzere
kökte birleşik bir `requirements.txt` var:

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
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
edebilirsiniz. Sistem metrikleri (latency, alarm sayısı) için:
`http://localhost:8000/stats`

**Frontend (dashboard):**

```bash
cd frontend
npm run dev
```

**Rules-engine pipeline (collector çıktısını otomatik işle):**

```bash
# Tek seferlik (events.jsonl'i okur, işler, backend'e gönderir):
python rules-engine/run_pipeline.py

# Canlı mod (collector yazarken otomatik işler):
python rules-engine/run_pipeline.py --watch

# Correlation'ı da otomatik çalıştır:
python rules-engine/run_pipeline.py --correlate
```

**ML Engine (CSV'den event üret):**

```bash
# Model eğitimi (CICIDS2017 gerekir):
PYTHONPATH=ml-engine/src python ml-engine/src/train_model.py

# Tahmin ve backend'e gönderim:
PYTHONPATH=ml-engine/src python ml-engine/src/predict.py \
    --csv data/raw/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv \
    --limit 5000
```

**Correlation engine:**

```bash
python -m app.correlation
```

## Test

```bash
pytest collector/tests rules-engine/tests shared/schema/tests
```
