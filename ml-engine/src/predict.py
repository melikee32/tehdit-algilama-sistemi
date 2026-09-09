"""
ml-engine/src/predict.py - Issue #18

Egitilmis modeli kullanarak akislari skorlar, esigi gecenleri
POST /events endpoint'ine gonderir. ML motorunu sisteme baglayan parca.

VERI AKISI
----------
    akis verisi -> oznitelik cikarimi (#15)
                -> model skoru (#16)
                -> kalibrasyon (0-1)
                -> esik filtresi
                -> POST /events  (correlation engine #22 buradan okur)

SEMA NOTU
---------
shared/schema/ml_output.py icindeki MLAlarmPayload'da severity ve details
alanlari var, ancak app/schemas.py'daki EventCreate bunlari tanimiyor ve
Pydantic fazladan alanlari sessizce atiyor. Kayip olmamasi icin ikisi de
raw_payload icine yaziliyor. EventCreate genisletilirse burasi sadelesir.

ESIK SECIMI
-----------
evaluate.py'nin esik taramasi (2M akis):
    0.40 -> F1 0.647  precision 0.701  FPR %6.9
    0.50 -> F1 0.613  precision 0.720  FPR %5.6
    0.85 -> F1 0.234  precision 0.705  FPR %1.6

Varsayilan 0.50: correlation engine'in kendi esigiyle ayni, ve %5.6 FPR
panelde tasinabilir bir yuk. Daha sessiz calismasi istenirse yukseltilir.

Not: correlation engine event'leri src_ip bazinda grupluyor. CICIDS2017'nin
MachineLearningCVE surumunde IP kolonu yok, dolayisiyla replay modunda
gonderilen event'ler src_ip=None ile gider ve hepsi tek grupta toplanir.
Canli ortamda collector (#5) IP bilgisini uretecek.

KULLANIM
--------
    # Once backend'i baslat:  uvicorn app.main:app --reload

    # Kuru calisma (istek gondermez, sadece ozet basar):
    PYTHONPATH=ml-engine/src python ml-engine/src/predict.py \
        --csv data/raw/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv \
        --limit 5000 --dry-run

    # Gercekten gonder:
    PYTHONPATH=ml-engine/src python ml-engine/src/predict.py \
        --csv data/raw/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv \
        --limit 5000
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Iterable

import httpx
import joblib
import numpy as np
import pandas as pd

from calibration import ScoreCalibrator  # noqa: F401  (joblib icin gerekli)
from dataset_adapter import MODEL_FEATURES, clean, load_csv, to_feature_frame, to_matrix

API_URL = "http://localhost:8000"
MODEL_PATH = Path("ml-engine/models/anomaly_model.joblib")

PUBLISH_THRESHOLD = 0.50
REQUEST_TIMEOUT = 10.0


def severity_from_score(score: float) -> str:
    """Kalibre skoru severity etiketine cevirir (correlation engine ile ayni esikler)."""
    if score >= 0.85:
        return "critical"
    if score >= 0.70:
        return "high"
    if score >= 0.50:
        return "medium"
    return "low"


class AnomalyDetector:
    """Egitilmis modeli sarmalar; akislari skorlayip event payload'i uretir."""

    def __init__(self, model_path: Path = MODEL_PATH):
        if not model_path.exists():
            raise FileNotFoundError(
                f"Model bulunamadi: {model_path}\n"
                "Once egitin: PYTHONPATH=ml-engine/src python ml-engine/src/train_model.py"
            )
        bundle = joblib.load(model_path)
        self.model = bundle["model"]
        self.scaler = bundle["scaler"]
        self.calibrator = bundle["calibrator"]
        self.feature_order = bundle["feature_order"]
        self.params = bundle.get("params", {})

    def score(self, features: pd.DataFrame) -> np.ndarray:
        """Oznitelik tablosunu 0-1 arasi anomali skorlarina cevirir."""
        X = self.scaler.transform(to_matrix(features, self.feature_order))
        return self.calibrator.transform(self.model.decision_function(X))

    def to_event(self, row: pd.Series, score: float) -> dict[str, Any]:
        """
        Tek bir akis + skorunu POST /events govdesine cevirir.

        severity ve details EventCreate'de tanimli olmadigi icin
        raw_payload altina yaziliyor (bkz. dosya basindaki sema notu).
        """
        severity = severity_from_score(score)

        return {
            "source_engine": "ml",
            "src_ip": row.get("src_ip"),
            "dst_ip": row.get("dst_ip"),
            "src_port": _as_str(row.get("src_port")),
            "dst_port": _as_str(row.get("dst_port")),
            "protocol": row.get("protocol"),
            "attack_type": "anomaly",
            "confidence": round(float(score), 4),
            "description": (
                f"Anomali skoru {score:.3f} ({severity}) - "
                f"{self.params.get('model_type', 'model')}"
            ),
            "raw_payload": {
                "source_module": "ml_engine",
                "severity": severity,
                "model_type": self.params.get("model_type"),
                "features": {
                    k: _as_native(row[k]) for k in self.feature_order if k in row
                },
            },
        }


def _as_str(value: Any) -> str | None:
    """EventCreate portlari string bekliyor; NaN'lari None'a cevirir."""
    if value is None or (isinstance(value, float) and np.isnan(value)):
        return None
    return str(int(value)) if isinstance(value, (int, float, np.integer)) else str(value)


def _as_native(value: Any) -> Any:
    """numpy tiplerini JSON'a serilestirilebilir hale getirir."""
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return round(float(value), 4)
    return value


def publish(events: Iterable[dict], api_url: str = API_URL) -> tuple[int, int]:
    """
    Event'leri POST /events'e gonderir. (basarili, basarisiz) sayilarini doner.

    Endpoint toplu gonderim desteklemiyor, tek tek gidiyor. Yuksek hacimde
    bulk endpoint eklenmesi gerekir; su anki demo olcegi icin yeterli.
    """
    ok = fail = 0
    with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
        for ev in events:
            try:
                resp = client.post(f"{api_url}/events", json=ev)
                if resp.status_code == 201:
                    ok += 1
                else:
                    fail += 1
                    if fail <= 3:
                        print(f"  ! {resp.status_code}: {resp.text[:200]}")
            except httpx.HTTPError as exc:
                fail += 1
                if fail <= 3:
                    print(f"  ! baglanti hatasi: {exc}")
    return ok, fail


def main() -> None:
    parser = argparse.ArgumentParser(description="ML anomali tespiti ve alarm yayini")
    parser.add_argument("--csv", required=True, help="Skorlanacak CICIDS2017 CSV dosyasi")
    parser.add_argument("--limit", type=int, default=5000, help="Islenecek satir sayisi")
    parser.add_argument("--threshold", type=float, default=PUBLISH_THRESHOLD,
                        help="Yayin esigi (bu skorun ustundekiler gonderilir)")
    parser.add_argument("--api", default=API_URL, help="Backend adresi")
    parser.add_argument("--dry-run", action="store_true",
                        help="Istek gonderme, sadece ozet bas")
    args = parser.parse_args()

    print("Model yukleniyor...")
    detector = AnomalyDetector()
    print(f"  tip={detector.params.get('model_type')} "
          f"oznitelik={len(detector.feature_order)}")

    print(f"Veri okunuyor: {args.csv}")
    df = clean(to_feature_frame(load_csv(args.csv)))
    if len(df) > args.limit:
        df = df.sample(args.limit, random_state=42).reset_index(drop=True)

    print("Skorlaniyor...")
    scores = detector.score(df)
    df["score"] = scores

    selected = df[df["score"] >= args.threshold]
    print(f"\n{len(df)} akis islendi, {len(selected)} tanesi "
          f"{args.threshold} esigini gecti (%{len(selected) / len(df) * 100:.1f})")

    # Etiket varsa gonderilenlerin ne kadari gercekten saldiriymis, goster
    if "label" in selected.columns and len(selected):
        true_positives = int((selected["label"] != "BENIGN").sum())
        print(f"  bunlarin {true_positives} tanesi gercek saldiri "
              f"(precision {true_positives / len(selected):.3f})")

    if len(selected) == 0:
        print("Gonderilecek event yok.")
        return

    sev_counts = selected["score"].apply(severity_from_score).value_counts()
    print("\nSeverity dagilimi:")
    for sev in ["critical", "high", "medium"]:
        if sev in sev_counts:
            print(f"  {sev:9s}: {sev_counts[sev]}")

    events = [detector.to_event(row, row["score"]) for _, row in selected.iterrows()]

    if args.dry_run:
        print("\n[dry-run] Ornek payload:")
        import json
        print(json.dumps(events[0], indent=2, ensure_ascii=False))
        print(f"\n[dry-run] {len(events)} event gonderilmedi.")
        return

    print(f"\n{args.api}/events adresine gonderiliyor...")
    ok, fail = publish(events, args.api)
    print(f"  basarili: {ok}  basarisiz: {fail}")

    if fail:
        print("\nBackend calisiyor mu? Baslatmak icin:")
        print("  uvicorn app.main:app --reload")


if __name__ == "__main__":
    main()