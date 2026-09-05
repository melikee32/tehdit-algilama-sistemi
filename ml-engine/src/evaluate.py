"""
ml-engine/src/evaluate.py - Issue #17

Egitilmis Isolation Forest modelinin CICIDS2017 uzerindeki
basarimini olcer ve raporlar.

Uretilen ciktilar:
  1. Sald>ri tipi bazinda metrik tablosu
  2. Genel (tum saldirilar birlestirilmis) metrikler
  3. Esik taramasi: farkli esiklerde precision/recall/FPR nasil degisiyor
  4. Precision-Recall egrisi (PNG)
  5. Sonuclarin CSV kopyasi (rapora yapistirmak icin)

Onemli metodolojik not:
    Model bir siniflandirici degil, anomali dedektorudur; "bu Heartbleed"
    demez, sadece "bu anormal" der. Bu yuzden tip bazli PRECISION dogrudan
    anlamli degildir. Her tip icin ayri bir ikili problem kuruyoruz:
        pozitif sinif = o tipe ait akislar
        negatif sinif = ayni dosyadaki TUM BENIGN akislar
    Boylece her satir "bu saldiri tipini normal trafikten ayirt edebiliyor
    muyuz?" sorusunu yanitlar.

Calistirma:
    PYTHONPATH=ml-engine/src python ml-engine/src/evaluate.py
"""
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # basliksiz ortamda calissin
import matplotlib.pyplot as plt
from sklearn.metrics import (
    average_precision_score,
    precision_recall_curve,
    roc_auc_score,
)

from calibration import ScoreCalibrator
from dataset_adapter import MODEL_FEATURES, clean, load_csv, to_feature_frame, to_matrix

DATA_DIR = Path("data/raw/MachineLearningCVE")
MODEL_PATH = Path("ml-engine/models/anomaly_model.joblib")
REPORT_DIR = Path("ml-engine/reports")

# Monday egitimde kullanildi, degerlendirmeye dahil etmiyoruz.
EVAL_FILES = [
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]

THRESHOLDS = [0.30, 0.40, 0.50, 0.60, 0.70, 0.85]
DEFAULT_THRESHOLD = 0.50  # correlation engine'in kullandigi esik


def binary_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    """Ikili siniflandirma metrikleri. y_true/y_pred: 1=saldiri, 0=normal."""
    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    return {
        "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "precision": precision, "recall": recall, "f1": f1, "fpr": fpr,
    }


def score_all(model, scaler, calibrator) -> pd.DataFrame:
    """Tum degerlendirme dosyalarini skorlar, tek tabloda birlestirir."""
    frames = []
    for fname in EVAL_FILES:
        path = DATA_DIR / fname
        if not path.exists():
            print(f"  ! atlandi (dosya yok): {fname}")
            continue

        df = clean(to_feature_frame(load_csv(path)))
        X = scaler.transform(to_matrix(df, MODEL_FEATURES))
        df["score"] = calibrator.transform(model.decision_function(X))
        df["source_file"] = fname
        frames.append(df[["label", "score", "source_file"]])
        print(f"  {fname}: {len(df)} satir")

    return pd.concat(frames, ignore_index=True)


def per_attack_table(df: pd.DataFrame, threshold: float) -> pd.DataFrame:
    """
    Her saldiri tipi icin ayri ikili problem:
    pozitif = o tip, negatif = TUM benign akislar.
    """
    benign = df[df["label"] == "BENIGN"]
    rows = []

    for label in sorted(df["label"].unique()):
        if label == "BENIGN":
            continue

        attack = df[df["label"] == label]
        scores = np.concatenate([attack["score"].values, benign["score"].values])
        y_true = np.concatenate([
            np.ones(len(attack), dtype=int),
            np.zeros(len(benign), dtype=int),
        ])
        y_pred = (scores >= threshold).astype(int)

        m = binary_metrics(y_true, y_pred)
        # AUC esikten bagimsiz: modelin ayirt etme gucunu tek sayida ozetler
        m["roc_auc"] = roc_auc_score(y_true, scores)
        m["avg_precision"] = average_precision_score(y_true, scores)
        rows.append({
            "attack_type": label,
            "n_attack": len(attack),
            "mean_score": attack["score"].mean(),
            "recall": m["recall"],
            "precision": m["precision"],
            "f1": m["f1"],
            "fpr": m["fpr"],
            "roc_auc": m["roc_auc"],
        })

    return pd.DataFrame(rows).sort_values("roc_auc", ascending=False)


def threshold_sweep(df: pd.DataFrame) -> pd.DataFrame:
    """Farkli esiklerde genel (tum saldirilar) metrikler."""
    y_true = (df["label"] != "BENIGN").astype(int).values
    scores = df["score"].values

    rows = []
    for t in THRESHOLDS:
        m = binary_metrics(y_true, (scores >= t).astype(int))
        rows.append({
            "threshold": t,
            "precision": m["precision"],
            "recall": m["recall"],
            "f1": m["f1"],
            "fpr": m["fpr"],
            "TP": m["TP"], "FP": m["FP"], "FN": m["FN"],
        })
    return pd.DataFrame(rows)


def plot_pr_curve(df: pd.DataFrame, out_path: Path) -> float:
    """PR egrisi cizer, F1'i maksimize eden esigi dondurur."""
    y_true = (df["label"] != "BENIGN").astype(int).values
    scores = df["score"].values

    precision, recall, thresholds = precision_recall_curve(y_true, scores)
    f1 = np.divide(
        2 * precision * recall,
        precision + recall,
        out=np.zeros_like(precision),
        where=(precision + recall) > 0,
    )
    best_i = int(np.argmax(f1[:-1]))  # son eleman thresholds'ta karsiligi yok
    best_threshold = float(thresholds[best_i])

    plt.figure(figsize=(7, 5))
    plt.plot(recall, precision, linewidth=1.5, label="PR egrisi")
    plt.scatter(
        recall[best_i], precision[best_i], color="red", zorder=5,
        label=f"En iyi F1={f1[best_i]:.3f} (esik={best_threshold:.3f})",
    )
    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.title("Isolation Forest - Precision/Recall (tum saldirilar)")
    plt.grid(alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()

    return best_threshold


def main() -> None:
    print("Model yukleniyor...")
    bundle = joblib.load(MODEL_PATH)
    model, scaler, calibrator = bundle["model"], bundle["scaler"], bundle["calibrator"]

    print("\nDosyalar skorlaniyor...")
    df = score_all(model, scaler, calibrator)
    print(f"\nToplam {len(df)} akis skorlandi.")

    n_attack = int((df["label"] != "BENIGN").sum())
    print(f"  BENIGN : {len(df) - n_attack}")
    print(f"  Saldiri: {n_attack} ({n_attack / len(df) * 100:.1f}%)")

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    # --- 1. Tip bazli tablo ---
    print(f"\n{'=' * 78}")
    print(f"SALDIRI TIPI BAZINDA (esik={DEFAULT_THRESHOLD})")
    print("=" * 78)
    per_type = per_attack_table(df, DEFAULT_THRESHOLD)
    print(per_type.to_string(index=False, float_format=lambda x: f"{x:.4f}"))
    per_type.to_csv(REPORT_DIR / "per_attack_metrics.csv", index=False)

    # --- 2. Genel metrikler ---
    print(f"\n{'=' * 78}")
    print("GENEL (tum saldirilar birlikte)")
    print("=" * 78)
    y_true = (df["label"] != "BENIGN").astype(int).values
    scores = df["score"].values
    overall = binary_metrics(y_true, (scores >= DEFAULT_THRESHOLD).astype(int))
    print(f"  Precision : {overall['precision']:.4f}")
    print(f"  Recall    : {overall['recall']:.4f}")
    print(f"  F1-Score  : {overall['f1']:.4f}")
    print(f"  FPR       : {overall['fpr']:.4f}")
    print(f"  ROC-AUC   : {roc_auc_score(y_true, scores):.4f}")
    print(f"  TP={overall['TP']}  FP={overall['FP']}  FN={overall['FN']}  TN={overall['TN']}")

    # --- 3. Esik taramasi ---
    print(f"\n{'=' * 78}")
    print("ESIK TARAMASI")
    print("=" * 78)
    sweep = threshold_sweep(df)
    print(sweep.to_string(index=False, float_format=lambda x: f"{x:.4f}"))
    sweep.to_csv(REPORT_DIR / "threshold_sweep.csv", index=False)

    # --- 4. PR egrisi ---
    best_t = plot_pr_curve(df, REPORT_DIR / "pr_curve.png")
    print(f"\nPR egrisi: {REPORT_DIR / 'pr_curve.png'}")
    print(f"F1'i maksimize eden esik: {best_t:.4f}")

    print("\n[KURUMSAL GUNCELLEME] Model bundle güncelleniyor (Dinamik Eşik Entegrasyonu)...")
    bundle["params"]["best_threshold"] = best_t
    joblib.dump(bundle, MODEL_PATH)
    print(f"  -> En iyi eşik değeri ({best_t:.4f}) model dosyasına (joblib) kalıcı olarak kaydedildi!")
    print("  -> Backend (FastAPI) artık hardcoded 0.5 yerine bu dinamik değeri okuyabilir.")

    if abs(best_t - DEFAULT_THRESHOLD) > 0.05:
        print(
            f"  NOT: Bu deger eski hardcoded "
            f"{DEFAULT_THRESHOLD} esiginden farkli."
        )

    print(f"\nRaporlar: {REPORT_DIR}/")


if __name__ == "__main__":
    main()