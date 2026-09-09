"""
ml-engine/src/diagnose_features.py - Issue #17 (tani)

SORU
----
Isolation Forest'in dusuk F1'i (0.51) nereden geliyor?

  A) Sectigimiz 13 oznitelik saldiri bilgisini tasimiyor (feature hatasi)
  B) Oznitelikler yeterli ama denetimsiz yontem bu bilgiyi cikaramiyor

DENEY
-----
Ayni veriyle uc kosul karsilastirilir:

  1. IsolationForest + 13 oznitelik   (mevcut durum, denetimsiz)
  2. RandomForest    + 13 oznitelik   (denetimli, ayni oznitelikler)
  3. RandomForest    + 78 oznitelik   (denetimli, tum CICIDS2017 kolonlari)

  2 vs 1 farki -> yontemin etkisi (hipotez B)
  3 vs 2 farki -> oznitelik seciminin etkisi (hipotez A)

Onemli: RandomForest burada bir COZUM onerisi degil, UST SINIR olcumudur.
Denetimli model etiketleri gordugu icin bilinmeyen saldirilari yakalama
iddiasini kaybeder; projenin hibrit mimarisinde ML'in gorevi tam da odur.

Calistirma:
    PYTHONPATH=ml-engine/src python ml-engine/src/diagnose_features.py
"""
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

from calibration import ScoreCalibrator
from dataset_adapter import FEATURE_ORDER, MODEL_FEATURES, clean, load_csv, to_feature_frame, to_matrix

DATA_DIR = Path("data/raw/MachineLearningCVE")
MODEL_PATH = Path("ml-engine/models/anomaly_model.joblib")
# Farkli saldiri ailelerini kapsayacak sekilde secildi
FILES = [
    "Tuesday-WorkingHours.pcap_ISCX.csv",                  # brute-force
    "Wednesday-workingHours.pcap_ISCX.csv",                # DoS ailesi
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",  # port tarama
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",    # DDoS
]

SAMPLE_PER_FILE = 120_000
RANDOM_STATE = 42


def summarize(name: str, y_true, y_pred, scores=None) -> dict:
    row = {
        "kosul": name,
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
    }
    if scores is not None:
        row["roc_auc"] = roc_auc_score(y_true, scores)
    return row


def main() -> None:
    print("Veri yukleniyor (13 oznitelik + tum kolonlar birlikte)...")

    feat_frames, full_frames = [], []
    for fname in FILES:
        path = DATA_DIR / fname
        if not path.exists():
            print(f"  ! atlandi: {fname}")
            continue

        raw = load_csv(path)
        if len(raw) > SAMPLE_PER_FILE:
            raw = raw.sample(SAMPLE_PER_FILE, random_state=RANDOM_STATE)

        feats = to_feature_frame(raw)
        # Ayni satirlari elemek icin temizligi indeks korumali yapiyoruz
        mask = feats.replace([np.inf, -np.inf], np.nan).notna().all(axis=1)
        mask &= (feats["duration_ms"] >= 0) & (feats["packet_count"] > 0)

        feat_frames.append(feats[mask])
        full_frames.append(raw[mask.values])
        print(f"  {fname}: {int(mask.sum())} satir")

    feats = pd.concat(feat_frames, ignore_index=True)
    full = pd.concat(full_frames, ignore_index=True)

    y = (feats["label"] != "BENIGN").astype(int).values
    print(f"\nToplam {len(y)} satir | saldiri orani %{y.mean() * 100:.1f}")

    results = []

    # ---------------------------------------------------------------
    # 1. IsolationForest + 13 oznitelik (mevcut durum)
    # ---------------------------------------------------------------
    print("\n[1] IsolationForest + 13 oznitelik (denetimsiz)")
    bundle = joblib.load(MODEL_PATH)
    if_scores = bundle["calibrator"].transform(
        bundle["model"].decision_function(
            bundle["scaler"].transform(to_matrix(feats, MODEL_FEATURES))
        )
    )
    results.append(summarize(
        "IsolationForest / 13 oznitelik",
        y, (if_scores >= 0.5).astype(int), if_scores,
    ))

    # ---------------------------------------------------------------
    # 2. RandomForest + 13 oznitelik
    # ---------------------------------------------------------------
    print("[2] RandomForest + 13 oznitelik (denetimli)")
    X13 = to_matrix(feats)
    X_tr, X_te, y_tr, y_te = train_test_split(
        X13, y, test_size=0.3, random_state=RANDOM_STATE, stratify=y
    )
    rf13 = RandomForestClassifier(
        n_estimators=100, max_depth=20, n_jobs=-1, random_state=RANDOM_STATE
    )
    rf13.fit(X_tr, y_tr)
    p13 = rf13.predict(X_te)
    results.append(summarize(
        "RandomForest / 13 oznitelik",
        y_te, p13, rf13.predict_proba(X_te)[:, 1],
    ))

    # ---------------------------------------------------------------
    # 3. RandomForest + tum sayisal kolonlar
    # ---------------------------------------------------------------
    print("[3] RandomForest + 78 oznitelik (denetimli)")
    num = full.drop(columns=["Label"], errors="ignore").select_dtypes(include=[np.number])
    num = num.replace([np.inf, -np.inf], np.nan).fillna(0)
    print(f"    kullanilan kolon sayisi: {num.shape[1]}")

    Xa_tr, Xa_te, ya_tr, ya_te = train_test_split(
        num.values, y, test_size=0.3, random_state=RANDOM_STATE, stratify=y
    )
    rf_all = RandomForestClassifier(
        n_estimators=100, max_depth=20, n_jobs=-1, random_state=RANDOM_STATE
    )
    rf_all.fit(Xa_tr, ya_tr)
    pa = rf_all.predict(Xa_te)
    results.append(summarize(
        "RandomForest / 78 oznitelik",
        ya_te, pa, rf_all.predict_proba(Xa_te)[:, 1],
    ))

    # ---------------------------------------------------------------
    # Sonuclar
    # ---------------------------------------------------------------
    print("\n" + "=" * 74)
    print("KARSILASTIRMA")
    print("=" * 74)
    print(pd.DataFrame(results).to_string(index=False, float_format=lambda x: f"{x:.4f}"))

    print("\n" + "=" * 74)
    print("13 OZNITELIGIN ONEM SIRASI (RandomForest)")
    print("=" * 74)
    imp = pd.DataFrame({
        "oznitelik": FEATURE_ORDER,
        "onem": rf13.feature_importances_,
    }).sort_values("onem", ascending=False)
    print(imp.to_string(index=False, float_format=lambda x: f"{x:.4f}"))

    print("\n" + "=" * 74)
    print("78 KOLON ICINDE EN ONEMLI 15")
    print("=" * 74)
    imp_all = pd.DataFrame({
        "kolon": num.columns,
        "onem": rf_all.feature_importances_,
    }).sort_values("onem", ascending=False).head(15)
    imp_all["bizde_var_mi"] = [
        "evet" if any(k.lower() in c.lower() or c.lower() in k.lower()
                      for k in ["Flow Duration", "Total Fwd Packets",
                                "Total Backward Packets", "Packet Length Mean",
                                "Packet Length Std", "Flow IAT Mean", "Flow IAT Std",
                                "SYN Flag", "FIN Flag", "RST Flag", "ACK Flag",
                                "Total Length of Fwd", "Total Length of Bwd"])
        else "HAYIR"
        for c in imp_all["kolon"]
    ]
    print(imp_all.to_string(index=False, float_format=lambda x: f"{x:.4f}"))

    print("\nYORUM:")
    f1_if, f1_13, f1_78 = (r["f1"] for r in results)
    print(f"  Yontem etkisi   (RF13 - IF13): {f1_13 - f1_if:+.4f}")
    print(f"  Oznitelik etkisi (RF78 - RF13): {f1_78 - f1_13:+.4f}")
    if f1_78 - f1_13 > 0.10:
        print("  -> Oznitelik secimi belirgin bilgi kaybediyor (hipotez A gecerli).")
    else:
        print("  -> 13 oznitelik yeterli bilgiyi tasiyor; fark yontemden geliyor (hipotez B).")


if __name__ == "__main__":
    main()