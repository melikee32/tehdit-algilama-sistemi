"""
ml-engine/src/compare_models.py - Issue #16 / #17

SORU
----
Isolation Forest dogru secim mi? Alternatif denetimsiz yontemler
ayni veride daha iyi sonuc verir mi?

KARSILASTIRILAN YONTEMLER
-------------------------
  IsolationForest    : rastgele bolmelerle izolasyon derinligi
  One-Class SVM      : normal veri etrafina karar siniri cizer
  Local Outlier Factor: yerel yogunluk sapmasi
  Elliptic Envelope  : robust kovaryans, eliptik normal bolge

Literaturde denetimsiz IDS calismalarinda standart karsilastirma seti
bu dortludur (bazi calismalar buna Autoencoder ekler).

PROTOKOL (sizintisiz)
---------------------
Egitim  : Pazartesi (sadece BENIGN) alt orneklemi
Test    : Sali + Carsamba + Cuma-DDoS karisimi
Model hicbir saldiri gormeden egitilir, farkli gunlerin trafiginde
test edilir. diagnose_leakage.py'da gosterildigi uzere rastgele bolme
yaniltici sonuc uretir; burada kullanilmaz.

KARSILASTIRMA OLCUTU
--------------------
Ana olcut ROC-AUC'dur: esikten bagimsizdir, dolayisiyla her yontemin
kendi skor olcegi farkli olsa da adil karsilastirma saglar.
Ayrica her yontem icin "en iyi F1" (tum esikler taranarak) raporlanir;
bu, yontemin ulasabilecegi tavani gosterir.

Calistirma:
    PYTHONPATH=ml-engine/src python ml-engine/src/compare_models.py
"""
import time
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.covariance import EllipticEnvelope
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_recall_curve, roc_auc_score
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

from dataset_adapter import clean, load_csv, to_feature_frame, to_matrix

warnings.filterwarnings("ignore")

DATA_DIR = Path("data/raw/MachineLearningCVE")
REPORT_DIR = Path("ml-engine/reports")
RANDOM_STATE = 42

TRAIN_FILE = "Monday-WorkingHours.pcap_ISCX.csv"
TEST_FILES = [
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]

# One-Class SVM O(n^2)-O(n^3); LOF bellek yiyor. Adil olmasi icin
# TUM yontemler ayni buyuklukteki veriyle calistirilir.
N_TRAIN = 50_000
N_TEST_PER_FILE = 60_000


def best_f1(y_true: np.ndarray, scores: np.ndarray) -> tuple[float, float]:
    """Tum esikleri tarayip ulasilabilecek en yuksek F1'i dondurur."""
    precision, recall, thresholds = precision_recall_curve(y_true, scores)
    f1 = np.divide(
        2 * precision * recall, precision + recall,
        out=np.zeros_like(precision), where=(precision + recall) > 0,
    )
    i = int(np.argmax(f1[:-1]))
    return float(f1[i]), float(thresholds[i])


def main() -> None:
    print("Egitim verisi (Pazartesi, sadece BENIGN)...")
    train_df = clean(to_feature_frame(load_csv(DATA_DIR / TRAIN_FILE)))
    train_df = train_df.sample(N_TRAIN, random_state=RANDOM_STATE)
    X_train_raw = to_matrix(train_df)

    print("Test verisi (diger gunler)...")
    test_frames = []
    for f in TEST_FILES:
        path = DATA_DIR / f
        if not path.exists():
            print(f"  ! atlandi: {f}")
            continue
        d = clean(to_feature_frame(load_csv(path)))
        if len(d) > N_TEST_PER_FILE:
            d = d.sample(N_TEST_PER_FILE, random_state=RANDOM_STATE)
        test_frames.append(d)
        print(f"  {f}: {len(d)}")

    test_df = pd.concat(test_frames, ignore_index=True)
    X_test_raw = to_matrix(test_df)
    y_test = (test_df["label"] != "BENIGN").astype(int).values

    print(f"\nEgitim: {X_train_raw.shape} | Test: {X_test_raw.shape} "
          f"| saldiri orani %{y_test.mean() * 100:.1f}")

    scaler = StandardScaler().fit(X_train_raw)
    X_train = scaler.transform(X_train_raw)
    X_test = scaler.transform(X_test_raw)

    results = []

    # --- Isolation Forest -------------------------------------------------
    print("\n[1/4] Isolation Forest...")
    t0 = time.time()
    m = IsolationForest(n_estimators=200, contamination=0.01,
                        random_state=RANDOM_STATE, n_jobs=-1).fit(X_train)
    # decision_function: BUYUK = normal. Anomali skoru icin isaret ters.
    s = -m.decision_function(X_test)
    results.append(("Isolation Forest", s, time.time() - t0))

    # --- One-Class SVM ----------------------------------------------------
    print("[2/4] One-Class SVM (yavas olabilir)...")
    t0 = time.time()
    m = OneClassSVM(kernel="rbf", nu=0.01, gamma="scale").fit(X_train)
    s = -m.decision_function(X_test)
    results.append(("One-Class SVM", s, time.time() - t0))

    # --- Local Outlier Factor --------------------------------------------
    print("[3/4] Local Outlier Factor...")
    t0 = time.time()
    # novelty=True: egitimde gormedigi veriye skor verebilsin
    m = LocalOutlierFactor(n_neighbors=20, novelty=True,
                           contamination=0.01, n_jobs=-1).fit(X_train)
    s = -m.decision_function(X_test)
    results.append(("Local Outlier Factor", s, time.time() - t0))

    # --- Elliptic Envelope ------------------------------------------------
    print("[4/4] Elliptic Envelope...")
    t0 = time.time()
    try:
        m = EllipticEnvelope(contamination=0.01,
                             support_fraction=0.9,
                             random_state=RANDOM_STATE).fit(X_train)
        s = -m.decision_function(X_test)
        results.append(("Elliptic Envelope", s, time.time() - t0))
    except Exception as e:
        print(f"    basarisiz ({type(e).__name__}): {e}")

    # --- Tablo ------------------------------------------------------------
    rows = []
    for name, scores, elapsed in results:
        auc = roc_auc_score(y_test, scores)
        f1, thr = best_f1(y_test, scores)
        rows.append({
            "yontem": name,
            "roc_auc": auc,
            "en_iyi_f1": f1,
            "sure_sn": elapsed,
        })

    df = pd.DataFrame(rows).sort_values("roc_auc", ascending=False)

    print("\n" + "=" * 70)
    print("DENETIMSIZ YONTEM KARSILASTIRMASI (gun bazli, sizintisiz)")
    print("=" * 70)
    print(df.to_string(index=False, float_format=lambda x: f"{x:.4f}"))

    # --- Saldiri turu bazinda AUC ----------------------------------------
    print("\n" + "=" * 70)
    print("SALDIRI TURU BAZINDA ROC-AUC")
    print("=" * 70)
    benign_mask = (test_df["label"] == "BENIGN").values

    per_type = []
    for label in sorted(test_df["label"].unique()):
        if label == "BENIGN":
            continue
        mask = (test_df["label"] == label).values
        row = {"saldiri": label, "n": int(mask.sum())}
        for name, scores, _ in results:
            sel = mask | benign_mask
            yy = mask[sel].astype(int)
            if yy.sum() == 0 or yy.sum() == len(yy):
                row[name] = float("nan")
            else:
                row[name] = roc_auc_score(yy, scores[sel])
        per_type.append(row)

    pt = pd.DataFrame(per_type)
    print(pt.to_string(index=False, float_format=lambda x: f"{x:.3f}"))

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    df.to_csv(REPORT_DIR / "model_comparison.csv", index=False)
    pt.to_csv(REPORT_DIR / "model_comparison_per_attack.csv", index=False)

    best = df.iloc[0]
    print(f"\nEn yuksek ROC-AUC: {best['yontem']} ({best['roc_auc']:.4f})")
    if best["yontem"] != "Isolation Forest":
        gap = best["roc_auc"] - df[df["yontem"] == "Isolation Forest"]["roc_auc"].iloc[0]
        print(f"Isolation Forest'tan {gap:+.4f} farkli.")
        if gap > 0.05:
            print("  -> Anlamli fark. Model degisikligi ekiple tartisilmali (#16).")
        else:
            print("  -> Fark kucuk; Isolation Forest'ta kalmak savunulabilir "
                  "(daha hizli, daha az bellek).")
    else:
        print("  -> Isolation Forest secimi dogrulandi.")

    print(f"\nRaporlar: {REPORT_DIR}/")


if __name__ == "__main__":
    main()