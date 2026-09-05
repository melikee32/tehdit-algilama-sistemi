"""
ml-engine/src/train_model.py - Issue #16

Anomali tespit modelini CICIDS2017'nin Pazartesi (sadece BENIGN)
verisiyle egitir ve diske kaydeder.

Neden sadece BENIGN?
    Denetimsiz anomali tespiti "normalin nasil gorundugunu" ogrenir ve
    ondan sapan her seyi anomali sayar. Egitime saldiri verisi
    karistirirsak model saldiriyi da normal saymaya baslar.
    Etiketler yalnizca degerlendirmede (#17) kullanilir.

Model secimi:
    ml-engine/analysis/compare_models.py dort denetimsiz yontemi
    sizintisiz protokolle karsilastirdi (240k satir test):

        One-Class SVM        ROC-AUC 0.816  (brute-force'a kor: 0.127)
        Elliptic Envelope    ROC-AUC 0.816  (en dusuk turu 0.682)
        Isolation Forest     ROC-AUC 0.729  (PortScan'i goremiyor: 0.379)
        Local Outlier Factor ROC-AUC 0.619

    Elliptic Envelope hicbir saldiri turunde cokmedigi icin varsayilan
    secim odur. MODEL_TYPE ile degistirilebilir.

Sayisal kararlilik:
    Elliptic Envelope kovaryans matrisinin TERSINI alir. Ozniteliklerimiz
    birbirine bagimli (mean_packet_size ~ byte_count/packet_count, flag
    kolonlari CICIDS2017'de 0/1 bayragi oldugu icin cok dusuk varyansli),
    bu yuzden matris tekillesiyor ve Mahalanobis mesafeleri trilyonlara
    firliyor. Sonucta kalibrasyon cipalari eziliyor ve ust esikler
    (0.6-0.85) kullanilamaz hale geliyordu.

    Iki onlem alindi:
      1. packet_count modele verilmiyor (fwd+bwd toplami, birebir bagimli)
      2. Olceklenmis veriye cok kucuk bir gurultu ekleniyor; bu, kovaryans
         matrisinin kosegenini hafifce sisirerek tersini alinabilir kilar
         (ridge/Tikhonov duzeltmesinin pratik karsiligi).

Calistirma:
    PYTHONPATH=ml-engine/src python ml-engine/src/train_model.py
"""
import warnings
from pathlib import Path

import joblib
import numpy as np
from sklearn.covariance import EllipticEnvelope
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from calibration import ScoreCalibrator
from dataset_adapter import MODEL_FEATURES, clean, load_csv, to_feature_frame, to_matrix

# MCD algoritmasi yakinsarken cok sayida RuntimeWarning uretiyor;
# sonucu etkilemiyor, ciktiyi boguyor.
warnings.filterwarnings("ignore", category=RuntimeWarning)

# --- Ayarlar ---------------------------------------------------------------

TRAIN_CSV = "data/raw/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv"
MODEL_DIR = Path("ml-engine/models")

# "elliptic" | "isolation"
MODEL_TYPE = "elliptic"

CONTAMINATION = 0.01
RANDOM_STATE = 42

# Isolation Forest parametresi
N_ESTIMATORS = 200

# Elliptic Envelope parametreleri
#
# 0.95 -> 0.995: hiperparametre taramasi (contamination x support_fraction,
# 25 kombinasyon, 7 degerlendirme dosyasi) support_fraction=1.0'a kadar
# yukseldikce en-iyi-F1'in monoton arttigini ama ROC-AUC'un 0.99'dan sonra
# dusmeye basladigini gosterdi (MCD'nin saglamligi kayboluyor). 0.995,
# ROC-AUC'u (0.853) korurken en-iyi-F1'i 0.620 -> 0.649'a cikaran denge
# noktasi. contamination'in bu metriklere etkisi yok (sadece predict()
# esigini kaydiriyor, decision_function siralamasini degistirmiyor).
SUPPORT_FRACTION = 0.995

# Kovaryans duzeltmesi: olceklenmis veriye eklenen gurultunun std'si.
# Cok kucuk oldugu icin oznitelik dagilimini bozmaz, ama matrisi
# tersi alinabilir hale getirir. 0 verilirse duzeltme uygulanmaz.
JITTER = 1e-3

MAX_TRAIN_ROWS = 50_000 if MODEL_TYPE == "elliptic" else 200_000


def build_model():
    """MODEL_TYPE'a gore model nesnesi olusturur."""
    if MODEL_TYPE == "elliptic":
        return EllipticEnvelope(
            contamination=CONTAMINATION,
            support_fraction=SUPPORT_FRACTION,
            random_state=RANDOM_STATE,
        )
    if MODEL_TYPE == "isolation":
        return IsolationForest(
            n_estimators=N_ESTIMATORS,
            contamination=CONTAMINATION,
            random_state=RANDOM_STATE,
            n_jobs=-1,
        )
    raise ValueError(f"Bilinmeyen MODEL_TYPE: {MODEL_TYPE}")


def main() -> None:
    print("1) Veri yukleniyor...")
    df = clean(to_feature_frame(load_csv(TRAIN_CSV)))

    labels = df["label"].unique()
    if list(labels) != ["BENIGN"]:
        raise ValueError(
            f"Egitim dosyasinda BENIGN disi etiket var: {labels}. "
            "Denetimsiz model sadece normal trafikle egitilmeli."
        )

    if len(df) > MAX_TRAIN_ROWS:
        df = df.sample(MAX_TRAIN_ROWS, random_state=RANDOM_STATE)
        print(f"   {MAX_TRAIN_ROWS} satirlik alt orneklem alindi")

    X = to_matrix(df, MODEL_FEATURES)
    print(f"   Egitim matrisi: {X.shape} ({len(MODEL_FEATURES)} oznitelik)")

    print("2) Olcekleme (StandardScaler)...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    if MODEL_TYPE == "elliptic" and JITTER > 0:
        print(f"   Kovaryans duzeltmesi uygulaniyor (jitter={JITTER})")
        rng = np.random.default_rng(RANDOM_STATE)
        X_scaled = X_scaled + rng.normal(0.0, JITTER, X_scaled.shape)

    print(f"3) Model egitiliyor ({MODEL_TYPE})...")
    model = build_model()
    model.fit(X_scaled)

    print("4) Skor kalibrasyonu...")
    benign_raw = model.decision_function(X_scaled)

    lo, hi = float(benign_raw.min()), float(benign_raw.max())
    print(f"   Ham skor araligi   : {lo:.4f} .. {hi:.4f}")

    if abs(lo) > 1e6 or abs(hi) > 1e6:
        print("   ! UYARI: ham skor araligi asiri genis. Kovaryans matrisi")
        print("     hala tekil olabilir. JITTER'i buyutmeyi (1e-2) veya")
        print("     MODEL_TYPE='isolation' denemeyi dusunun.")

    calibrator = ScoreCalibrator(benign_raw)
    calibrated = calibrator.transform(benign_raw)

    print(f"   Kalibre skor ort.  : {calibrated.mean():.4f}")
    print(f"   Normal trafigin %{(calibrated >= 0.5).mean() * 100:.2f}'i "
          f"0.5 esigini geciyor (beklenen FPR)")

    print("5) Kaydediliyor...")
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    out_path = MODEL_DIR / "anomaly_model.joblib"
    joblib.dump(
        {
            "model": model,
            "scaler": scaler,
            "calibrator": calibrator,
            "feature_order": MODEL_FEATURES,
            "params": {
                "model_type": MODEL_TYPE,
                "contamination": CONTAMINATION,
                "support_fraction": SUPPORT_FRACTION if MODEL_TYPE == "elliptic" else None,
                "n_estimators": N_ESTIMATORS if MODEL_TYPE == "isolation" else None,
                "jitter": JITTER if MODEL_TYPE == "elliptic" else None,
                "random_state": RANDOM_STATE,
                "train_rows": len(df),
                "train_file": TRAIN_CSV,
                "raw_score_range": [lo, hi],
            },
        },
        out_path,
    )
    print(f"   -> {out_path}")
    print("\nTamamlandi.")


if __name__ == "__main__":
    main()
