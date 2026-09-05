"""
ml-engine/src/train_model.py - Issue #16

Isolation Forest modelini CICIDS2017'nin Pazartesi (sadece BENIGN)
verisiyle egitir ve diske kaydeder.

Neden sadece BENIGN?
    Isolation Forest denetimsiz bir yontemdir; "normalin nasil gorundugunu"
    ogrenir ve ondan sapan her seyi anomali sayar. Egitime saldiri verisi
    karistirirsak model saldiriyi da normal saymaya baslar.
    Etiketler yalnizca degerlendirmede (#17) kullanilir.

Skor kalibrasyonu:
    decision_function ciktisi kabaca [-0.5, +0.5] araligindadir ve
    correlation engine 0-1 arasi 'confidence' bekler (esik 0.5,
    critical 0.85). Ham skoru dogrudan olceklersek degerler ortada
    toplanir ve severity katmanlari hic kullanilmaz.

    Bunun yerine egitim verisindeki skor dagilimini saklayip yuzdelik
    siralama kullaniyoruz: bir akis normal trafigin %99'undan daha
    anormal gorunuyorsa skoru 0.99 olur. Hem yorumlanabilir hem de
    0-1 araligini gercekten kullanir.

Calistirma:
    python ml-engine/src/train_model.py
"""
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from calibration import ScoreCalibrator
from dataset_adapter import FEATURE_ORDER, clean, load_csv, to_feature_frame, to_matrix

# --- Ayarlar ---------------------------------------------------------------

TRAIN_CSV = "data/raw/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv"
MODEL_DIR = Path("ml-engine/models")

# Egitim verisi tamamen normal oldugu icin dusuk tutuyoruz.
# 'auto' yerine acik deger veriyoruz ki sonuc tekrarlanabilir olsun.
CONTAMINATION = 0.01
N_ESTIMATORS = 200
RANDOM_STATE = 42

# Egitim seti 480k satir; hepsini kullanmak gereksiz yavas.
# Isolation Forest zaten alt orneklem uzerinde calisir.
MAX_TRAIN_ROWS = 200_000


# --- Egitim ----------------------------------------------------------------

def main() -> None:
    print("1) Veri yukleniyor...")
    df = clean(to_feature_frame(load_csv(TRAIN_CSV)))

    labels = df["label"].unique()
    if list(labels) != ["BENIGN"]:
        raise ValueError(
            f"Egitim dosyasinda BENIGN disi etiket var: {labels}. "
            "Isolation Forest sadece normal trafikle egitilmeli."
        )

    if len(df) > MAX_TRAIN_ROWS:
        df = df.sample(MAX_TRAIN_ROWS, random_state=RANDOM_STATE)
        print(f"   {MAX_TRAIN_ROWS} satirlik alt orneklem alindi")

    X = to_matrix(df)
    print(f"   Egitim matrisi: {X.shape}")

    print("2) Olcekleme (StandardScaler)...")
    # byte_count milyonlarken syn_count 0-1 arasinda; agac tabanli
    # modeller olceklemeye cok duyarli olmasa da bolme noktalarinin
    # daha dengeli secilmesine yardim eder.
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    print("3) Isolation Forest egitiliyor...")
    model = IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination=CONTAMINATION,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X_scaled)

    print("4) Skor kalibrasyonu...")
    benign_raw = model.decision_function(X_scaled)
    calibrator = ScoreCalibrator(benign_raw)

    calibrated = calibrator.transform(benign_raw)
    print(f"   Ham skor araligi   : {benign_raw.min():.4f} .. {benign_raw.max():.4f}")
    print(f"   Kalibre skor ort.  : {calibrated.mean():.4f}")
    print(f"   Normal trafigin %{(calibrated >= 0.5).mean() * 100:.2f}'i "
          f"0.5 esigini geciyor (false positive beklentisi)")

    print("5) Kaydediliyor...")
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": model,
            "scaler": scaler,
            "calibrator": calibrator,
            "feature_order": FEATURE_ORDER,
            "params": {
                "contamination": CONTAMINATION,
                "n_estimators": N_ESTIMATORS,
                "random_state": RANDOM_STATE,
                "train_rows": len(df),
                "train_file": TRAIN_CSV,
            },
        },
        MODEL_DIR / "isolation_forest.joblib",
    )
    print(f"   -> {MODEL_DIR / 'isolation_forest.joblib'}")
    print("\nTamamlandi.")


if __name__ == "__main__":
    main()