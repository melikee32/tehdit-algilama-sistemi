import warnings
from pathlib import Path
import joblib
import numpy as np
from sklearn.covariance import EllipticEnvelope
from sklearn.preprocessing import PowerTransformer
from calibration import ScoreCalibrator
from dataset_adapter import MODEL_FEATURES, clean, load_csv, to_feature_frame, to_matrix

warnings.filterwarnings("ignore", category=RuntimeWarning)

TRAIN_CSV = "data/raw/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv"
MODEL_DIR = Path("ml-engine/models")

CONTAMINATION = 0.01
RANDOM_STATE = 42
SUPPORT_FRACTION = 0.995
JITTER = 1e-3
MAX_TRAIN_ROWS = 50_000

def main() -> None:
    print("1) Veri yukleniyor (Sadece Normal Trafik - Pazartesi)...")
    df = clean(to_feature_frame(load_csv(TRAIN_CSV)))

    labels = df["label"].unique()
    if list(labels) != ["BENIGN"]:
        raise ValueError("Egitimde sadece BENIGN olmali! Zero-Day mantigi bozulur.")

    if len(df) > MAX_TRAIN_ROWS:
        df = df.sample(MAX_TRAIN_ROWS, random_state=RANDOM_STATE)
        print(f"   {MAX_TRAIN_ROWS} satirlik alt orneklem alindi")

    X = to_matrix(df, MODEL_FEATURES)

    print("2) Olcekleme (PowerTransformer ile Gauss Donusumu)...")
    scaler = PowerTransformer(method='yeo-johnson')
    X_scaled = scaler.fit_transform(X)

    if JITTER > 0:
        print(f"   Kovaryans duzeltmesi (jitter={JITTER}) uygulaniyor...")
        rng = np.random.default_rng(RANDOM_STATE)
        X_scaled = X_scaled + rng.normal(0.0, JITTER, X_scaled.shape)

    print("3) Model egitiliyor (Elliptic Envelope - Gozetimsiz)...")
    model = EllipticEnvelope(
        contamination=CONTAMINATION,
        support_fraction=SUPPORT_FRACTION,
        random_state=RANDOM_STATE,
    )
    model.fit(X_scaled)

    print("4) Skor kalibrasyonu...")
    benign_raw = model.decision_function(X_scaled)
    calibrator = ScoreCalibrator(benign_raw)
    calibrated = calibrator.transform(benign_raw)

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
                "model_type": "elliptic_envelope",
                "best_threshold": 0.5
            },
        },
        out_path,
    )
    print(f"   -> {out_path}")
    print("\nTamamlandi.")

if __name__ == "__main__":
    main()
