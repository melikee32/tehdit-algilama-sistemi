"""
ml-engine/src/dataset_adapter.py - Issue #15

CICIDS2017 CSV satirlarini shared/schema/features.py icindeki
MLFeatureVector formatina cevirir.

Ayni cikti formati canli trafik icin de kullanilacak (flow_adapter.py),
boylece egitim ve tahmin ayni oznitelik siralamasini paylasir.
"""
from pathlib import Path

import numpy as np
import pandas as pd

# CICIDS2017 kolon adlarinda bastaki bosluklar var (' Flow Duration' gibi).
# read_csv'de skipinitialspace kullanmiyoruz, bunun yerine kolonlari
# yuklerken strip ediyoruz. Asagidaki isimler strip SONRASI halleridir.
COLUMN_MAP = {
    "duration_us":      "Flow Duration",
    "fwd_packet_count": "Total Fwd Packets",
    "bwd_packet_count": "Total Backward Packets",
    "fwd_bytes":        "Total Length of Fwd Packets",
    "bwd_bytes":        "Total Length of Bwd Packets",
    "mean_packet_size": "Packet Length Mean",
    "std_packet_size":  "Packet Length Std",
    "mean_iat_us":      "Flow IAT Mean",
    "std_iat_us":       "Flow IAT Std",
    "syn_count":        "SYN Flag Count",
    "fin_count":        "FIN Flag Count",
    "rst_count":        "RST Flag Count",
    "ack_count":        "ACK Flag Count",
    "dst_port":         "Destination Port",
    "label":            "Label",
}

# MLFeatureVector.to_array() ile AYNI sira. Degistirilirse model bozulur.
FEATURE_ORDER = [
    "duration_ms",
    "packet_count",
    "byte_count",
    "fwd_packet_count",
    "bwd_packet_count",
    "mean_packet_size",
    "std_packet_size",
    "mean_iat_ms",
    "std_iat_ms",
    "syn_count",
    "fin_count",
    "rst_count",
    "ack_count",
]


def load_csv(path: str | Path) -> pd.DataFrame:
    """Tek bir CICIDS2017 CSV dosyasini okur ve kolon adlarini temizler."""
    df = pd.read_csv(path, low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    return df


def to_feature_frame(df: pd.DataFrame) -> pd.DataFrame:
    """
    Ham CICIDS2017 tablosunu MLFeatureVector alanlarina cevirir.

    Donen tablo: FEATURE_ORDER kolonlari + 'dst_port' + 'label'
    """
    missing = [c for c in COLUMN_MAP.values() if c not in df.columns]
    if missing:
        raise KeyError(f"CSV'de beklenen kolonlar yok: {missing}")

    c = COLUMN_MAP
    out = pd.DataFrame({
        # CICIDS2017 sureleri mikrosaniye cinsinden tutar, ms'ye ceviriyoruz
        "duration_ms":      df[c["duration_us"]] / 1000.0,
        "packet_count":     df[c["fwd_packet_count"]] + df[c["bwd_packet_count"]],
        "byte_count":       df[c["fwd_bytes"]] + df[c["bwd_bytes"]],
        "fwd_packet_count": df[c["fwd_packet_count"]],
        "bwd_packet_count": df[c["bwd_packet_count"]],
        "mean_packet_size": df[c["mean_packet_size"]],
        "std_packet_size":  df[c["std_packet_size"]],
        "mean_iat_ms":      df[c["mean_iat_us"]] / 1000.0,
        "std_iat_ms":       df[c["std_iat_us"]] / 1000.0,
        "syn_count":        df[c["syn_count"]],
        "fin_count":        df[c["fin_count"]],
        "rst_count":        df[c["rst_count"]],
        "ack_count":        df[c["ack_count"]],
        "dst_port":         df[c["dst_port"]],
        "label":            df[c["label"]].astype(str).str.strip(),
    })
    return out


def clean(df: pd.DataFrame) -> pd.DataFrame:
    """
    Bilinen CICIDS2017 bozukluklarini temizler:
      - inf / -inf degerleri (Flow Bytes/s gibi bolme sonuclarindan gelir)
      - NaN satirlar
      - tamamen ayni satirlarin tekrari
      - negatif sure/sayim degerleri
    """
    before = len(df)

    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    df = df.drop_duplicates()
    df = df[(df["duration_ms"] >= 0) & (df["packet_count"] > 0)]

    print(f"[clean] {before} -> {len(df)} satir ({before - len(df)} atildi)")
    return df.reset_index(drop=True)


def to_matrix(df: pd.DataFrame) -> np.ndarray:
    """Modele beslenecek sayisal matris. Kolon sirasi FEATURE_ORDER."""
    return df[FEATURE_ORDER].to_numpy(dtype=float)


if __name__ == "__main__":
    # Hizli kontrol: Pazartesi dosyasi sadece normal trafik icerir,
    # Isolation Forest bu veriyle egitilecek.
    path = "data/raw/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv"

    raw = load_csv(path)
    print(f"Ham: {raw.shape[0]} satir, {raw.shape[1]} kolon")

    feats = clean(to_feature_frame(raw))
    print(f"Oznitelik tablosu: {feats.shape}")
    print("\nEtiket dagilimi:")
    print(feats["label"].value_counts())
    print("\nIlk 3 satir:")
    print(feats.head(3).to_string())

    X = to_matrix(feats)
    print(f"\nMatris: {X.shape}, dtype={X.dtype}")
