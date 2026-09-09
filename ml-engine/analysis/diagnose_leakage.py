"""
ml-engine/src/diagnose_leakage.py - Issue #17 (tani)

SORU
----
diagnose_features.py'da RandomForest F1 = 0.98 cikti. Bu gercek bir
genelleme mi, yoksa veri sizintisi mi?

SUPHE
-----
train_test_split satirlari RASTGELE boluyor. Ama CICIDS2017'de bir
saldiri (ornegin DoS Hulk) tek bir oturumda, dakikalar icinde uretilmis
yuz binlerce neredeyse ayni akistan olusuyor. Rastgele bolunce ayni
saldiri patlamasinin bir kismi egitimde, bir kismi testte kaliyor.
Model genelleme yapmiyor; ezberledigi akisin kopyasini taniyor.

DENEY
-----
Ayni model, iki farkli bolme stratejisiyle egitilir:

  A) Rastgele bolme     : train_test_split (mevcut yontem)
  B) Gun bazli bolme    : Sali'da egit, Carsamba'da test et

B'de model hic gormedigi bir gunun trafigiyle ve farkli saldiri
turleriyle karsilasir. Aradaki fark dogrudan sizinti miktaridir.

Ek olarak C) senaryosu: ayni gun icinde egit/test (Carsamba -> Carsamba,
rastgele) ile B karsilastirilirsa, farkin gun degisiminden mi yoksa
saldiri turu degisiminden mi geldigi de gorulur.

Calistirma:
    PYTHONPATH=ml-engine/src python ml-engine/src/diagnose_leakage.py
"""
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

from dataset_adapter import clean, load_csv, to_feature_frame, to_matrix

DATA_DIR = Path("data/raw/MachineLearningCVE")
RANDOM_STATE = 42
SAMPLE = 150_000

TUESDAY = "Tuesday-WorkingHours.pcap_ISCX.csv"        # FTP/SSH brute-force
WEDNESDAY = "Wednesday-workingHours.pcap_ISCX.csv"    # DoS ailesi + Heartbleed
FRIDAY_DDOS = "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"


def load(fname: str) -> pd.DataFrame:
    df = clean(to_feature_frame(load_csv(DATA_DIR / fname)))
    if len(df) > SAMPLE:
        df = df.sample(SAMPLE, random_state=RANDOM_STATE)
    return df.reset_index(drop=True)


def xy(df: pd.DataFrame):
    return to_matrix(df), (df["label"] != "BENIGN").astype(int).values


def run(name: str, X_tr, y_tr, X_te, y_te, note: str = "") -> dict:
    rf = RandomForestClassifier(
        n_estimators=100, max_depth=20, n_jobs=-1, random_state=RANDOM_STATE
    )
    rf.fit(X_tr, y_tr)
    pred = rf.predict(X_te)
    proba = rf.predict_proba(X_te)[:, 1]

    row = {
        "senaryo": name,
        "egitim_n": len(y_tr),
        "test_n": len(y_te),
        "precision": precision_score(y_te, pred, zero_division=0),
        "recall": recall_score(y_te, pred, zero_division=0),
        "f1": f1_score(y_te, pred, zero_division=0),
        "roc_auc": roc_auc_score(y_te, proba) if len(set(y_te)) > 1 else float("nan"),
    }
    print(f"  {name}: F1={row['f1']:.4f}  {note}")
    return row


def main() -> None:
    print("Veri yukleniyor...")
    tue = load(TUESDAY)
    wed = load(WEDNESDAY)
    fri = load(FRIDAY_DDOS)

    for nm, d in [("Sali", tue), ("Carsamba", wed), ("Cuma-DDoS", fri)]:
        atk = (d["label"] != "BENIGN")
        print(f"  {nm:10s} {len(d):7d} satir | saldiri %{atk.mean() * 100:5.1f} | "
              f"turler: {sorted(d.loc[atk, 'label'].unique())}")

    X_tue, y_tue = xy(tue)
    X_wed, y_wed = xy(wed)
    X_fri, y_fri = xy(fri)

    results = []

    print("\n[A] RASTGELE BOLME (mevcut yontem)")
    X_all = np.vstack([X_tue, X_wed, X_fri])
    y_all = np.concatenate([y_tue, y_wed, y_fri])
    Xtr, Xte, ytr, yte = train_test_split(
        X_all, y_all, test_size=0.3, random_state=RANDOM_STATE, stratify=y_all
    )
    results.append(run("A) Rastgele bolme (3 gun karisik)", Xtr, ytr, Xte, yte,
                       "<- sizinti supheli"))

    print("\n[B] GUN BAZLI BOLME")
    results.append(run("B1) Sali -> Carsamba", X_tue, y_tue, X_wed, y_wed,
                       "brute-force ogrendi, DoS'a bakiyor"))
    results.append(run("B2) Carsamba -> Sali", X_wed, y_wed, X_tue, y_tue,
                       "DoS ogrendi, brute-force'a bakiyor"))
    results.append(run("B3) Sali+Carsamba -> Cuma DDoS", 
                       np.vstack([X_tue, X_wed]), np.concatenate([y_tue, y_wed]),
                       X_fri, y_fri, "hic gormedigi saldiri turu"))

    print("\n[C] AYNI GUN ICINDE RASTGELE (kontrol)")
    Xtr_w, Xte_w, ytr_w, yte_w = train_test_split(
        X_wed, y_wed, test_size=0.3, random_state=RANDOM_STATE, stratify=y_wed
    )
    results.append(run("C) Carsamba -> Carsamba (rastgele)", Xtr_w, ytr_w, Xte_w, yte_w,
                       "ayni oturum, ust sinir"))

    print("\n" + "=" * 86)
    print("SONUCLAR")
    print("=" * 86)
    df = pd.DataFrame(results)
    print(df.to_string(index=False, float_format=lambda x: f"{x:.4f}"))

    f1_random = df.loc[0, "f1"]
    f1_day = df[df["senaryo"].str.startswith("B")]["f1"].mean()

    print("\nYORUM")
    print("-" * 86)
    print(f"  Rastgele bolme F1      : {f1_random:.4f}")
    print(f"  Gun bazli bolme F1 (ort): {f1_day:.4f}")
    print(f"  Fark                   : {f1_random - f1_day:+.4f}")

    if f1_random - f1_day > 0.20:
        print("\n  -> Rastgele bolmedeki yuksek skor buyuk olcude VERI SIZINTISI.")
        print("     Ayni saldiri oturumundan gelen benzer akislar hem egitimde")
        print("     hem testte bulundugu icin model ezberliyor. Denetimli modelin")
        print("     gercek genelleme basarimi gun bazli sonuca daha yakindir.")
        print("     Raporda rastgele bolme sonucu KULLANILMAMALIDIR.")
    else:
        print("\n  -> Sizinti sinirli; denetimli model gercekten genelliyor.")
        print("     Model secimi ekiple tartisilabilir.")

    print("\n  Not: B3 senaryosu (hic gorulmemis saldiri turu) ozellikle onemli;")
    print("  denetimli modelin 'bilinmeyen saldiri' karsisindaki gercek durumunu")
    print("  gosterir. Isolation Forest'in var olma sebebi tam olarak bu senaryodur.")

    out = Path("ml-engine/reports")
    out.mkdir(parents=True, exist_ok=True)
    df.to_csv(out / "leakage_test.csv", index=False)
    print(f"\n  -> {out / 'leakage_test.csv'}")


if __name__ == "__main__":
    main()