"""
ml-engine/src/calibration.py - Issue #16 / #17

Anomali skoru kalibrasyonu. Ayri bir modulde tutuluyor cunku joblib ile
kaydedilen nesnenin sinifi, yuklenirken de ayni modul yolundan bulunabilmeli.
"""
import numpy as np


class ScoreCalibrator:
    """
    Ham decision_function ciktisini 0-1 arasi anomali skoruna cevirir.

    CIPALAR
    -------
    Esik degerleri, egitim verisindeki (sadece BENIGN) skor dagiliminin
    yuzdeliklerine sabitlenir. Boylece her skor esigi somut bir yanlis
    alarm oranina karsilik gelir:

        skor 0.50  <- benign'in en anormal %5'i     (FPR ~%5, alarm esigi)
        skor 0.70  <- benign'in en anormal %1'i     (FPR ~%1, "high")
        skor 0.85  <- benign'in en anormal %0.1'i   (FPR ~%0.1, "critical")
        skor 1.00  <- egitimde gorulen her seyden anormal
        skor 0.25  <- benign'in medyani

    NEDEN %5?
    ---------
    Esik taramasi (#17) F1'i maksimize eden noktayi FPR ~%8'de buluyor.
    Ancak F1, precision ve recall'u esit agirlikta tuttugu ve CICIDS2017'de
    saldiri orani %21 oldugu icin bu deger yaniltici: gercek ag trafiginde
    saldiri orani binde birler seviyesindedir ve %8 FPR, panelde bogucu
    sayida yanlis alarm demektir (alarm fatigue).

    %5 bilincli bir orta yol: F1'den bir miktar feragat edip operasyonel
    olarak kullanilabilir bir yanlis alarm orani hedefliyoruz. Bu tercih
    raporda acikca tartisilmalidir.

    ONCEKI SURUMLER
    ---------------
    v1: benign'e karsi yuzdelik siralama -> tanim geregi duzgun dagilim,
        normal trafigin yarisi 0.5'i geciyordu. Hataliydi.
    v2: 0.5 -> benign'in en anormal %1'i. FPR iyiydi (%1.4) ama recall
        %25'e dusuyordu ve 0.6 ustu skorlar pratikte hic olusmadigi icin
        severity katmanlari (high/critical) kullanilamiyordu.
    v3: bu surum.
    """

    # (benign yuzdeligi, karsilik gelen kalibre skor)
    #
    # Cipalar tahminle degil olcumle secildi (#17 esik taramasi):
    #   benign p0.5 altinda: 11 TP / 4446 FP  -> saldiri yok, benign gurultusu
    #   benign p2  civarinda: precision 0.887 -> saldirilarin kutlesi burada
    #   benign p5  civarinda: precision 0.787, recall 0.50
    #
    # Onceki surumde 0.85 -> p0.1 idi; o bant neredeyse tamamen yanlis
    # alarmdan olusuyordu (21 TP / 2097 FP). Simdi 0.85 -> p2.
    ANCHORS = [
        (0.5, 1.00),   # 1.00: egitim benign'inin en uc %0.5'i
        (2.0, 0.85),   # critical
        (3.0, 0.70),   # high
        (5.0, 0.50),   # alarm esigi (FPR ~%5)
        (50.0, 0.25),  # medyan
    ]

    def __init__(self, benign_scores: np.ndarray):
        raw_points, score_points = [], []

        for pct, score in self.ANCHORS:
            raw_points.append(float(np.percentile(benign_scores, pct)))
            score_points.append(score)

        raw_points.append(float(np.max(benign_scores)))
        score_points.append(0.0)

        # np.interp artan x ister; esit degerler varsa mikro kaydirma yap.
        for i in range(1, len(raw_points)):
            if raw_points[i] <= raw_points[i - 1]:
                raw_points[i] = raw_points[i - 1] + 1e-9

        self.xp = np.array(raw_points)
        self.fp = np.array(score_points)

    def transform(self, raw_scores: np.ndarray) -> np.ndarray:
        # np.interp aralik disini uc degerlere sabitler: egitimde
        # gorulenden daha anormal olan her sey 1.0 alir.
        return np.clip(np.interp(raw_scores, self.xp, self.fp), 0.0, 1.0)

    def describe(self) -> str:
        """Cipalari okunabilir sekilde dondurur (rapor icin)."""
        lines = ["Kalibrasyon cipalari (ham skor -> kalibre skor):"]
        for x, f in zip(self.xp, self.fp):
            lines.append(f"  {x:+.4f} -> {f:.2f}")
        return "\n".join(lines)
