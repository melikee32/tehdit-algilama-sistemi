"""
ml-engine/src/calibration.py - Issue #16

Anomali skoru kalibrasyonu. Ayri bir modulde tutuluyor cunku
joblib ile kaydedilen nesnenin sinifi, yuklenirken de ayni
modul yolundan bulunabilmeli.
"""
import numpy as np


class ScoreCalibrator:
    """
    Ham decision_function ciktisini 0-1 arasi anomali skoruna cevirir.

    Esik degerleri benign dagiliminin uc noktalarina sabitlenir:
        skor 0.50  <- benign'in en anormal %1'i    (beklenen FPR ~%1)
        skor 0.85  <- benign'in en anormal %0.1'i  (critical esigi)
        skor 1.00  <- egitimde gorulen her seyden anormal
    """

    def __init__(self, benign_scores: np.ndarray):
        r_max = float(np.max(benign_scores))
        r_med = float(np.median(benign_scores))
        r_p1 = float(np.percentile(benign_scores, 1.0))
        r_p01 = float(np.percentile(benign_scores, 0.1))
        r_min = float(np.min(benign_scores))

        pts = [r_min, r_p01, r_p1, r_med, r_max]
        for i in range(1, len(pts)):
            if pts[i] <= pts[i - 1]:
                pts[i] = pts[i - 1] + 1e-9

        self.xp = np.array(pts)
        self.fp = np.array([1.0, 0.85, 0.5, 0.25, 0.0])

    def transform(self, raw_scores: np.ndarray) -> np.ndarray:
        return np.clip(np.interp(raw_scores, self.xp, self.fp), 0.0, 1.0)