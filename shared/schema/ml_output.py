"""
shared/schema/ml_output.py — Issue #30

ML motorunun urettigi cikti modelleri.

MLPrediction  : Ham model ciktisi (anomali skoru + sinif tahmini)
MLAlarmPayload: POST /events'e gonderilecek, #28 ortak zarfiyla
                uyumlu nihai cikti.

#28 ortak zarf formati:
    alarm_id      : str  (uuid)
    source_module : str  ("ml_engine")
    severity      : str  ("low" | "medium" | "high" | "critical")
    details       : dict (serbest ek bilgi)
"""
import uuid
from typing import Optional, Literal
from pydantic import BaseModel, Field


# -----------------------------------------------------------------
# 1. Ham model ciktisi
# -----------------------------------------------------------------

class MLPrediction(BaseModel):
    """
    IsolationForest veya baska anomali modelinin dogrudan ciktisi.
    Kisi 3 bu modeli doldurur; buradan MLAlarmPayload uretilir.
    """
    anomaly_score: float = Field(
        ..., ge=0.0, le=1.0,
        description="Normallestirilmis anomali skoru (1 = kesin anomali)"
    )
    is_anomaly: bool = Field(
        ...,
        description="Model esigine gore ikili karar"
    )
    raw_score: Optional[float] = Field(
        None,
        description="Modelin ham ciktisi (ornegin IsolationForest decision_function)"
    )
    predicted_class: Optional[str] = Field(
        None,
        description="Siniflandirici varsa tahmin edilen sinif etiketi"
    )
    feature_vector_id: Optional[str] = Field(
        None,
        description="Bu tahminin dayandigi MLFeatureVector'in takip ID'si"
    )


# -----------------------------------------------------------------
# 2. #28 uyumlu ortak alarm zarfi
# -----------------------------------------------------------------

class MLAlarmPayload(BaseModel):
    """
    ML motorunun POST /events'e gonderdigi nihai cikti.

    source_module = 'ml_engine' sabittir; boylece correlation engine
    (Issue #22) bu alarmi ML kaynakli olarak tanir.

    severity hesaplama onerileri:
        anomaly_score >= 0.85  -> critical
        anomaly_score >= 0.70  -> high
        anomaly_score >= 0.50  -> medium
        anomaly_score <  0.50  -> low  (genellikle gonderilmez)
    """
    alarm_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="#28 ortak zarf: benzersiz alarm kimlik numarasi"
    )
    source_module: Literal["ml_engine"] = "ml_engine"

    # /events endpoint'inin beklediği alanlar
    source_engine: Literal["ml"] = "ml"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[str] = None
    dst_port: Optional[str] = None
    protocol: Optional[str] = None
    attack_type: str = Field(
        default="anomaly",
        description="ML genel olarak 'anomaly' uretir; siniflandirici varsa ozellestirilebilir"
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0,
        description="anomaly_score ile ayni deger; /events confidence alaniyla uyumlu"
    )
    severity: Literal["low", "medium", "high", "critical"]

    # #28 ortak zarf: ek bilgi
    details: dict = Field(
        default_factory=dict,
        description="#28 ortak zarf: serbest ek bilgi alani (raw_score, predicted_class vb.)"
    )

    @classmethod
    def from_prediction(
        cls,
        prediction: "MLPrediction",
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        protocol: Optional[str] = None,
    ) -> "MLAlarmPayload":
        """MLPrediction'dan otomatik olarak MLAlarmPayload olusturur."""

        if prediction.anomaly_score >= 0.85:
            severity = "critical"
        elif prediction.anomaly_score >= 0.70:
            severity = "high"
        elif prediction.anomaly_score >= 0.50:
            severity = "medium"
        else:
            severity = "low"

        return cls(
            source_engine="ml",
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            attack_type=prediction.predicted_class or "anomaly",
            confidence=prediction.anomaly_score,
            severity=severity,
            details={
                "raw_score": prediction.raw_score,
                "is_anomaly": prediction.is_anomaly,
                "predicted_class": prediction.predicted_class,
                "feature_vector_id": prediction.feature_vector_id,
            },
        )
