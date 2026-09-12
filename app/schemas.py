"""
Pydantic Semalari - Ekip API Sozlesmesi.

Bu dosya, fizibilite dokumaninda belirtilen "ortak veri semasi (JSON schema)
ve API sozlesmesi (OpenAPI)" gereksinimini karsilar. Kisi 2 (kural motoru) ve
Kisi 3 (ML motoru), tespitlerini bu semalara uygun JSON olarak
POST /events endpoint'ine gondermeli. Kisi 4 (bu backend), bu semay
tum ekip icin otomatik olarak /docs adresinde OpenAPI dokumantas
seklinde sunar.
"""
from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel, ConfigDict, Field

from .models import EngineSource, Severity


# ---------- Event semalari (Kural/ML motorlarindan gelen ham veri) ----------

class EventCreate(BaseModel):
    """Kural veya ML motorunun POST /events'e gonderdigi veri formati."""

    source_engine: EngineSource
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    detection_source: Optional[str] = None
    src_port: Optional[str] = None
    dst_port: Optional[str] = None
    protocol: Optional[str] = None
    attack_type: str = Field(..., examples=["port_scan", "brute_force", "syn_flood", "anomaly"])
    confidence: float = Field(..., ge=0.0, le=1.0, description="Motorun kendi guven skoru (0-1)")
    description: Optional[str] = None
    raw_payload: Optional[dict[str, Any]] = None


class EventOut(EventCreate):
    model_config = ConfigDict(from_attributes=True)

    id: str
    timestamp: datetime
    correlated: str


# ---------- Alarm semalari (Correlation engine ciktisi, panel bunu okur) ----------

class AlarmCreate(BaseModel):
    """Correlation engine'in nihai alarm uretirken kullanacagi format."""

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    detection_source: Optional[str] = None
    attack_type: str
    severity: Severity = Severity.MEDIUM
    score: float = Field(..., ge=0.0, le=1.0)
    rule_event_id: Optional[str] = None
    ml_event_id: Optional[str] = None
    description: Optional[str] = None


class AlarmOut(AlarmCreate):
    model_config = ConfigDict(from_attributes=True)

    id: str
    timestamp: datetime
    acknowledged: str


class AlarmAcknowledge(BaseModel):
    acknowledged: bool = True


# ---------- Genel ----------

class HealthOut(BaseModel):
    status: str
    service: str
    version: str
