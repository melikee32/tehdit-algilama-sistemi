"""
Pydantic ÅemalarÄ± â€” Ekip API SÃ¶zleÅŸmesi.

Bu dosya, fizibilite dokÃ¼manÄ±nda belirtilen "ortak veri ÅŸemasÄ± (JSON schema)
ve API sÃ¶zleÅŸmesi (OpenAPI)" gereksinimini karÅŸÄ±lar. KiÅŸi 2 (kural motoru) ve
KiÅŸi 3 (ML motoru), tespitlerini bu ÅŸemalara uygun JSON olarak
POST /events endpoint'ine gÃ¶ndermelidir. KiÅŸi 4 (bu backend), bu ÅŸemayÄ±
tÃ¼m ekip iÃ§in otomatik olarak /docs adresinde OpenAPI dokÃ¼mantasyonu
ÅŸeklinde sunar.
"""
from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel, ConfigDict, Field

from .models import EngineSource, Severity


# ---------- Event ÅŸemalarÄ± (Kural/ML motorlarÄ±ndan gelen ham veri) ----------

class EventCreate(BaseModel):
    """Kural veya ML motorunun POST /events'e gÃ¶nderdiÄŸi veri formatÄ±."""

    source_engine: EngineSource
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[str] = None
    detection_source: Optional[str] = None
    src_port: Optional[str] = None
    dst_port: Optional[str] = None
    protocol: Optional[str] = None
    attack_type: str = Field(..., examples=["port_scan", "brute_force", "syn_flood", "anomaly"])
    confidence: float = Field(..., ge=0.0, le=1.0, description="Motorun kendi gÃ¼ven skoru (0-1)")
    description: Optional[str] = None
    raw_payload: Optional[dict[str, Any]] = None


class EventOut(EventCreate):
    model_config = ConfigDict(from_attributes=True)

    id: str
    timestamp: datetime
    correlated: str


# ---------- Alarm ÅŸemalarÄ± (Correlation engine Ã§Ä±ktÄ±sÄ±, panel bunu okur) ----------

class AlarmCreate(BaseModel):
    """Correlation engine'in (Issue #22) nihai alarm Ã¼retirken kullanacaÄŸÄ± format."""

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[str] = None
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

