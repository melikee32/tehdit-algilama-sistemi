"""
Pydantic Şemaları — Ekip API Sözleşmesi.

Bu dosya, fizibilite dokümanında belirtilen "ortak veri şeması (JSON schema)
ve API sözleşmesi (OpenAPI)" gereksinimini karşılar. Kişi 2 (kural motoru) ve
Kişi 3 (ML motoru), tespitlerini bu şemalara uygun JSON olarak
POST /events endpoint'ine göndermelidir. Kişi 4 (bu backend), bu şemayı
tüm ekip için otomatik olarak /docs adresinde OpenAPI dokümantasyonu
şeklinde sunar.
"""
from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel, ConfigDict, Field

from .models import EngineSource, Severity


# ---------- Event şemaları (Kural/ML motorlarından gelen ham veri) ----------

class EventCreate(BaseModel):
    """Kural veya ML motorunun POST /events'e gönderdiği veri formatı."""

    source_engine: EngineSource
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[str] = None
    dst_port: Optional[str] = None
    protocol: Optional[str] = None
    attack_type: str = Field(..., examples=["port_scan", "brute_force", "syn_flood", "anomaly"])
    confidence: float = Field(..., ge=0.0, le=1.0, description="Motorun kendi güven skoru (0-1)")
    description: Optional[str] = None
    raw_payload: Optional[dict[str, Any]] = None


class EventOut(EventCreate):
    model_config = ConfigDict(from_attributes=True)

    id: str
    timestamp: datetime
    correlated: str


# ---------- Alarm şemaları (Correlation engine çıktısı, panel bunu okur) ----------

class AlarmCreate(BaseModel):
    """Correlation engine'in (Issue #22) nihai alarm üretirken kullanacağı format."""

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
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
