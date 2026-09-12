"""
ORM Modelleri.

Ä°ki ana tablo var:
- Event: Kural motoru (KiÅŸi 2) veya ML motorundan (KiÅŸi 3) gelen HAM tespit
  kayÄ±tlarÄ±. Correlation engine (Issue #22, KiÅŸi 4) bunlarÄ± okuyup birleÅŸtirir.
- Alarm: Correlation engine tarafÄ±ndan Ã¼retilen NÄ°HAÄ°, panelde gÃ¶sterilecek
  kayÄ±tlar (aÄŸÄ±rlÄ±klÄ± skorlama sonucu).

Bu ayrÄ±m, dokÃ¼man BÃ¶lÃ¼m 2'deki "Korelasyon Motoru & Panel: Ä°ki motorun
alarmlarÄ±nÄ± aÄŸÄ±rlÄ±klÄ± skorlama ile birleÅŸtiren mantÄ±k" gereksinimini
yansÄ±tÄ±r.
"""
import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, Float, DateTime, Enum, Text, JSON
from .database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class EngineSource(str, enum.Enum):
    RULE = "rule"
    ML = "ml"


class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Event(Base):
    """Kural veya ML motorundan gelen ham tespit kaydÄ± (correlation Ã¶ncesi)."""

    __tablename__ = "events"

    id = Column(String, primary_key=True, default=_uuid)
    source_engine = Column(Enum(EngineSource), nullable=False)
    timestamp = Column(DateTime(timezone=True), default=_now, nullable=False)

    src_ip = Column(String, nullable=True)
    dst_ip = Column(String, nullable=True)
    dst_port = Column(String, nullable=True)
    detection_source = Column(String, nullable=True)
    src_port = Column(String, nullable=True)
    dst_port = Column(String, nullable=True)
    protocol = Column(String, nullable=True)

    attack_type = Column(String, nullable=False)  # Ã¶rn: "port_scan", "brute_force", "syn_flood", "anomaly"
    confidence = Column(Float, nullable=False, default=0.0)  # 0.0 - 1.0 arasÄ±
    description = Column(Text, nullable=True)

    raw_payload = Column(JSON, nullable=True)  # motora Ã¶zgÃ¼ ek veri (esneklik iÃ§in)
    correlated = Column(String, default="false")  # correlation engine iÅŸledi mi (Issue #22'de kullanÄ±lacak)


class Alarm(Base):
    """Correlation engine tarafÄ±ndan Ã¼retilen, panelde gÃ¶sterilecek nihai alarm."""

    __tablename__ = "alarms"

    id = Column(String, primary_key=True, default=_uuid)
    timestamp = Column(DateTime(timezone=True), default=_now, nullable=False)

    src_ip = Column(String, nullable=True)
    dst_ip = Column(String, nullable=True)
    dst_port = Column(String, nullable=True)
    detection_source = Column(String, nullable=True)
    attack_type = Column(String, nullable=False)

    severity = Column(Enum(Severity), nullable=False, default=Severity.MEDIUM)
    score = Column(Float, nullable=False)  # korelasyon motorunun aÄŸÄ±rlÄ±klÄ± nihai skoru (0.0 - 1.0)

    rule_event_id = Column(String, nullable=True)  # kaynak Event.id (rule engine)
    ml_event_id = Column(String, nullable=True)    # kaynak Event.id (ml engine)

    description = Column(Text, nullable=True)
    acknowledged = Column(String, default="false")  # analist tarafÄ±ndan gÃ¶rÃ¼ldÃ¼ mÃ¼

