"""
ORM Modelleri.

İki ana tablo var:
- Event: Kural motoru (Kişi 2) veya ML motorundan (Kişi 3) gelen HAM tespit
  kayıtları. Correlation engine (Issue #22, Kişi 4) bunları okuyup birleştirir.
- Alarm: Correlation engine tarafından üretilen NİHAİ, panelde gösterilecek
  kayıtlar (ağırlıklı skorlama sonucu).

Bu ayrım, doküman Bölüm 2'deki "Korelasyon Motoru & Panel: İki motorun
alarmlarını ağırlıklı skorlama ile birleştiren mantık" gereksinimini
yansıtır.
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
    """Kural veya ML motorundan gelen ham tespit kaydı (correlation öncesi)."""

    __tablename__ = "events"

    id = Column(String, primary_key=True, default=_uuid)
    source_engine = Column(Enum(EngineSource), nullable=False)
    timestamp = Column(DateTime(timezone=True), default=_now, nullable=False)

    src_ip = Column(String, nullable=True)
    dst_ip = Column(String, nullable=True)
    detection_source = Column(String, nullable=True)
    src_port = Column(String, nullable=True)
    dst_port = Column(String, nullable=True)
    protocol = Column(String, nullable=True)

    attack_type = Column(String, nullable=False)  # ornek: "port_scan", "brute_force", "syn_flood", "anomaly"
    confidence = Column(Float, nullable=False, default=0.0)  # 0.0 - 1.0 arasi
    description = Column(Text, nullable=True)

    raw_payload = Column(JSON, nullable=True)  # motora ozgu ek veri (esneklik icin)
    correlated = Column(String, default="false")  # correlation engine isledi mi


class Alarm(Base):
    """Correlation engine tarafindan uretilen, panelde gosterilecek nihai alarm."""

    __tablename__ = "alarms"

    id = Column(String, primary_key=True, default=_uuid)
    timestamp = Column(DateTime(timezone=True), default=_now, nullable=False)

    src_ip = Column(String, nullable=True)
    dst_ip = Column(String, nullable=True)
    detection_source = Column(String, nullable=True)
    attack_type = Column(String, nullable=False)

    severity = Column(Enum(Severity), nullable=False, default=Severity.MEDIUM)
    score = Column(Float, nullable=False)  # korelasyon motorunun agirlikli nihai skoru (0.0 - 1.0)

    rule_event_id = Column(String, nullable=True)  # kaynak Event.id (rule engine)
    ml_event_id = Column(String, nullable=True)    # kaynak Event.id (ml engine)

    description = Column(Text, nullable=True)
    acknowledged = Column(String, default="false")  # analist tarafindan goruldu mu
