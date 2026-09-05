"""
shared/schema/dashboard.py - Issue #31

Backend'den React paneline giden veri modelleri:
  1. WebSocket mesaj zarfi ve payload'lari
  2. Ozet tehdit metrikleri
  3. Panelin okudugu liste ogeleri

Bu dosya app/schemas.py'yi TEKRARLAMAZ. app/schemas.py backend'in ic
API sozlesmesidir (motorlardan gelen veri, veritabani ciktilari).
Buradaki modeller panelin TUKETTIGI veriyi tanimlar; ozellikle
WebSocket mesajlarinin sekli ve ozet metrikler backend semasinda
karsiligi olmayan seylerdir.

MEVCUT DURUM
------------
app/routers/alarms.py zaten su zarfi gonderiyor:

    {"type": "new_alarm", "data": {id, attack_type, severity,
                                   score, src_ip, timestamp}}

Bu calisan bir sozlesme; asagidaki modeller onu bozmadan resmilestirir
ve eksik alanlari ekler. WSMessageType.NEW_ALARM degeri bilerek
"new_alarm" olarak birakildi.

EKSIKLER (ekip onayi gerektirir)
--------------------------------
Mevcut broadcast payload'inda su bilgiler yok:
  - dst_ip, description
  - alarmi hangi motorun urettigi (rule_event_id / ml_event_id)

Sonuncusu panel icin onemli: kullanici "bu alarm kural motorundan mi,
ML'den mi, ikisinin korelasyonundan mi geldi" gorebilmeli. Hibrit
mimarinin katkisi ancak boyle gorunur olur.
AlarmPayload bu alanlari icerir; alarms.py'nin broadcast cagrisi
guncellenirse panel de gosterebilir.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------
# 1. Ortak tipler
# ---------------------------------------------------------------------

class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionSource(str, Enum):
    """Alarmi hangi motorun urettigi. Panel filtrelemesi icin."""
    RULE = "rule"          # sadece kural motoru
    ML = "ml"              # sadece ML motoru
    CORRELATED = "both"    # ikisi birlikte, korelasyon sonucu


class WSMessageType(str, Enum):
    """
    WebSocket mesaj tipleri.

    NEW_ALARM degeri mevcut backend koduyla uyumlu olmasi icin
    "new_alarm" (yeni alarm) olarak birakildi.
    """
    NEW_ALARM = "new_alarm"
    METRICS_UPDATE = "metrics_update"
    CONNECTION_ACK = "connection_ack"


# ---------------------------------------------------------------------
# 2. WebSocket payload'lari
# ---------------------------------------------------------------------

class AlarmPayload(BaseModel):
    """
    Yeni alarm bildirimi. Panelin alarm listesine ekledigi kayit.

    Mevcut broadcast'te olmayan alanlar Optional; alarms.py guncellenene
    kadar None gelecekler ve panel bunlari gormezden gelebilir.
    """
    id: str
    attack_type: str
    severity: SeverityLevel
    score: float = Field(..., ge=0.0, le=1.0)
    src_ip: Optional[str] = None
    timestamp: datetime

    # Mevcut broadcast'te yok - alarms.py guncellenirse dolar
    dst_ip: Optional[str] = None
    description: Optional[str] = None
    detection_source: Optional[DetectionSource] = None
    rule_event_id: Optional[str] = None
    ml_event_id: Optional[str] = None

    @classmethod
    def source_from_ids(
        cls, rule_event_id: Optional[str], ml_event_id: Optional[str]
    ) -> DetectionSource:
        """Event id'lerine bakarak alarmin kaynagini belirler."""
        if rule_event_id and ml_event_id:
            return DetectionSource.CORRELATED
        if ml_event_id:
            return DetectionSource.ML
        return DetectionSource.RULE


class ThreatMetrics(BaseModel):
    """
    Panelin ust kismindaki ozet kartlar ve grafikler icin.

    Dagilim sozlukleri sabit anahtar listesi tasimaz; panel gelen
    anahtarlar uzerinde donmelidir (yeni saldiri tipi eklenirse
    frontend degismeden calissin).
    """
    total_alarms: int = 0
    unacknowledged: int = Field(0, description="Henuz onaylanmamis alarm sayisi")

    severity_counts: dict[str, int] = Field(
        default_factory=dict,
        description='ornegin {"critical": 3, "high": 12, "medium": 40}',
    )
    attack_type_counts: dict[str, int] = Field(
        default_factory=dict,
        description='ornegin {"port_scan": 8, "anomaly": 31}',
    )
    source_counts: dict[str, int] = Field(
        default_factory=dict,
        description='alarmi ureten motor: {"rule": 10, "ml": 25, "both": 4}',
    )

    alarms_last_hour: int = 0
    top_source_ips: list[dict[str, Any]] = Field(
        default_factory=list,
        description='en cok alarm ureten IP\'ler: [{"ip": "10.0.0.5", "count": 12}]',
    )

    generated_at: datetime = Field(default_factory=datetime.now)


class ConnectionAck(BaseModel):
    """Baglanti kurulunca gonderilen ilk mesaj; panel hazir oldugunu bilir."""
    message: str = "baglanti kuruldu"
    server_time: datetime = Field(default_factory=datetime.now)
    active_clients: int = 0


# ---------------------------------------------------------------------
# 3. Mesaj zarfi
# ---------------------------------------------------------------------

class WSAlarmMessage(BaseModel):
    type: Literal[WSMessageType.NEW_ALARM] = WSMessageType.NEW_ALARM
    data: AlarmPayload


class WSMetricsMessage(BaseModel):
    type: Literal[WSMessageType.METRICS_UPDATE] = WSMessageType.METRICS_UPDATE
    data: ThreatMetrics


class WSConnectionMessage(BaseModel):
    type: Literal[WSMessageType.CONNECTION_ACK] = WSMessageType.CONNECTION_ACK
    data: ConnectionAck


WSMessage = Union[WSAlarmMessage, WSMetricsMessage, WSConnectionMessage]


# ---------------------------------------------------------------------
# 4. REST liste ogeleri
# ---------------------------------------------------------------------

class AlarmListItem(BaseModel):
    """GET /alarms yanitindaki her satir (panel tablosu)."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    timestamp: datetime
    attack_type: str
    severity: SeverityLevel
    score: float
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    description: Optional[str] = None
    acknowledged: bool = False
    detection_source: Optional[DetectionSource] = None


class EventListItem(BaseModel):
    """
    GET /events yanitindaki her satir (ham tespit akisi).

    Panelde "log akisi" bolumu bunu gosterir: korelasyon oncesi,
    motorlarin urettigi ham tespitler.
    """
    model_config = ConfigDict(from_attributes=True)

    id: str
    timestamp: datetime
    source_engine: str = Field(..., description='"rule" | "ml"')
    attack_type: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[str] = None
    protocol: Optional[str] = None
    description: Optional[str] = None
    correlated: bool = False


class PaginatedAlarms(BaseModel):
    """Sayfalanmis alarm listesi; panel 'daha fazla yukle' icin kullanir."""
    items: list[AlarmListItem]
    total: int
    limit: int
    offset: int
    has_more: bool = False