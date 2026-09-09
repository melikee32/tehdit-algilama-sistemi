"""Ham Ağ Trafiği Veri Modeli (Issue #28)
==========================================
`collector/capture/sniffer.py` (Issue #5) tarafından üretilen bağlantı
denemesi olaylarının resmi şeması. Taslak: `traffic_event.example.json`.

rules-engine (bkz. port_scan_detector.py) bu modelin ürettiği JSON'u
düz dict olarak tüketir; burada Pydantic kullanılmasının amacı, collector
tarafında yazılmadan önce alanların (IP formatı, port aralığı, timestamp)
doğrulanmasıdır.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_serializer


class EventType(str, Enum):
    CONNECTION_ATTEMPT = "connection_attempt"
    LOGIN_ATTEMPT = "login_attempt"


class NetworkProtocol(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"


class TrafficEvent(BaseModel):
    """Ağ arayüzünden yakalanan tek bir bağlantı denemesi."""

    model_config = ConfigDict(extra="forbid")

    event_type: Literal[EventType.CONNECTION_ATTEMPT] = EventType.CONNECTION_ATTEMPT
    src_ip: IPvAnyAddress
    dst_ip: IPvAnyAddress
    dst_port: int = Field(ge=0, le=65535)
    protocol: NetworkProtocol
    timestamp: datetime
    success: bool

    @field_serializer("src_ip", "dst_ip")
    def _serialize_ip(self, value: IPvAnyAddress) -> str:
        return str(value)

    @field_serializer("timestamp", when_used="json")
    def _serialize_timestamp(self, value: datetime) -> str:
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return (
            value.astimezone(timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )
