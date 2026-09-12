"""Ham Log Veri Modeli (Issue #28)
===================================
`collector`'ın sistem/uygulama loglarından (auth.log vb.) çıkaracağı
giriş denemesi olaylarının resmi şeması (Issue #6 log okuyucusu bu
modele göre üretim yapacak). Taslak: `log_event.example.json`.

rules-engine (bkz. brute_force_detector.py) bu modelin ürettiği JSON'u
düz dict olarak tüketir.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, IPvAnyAddress, field_serializer

from .traffic_event import EventType


class LoginAttemptEvent(BaseModel):
    """Bir sistem/uygulama logundan çıkarılan giriş denemesi."""

    model_config = ConfigDict(extra="forbid")

    event_type: Literal[EventType.LOGIN_ATTEMPT] = EventType.LOGIN_ATTEMPT
    src_ip: IPvAnyAddress
    dst_ip: IPvAnyAddress
    username: str
    protocol: str
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
