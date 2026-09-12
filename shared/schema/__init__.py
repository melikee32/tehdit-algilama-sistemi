"""Modüller arası ortak veri şeması (Issue #28, #29).

Kullanım (repo kökü sys.path'te olacak şekilde):
    from shared.schema import TrafficEvent, LoginAttemptEvent
"""

from .log_event import LoginAttemptEvent
from .traffic_event import EventType, NetworkProtocol, TrafficEvent

__all__ = [
    "EventType",
    "NetworkProtocol",
    "TrafficEvent",
    "LoginAttemptEvent",
]
