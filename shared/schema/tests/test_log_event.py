import json
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).parents[3]))

from shared.schema import LoginAttemptEvent

EXAMPLE_PATH = Path(__file__).parents[1] / "log_event.example.json"


def _load_example() -> dict:
    with open(EXAMPLE_PATH, encoding="utf-8") as f:
        return json.load(f)


def test_example_json_is_valid():
    event = LoginAttemptEvent.model_validate(_load_example())
    assert event.username == "admin"
    assert event.success is False


def test_json_round_trip_keeps_z_suffixed_timestamp_and_plain_ip_strings():
    event = LoginAttemptEvent.model_validate(_load_example())
    dumped = json.loads(event.model_dump_json())

    assert dumped["src_ip"] == "192.168.1.60"
    assert dumped["timestamp"] == "2026-08-23T15:00:01.200Z"


def test_unknown_extra_field_is_rejected():
    data = _load_example()
    data["unexpected_field"] = "x"
    with pytest.raises(ValidationError):
        LoginAttemptEvent.model_validate(data)


def test_wrong_event_type_is_rejected():
    data = _load_example()
    data["event_type"] = "connection_attempt"
    with pytest.raises(ValidationError):
        LoginAttemptEvent.model_validate(data)
