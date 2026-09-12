import json
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).parents[3]))

from shared.schema import TrafficEvent

EXAMPLE_PATH = Path(__file__).parents[1] / "traffic_event.example.json"


def _load_example() -> dict:
    with open(EXAMPLE_PATH, encoding="utf-8") as f:
        data = json.load(f)
    data.pop("_aciklama", None)
    return data


def test_example_json_is_valid():
    event = TrafficEvent.model_validate(_load_example())
    assert event.src_ip == "192.168.1.50" or str(event.src_ip) == "192.168.1.50"
    assert event.dst_port == 22


def test_json_round_trip_keeps_z_suffixed_timestamp_and_plain_ip_strings():
    event = TrafficEvent.model_validate(_load_example())
    dumped = json.loads(event.model_dump_json())

    assert dumped["src_ip"] == "192.168.1.50"
    assert dumped["timestamp"].endswith("Z")
    assert dumped["timestamp"] == "2026-08-23T14:32:10.123Z"


def test_invalid_ip_is_rejected():
    data = _load_example()
    data["src_ip"] = "not-an-ip"
    with pytest.raises(ValidationError):
        TrafficEvent.model_validate(data)


def test_out_of_range_port_is_rejected():
    data = _load_example()
    data["dst_port"] = 70000
    with pytest.raises(ValidationError):
        TrafficEvent.model_validate(data)


def test_unknown_extra_field_is_rejected():
    data = _load_example()
    data["unexpected_field"] = "x"
    with pytest.raises(ValidationError):
        TrafficEvent.model_validate(data)


def test_wrong_event_type_is_rejected():
    data = _load_example()
    data["event_type"] = "login_attempt"
    with pytest.raises(ValidationError):
        TrafficEvent.model_validate(data)
