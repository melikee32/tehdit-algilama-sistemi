import json
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).parent.parent / "writer"))

from event_writer import EventWriter


def test_connection_attempt_without_success_defaults_to_false(tmp_path):
    writer = EventWriter(tmp_path / "events.jsonl")
    raw = {
        "src_ip": "192.168.1.50",
        "dst_ip": "192.168.1.10",
        "dst_port": 22,
        "protocol": "TCP",
        "timestamp": "2026-08-23T14:32:10.123Z",
    }

    written = writer.write(raw, event_type="connection_attempt")

    assert written["success"] is False
    assert written["event_type"] == "connection_attempt"


def test_connection_attempt_respects_explicit_success(tmp_path):
    writer = EventWriter(tmp_path / "events.jsonl")
    raw = {
        "src_ip": "192.168.1.50",
        "dst_ip": "192.168.1.10",
        "dst_port": 443,
        "protocol": "TCP",
        "timestamp": "2026-08-23T14:32:10.123Z",
        "success": True,
    }

    written = writer.write(raw, event_type="connection_attempt")

    assert written["success"] is True


def test_login_attempt_is_written_as_is(tmp_path):
    writer = EventWriter(tmp_path / "events.jsonl")
    raw = {
        "src_ip": "192.168.1.60",
        "dst_ip": "192.168.1.10",
        "username": "admin",
        "protocol": "SSH",
        "timestamp": "2026-08-23T15:00:01.200Z",
        "success": False,
    }

    written = writer.write(raw, event_type="login_attempt")

    assert written["username"] == "admin"
    assert written["event_type"] == "login_attempt"


def test_events_are_appended_as_jsonl_lines(tmp_path):
    output_path = tmp_path / "events.jsonl"
    writer = EventWriter(output_path)
    raw = {
        "src_ip": "192.168.1.50",
        "dst_ip": "192.168.1.10",
        "dst_port": 22,
        "protocol": "TCP",
        "timestamp": "2026-08-23T14:32:10.123Z",
    }

    writer.write(raw, event_type="connection_attempt")
    writer.write(raw, event_type="connection_attempt")

    lines = output_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    for line in lines:
        json.loads(line)  # her satir bagimsiz gecerli bir JSON olmali


def test_unknown_event_type_raises():
    writer = EventWriter(Path("unused.jsonl"))
    with pytest.raises(KeyError):
        writer.write({}, event_type="something_else")


def test_invalid_field_raises_validation_error(tmp_path):
    writer = EventWriter(tmp_path / "events.jsonl")
    raw = {
        "src_ip": "not-an-ip",
        "dst_ip": "192.168.1.10",
        "dst_port": 22,
        "protocol": "TCP",
        "timestamp": "2026-08-23T14:32:10.123Z",
    }

    with pytest.raises(ValidationError):
        writer.write(raw, event_type="connection_attempt")
