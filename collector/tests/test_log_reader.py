import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "logs"))

from log_reader import parse_auth_log_line


def test_failed_password_for_known_user_is_parsed():
    line = "Sep  2 10:00:00 target sshd[123]: Failed password for testuser from 192.168.1.60 port 51230 ssh2"
    event = parse_auth_log_line(line, dst_ip="192.168.1.10")

    assert event == {
        "src_ip": "192.168.1.60",
        "dst_ip": "192.168.1.10",
        "username": "testuser",
        "protocol": "SSH",
        "timestamp": event["timestamp"],  # format ayri asagida dogrulaniyor
        "event_type": "login_attempt",
        "success": False,
    }
    assert event["timestamp"].endswith("Z")
    assert "." in event["timestamp"]


def test_failed_password_for_invalid_user_is_parsed():
    line = "Sep  2 10:00:00 target sshd[123]: Failed password for invalid user admin from 192.168.1.60 port 51231 ssh2"
    event = parse_auth_log_line(line, dst_ip="192.168.1.10")

    assert event["username"] == "admin"
    assert event["success"] is False


def test_accepted_password_is_parsed_as_success():
    line = "Sep  2 10:00:05 target sshd[123]: Accepted password for testuser from 192.168.1.60 port 51232 ssh2"
    event = parse_auth_log_line(line, dst_ip="192.168.1.10")

    assert event["success"] is True
    assert event["username"] == "testuser"


def test_unrelated_log_line_is_ignored():
    line = "Sep  2 10:00:06 target CRON[456]: pam_unix(cron:session): session opened for user root"
    assert parse_auth_log_line(line, dst_ip="192.168.1.10") is None


def test_pubkey_auth_line_is_ignored():
    line = "Sep  2 10:00:07 target sshd[123]: Accepted publickey for testuser from 192.168.1.60 port 51233 ssh2"
    assert parse_auth_log_line(line, dst_ip="192.168.1.10") is None
