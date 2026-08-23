import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from port_scan_detector import detect_port_scans


def load_sample_events():
    path = Path(__file__).parent / "sample_events.json"
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def test_normal_traffic_does_not_trigger_alarm():
    """2 baglantili normal kullanici (192.168.1.20) alarm uretmemeli."""
    events = load_sample_events()
    normal_only = [e for e in events if e["src_ip"] == "192.168.1.20"]
    alarms = detect_port_scans(normal_only)
    assert alarms == []


def test_port_scan_is_detected():
    """20 farkli porta kisa surede baglanan IP (192.168.1.50) yakalanmali."""
    events = load_sample_events()
    alarms = detect_port_scans(events)
    scan_alarms = [a for a in alarms if a["src_ip"] == "192.168.1.50"]
    assert len(scan_alarms) >= 1
    assert scan_alarms[0]["alarm_type"] == "port_scan"


def test_threshold_is_respected():
    """Esigin altinda kalan port sayisi alarm uretmemeli."""
    events = [
        {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "dst_port": p,
            "protocol": "TCP",
            "timestamp": f"2026-08-23T10:00:0{p % 5}Z",
            "event_type": "connection_attempt",
            "success": False,
        }
        for p in range(5)  # sadece 5 farkli port -> esigin (15) altinda
    ]
    alarms = detect_port_scans(events)
    assert alarms == []


if __name__ == "__main__":
    test_normal_traffic_does_not_trigger_alarm()
    test_port_scan_is_detected()
    test_threshold_is_respected()
    print("Tum testler gecti!")
