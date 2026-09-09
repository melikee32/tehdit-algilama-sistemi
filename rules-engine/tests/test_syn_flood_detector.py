import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from syn_flood_detector import detect_syn_flood


def load_sample_events():
    path = Path(__file__).parent / "sample_syn_events.json"
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def test_normal_traffic_does_not_trigger_alarm():
    """3 SYN gonderen normal IP (192.168.1.25) alarm uretmemeli."""
    events = load_sample_events()
    normal_only = [e for e in events if e["src_ip"] == "192.168.1.25"]
    alarms = detect_syn_flood(normal_only)
    assert alarms == []


def test_syn_flood_is_detected():
    """60 SYN gonderen saldirgan (192.168.1.70) yakalanmali."""
    events = load_sample_events()
    alarms = detect_syn_flood(events)
    attacker_alarms = [a for a in alarms if a["src_ip"] == "192.168.1.70"]
    assert len(attacker_alarms) >= 1
    assert attacker_alarms[0]["alarm_type"] == "syn_flood"


if __name__ == "__main__":
    test_normal_traffic_does_not_trigger_alarm()
    test_syn_flood_is_detected()
    print("Tum testler gecti!")