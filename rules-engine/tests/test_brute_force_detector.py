import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from brute_force_detector import detect_brute_force


def load_sample_events():
    path = Path(__file__).parent / "sample_login_events.json"
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def test_successful_login_does_not_trigger_alarm():
    """Basarili giris (mel) alarm uretmemeli."""
    events = load_sample_events()
    normal_only = [e for e in events if e["username"] == "mel"]
    alarms = detect_brute_force(normal_only)
    assert alarms == []


def test_brute_force_is_detected():
    """8 basarisiz deneme yapan IP (192.168.1.60) yakalanmali."""
    events = load_sample_events()
    alarms = detect_brute_force(events)
    attacker_alarms = [a for a in alarms if a["src_ip"] == "192.168.1.60"]
    assert len(attacker_alarms) >= 1
    assert attacker_alarms[0]["alarm_type"] == "brute_force"


if __name__ == "__main__":
    test_successful_login_does_not_trigger_alarm()
    test_brute_force_is_detected()
    print("Tum testler gecti!")