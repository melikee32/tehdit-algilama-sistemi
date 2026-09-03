import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from alarm_formatter import format_alarms


def test_common_fields_are_present():
    """Her formatlanmis alarmda ortak alanlar (alarm_id, source_module vb.) olmali."""
    raw = [{"alarm_type": "port_scan", "src_ip": "1.2.3.4", "severity": "high",
            "window_start": "t1", "window_end": "t2", "distinct_ports": 20}]
    result = format_alarms(raw)

    assert len(result) == 1
    alarm = result[0]
    assert "alarm_id" in alarm
    assert alarm["source_module"] == "rules-engine"
    assert alarm["alarm_type"] == "port_scan"
    assert alarm["src_ip"] == "1.2.3.4"


def test_module_specific_fields_go_into_details():
    """distinct_ports gibi modul-ozel alanlar 'details' icine gitmeli, kaybolmamali."""
    raw = [{"alarm_type": "port_scan", "src_ip": "1.2.3.4", "severity": "high",
            "window_start": "t1", "window_end": "t2", "distinct_ports": 20}]
    result = format_alarms(raw)

    assert result[0]["details"]["distinct_ports"] == 20


def test_missing_dst_ip_does_not_crash():
    """port_scan alarminda dst_ip yok -- hata vermemeli, None donmeli."""
    raw = [{"alarm_type": "port_scan", "src_ip": "1.2.3.4", "severity": "medium",
            "window_start": "t1", "window_end": "t2", "distinct_ports": 15}]
    result = format_alarms(raw)

    assert result[0]["dst_ip"] is None


def test_each_alarm_gets_unique_id():
    """Iki farkli alarm ayni alarm_id'yi almamali."""
    raw = [
        {"alarm_type": "port_scan", "src_ip": "1.2.3.4", "severity": "high",
         "window_start": "t1", "window_end": "t2", "distinct_ports": 20},
        {"alarm_type": "syn_flood", "src_ip": "5.6.7.8", "dst_ip": "9.9.9.9",
         "severity": "high", "window_start": "t3", "window_end": "t4", "syn_count": 60},
    ]
    result = format_alarms(raw)

    assert result[0]["alarm_id"] != result[1]["alarm_id"]


if __name__ == "__main__":
    test_common_fields_are_present()
    test_module_specific_fields_go_into_details()
    test_missing_dst_ip_does_not_crash()
    test_each_alarm_gets_unique_id()
    print("Tum testler gecti!")