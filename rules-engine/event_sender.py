"""
Event Gonderici
==================
Amac: rules-engine'in urettigi alarmlari (alarm_formatter.py ciktisi),
backend'in bekledigi EventCreate semasina cevirip POST /events'e gondermek.

Backend semasi (app/schemas.py -> EventCreate):
    source_engine, src_ip, dst_ip, src_port, dst_port, protocol,
    attack_type, confidence, description, raw_payload
"""

import requests

API_URL = "http://localhost:8000/events"


def to_event_payload(formatted_alarm: dict) -> dict:
    """
    alarm_formatter.py'nin urettigi bir alarmi, backend'in
    EventCreate semasina uygun payload'a cevirir.
    """
    details = formatted_alarm.get("details", {})

    return {
        "source_engine": "rule",
        "src_ip": formatted_alarm.get("src_ip"),
        "dst_ip": formatted_alarm.get("dst_ip"),
        "src_port": None,   # rules-engine su an src_port uretmiyor
        "dst_port": None,   # ileride nmap/collector'dan eklenebilir
        "protocol": None,
        # DIKKAT: alarm_type -> attack_type isim degisikligi burada yapiliyor
        "attack_type": formatted_alarm["alarm_type"],
        "confidence": formatted_alarm.get("confidence", 0.5),
        "description": (
            f"{formatted_alarm['alarm_type']} tespit edildi "
            f"(severity: {formatted_alarm.get('severity')})"
        ),
        # severity, window_start/end ve details'i backend'in
        # tanimadigi ekstra bilgi olarak raw_payload'a koyuyoruz,
        # kaybolmasinlar
        "raw_payload": {
            "severity": formatted_alarm.get("severity"),
            "window_start": formatted_alarm.get("window_start"),
            "window_end": formatted_alarm.get("window_end"),
            **details,
        },
    }


def send_events(formatted_alarms: list[dict]) -> None:
    """Formatlanmis alarmlarin hepsini backend'e POST eder."""
    for alarm in formatted_alarms:
        payload = to_event_payload(alarm)
        response = requests.post(API_URL, json=payload, timeout=5)
        response.raise_for_status()
        print(f"Event gonderildi: {response.json().get('id', '?')} ({payload['attack_type']})")


if __name__ == "__main__":
    # Hizli manuel test: 3 tespit fonksiyonunu calistir, formatla, gonder
    import json
    from pathlib import Path

    from port_scan_detector import detect_port_scans
    from brute_force_detector import detect_brute_force
    from syn_flood_detector import detect_syn_flood
    from alarm_formatter import format_alarms

    tests_dir = Path(__file__).parent / "tests"

    with open(tests_dir / "sample_events.json", encoding="utf-8") as f:
        port_scan_alarms = detect_port_scans(json.load(f))
    with open(tests_dir / "sample_login_events.json", encoding="utf-8") as f:
        brute_force_alarms = detect_brute_force(json.load(f))
    with open(tests_dir / "sample_syn_events.json", encoding="utf-8") as f:
        syn_flood_alarms = detect_syn_flood(json.load(f))

    all_raw = port_scan_alarms + brute_force_alarms + syn_flood_alarms
    all_formatted = format_alarms(all_raw)

    print(f"{len(all_formatted)} event gonderiliyor...\n")
    send_events(all_formatted)