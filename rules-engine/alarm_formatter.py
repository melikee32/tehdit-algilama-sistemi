"""
Alarm Formatlayici (Adapter)
===============================
Amac: port_scan, brute_force, syn_flood fonksiyonlarinin biraz
farkli olan cikti formatlarini, TEK ve ORTAK bir "alarm zarfi"
formatina cevirmek. Boylece Kisi 4'un paneli (dashboard) sadece
TEK bir format ogrenip hepsini gosterebilir.

Ortak format:
    {
        "alarm_id": benzersiz bir kimlik (string),
        "source_module": "rules-engine",
        "alarm_type": "port_scan" | "brute_force" | "syn_flood",
        "src_ip": ...,
        "dst_ip": ... (varsa),
        "severity": "high" | "medium",
        "window_start": ...,
        "window_end": ...,
        "details": {orijinal fonksiyonun ozel alanlari, oldugu gibi}
    }
"""

import uuid
from typing import Iterable


def format_alarms(raw_alarms: Iterable[dict]) -> list[dict]:
    """
    port_scan_detector, brute_force_detector, syn_flood_detector
    fonksiyonlarindan gelen ham alarm listelerini ortak formata cevirir.

    Args:
        raw_alarms: yukaridaki 3 fonksiyondan herhangi birinin
                     urettigi alarm dict'lerinin listesi (karisik da olabilir).

    Returns:
        Ortak "zarf" formatinda alarm listesi.
    """
    formatted = []

    # Her ham alarmdan hangi alanlarin "ortak" hangilerinin
    # "modul-ozel" (details) oldugunu ayirt ediyoruz
    common_fields = {"alarm_type", "src_ip", "dst_ip", "severity", "window_start", "window_end", "confidence"}

    for raw in raw_alarms:
        # dst_ip her fonksiyonda yok (port_scan'de yok), o yuzden .get() kullaniyoruz
        # -- eger alan yoksa hata vermez, None doner
        envelope = {
            "alarm_id": str(uuid.uuid4()),  # her alarma benzersiz bir kimlik uretiyoruz
            "source_module": "rules-engine",
            "alarm_type": raw["alarm_type"],
            "src_ip": raw.get("src_ip"),
            "dst_ip": raw.get("dst_ip"),
            "severity": raw.get("severity"),
            "window_start": raw.get("window_start"),
            "window_end": raw.get("window_end"),
            "confidence": raw.get("confidence"),
            # details: ortak alanlarin DISINDA kalan her seyi buraya koyuyoruz
            # -- ornegin distinct_ports, failed_attempts, syn_count gibi
            # modul-ozel bilgiler burada kayboluyor degil, sadece toplaniyor
            "details": {k: v for k, v in raw.items() if k not in common_fields},
        }
        formatted.append(envelope)

    return formatted


if __name__ == "__main__":
    # Hizli manuel test: 3 fonksiyonu calistir, hepsini birlikte formatla
    import json
    from pathlib import Path

    from port_scan_detector import detect_port_scans
    from brute_force_detector import detect_brute_force
    from syn_flood_detector import detect_syn_flood

    tests_dir = Path(__file__).parent / "tests"

    with open(tests_dir / "sample_events.json", encoding="utf-8") as f:
        port_scan_alarms = detect_port_scans(json.load(f))

    with open(tests_dir / "sample_login_events.json", encoding="utf-8") as f:
        brute_force_alarms = detect_brute_force(json.load(f))

    with open(tests_dir / "sample_syn_events.json", encoding="utf-8") as f:
        syn_flood_alarms = detect_syn_flood(json.load(f))

    all_raw = port_scan_alarms + brute_force_alarms + syn_flood_alarms
    all_formatted = format_alarms(all_raw)

    print(f"{len(all_formatted)} alarm formatlandi:\n")
    for a in all_formatted:
        print(json.dumps(a, indent=2, ensure_ascii=False))