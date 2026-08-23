"""
Port Tarama Tespit Modulu
==========================
Mantik: Ayni kaynak IP, kisa bir zaman penceresi icinde farkli sayida
hedef porta baglanti denemesi yaparsa, bu port taramasi olarak
isaretlenir (nmap gibi araclarin tipik davranisi).

Girdi formati (shared/schema/traffic_event.example.json'a bakin):
    {
        "src_ip": "192.168.1.50",
        "dst_ip": "192.168.1.10",
        "dst_port": 22,
        "protocol": "TCP",
        "timestamp": "2026-08-23T14:32:10.123Z",
        "event_type": "connection_attempt",
        "success": false
    }
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Iterable


# Ayarlanabilir esik degerleri
TIME_WINDOW_SECONDS = 5      # kac saniyelik pencerede bakilacak
PORT_COUNT_THRESHOLD = 15    # bu pencerede kac FARKLI port denenirse alarm


def _parse_timestamp(ts: str) -> datetime:
    """ISO 8601 timestamp string'ini datetime objesine cevirir."""
    # "Z" son ekini Python'un anlayacagi formata cevir
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def detect_port_scans(
    events: Iterable[dict],
    time_window_seconds: int = TIME_WINDOW_SECONDS,
    port_threshold: int = PORT_COUNT_THRESHOLD,
) -> list[dict]:
    """
    Verilen trafik olaylari listesinde port taramasi paternini arar.

    Args:
        events: traffic_event formatinda dict listesi (zaman sirali olmasi sart degil,
                fonksiyon icerde sort ediyor).
        time_window_seconds: kac saniyelik kayan pencerede bakilacak.
        port_threshold: pencerede kac farkli port gorulurse alarm uretilecek.

    Returns:
        Alarm listesi. Her alarm ortak alarm formatinda bir dict:
        {
            "alarm_type": "port_scan",
            "src_ip": ...,
            "distinct_ports": ...,
            "window_start": ...,
            "window_end": ...,
            "severity": "high" | "medium"
        }
    """
    # Sadece baglanti denemesi olaylarini al, zamana gore sirala
    conn_events = sorted(
        (e for e in events if e.get("event_type") == "connection_attempt"),
        key=lambda e: _parse_timestamp(e["timestamp"]),
    )

    # IP bazli olay listesi olustur
    events_by_ip: dict[str, list[dict]] = defaultdict(list)
    for e in conn_events:
        events_by_ip[e["src_ip"]].append(e)

    alarms = []

    for src_ip, ip_events in events_by_ip.items():
        window = timedelta(seconds=time_window_seconds)
        start_idx = 0

        # Kayan pencere (sliding window) ile ilerle
        for end_idx in range(len(ip_events)):
            end_time = _parse_timestamp(ip_events[end_idx]["timestamp"])

            # Pencerenin basini, esik suresinin disina cikan olaylari atlayarak ilerlet
            while (
                end_time - _parse_timestamp(ip_events[start_idx]["timestamp"])
                > window
            ):
                start_idx += 1

            window_events = ip_events[start_idx : end_idx + 1]
            distinct_ports = {ev["dst_port"] for ev in window_events}

            if len(distinct_ports) >= port_threshold:
                alarms.append(
                    {
                        "alarm_type": "port_scan",
                        "src_ip": src_ip,
                        "distinct_ports": len(distinct_ports),
                        "window_start": window_events[0]["timestamp"],
                        "window_end": window_events[-1]["timestamp"],
                        "severity": "high" if len(distinct_ports) >= port_threshold * 2 else "medium",
                    }
                )
                # Ayni pencere icin tekrar tekrar alarm uretmemek icin
                # start_idx'i sona sar, bir sonraki farkli pencereye gec
                start_idx = end_idx + 1
                if start_idx > end_idx:
                    break

    return alarms


if __name__ == "__main__":
    # Hizli manuel test icin: sahte veriyle calistir
    import json
    from pathlib import Path

    sample_path = Path(__file__).parent / "tests" / "sample_events.json"
    with open(sample_path, encoding="utf-8") as f:
        sample_events = json.load(f)

    result = detect_port_scans(sample_events)
    print(f"{len(result)} alarm uretildi:\n")
    for alarm in result:
        print(alarm)
