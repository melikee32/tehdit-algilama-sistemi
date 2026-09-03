"""
SYN Flood / DoS Tespit Modulu
================================
Mantik: Ayni kaynak IP'den, kisa bir zaman penceresi icinde AYNI
hedefe (dst_ip) cok sayida baglanti baslatma istegi (SYN paketi)
gelirse, bu SYN flood / DoS saldirisi olarak isaretlenir.

Port taramasindan farki: port taramasi "kac FARKLI port" der,
SYN flood "TOPLAM kac istek" der -- ayni porta yigilan istekler
de sayilir, cesitlilik onemli degil, HACIM onemli.

Girdi formati (syn_packet event_type'i beklenir):
    {
        "src_ip": "192.168.1.50",
        "dst_ip": "192.168.1.10",
        "dst_port": 443,
        "protocol": "TCP",
        "timestamp": "2026-08-23T14:32:10.123Z",
        "event_type": "syn_packet",
        "flags": "SYN"
    }
"""

from collections import defaultdict
from datetime import timedelta
from typing import Iterable

# Ayni yardimci fonksiyonu port_scan_detector'dan tekrar kullaniyoruz
from port_scan_detector import _parse_timestamp


# Ayarlanabilir esik degerleri
# Not: SYN flood cok hizli gelisen bir saldiri oldugu icin pencere
# port taramasi/brute-force'a gore daha KISA tutuluyor (2 saniye).
TIME_WINDOW_SECONDS = 2
SYN_COUNT_THRESHOLD = 50   # bu pencerede kac SYN paketi gelirse alarm


def detect_syn_flood(
    events: Iterable[dict],
    time_window_seconds: int = TIME_WINDOW_SECONDS,
    syn_threshold: int = SYN_COUNT_THRESHOLD,
) -> list[dict]:
    """
    Verilen SYN paket olaylarinda SYN flood / DoS paternini arar.

    Args:
        events: traffic_event formatinda dict listesi (syn_packet turunde).
        time_window_seconds: kac saniyelik kayan pencerede bakilacak.
        syn_threshold: pencerede kac SYN paketi gorulurse alarm uretilecek.

    Returns:
        Alarm listesi. Her alarm:
        {
            "alarm_type": "syn_flood",
            "src_ip": ...,
            "dst_ip": ...,
            "syn_count": ...,
            "window_start": ...,
            "window_end": ...,
            "severity": "high" | "medium"
        }
    """
    # Sadece SYN paketlerini al, zamana gore sirala
    syn_events = sorted(
        (e for e in events if e.get("event_type") == "syn_packet"),
        key=lambda e: _parse_timestamp(e["timestamp"]),
    )

    # (src_ip, dst_ip) ciftine gore grupla -- brute-force ile ayni mantik:
    # ayni saldirgan farkli hedeflere de flood atiyor olabilir, ayri sayariz
    events_by_pair: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for e in syn_events:
        key = (e["src_ip"], e["dst_ip"])
        events_by_pair[key].append(e)

    alarms = []

    for (src_ip, dst_ip), pair_events in events_by_pair.items():
        window = timedelta(seconds=time_window_seconds)
        start_idx = 0

        for end_idx in range(len(pair_events)):
            end_time = _parse_timestamp(pair_events[end_idx]["timestamp"])

            while (
                end_time - _parse_timestamp(pair_events[start_idx]["timestamp"])
                > window
            ):
                start_idx += 1

            window_events = pair_events[start_idx : end_idx + 1]
            # BURASI port taramasindan farkli: distinct_ports (set) degil,
            # duz sayim (len) kullaniyoruz -- cesitlilik degil, hacim onemli
            syn_count = len(window_events)

            if syn_count >= syn_threshold:
                alarms.append(
                    {
                        "alarm_type": "syn_flood",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "syn_count": syn_count,
                        "window_start": window_events[0]["timestamp"],
                        "window_end": window_events[-1]["timestamp"],
                        "severity": "high" if syn_count >= syn_threshold * 2 else "medium",
                    }
                )
                start_idx = end_idx + 1
                if start_idx > end_idx:
                    break

    return alarms


if __name__ == "__main__":
    import json
    from pathlib import Path

    sample_path = Path(__file__).parent / "tests" / "sample_syn_events.json"
    with open(sample_path, encoding="utf-8") as f:
        sample_events = json.load(f)

    result = detect_syn_flood(sample_events)
    print(f"{len(result)} alarm uretildi:\n")
    for alarm in result:
        print(alarm)