""" Brute-Force Tespit Modulu
===========================
Mantik: Ayni kaynak IP'den, kisa bir zaman penceresi icinde ayni
hedefe (dst_ip) cok sayida BASARISIZ giris denemesi gelirse, bu
brute-force saldirisi olarak isaretlenir.

Girdi formati (login_attempt event_type'i beklenir):
    {
        "src_ip": "192.168.1.50",
        "dst_ip": "192.168.1.10",
        "username": "admin",
        "protocol": "SSH",
        "timestamp": "2026-08-23T14:32:10.123Z",
        "event_type": "login_attempt",
        "success": false
    } """

# collections içinden defaultdict sınıfını al.
from collections import defaultdict

# datetime modülünden timedelta sınıfını al.
# İki tarih/saat arasındaki süreyi temsil etmek veya tarihe süre eklemek için kullanılır.
from datetime import timedelta

# typing modülünden Iterable türünü al. 
# "for (üzerinde) ile gezilebilir veri" anlamında tip belirtmek için.
from typing import Iterable

# port_scan_detector.py'deki ayni yardimci fonksiyonu tekrar kullaniyoruz.
from port_scan_detector import _parse_timestamp



# Sabit Eşik değerleri. başarısız giriş denemelerini sınırlama
TIME_WINDOW_SECONDS = 30 
# threshold = eşik / sınır
FAILED_ATTEMPT_THRESHOLD = 5 



def detect_brute_force(
    events: Iterable[dict],
    time_window_seconds: int = TIME_WINDOW_SECONDS,
    attempt_threshold: int = FAILED_ATTEMPT_THRESHOLD,
) -> list[dict]:
    """
    Verilen giris denemesi olaylarinda brute-force paternini arar.

    Args:
        events: traffic_event formatinda dict listesi (login_attempt turunde).
        time_window_seconds: kac saniyelik kayan pencerede bakilacak.
        attempt_threshold: pencerede kac basarisiz deneme gorulurse alarm uretilecek.

    Returns:
        Alarm listesi. Her alarm:
        {
            "alarm_type": "brute_force",
            "src_ip": ...,
            "dst_ip": ...,
            "failed_attempts": ...,
            "window_start": ...,
            "window_end": ...,
            "severity": "high" | "medium"
        }
    """
    # Sadece giris denemesi olaylarini al, zamana gore sirala
    login_events = sorted(
        (e for e in events if e.get("event_type") == "login_attempt"),
        key=lambda e: _parse_timestamp(e["timestamp"]),
    )

    # (src_ip, dst_ip) ciftine gore grupla
    # Neden port_scan'deki gibi sadece src_ip degil de cift kullaniyoruz?
    # Cunku ayni saldirgan IP, birden fazla hedefe brute-force deniyor olabilir,
    # bunlari ayri ayri saymak istiyoruz.
    events_by_pair: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for e in login_events:
        # Sadece BASARISIZ denemeleri sayiyoruz -> basarili giris varsa
        # zaten saldirgan degil, gercek kullanicidir
        if e.get("success") is False:
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
            failed_count = len(window_events)

            if failed_count >= attempt_threshold:
                alarms.append(
                    {
                        "alarm_type": "brute_force",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "failed_attempts": failed_count,
                        "window_start": window_events[0]["timestamp"],
                        "window_end": window_events[-1]["timestamp"],
                        "severity": "high" if failed_count >= attempt_threshold * 2 else "medium",
                    }
                )
                start_idx = end_idx + 1
                if start_idx > end_idx:
                    break

    return alarms


if __name__ == "__main__":
    # Hizli manuel test icin: sahte veriyle calistir
    import json
    from pathlib import Path

    sample_path = Path(__file__).parent / "tests" / "sample_login_events.json"
    with open(sample_path, encoding="utf-8") as f:
        sample_events = json.load(f)

    result = detect_brute_force(sample_events)
    print(f"{len(result)} alarm uretildi:\n")
    for alarm in result:
        print(alarm)

