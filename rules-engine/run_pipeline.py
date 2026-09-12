"""
Rules Engine Pipeline - Uctan Uca Otomatik Akis
================================================
Bu script collector ciktisini (events.jsonl) okuyup tespit motorlarindan
gecirerek sonuclari backend'e gonderir.

Akis:
    collector/output/events.jsonl
        -> port_scan_detector
        -> brute_force_detector
        -> syn_flood_detector
        -> alarm_formatter
        -> event_sender  (POST /events)
        -> app.correlation (POST /alarms)

Kullanim:
    # Tek sefer calistir (mevcut events.jsonl'i isle):
    python rules-engine/run_pipeline.py

    # Surekli izle (collector yazarken canli isle):
    python rules-engine/run_pipeline.py --watch

    # Baska bir dosyayi isle:
    python rules-engine/run_pipeline.py --input collector/output/events.jsonl

    # Correlation da otomatik calistir:
    python rules-engine/run_pipeline.py --correlate
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

# rules-engine modulleri
_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE))

from alarm_formatter import format_alarms
from brute_force_detector import detect_brute_force
from event_sender import send_events
from port_scan_detector import detect_port_scans
from syn_flood_detector import detect_syn_flood

DEFAULT_INPUT = Path(__file__).parent.parent / "collector" / "output" / "events.jsonl"


def load_jsonl(path: Path) -> list[dict]:
    """JSONL dosyasindaki tum satirlari dict listesi olarak dondurur."""
    events = []
    if not path.exists():
        print(f"[Pipeline] Dosya bulunamadi: {path}")
        return events
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(f"  [!] JSON parse hatasi (satir atlandi): {e}")
    return events


def run_once(input_path: Path, correlate: bool = False) -> int:
    """Dosyayi bir kez okur, tespit eder, gonderir. Uretilen alarm sayisini dondurur."""
    events = load_jsonl(input_path)
    if not events:
        print("[Pipeline] Islenecek event yok.")
        return 0

    print(f"[Pipeline] {len(events)} event okundu -> tespit motorlari calistiriliyor...")

    port_scan_alarms  = detect_port_scans(events)
    brute_force_alarms = detect_brute_force(events)
    syn_flood_alarms  = detect_syn_flood(events)

    all_raw = port_scan_alarms + brute_force_alarms + syn_flood_alarms
    print(f"  Port Scan : {len(port_scan_alarms)} alarm")
    print(f"  BruteForce: {len(brute_force_alarms)} alarm")
    print(f"  SYN Flood : {len(syn_flood_alarms)} alarm")
    print(f"  Toplam    : {len(all_raw)} alarm")

    if not all_raw:
        print("[Pipeline] Hicbir esik asilmadi, backend'e gonderilecek event yok.")
        return 0

    formatted = format_alarms(all_raw)
    print(f"\n[Pipeline] {len(formatted)} event backend'e gonderiliyor...")
    send_events(formatted)

    if correlate:
        print("\n[Pipeline] Correlation engine calistiriliyor...")
        import subprocess
        result = subprocess.run(
            [sys.executable, "-m", "app.correlation"],
            capture_output=True, text=True,
            cwd=str(_HERE.parent)
        )
        print(result.stdout)
        if result.returncode != 0:
            print(f"[Pipeline] Correlation hatasi: {result.stderr[:300]}")

    return len(formatted)


def watch_mode(input_path: Path, interval: int = 5, correlate: bool = False) -> None:
    """Dosyayi her `interval` saniyede bir kontrol eder, degisim varsa isle."""
    print(f"[Pipeline] Izleme modu: {input_path} her {interval}s kontrol ediliyor. Cikis: Ctrl+C")
    last_size = -1
    while True:
        try:
            current_size = input_path.stat().st_size if input_path.exists() else 0
            if current_size != last_size:
                print(f"\n[Pipeline] Degisim tespit edildi ({current_size} byte).")
                run_once(input_path, correlate=correlate)
                last_size = current_size
            time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[Pipeline] Durduruldu.")
            break


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Rules Engine Pipeline: JSONL -> Tespit -> Backend")
    parser.add_argument("--input", default=str(DEFAULT_INPUT),
                        help="Islenecek JSONL dosyasi (varsayilan: collector/output/events.jsonl)")
    parser.add_argument("--watch", action="store_true",
                        help="Dosyayi surekli izle (canli mod)")
    parser.add_argument("--interval", type=int, default=5,
                        help="Izleme modu: kontrol arasi (saniye, varsayilan: 5)")
    parser.add_argument("--correlate", action="store_true",
                        help="Gonderimden sonra correlation engine'i de calistir")
    args = parser.parse_args()

    input_path = Path(args.input)

    if args.watch:
        watch_mode(input_path, interval=args.interval, correlate=args.correlate)
    else:
        run_once(input_path, correlate=args.correlate)
