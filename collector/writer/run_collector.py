"""Collector Ana Giris Noktasi (Issue #9)
===========================================
`capture/sniffer.py` (paket yakalama, #5) ve `logs/log_reader.py`
(log izleme, #6) modullerini ayni anda calistirir; ikisinin de
ciktisini `EventWriter` uzerinden dogrulayip `collector/output/events.jsonl`
dosyasina yazar.

Kullanim (testenv icinde):
    python3 writer/run_collector.py --iface eth0 \\
        --log-path /var/log/target/auth.log --dst-ip <target_ip>
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "capture"))
sys.path.insert(0, str(Path(__file__).parent.parent / "logs"))

from event_writer import EventWriter  # noqa: E402
from log_reader import follow as follow_logs  # noqa: E402
from sniffer import capture as capture_packets  # noqa: E402

DEFAULT_OUTPUT_PATH = Path(__file__).parent.parent / "output" / "events.jsonl"


def run(iface: str, log_path: str, dst_ip: str, output_path: Path = DEFAULT_OUTPUT_PATH) -> None:
    writer = EventWriter(output_path)

    capture_thread = threading.Thread(
        target=capture_packets,
        kwargs={"iface": iface, "on_event": lambda e: writer.write(e, "connection_attempt")},
        daemon=True,
    )
    log_thread = threading.Thread(
        target=follow_logs,
        kwargs={"path": log_path, "dst_ip": dst_ip, "on_event": lambda e: writer.write(e, "login_attempt")},
        daemon=True,
    )

    capture_thread.start()
    log_thread.start()

    capture_thread.join()
    log_thread.join()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Collector: paket yakalama + log izleme -> shared/schema JSONL")
    parser.add_argument("--iface", default="eth0", help="Dinlenecek ag arayuzu")
    parser.add_argument("--log-path", default="/var/log/target/auth.log", help="Izlenecek auth.log dosyasi")
    parser.add_argument("--dst-ip", required=True, help="Hedef makinenin IP'si (auth.log'da yer almaz)")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT_PATH), help="Yazilacak .jsonl dosyasi")
    args = parser.parse_args()

    run(iface=args.iface, log_path=args.log_path, dst_ip=args.dst_ip, output_path=Path(args.output))
