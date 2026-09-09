"""Sistem/Uygulama Loglarini Izleme (Issue #6)
================================================
`auth.log` (sshd) dosyasini tail eder, SSH giris denemelerini
(basarili/basarisiz) cikarir. Cikti formati: shared/schema/log_event.example.json.

Bu modul henuz shared/schema ile eslesen tam event formatini uretmiyor
(bu, Faz 6 / Issue #9'da event_writer uzerinden yapilacak) -- sadece
log satirindan cikarilabilen ham alanlari (src_ip, username, protocol,
success) verir.

Not: auth.log satirlarinda hedef (yerel makinenin) IP'si yer almaz --
bu yuzden dst_ip, cagiran taraf (ornegin testenv'de target konteynerinin
kendi IP'si) tarafindan parametre olarak verilir.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional, Union

# Debian/OpenSSH auth.log tipik satirlari:
#   ... sshd[123]: Failed password for testuser from 1.2.3.4 port 51230 ssh2
#   ... sshd[123]: Failed password for invalid user admin from 1.2.3.4 port 51230 ssh2
#   ... sshd[123]: Accepted password for testuser from 1.2.3.4 port 51230 ssh2
_LOGIN_RE = re.compile(
    r"sshd\[\d+\]:\s+"
    r"(?P<result>Failed password|Accepted password)\s+for\s+"
    r"(?:invalid user\s+)?(?P<username>\S+)\s+from\s+"
    r"(?P<src_ip>[0-9a-fA-F:.]+)\s+port\s+\d+\s+ssh2"
)


def parse_auth_log_line(line: str, dst_ip: str) -> Optional[dict]:
    """Bir auth.log satirini inceler; SSH giris denemesi ise alanlari cikarir.

    Returns:
        Eslesme yoksa None, eslesirse:
        {"src_ip", "dst_ip", "username", "protocol", "timestamp", "event_type", "success"}
    """
    match = _LOGIN_RE.search(line)
    if match is None:
        return None

    return {
        "src_ip": match.group("src_ip"),
        "dst_ip": dst_ip,
        "username": match.group("username"),
        "protocol": "SSH",
        # auth.log satirlarinin kendi zaman damgasi yil bilgisi icermez ve
        # syslog/journald'a gore formati degisebilir; bunun yerine satirin
        # okundugu andaki (gercek zamanli izleme oldugu icin pratikte satirin
        # yazildigi ana cok yakin) UTC zamani kullaniliyor.
        "timestamp": datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z"),
        "event_type": "login_attempt",
        "success": match.group("result") == "Accepted password",
    }


def follow(
    path: Union[str, Path],
    on_event: Callable[[dict], None],
    dst_ip: str,
    poll_interval: float = 0.5,
) -> None:
    """Verilen log dosyasini `tail -f` gibi izler, her giris denemesi icin on_event'i cagirir.

    Dosyanin var olan icerigini atlar, sadece sonradan eklenen satirlari isler.
    """
    path = Path(path)
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)  # dosyanin sonuna git, gecmisi isleme
        while True:
            line = f.readline()
            if not line:
                time.sleep(poll_interval)
                continue
            event = parse_auth_log_line(line, dst_ip=dst_ip)
            if event is not None:
                on_event(event)


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description="auth.log SSH giris denemesi izleyici")
    parser.add_argument("--path", default="/var/log/target/auth.log", help="Izlenecek log dosyasi")
    parser.add_argument("--dst-ip", required=True, help="Hedef makinenin IP'si (auth.log'da yer almaz)")
    args = parser.parse_args()

    follow(
        path=args.path,
        on_event=lambda e: print(json.dumps(e, ensure_ascii=False)),
        dst_ip=args.dst_ip,
    )
