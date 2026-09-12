"""Ag Trafigi Dinleme / Paket Yakalama (Issue #5)
===================================================
Bir arayuzu dinler, TCP SYN paketlerinden (ACK'siz, yani yeni baglanti
denemesi) bağlantı denemelerini çıkarır.

Bu modül henüz shared/schema ile eşleşen tam event formatını üretmiyor
(bu, Faz 6 / Issue #9'da event_writer üzerinden yapılacak) — sadece
paketten çıkarılabilen ham alanları (src_ip, dst_ip, dst_port, protocol,
timestamp) verir.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Optional

from scapy.all import IP, TCP, Packet, sniff


def parse_syn_packet(pkt: Packet) -> Optional[dict]:
    """Bir paketi inceler; TCP SYN (baglanti denemesi) ise alanlari cikarir.

    ACK biti set edilmemis SYN paketi = yeni baglanti denemesi (3-way
    handshake'in ilk adimi). Bu, nmap gibi araclarin port taramasinda
    urettigi tipik pakettir.

    Returns:
        Eslesme yoksa None, eslesirse:
        {"src_ip", "dst_ip", "dst_port", "protocol", "timestamp"}
    """
    if IP not in pkt or TCP not in pkt:
        return None

    tcp = pkt[TCP]
    flags = tcp.flags
    is_syn_only = ("S" in flags) and ("A" not in flags)
    if not is_syn_only:
        return None

    return {
        "src_ip": pkt[IP].src,
        "dst_ip": pkt[IP].dst,
        "dst_port": int(tcp.dport),
        "protocol": "TCP",
        "timestamp": datetime.fromtimestamp(
            float(pkt.time), tz=timezone.utc
        ).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
    }


def capture(
    iface: str,
    on_event: Callable[[dict], None],
    count: int = 0,
    timeout: Optional[int] = None,
) -> None:
    """Belirtilen arayuzu dinler, her SYN paketi icin on_event'i cagirir.

    Args:
        iface: Dinlenecek ag arayuzu (ör. "eth0").
        on_event: Her tespit edilen baglanti denemesi icin cagrilacak callback.
        count: Kac paket sonra durulacak (0 = sinirsiz).
        timeout: Saniye cinsinden ust sinir (None = sinirsiz).
    """

    def _handle(pkt: Packet) -> None:
        event = parse_syn_packet(pkt)
        if event is not None:
            on_event(event)

    sniff(iface=iface, filter="tcp", prn=_handle, store=False, count=count, timeout=timeout)


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description="TCP SYN baglanti denemesi dinleyici")
    parser.add_argument("--iface", default="eth0", help="Dinlenecek ag arayuzu")
    parser.add_argument("--count", type=int, default=0, help="Kac paket sonra durulacak (0 = sinirsiz)")
    parser.add_argument("--timeout", type=int, default=None, help="Saniye cinsinden ust sinir")
    args = parser.parse_args()

    capture(
        iface=args.iface,
        on_event=lambda e: print(json.dumps(e, ensure_ascii=False)),
        count=args.count,
        timeout=args.timeout,
    )
