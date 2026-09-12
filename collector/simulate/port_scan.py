"""Port Tarama Simulasyonu (Issue #8)
=======================================
Izole test lab'inda (bkz. testenv/) `target` konteynerine karsi nmap ile
SYN port taramasi calistirir. `rules-engine/port_scan_detector.py`'nin
tespit etmesi beklenen taramayi (kisa surede cok sayida farkli porta
baglanti denemesi) uretir.

SADECE izole test lab agi icindir -- gercek/uretim sistemlerine karsi
calistirilmamalidir.

Kullanim (attacker konteyneri icinde):
    python3 simulate/port_scan.py --target target --ports 1-100
"""

from __future__ import annotations

import argparse
import subprocess


def run_port_scan(target: str, ports: str = "1-1000") -> subprocess.CompletedProcess:
    """nmap SYN taramasi (-sS) calistirir. -Pn: host'u once ping'lemeden dogrudan tara."""
    cmd = ["nmap", "-sS", "-Pn", "-p", ports, target]
    return subprocess.run(cmd, check=False, capture_output=True, text=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Izole test lab'inda port tarama simulasyonu")
    parser.add_argument("--target", required=True, help="Hedef host/IP (ornek: target)")
    parser.add_argument("--ports", default="1-1000", help="Taranacak port araligi")
    args = parser.parse_args()

    result = run_port_scan(args.target, args.ports)
    print(result.stdout)
    if result.returncode != 0:
        print(result.stderr)
