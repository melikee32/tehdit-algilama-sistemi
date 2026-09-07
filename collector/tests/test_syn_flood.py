import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "simulate"))

from syn_flood import MAX_COUNT, run_syn_flood


def test_count_above_max_is_rejected_without_touching_network():
    with pytest.raises(ValueError):
        run_syn_flood("target", port=22, count=MAX_COUNT + 1)


def test_count_at_max_is_allowed():
    scapy_all = pytest.importorskip("scapy.all")

    sent = []
    original_send = scapy_all.send
    scapy_all.send = lambda pkt, verbose=False: sent.append(pkt)
    try:
        result = run_syn_flood("127.0.0.1", port=22, count=3)
    finally:
        scapy_all.send = original_send

    assert result == 3
    assert len(sent) == 3
