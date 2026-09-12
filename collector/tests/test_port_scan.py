import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "simulate"))

from port_scan import run_port_scan


def test_run_port_scan_builds_expected_nmap_command():
    with patch("port_scan.subprocess.run") as mock_run:
        run_port_scan("target", ports="1-100")

    args = mock_run.call_args.args[0]
    assert args == ["nmap", "-sS", "-Pn", "-p", "1-100", "target"]


def test_run_port_scan_uses_default_port_range():
    with patch("port_scan.subprocess.run") as mock_run:
        run_port_scan("target")

    args = mock_run.call_args.args[0]
    assert "-p" in args
    assert args[args.index("-p") + 1] == "1-1000"
