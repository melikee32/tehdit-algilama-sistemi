import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "simulate"))

from brute_force import run_brute_force


def test_run_brute_force_builds_expected_hydra_command(tmp_path, monkeypatch):
    import brute_force

    monkeypatch.setattr(brute_force, "WORDLIST_PATH", tmp_path / "wordlist.txt")

    with patch("brute_force.subprocess.run") as mock_run:
        run_brute_force("target", "testuser")

    args = mock_run.call_args.args[0]
    assert args[0] == "hydra"
    assert args[1:3] == ["-l", "testuser"]
    assert "ssh://target" in args


def test_run_brute_force_writes_wordlist_file(tmp_path, monkeypatch):
    import brute_force

    wordlist_path = tmp_path / "wordlist.txt"
    monkeypatch.setattr(brute_force, "WORDLIST_PATH", wordlist_path)

    with patch("brute_force.subprocess.run"):
        run_brute_force("target", "testuser", passwords=["123456", "admin"])

    content = wordlist_path.read_text(encoding="utf-8")
    assert content == "123456\nadmin\n"
