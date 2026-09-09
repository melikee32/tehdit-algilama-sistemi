import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "capture"))
from scapy.all import IP, TCP, Ether

from sniffer import parse_syn_packet


def _pkt(flags: str, sport: int = 40000, dport: int = 22):
    return (
        Ether()
        / IP(src="192.168.1.50", dst="192.168.1.10")
        / TCP(sport=sport, dport=dport, flags=flags)
    )


def test_syn_only_packet_is_parsed_as_connection_attempt():
    event = parse_syn_packet(_pkt("S", dport=22))

    assert event == {
        "src_ip": "192.168.1.50",
        "dst_ip": "192.168.1.10",
        "dst_port": 22,
        "protocol": "TCP",
        "timestamp": event["timestamp"],  # format ayri asagida dogrulaniyor
    }
    # ISO 8601, milisaniye hassasiyetinde, "Z" ile bitmeli
    assert event["timestamp"].endswith("Z")
    assert "." in event["timestamp"]


def test_syn_ack_packet_is_ignored():
    """SYN+ACK bir el sikismanin devami, yeni baglanti denemesi degil."""
    assert parse_syn_packet(_pkt("SA")) is None


def test_ack_only_packet_is_ignored():
    assert parse_syn_packet(_pkt("A")) is None


def test_non_tcp_packet_is_ignored():
    assert parse_syn_packet(Ether() / IP(src="1.1.1.1", dst="2.2.2.2")) is None


def test_different_dst_port_is_reflected():
    event = parse_syn_packet(_pkt("S", dport=8080))
    assert event["dst_port"] == 8080
