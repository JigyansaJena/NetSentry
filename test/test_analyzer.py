
from scapy.all import Ether, IP, TCP, UDP, wrpcap
from analyzer import analyze_pcap


def test_extracts_tcp_packet(tmp_path):
    capture = tmp_path / "test.pcap"

    packet = (
        Ether()
        / IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=51515, dport=443)
    )

    wrpcap(str(capture), [packet])

    df = analyze_pcap(str(capture))

    assert len(df) == 1
    assert df.iloc[0]["src_ip"] == "192.168.1.10"
    assert df.iloc[0]["dst_ip"] == "192.168.1.20"
    assert df.iloc[0]["protocol"] == "TCP"
    assert df.iloc[0]["dst_port"] == 443
    assert df.iloc[0]["packet_size"] > 0


def test_empty_capture(tmp_path):
    capture = tmp_path / "empty.pcap"
    wrpcap(str(capture), [])

    df = analyze_pcap(str(capture))

    assert df.empty
    assert "protocol" in df.columns
