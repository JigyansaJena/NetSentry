
from scapy.all import (
    rdpcap, IP, IPv6, TCP, UDP, ICMP, ARP
)
import pandas as pd


def analyze_pcap(file_path):
    """Extract useful metadata from packets in a PCAP file."""

    packets = rdpcap(file_path)
    records = []

    for packet in packets:
        src_ip = None
        dst_ip = None
        ip_version = None
        network_layer = "NON_IP"

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            ip_version = 4
            network_layer = "IPv4"

        elif IPv6 in packet:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            ip_version = 6
            network_layer = "IPv6"

        elif ARP in packet:
            src_ip = packet[ARP].psrc or None
            dst_ip = packet[ARP].pdst or None
            network_layer = "ARP"

        protocol = "OTHER"
        src_port = None
        dst_port = None

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        elif ICMP in packet:
            protocol = "ICMP"

        elif ARP in packet:
            protocol = "ARP"

        records.append({
            "timestamp": float(packet.time),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "ip_version": ip_version,
            "network_layer": network_layer,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "packet_size": len(packet),
        })

    columns = [
        "timestamp", "src_ip", "dst_ip", "ip_version",
        "network_layer", "protocol", "src_port",
        "dst_port", "packet_size"
    ]

    df = pd.DataFrame(records, columns=columns)

    if not df.empty:
        df["timestamp"] = pd.to_datetime(
            df["timestamp"], unit="s", utc=True
        )

    return df
