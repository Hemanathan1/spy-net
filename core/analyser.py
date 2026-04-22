"""
Packet Analyser Module
Analyses captured packets — classifies by protocol, extracts IPs,
ports, sizes, and builds a structured summary.
"""

import time
from collections import Counter
from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, Raw


def classify_protocol(packet) -> str:
    """Return a human-readable protocol name for a packet."""
    if packet.haslayer(ARP):
        return "ARP"
    if packet.haslayer(DNS):
        return "DNS"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        if tcp.dport == 443 or tcp.sport == 443:
            return "HTTPS"
        if tcp.dport == 80 or tcp.sport == 80:
            return "HTTP"
        if tcp.dport == 22 or tcp.sport == 22:
            return "SSH"
        if tcp.dport == 21 or tcp.sport == 21:
            return "FTP"
        if tcp.dport == 25 or tcp.sport == 25:
            return "SMTP"
        return "TCP"
    if packet.haslayer(UDP):
        udp = packet[UDP]
        if udp.dport == 53 or udp.sport == 53:
            return "DNS"
        if udp.dport == 67 or udp.dport == 68:
            return "DHCP"
        return "UDP"
    return "OTHER"


def analyse_packets(packets: list) -> dict:
    """
    Analyse a list of scapy packets and return a structured summary.
    """
    start = time.time()

    protocol_counts = Counter()
    src_ips         = Counter()
    dst_ips         = Counter()
    src_ports       = Counter()
    dst_ports       = Counter()
    sizes           = []
    packet_details  = []

    for pkt in packets:
        proto = classify_protocol(pkt)
        protocol_counts[proto] += 1

        size = len(pkt)
        sizes.append(size)

        src_ip = dst_ip = src_port = dst_port = "N/A"

        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            src_ips[src_ip] += 1
            dst_ips[dst_ip] += 1

        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            src_ports[str(src_port)] += 1
            dst_ports[str(dst_port)] += 1
        elif pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            src_ports[str(src_port)] += 1
            dst_ports[str(dst_port)] += 1

        # Flag suspicious activity
        flags = []
        if pkt.haslayer(TCP):
            tcp_flags = pkt[TCP].flags
            if "S" in str(tcp_flags) and "A" not in str(tcp_flags):
                flags.append("SYN")
            if "R" in str(tcp_flags):
                flags.append("RST")
            if "F" in str(tcp_flags):
                flags.append("FIN")

        packet_details.append({
            "protocol":  proto,
            "src_ip":    src_ip,
            "dst_ip":    dst_ip,
            "src_port":  str(src_port),
            "dst_port":  str(dst_port),
            "size":      size,
            "flags":     ", ".join(flags) if flags else "",
        })

    duration = round(time.time() - start, 3)

    # Sort counters by most common
    top_src_ips  = dict(src_ips.most_common(10))
    top_dst_ips  = dict(dst_ips.most_common(10))
    top_dst_ports = dict(dst_ports.most_common(10))

    return {
        "total":            len(packets),
        "duration_s":       duration,
        "avg_size_bytes":   round(sum(sizes) / len(sizes), 1) if sizes else 0,
        "total_bytes":      sum(sizes),
        "protocol_counts":  dict(protocol_counts),
        "top_src_ips":      top_src_ips,
        "top_dst_ips":      top_dst_ips,
        "top_dst_ports":    top_dst_ports,
        "packet_details":   packet_details,
        "captured_at":      time.strftime("%Y-%m-%d %H:%M:%S"),
        "run_id":           time.strftime("%Y%m%d_%H%M%S"),
    }
