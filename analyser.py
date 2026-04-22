"""
NetSight — Network Packet Analyser
Captures and analyses live network packets, classifies by protocol,
and generates a detailed HTML + JSON report.
"""

import argparse
import time
from datetime import datetime
from core.capture import capture_packets
from core.analyser import analyse_packets
from reports.reporter import generate_report


def main():
    parser = argparse.ArgumentParser(description="NetSight — Network Packet Analyser")
    parser.add_argument("--count",    type=int, default=50,   help="Number of packets to capture (default: 50)")
    parser.add_argument("--timeout",  type=int, default=15,   help="Capture timeout in seconds (default: 15)")
    parser.add_argument("--filter",   type=str, default=None, help="BPF filter e.g. 'tcp', 'udp', 'icmp', 'port 80'")
    parser.add_argument("--format",   choices=["html", "json", "both"], default="both")
    args = parser.parse_args()

    print("\n🔬 NetSight — Network Packet Analyser")
    print(f"   Capturing : {args.count} packets")
    print(f"   Timeout   : {args.timeout}s")
    print(f"   Filter    : {args.filter or 'none (all traffic)'}")
    print(f"   Format    : {args.format}")
    print("\n⏳ Capturing packets... (browse the web or ping something to generate traffic)\n")

    packets = capture_packets(count=args.count, timeout=args.timeout, bpf_filter=args.filter)

    if not packets:
        print("❌ No packets captured. Try increasing --timeout or check your network interface.")
        return

    print(f"✅ Captured {len(packets)} packets. Analysing...\n")
    summary = analyse_packets(packets)

    # Print summary to terminal
    print(f"{'='*55}")
    print(f"  PROTOCOL BREAKDOWN")
    print(f"{'='*55}")
    for proto, count in sorted(summary["protocol_counts"].items(), key=lambda x: -x[1]):
        bar = "█" * min(count, 40)
        print(f"  {proto:<10} {count:>4}  {bar}")

    print(f"\n{'='*55}")
    print(f"  TOP SOURCE IPs")
    print(f"{'='*55}")
    for ip, count in list(summary["top_src_ips"].items())[:5]:
        print(f"  {ip:<25} {count} packets")

    print(f"\n{'='*55}")
    print(f"  TOP DESTINATION IPs")
    print(f"{'='*55}")
    for ip, count in list(summary["top_dst_ips"].items())[:5]:
        print(f"  {ip:<25} {count} packets")

    print(f"\n  Total packets : {summary['total']}")
    print(f"  Avg pkt size  : {summary['avg_size_bytes']} bytes")
    print(f"  Capture time  : {summary['duration_s']}s")

    generate_report(summary, fmt=args.format)
    print("\n✅ Done!\n")


if __name__ == "__main__":
    main()
