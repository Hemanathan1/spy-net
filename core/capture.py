"""
Packet Capture Module
Uses scapy to sniff live packets from the network interface.
"""

from scapy.all import sniff


def capture_packets(count: int = 50, timeout: int = 15, bpf_filter: str = None) -> list:
    """
    Capture live network packets using scapy.

    Args:
        count      : max number of packets to capture
        timeout    : stop after this many seconds even if count not reached
        bpf_filter : optional BPF filter string e.g. 'tcp', 'udp port 80'

    Returns:
        List of scapy packet objects
    """
    try:
        kwargs = {
            "count":   count,
            "timeout": timeout,
            "store":   True,
        }
        if bpf_filter:
            kwargs["filter"] = bpf_filter

        packets = sniff(**kwargs)
        return list(packets)

    except PermissionError:
        print("\n❌ Permission denied!")
        print("   On Windows: Run your terminal as Administrator")
        print("   On Linux/Mac: Run with sudo\n")
        return []
    except Exception as e:
        print(f"\n❌ Capture error: {e}\n")
        return []
