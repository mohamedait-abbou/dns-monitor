#!/usr/bin/env python3
"""
DNS Traffic Monitor
A Python-based DNS packet analyzer for network security monitoring.
Requires root/admin privileges for packet capture.
"""

from scapy.all import sniff, DNSQR, IP
from collections import defaultdict, deque
import datetime
import time
import argparse
import sys
import os




SUSPICIOUS_KEYWORDS = [".xyz", ".ru", "malware", "phishing", "botnet", "c2", "command"]
LOG_FILE = "dns_log.txt"
RATE_LIMIT_THRESHOLD = 50      # queries per minute
RATE_LIMIT_WINDOW = 60         # seconds
TOP_N_REPORT = 10              # top domains/IPs to show in report




domains_count = defaultdict(int)           # domain -> query count
ip_domains = defaultdict(set)              # ip -> set of queried domains
ip_queries = defaultdict(lambda: deque(maxlen=200))  # ip -> timestamps of queries


def is_suspicious(domain: str) -> bool:
    """
    Check if a domain contains suspicious keywords.
    
    Args:
        domain: The domain name to check.
    
    Returns:
        True if suspicious, False otherwise.
    """
    domain_lower = domain.lower()
    return any(keyword in domain_lower for keyword in SUSPICIOUS_KEYWORDS)


def check_rate_limit(ip_src: str) -> bool:
    """
    Check if an IP has exceeded the query rate limit.
    
    Args:
        ip_src: Source IP address.
    
    Returns:
        True if rate limit exceeded, False otherwise.
    """
    now = time.time()
    ip_queries[ip_src].append(now)
    
    # Count queries within the time window
    recent_count = sum(1 for t in ip_queries[ip_src] if now - t < RATE_LIMIT_WINDOW)
    return recent_count > RATE_LIMIT_THRESHOLD


def log_to_file(message: str) -> None:
    """
    Append a message to the log file with timestamp.
    
    Args:
        message: The message to log.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {message}\n")


def process_packet(packet) -> None:
    """
    Process a captured packet and extract DNS query information.
    
    Args:
        packet: Scapy packet object.
    """
    if not packet.haslayer(DNSQR):
        return
    
    # Extract source IP
    ip_src = packet[IP].src if packet.haslayer(IP) else "unknown"
    
    # Extract domain name (remove trailing dot)
    try:
        domain = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
    except (AttributeError, UnicodeDecodeError):
        return
    
    if not domain:
        return
    
    # Update statistics
    domains_count[domain] += 1
    ip_domains[ip_src].add(domain)
    
    # Build base log entry
    log_entry = f"{ip_src} -> {domain}"
    
    # Check for suspicious domain
    if is_suspicious(domain):
        alert = f"[ALERT:SUSPICIOUS] {log_entry}"
        print(f"[!] {alert}")
        log_to_file(alert)
    
    # Check for rate limiting
    if check_rate_limit(ip_src):
        alert = f"[ALERT:RATE_LIMIT] {ip_src} exceeded {RATE_LIMIT_THRESHOLD} queries/min"
        print(f"[!] {alert}")
        log_to_file(alert)
    
    # Log all queries (optional - comment out if too noisy)
    log_to_file(f"[QUERY] {log_entry}")


def generate_report() -> None:
    """
    Generate and display a summary report of captured DNS traffic.
    """
    print("\n" + "=" * 60)
    print("           DNS MONITORING REPORT")
    print("=" * 60)
    
    print(f"\n📊 Total unique domains queried: {len(domains_count)}")
    print(f"📊 Total unique source IPs: {len(ip_domains)}")
    
    if domains_count:
        print(f"\n🔥 Top {TOP_N_REPORT} Most Queried Domains:")
        sorted_domains = sorted(domains_count.items(), key=lambda x: x[1], reverse=True)
        for i, (domain, count) in enumerate(sorted_domains[:TOP_N_REPORT], 1):
            print(f"   {i:2}. {domain:<40} {count:>5} queries")
    
    if ip_domains:
        print(f"\n🌐 Top {TOP_N_REPORT} IPs by Unique Domains:")
        sorted_ips = sorted(ip_domains.items(), key=lambda x: len(x[1]), reverse=True)
        for i, (ip, domains) in enumerate(sorted_ips[:TOP_N_REPORT], 1):
            print(f"   {i:2}. {ip:<20} {len(domains):>5} unique domains")
    
    print("\n" + "=" * 60)


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def start_sniffer(interface: str = None, offline_file: str = None) -> None:
    """
    Start the DNS packet sniffer.
    
    Args:
        interface: Network interface to capture on (e.g., 'eth0', 'Wi-Fi').
        offline_file: Path to pcap file for offline analysis.
    """
    # Clear/create log file at start
    open(LOG_FILE, "w").close()
    
    print("=" * 60)
    print("       DNS TRAFFIC MONITOR")
    print("=" * 60)
    print(f"[*] Log file: {os.path.abspath(LOG_FILE)}")
    print(f"[*] Suspicious keywords: {SUSPICIOUS_KEYWORDS}")
    print(f"[*] Rate limit: {RATE_LIMIT_THRESHOLD} queries / {RATE_LIMIT_WINDOW}s")
    print("[*] Press Ctrl+C to stop and view report\n")
    
    try:
        if offline_file:
            print(f"[*] Reading from file: {offline_file}")
            sniff(offline=offline_file, filter="udp port 53", prn=process_packet, store=0)
        else:
            iface_msg = f" on interface '{interface}'" if interface else ""
            print(f"[*] Capturing live traffic{iface_msg}...")
            sniff(iface=interface, filter="udp port 53", prn=process_packet, store=0)
            
    except PermissionError:
        print("\n[ERROR] Permission denied. Run as root/administrator.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n[*] Stopping monitor...")
    finally:
        generate_report()


def main():
    """
    Parse command-line arguments and start the monitor.
    """
    global RATE_LIMIT_THRESHOLD
    
    parser = argparse.ArgumentParser(
        description="DNS Traffic Monitor - Analyze DNS queries for suspicious activity",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python dns_monitor.py                    # Live capture on default interface
  sudo python dns_monitor.py -i eth0            # Capture on specific interface
  python dns_monitor.py -f capture.pcap         # Analyze pcap file
        """
    )
    
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to capture on (e.g., eth0, Wi-Fi, en0)"
    )
    parser.add_argument(
        "-f", "--file",
        dest="offline_file",
        help="Read from pcap file instead of live capture"
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=RATE_LIMIT_THRESHOLD,
        help=f"Rate limit threshold (default: {RATE_LIMIT_THRESHOLD})"
    )
    
    args = parser.parse_args()
    
    # Update threshold if provided
    if args.threshold:
        RATE_LIMIT_THRESHOLD = args.threshold
    
    start_sniffer(interface=args.interface, offline_file=args.offline_file)


if __name__ == "__main__":
    main()