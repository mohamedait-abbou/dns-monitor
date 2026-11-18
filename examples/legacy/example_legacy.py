from scapy.all import sniff, DNSQR, IP
from collections import defaultdict
import datetime

# Store counts
domains_count = defaultdict(int)

# Track domains per IP
ip_domains = defaultdict(set)

# Suspicious patterns
SUSPICIOUS_KEYWORDS = [".xyz", ".ru", "malware", "phishing"]

# Log file
LOG_FILE = "dns_log.txt"


def is_suspicious(domain):
    return any(keyword in domain.lower() for keyword in SUSPICIOUS_KEYWORDS)


def log_to_file(message):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(message + "\n")
#so haw push gityibn now  


def process_packet(packet):
    if packet.haslayer(DNSQR):
        try:
            # Extract domain safely
            domain = packet[DNSQR].qname.decode(errors="ignore").strip('.')

            # Extract source IP
            ip_src = packet[IP].dst if packet.haslayer(IP) else "Unknown"

            # Update stats
            domains_count[domain] += 1
            ip_domains[ip_src].add(domain)

            timestamp = datetime.datetime.now().strftime("%H:%M:%S")

            message = f"[{timestamp}] {ip_src} → {domain} (count: {domains_count[domain]})"

            # Suspicious detection
            if is_suspicious(domain):
                message = "⚠️ " + message

            print(message)
            log_to_file(message)

        except Exception as e:
            print(f"[ERROR] {e}")


def show_summary():
    print("\n📊 ===== SUMMARY =====")

    print("\nTop Domains:")
    sorted_domains = sorted(domains_count.items(), key=lambda x: x[1], reverse=True)
    for domain, count in sorted_domains[:10]:
        print(f"{domain} → {count}")

    print("\nIP Activity:")
    for ip, domains in ip_domains.items():
        print(f"{ip} → {len(domains)} domains")


def start_sniffing():
    print("🚀 Starting DNS Analyzer... (Press Ctrl+C to stop)\n")

    try:
        sniff(filter="udp port 53", prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("\n🛑 Stopping capture...")
        show_summary()


if __name__ == "__main__":
    start_sniffing()