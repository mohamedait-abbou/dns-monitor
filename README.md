# DNS Traffic Monitor 🔍

A Python-based DNS packet analyzer for network security monitoring and threat detection.

![Python](https://img.shields.io/badge/python-3.7+-blue.svg)
![Scapy](https://img.shields.io/badge/scapy-2.4.5+-orange.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Features

- 🔴 **Real-time DNS traffic capture**
- 🚨 **Suspicious domain detection** (malware, phishing, DGA indicators)
- ⚡ **Rate-limiting alerts** per IP address
- 📊 **Summary report** with top queried domains and IPs
- 📁 **Offline pcap analysis** support
- 📝 **Structured logging** to file

## Requirements

- Python 3.7+
- Scapy library
- Root/admin privileges for packet capture

## Installation

```bash
git clone <your-repo-url>
cd dns-monitor
pip install -r requirements.txt
```

## Usage

### Real-time Monitoring

```bash
sudo python dns_monitor.py
```

### Analyze PCAP File

```bash
python dns_monitor.py -f capture.pcap
```

### Options

- `-i, --interface`: Network interface to monitor (default: auto-detect)
- `-f, --file`: PCAP file to analyze
- `-t, --threshold`: Rate limit threshold (default: 50 queries/min)
- `-w, --window`: Rate limit window in seconds (default: 60)
- `-v, --verbose`: Enable verbose output

## Example Output

```
Starting DNS traffic monitor on interface: eth0
[2023-10-01 12:00:00] Suspicious domain detected: malware.example.ru from 192.168.1.100
[2023-10-01 12:01:00] Rate limit exceeded for IP 192.168.1.100: 60 queries in 60 seconds

Summary Report:
Top Domains:
1. google.com: 150 queries
2. example.com: 120 queries

Top IPs:
1. 192.168.1.100: 200 queries
2. 192.168.1.101: 180 queries
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.