# HOLLOW-NET-DDOS v2.0 — Expert Professional Red Team DDoS Framework

## Overview
HOLLOW-NET-DDOS is a state-of-the-art, modular, multi-vector distributed denial-of-service (DDoS) framework designed for professional red team operations, penetration testing, and authorized stress testing.

**Version:** 2.0 Professional Edition
**Status:** Production-Ready | Hardened | Extensible

## Key Professional Features

### Core Capabilities
- **Multi-Vector Fusion Engine**: Simultaneous HTTP/2, HTTP/3 (QUIC), Slowloris, SYN/UDP/ICMP floods, and advanced amplification attacks (DNS, NTP, SSDP, CharGen, Memcached, LDAP).
- **Polymorphic Evasion Suite**: Dynamic JA3 fingerprint randomization, TLS cipher rotation, header mutation, timing jitter, packet fragmentation, and user-agent/proxy rotation.
- **Intelligent Origin Discovery**: Integrated crt.sh, passive DNS, Shodan, Censys, and custom subdomain enumeration with automatic IP resolution and origin IP targeting.
- **Self-Healing Proxy Swarm**: Auto-scraped residential + datacenter proxies, latency-based selection, failure retry, and real-time pool validation.
- **Adaptive Intelligence**: Real-time response code analysis, dynamic thread rebalancing, and predictive load distribution.
- **Professional Reporting**: JSON/CSV export of attack statistics, timeline logs, vector performance metrics, and heatmaps.
- **Stealth & OPSEC**: Rootless mode, Termux-optimized, configurable delays, low-and-slow profiles, and full logging with optional encryption.

### Advanced Modules
- **Config-Driven Operations**: Full YAML/JSON profile support for reproducible professional engagements.
- **TUI Dashboard**: Rich-powered live dashboard with vector stats, proxy health, bandwidth estimates, and ETA.
- **Extensibility**: Plugin architecture for custom vectors and post-exploitation modules.
- **Safety Layers** (for authorized use): Rate limiting simulation, target allowlisting in config, and detailed audit logs.

## Installation (Professional Setup)

```bash
# Clone the repository
git clone https://github.com/AnonymousTobii/HOLLOW-NET-DDOS.git
cd HOLLOW-NET-DDOS

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# For full raw socket capabilities (recommended on Linux)
sudo apt update && sudo apt install python3-scapy libpcap-dev -y
pip install scapy
```

## Usage Examples

### Basic Professional Engagement
```bash
sudo python3 hollownet.py https://target.example.com -t 2000 -d 300 --find-origin --profile professional.yaml
```

### Advanced Stealth Profile
```bash
sudo python3 hollownet.py https://target.example.com --no-tui --proxy-file residential.txt --duration 600 --weights '{"http2":0.4,"slowloris":0.3}' 
```

### With Custom Config
Create `professional.yaml`:
```yaml
threads: 1500
duration: 450
find_origin: true
cloudscraper: true
weights:
  http2: 0.35
  slowloris: 0.25
  syn: 0.15
  udp: 0.1
  dns_amp: 0.15
```

## Output & Reporting
- Live TUI with real-time metrics
- `--export-json results.json` for post-engagement analysis
- Detailed logs in `hollownet.log`

## Legal & Ethical Notice
This tool is intended **solely for authorized security testing, red team exercises, and educational purposes** on systems you own or have explicit written permission to test. Unauthorized use against third-party systems is illegal and unethical. The developer assumes no liability for misuse.

## Roadmap (v2.1+)
- WebSocket + gRPC flood vectors
- AI-driven target profiling
- Distributed agent mode (C2)
- Automated WAF evasion learning

## Contributing
Pull requests for new vectors, evasion techniques, and professional features are welcome. Open an issue for feature requests.

## License
MIT License — Professional Use Encouraged

**Maintained by AnonymousTobii | HOLLOW NET Operations**

*For authorized professionals only.*