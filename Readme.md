# mlPcapAnalyzer

**Professional PCAP Analysis Toolkit for Network Security Engineers**

A Python-based network packet analysis framework built on Scapy, designed for cybersecurity professionals performing threat hunting, unencrypted traffic detection, and beaconing analysis operations.

---

## 🎯 Overview

mlPcapAnalyzer is a comprehensive network traffic analysis toolkit developed by TachTech for enterprise security operations. The project includes:

- **Unencrypted Protocol Detection**: Identifies cleartext HTTP, FTP, Telnet, SMTP, DNS, POP3, and IMAP traffic
- **Automated PCAP Analysis**: Generates detailed markdown reports with protocol statistics and IP conversation mapping
- **Interactive Learning Environment**: Quickstart module with hands-on exercises for PCAP analysis techniques
- **Beacon Detection**: Statistical analysis to identify C2 beaconing patterns using Coefficient of Variation (CoV)
- **Dockerized Development**: Isolated Ubuntu 24.04 container with pre-configured Scapy environment

---

## 📋 Table of Contents

- [Features](#-features)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
  - [Option 1: Docker Container Setup (Recommended)](#option-1-docker-container-setup-recommended)
  - [Option 2: Native Installation](#option-2-native-installation)
- [Usage](#-usage)
  - [Quick Start Interactive Mode](#quick-start-interactive-mode)
  - [Automated Analysis Mode](#automated-analysis-mode)
- [Analysis Modules](#-analysis-modules)
- [Output Format](#-output-format)
- [Detection Methodology](#-detection-methodology)
- [Architecture](#-architecture)
- [Contributing](#-contributing)
- [License](#-license)
- [Contact](#-contact)

---

## ✨ Features

### Core Capabilities

- **Multi-Protocol Detection**
  - Identifies 7+ unencrypted protocols (HTTP, FTP, Telnet, SMTP, DNS, POP3, IMAP)
  - Port-based classification with configurable detection rules
  - Protocol-specific payload extraction (HTTP request lines, DNS queries)

- **Comprehensive Reporting**
  - Timestamped markdown reports with embedded code blocks
  - Dual summaries: Unencrypted traffic + Full PCAP analysis
  - Protocol/port distribution statistics
  - Source/destination IP conversation mapping
  - DNS query aggregation and frequency analysis

- **Interactive Learning Platform**
  - 6 modular training exercises covering PCAP fundamentals
  - Live packet capture with real-time protocol analysis
  - Simulated C2 beacon traffic generation for detection practice
  - DNS exfiltration pattern detection demonstrations

- **Beacon Detection Engine**
  - Statistical beaconing analysis using numpy
  - Coefficient of Variation (CoV) scoring: `CoV = σ / μ`
  - Confidence tiers: HIGH (CoV < 0.1), MEDIUM (0.1-0.3), LOW (> 0.3)
  - Connection pattern tracking by (src_ip, dst_ip, dst_port) tuples

### Security Applications

- **Threat Hunting**: Identify cleartext credential transmission and legacy protocol usage
- **Network Forensics**: Post-incident packet analysis with automated report generation
- **C2 Detection**: Identify regular beaconing patterns indicative of malware callbacks
- **Compliance Validation**: Verify encryption implementation across enterprise networks
- **SOC Training**: Educational toolkit for junior analysts learning PCAP analysis

---

## 🔧 Prerequisites

### System Requirements

- **Operating System**: Linux (Ubuntu 24.04 recommended), macOS, or Windows with WSL2
- **Python**: Version 3.8 or higher
- **Privileges**: Root/sudo access required for live packet capture
- **Memory**: 2GB RAM minimum (4GB+ recommended for large PCAPs)
- **Disk**: 500MB for dependencies + storage for capture files

### Required Dependencies

```
scapy >= 2.6.1
numpy >= 2.3.4
```

### Optional Tools

- **Docker**: Version 20.10+ (for containerized deployment)
- **tcpdump**: For external packet capture verification
- **Wireshark**: For visual PCAP inspection alongside automated analysis

---

## 🚀 Installation

### Option 1: Docker Container Setup (Recommended)

This approach provides an isolated Ubuntu 24.04 environment with all dependencies pre-configured. Ideal for Arch Linux users or those who want environment isolation.

#### Step 1: Install Docker on Host System

**For Arch Linux:**
```bash
sudo pacman -Syu docker
sudo systemctl start docker.service
sudo systemctl enable docker.service
sudo usermod -aG docker $USER
```

**Reboot** to apply group changes, then verify:
```bash
docker --version
```

#### Step 2: Create Project Directory Structure

```bash
cd ~/Development/Projects/
mkdir -p containers/ubuntuScapy
cd containers/ubuntuScapy/
```

#### Step 3: Build and Launch Ubuntu Container

The `--net=host` flag is critical for packet capture functionality:

```bash
# Initial build and launch
docker run -it --name mlpcap-analyzer --net=host ubuntu:24.04 bash

# For subsequent sessions
docker start mlpcap-analyzer
docker attach mlpcap-analyzer
```

#### Step 4: Configure Ubuntu Environment

Inside the container:

```bash
# Update package repositories
apt update

# Install core dependencies
apt install -y python3 python3-pip python3-venv nano tcpdump build-essential python3-dev

# Create project directory
mkdir -p /root/scapy
cd /root/scapy
```

#### Step 5: Install Python Dependencies

```bash
# Create requirements.txt
cat > requirements.txt << EOF
scapy>=2.6.1
numpy>=2.3.4
EOF

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install Python packages
pip install -r requirements.txt
```

#### Step 6: Deploy Analysis Scripts

Create the following files using `nano` (or copy from host):

**quickstart_mlpcapanalyzer.py** - Interactive learning module  
**mlpcapanalyzer.py** - Automated analysis engine

```bash
# Example: Create main analyzer
nano mlpcapanalyzer.py
# Paste script contents, then: Ctrl+O (save), Ctrl+X (exit)

# Make scripts executable
chmod +x *.py
```

#### Step 7: Verify Installation

```bash
# Test packet capture (generates scapy.pcap)
sudo .venv/bin/python3 -c 'from scapy.all import *; wrpcap("test.pcap", sniff(count=100))'

# Run automated analysis
.venv/bin/python3 mlpcapanalyzer.py

# Launch interactive mode
.venv/bin/python3 quickstart_mlpcapanalyzer.py
```

#### Container Management Commands

```bash
# Exit container (keeps it running in background)
Ctrl+P, Ctrl+Q

# Exit and stop container
exit

# Restart stopped container
docker start mlpcap-analyzer
docker attach mlpcap-analyzer

# View container logs
docker logs mlpcap-analyzer

# Remove container (data will be lost)
docker rm mlpcap-analyzer
```

---

### Option 2: Native Installation

For users who prefer to run directly on their host system:

```bash
# Clone repository
git clone https://github.com/yourusername/mlPcapAnalyzer.git
cd mlPcapAnalyzer

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Verify installation
python3 -c "from scapy.all import *; print('Scapy version:', scapy.__version__)"
```

---

## 💻 Usage

### Quick Start Interactive Mode

The quickstart module provides 6 hands-on learning modules for PCAP analysis fundamentals:

```bash
sudo .venv/bin/python3 quickstart_mlpcapanalyzer.py
```

**Available Modules:**

1. **Live Traffic Capture** - Capture and inspect real-time network packets
2. **Existing PCAP Analysis** - Load and analyze pre-captured traffic files
3. **Beacon Traffic Simulation** - Generate synthetic C2 beaconing patterns
4. **Protocol Deep Dive** - Layer-by-layer packet dissection and analysis
5. **DNS Analysis** - Query extraction, suspicious domain detection, DGA identification
6. **Beacon Detection** - Statistical analysis for identifying callback patterns

**Example Workflow:**

```bash
# Module 1: Capture 50 packets
[1] Enter choice: 1
[?] Packet count: 50
[+] Saved to: quick_capture.pcap

# Module 2: Analyze captured traffic
[1] Enter choice: 2
[?] Filename: quick_capture.pcap
[+] Protocol Distribution:
    TCP:        35 (70.0%)
    UDP:        12 (24.0%)
    ICMP:        3 ( 6.0%)

# Module 3: Generate test beacon
[1] Enter choice: 3
[?] Target IP: 192.168.1.100
[?] Interval: 10
[?] Beacon count: 20
[+] Saved to: simulated_beacon.pcap

# Module 6: Detect beaconing
[1] Enter choice: 6
[?] Filename: simulated_beacon.pcap
[!] DETECTED 1 POTENTIAL BEACON
    [HIGH] 192.168.1.50 → 192.168.1.100:443
           20 connections, ~10.0s interval, CoV=0.02
```

---

### Automated Analysis Mode

For production security operations and automated threat hunting:

```bash
# Analyze pre-captured PCAP
.venv/bin/python3 mlpcapanalyzer.py

# The script expects "scapy.pcap" in the current directory
# Generates: YYYY-MM-DD_HH-MM-SS_tachtech_scapy.md
```

**Configuration Options:**

Edit `mlpcapanalyzer.py` to customize detection parameters:

```python
# Line 12-20: Configure target PCAP and detection rules
PCAP_FILE = "scapy.pcap"  # Target file

UNENCRYPTED_PORTS = {
    80: "HTTP",
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    110: "POP3",
    143: "IMAP"
}
```

**Advanced Usage Examples:**

```bash
# Analyze custom PCAP file
sed -i 's/scapy.pcap/mytraffic.pcap/g' mlpcapanalyzer.py
.venv/bin/python3 mlpcapanalyzer.py

# Batch analysis of multiple PCAPs
for pcap in *.pcap; do
    sed -i "s/PCAP_FILE = .*/PCAP_FILE = \"$pcap\"/g" mlpcapanalyzer.py
    .venv/bin/python3 mlpcapanalyzer.py
done

# Integration with tcpdump for live analysis
sudo tcpdump -i eth0 -w live_capture.pcap -c 1000 &
sleep 30
sed -i 's/scapy.pcap/live_capture.pcap/g' mlpcapanalyzer.py
.venv/bin/python3 mlpcapanalyzer.py
```

---

## 📊 Analysis Modules

### Module 1: Live Traffic Capture

**Purpose**: Capture network packets directly from an interface.

**Capabilities**:
- Configurable packet count and timeout
- Real-time protocol distribution analysis
- Automatic PCAP file generation
- Summary output with packet counts

**Use Cases**:
- Network troubleshooting and diagnostics
- Baseline traffic profiling
- Real-time threat detection
- Training and demonstration environments

---

### Module 2: PCAP File Analysis

**Purpose**: Comprehensive analysis of existing packet captures.

**Output Includes**:
- Protocol distribution with percentages
- Top 5 IP conversations by packet count
- DNS query aggregation and unique domain counts
- Per-protocol statistics (TCP/UDP/ICMP)

**Ideal For**:
- Post-incident forensic investigation
- Historical traffic analysis
- Compliance auditing
- Network behavior documentation

---

### Module 3: Beacon Traffic Simulation

**Purpose**: Generate synthetic C2 beaconing patterns for detection testing.

**Parameters**:
- Target IP address
- Beacon interval (seconds)
- Total beacon count

**Generated Traffic**:
- TCP SYN packets to specified destination
- Precise timestamp spacing for regularity testing
- Saves to `simulated_beacon.pcap`

**Training Applications**:
- SOC analyst training on beacon detection
- SIEM rule development and testing
- Detection algorithm validation
- Red team exercise preparation

---

### Module 4: Protocol Analysis Demo

**Purpose**: Layer-by-layer packet dissection with detailed field inspection.

**Displays**:
- Ethernet layer: Source/Destination MAC addresses
- IP layer: Addresses, protocol number, TTL values
- TCP/UDP layer: Port numbers, flags, sequence numbers
- Application layer: Protocol-specific metadata

**Learning Outcomes**:
- Understanding OSI model layering
- Protocol header structure comprehension
- Network troubleshooting fundamentals
- Packet craft preparation

---

### Module 5: DNS Analysis

**Purpose**: Extract and analyze DNS query patterns for threat detection.

**Detection Capabilities**:
- **DGA Detection**: Flags domains > 30 characters
- **Suspicious TLDs**: Identifies high-risk extensions (.tk, .ml, .ga, .cf, .gq, .xyz, .top)
- **High Entropy**: Detects random-looking domains (entropy ratio > 0.7)

**Output Statistics**:
- Total queries vs. unique domains
- Query type distribution (A, AAAA, CNAME, MX, TXT, NS)
- Top 10 most queried domains
- Suspicious domain list with classification reasons

**Security Value**:
- Identify DNS exfiltration attempts
- Detect malware-generated domains
- Discover command-and-control infrastructure
- Investigate typosquatting campaigns

---

### Module 6: Beacon Detection

**Purpose**: Statistical analysis to identify C2 callback patterns.

**Methodology**:
- Tracks TCP SYN packets grouped by (src_ip, dst_ip, dst_port)
- Calculates inter-connection time deltas (Δt)
- Computes mean interval (μ) and standard deviation (σ)
- Derives Coefficient of Variation: **CoV = σ / μ**

**Classification Tiers**:
- **HIGH Confidence** (CoV < 0.1): Very regular intervals, strong beacon indicator
- **MEDIUM Confidence** (0.1 ≤ CoV < 0.3): Somewhat regular, possible beacon
- **LOW Confidence** (CoV ≥ 0.3): Irregular timing, likely normal traffic

**Example Output**:
```
192.168.1.50 → 8.8.8.8:443
  Connections: 25
  Mean interval: 60.02s
  Std deviation: 0.85s
  CoV: 0.014
  ⚠️ HIGH CONFIDENCE BEACON (very regular)
```

**Detection Scenarios**:
- Cobalt Strike default beacon (60s)
- Metasploit Meterpreter callbacks
- APT malware with jittered intervals
- IoT botnet check-ins

---

## 📄 Output Format

### Automated Analysis Report Structure

The `mlpcapanalyzer.py` script generates timestamped markdown reports:

**Filename Format**: `YYYY-MM-DD_HH-MM-SS_tachtech_scapy.md`

**Report Sections**:

#### Section 1: Flagged Unencrypted Packet Details

Detailed listing of every packet matching unencrypted port rules:

```
--- [ Packet #42: Flagged HTTP ] ---
  [Header] Protocol: HTTP
  [Header] Source:      192.168.1.100:54321
  [Header] Destination: 93.184.216.34:80
  [HTTP Info] Data: GET /index.html HTTP/1.1
--------------------------------------------------
```

#### Section 2: Unencrypted Traffic Summary

Aggregated statistics for flagged protocols only:

```
[ UNENCRYPTED PACKET SUMMARY ]
Total unencrypted packets flagged: 47

--- Summary by Protocol / Port ---
  HTTP (Port 80)           : 35 packets
  DNS (Port 53)            : 10 packets
  SMTP (Port 25)           : 2 packets

--- Summary by Source IP ---
  192.168.1.100           : 28 packets
  10.0.0.15               : 19 packets

--- Summary by DNS Query ---
  example.com.            : 5 queries
  google.com.             : 3 queries
```

#### Section 3: Entire PCAP File Summary

Comprehensive analysis of all traffic in the capture:

```
[ ENTIRE PCAP FILE SUMMARY ]
Total IP packets analyzed: 1,234 (out of 1,250 total packets)

--- Summary by Protocol / Port (All Packets) ---
  TCP (Port 443)          : 450 packets
  UDP (Port 53)           : 280 packets
  TCP (Port 80)           : 185 packets

--- Summary by Source IP (All Packets) ---
  192.168.1.100           : 520 packets
  10.0.0.15               : 380 packets

--- Summary by Destination IP (All Packets) ---
  8.8.8.8                 : 280 packets
  93.184.216.34           : 185 packets
```

#### Section 4: Non-IP Packet Summary

Captures non-IPv4 traffic (ARP, IPv6, etc.):

```
[ OTHER NON-IP PACKET SUMMARY ]
Found 16 packets without an IPv4 layer

--- Summary by Packet Type ---
  ARP who has 192.168.1.1                    : 8 packets
  IPv6 / UDP / DNS                            : 6 packets
  Ethernet / Padding                          : 2 packets
```

---

## 🔍 Detection Methodology

### Unencrypted Protocol Detection

**Approach**: Port-based classification with protocol verification

**Supported Protocols**:

| Protocol | Port | Detection Method | Payload Extraction |
|----------|------|------------------|-------------------|
| HTTP     | 80   | TCP dst/src      | First line of request |
| FTP      | 21   | TCP dst/src      | Control channel commands |
| Telnet   | 23   | TCP dst/src      | Terminal data |
| SMTP     | 25   | TCP dst/src      | Email envelope |
| DNS      | 53   | UDP dst/src      | Query name (qname) |
| POP3     | 110  | TCP dst/src      | Email retrieval |
| IMAP     | 143  | TCP dst/src      | Mailbox access |

**Implementation Details**:
```python
# Port matching logic
if transport_layer.sport in UNENCRYPTED_PORTS:
    protocol_name = UNENCRYPTED_PORTS[transport_layer.sport]
elif transport_layer.dport in UNENCRYPTED_PORTS:
    protocol_name = UNENCRYPTED_PORTS[transport_layer.dport]
```

**Limitations**:
- Non-standard ports are not detected (e.g., HTTP on port 8080)
- Encrypted versions (HTTPS/TLS) are correctly ignored
- Application-layer inspection not performed (protocol is assumed based on port)

**Enhancement Opportunities**:
- Add DPI (Deep Packet Inspection) for protocol verification
- Implement regular expressions for protocol signature matching
- Support custom port configurations via external config file

---

### Beaconing Detection Algorithm

**Mathematical Foundation**:

The Coefficient of Variation quantifies timing regularity:

```
Given timestamps: [t₁, t₂, t₃, ..., tₙ]
Calculate deltas: Δt = [t₂-t₁, t₃-t₂, ..., tₙ-tₙ₋₁]

μ = mean(Δt)        # Average interval
σ = std(Δt)         # Standard deviation
CoV = σ / μ         # Coefficient of Variation
```

**Classification Logic**:

| CoV Range | Confidence | Interpretation | Typical Scenarios |
|-----------|-----------|----------------|-------------------|
| < 0.1     | HIGH      | Very regular timing | Default C2 beacons, heartbeats |
| 0.1 - 0.3 | MEDIUM    | Somewhat regular | Jittered beacons, periodic tasks |
| > 0.3     | LOW       | Irregular timing | Normal user traffic, web browsing |

**Example Calculation**:

```
Timestamps: [0, 60.1, 120.2, 180.0, 240.3]
Deltas: [60.1, 60.1, 59.8, 60.3]

μ = (60.1 + 60.1 + 59.8 + 60.3) / 4 = 60.075s
σ = sqrt(((60.1-60.075)² + ... + (60.3-60.075)²) / 4) = 0.206s
CoV = 0.206 / 60.075 = 0.0034

Result: HIGH confidence beacon (CoV = 0.0034 < 0.1)
```

**Implementation**:
```python
import numpy as np

timestamps = [pkt.time for pkt in packets]
deltas = np.diff(sorted(timestamps))
cov = np.std(deltas) / np.mean(deltas)

if cov < 0.1:
    confidence = "HIGH"
elif cov < 0.3:
    confidence = "MEDIUM"
else:
    confidence = "LOW"
```

**Detection Tuning**:
- Minimum connection count: 3 (prevents false positives from single connections)
- Connection grouping: By (src_ip, dst_ip, dst_port) tuple
- Packet filtering: TCP SYN packets only (flags & 0x02 and not flags & 0x10)

**Known Evasion Techniques**:
- **Sleep jitter**: Malware adds random delays to avoid regular intervals
- **Domain rotation**: Changes destination IPs while maintaining timing
- **Multi-channel**: Uses multiple ports/protocols to fragment beacon signature

---

## 🏗 Architecture

### Project Structure

```
mlPcapAnalyzer/
├── README.md                          # This file
├── requirements.txt                   # Python dependencies
├── mlpcapanalyzer.py                 # Automated analysis engine
├── quickstart_mlpcapanalyzer.py      # Interactive learning platform
├── build_ubuntu_container.md         # Docker setup guide
└── docs/                             # Additional documentation
    ├── DETECTION_RULES.md            # Custom detection rule development
    ├── TROUBLESHOOTING.md            # Common issues and solutions
    └── EXAMPLES.md                   # Usage examples and case studies
```

### Component Overview

**mlpcapanalyzer.py** (380 lines)
- Core analysis engine
- Unencrypted protocol detection
- Report generation system
- Dual summary statistics (flagged + full PCAP)

**quickstart_mlpcapanalyzer.py** (543 lines)
- Interactive CLI menu system
- 6 modular learning exercises
- Live capture and analysis
- Beacon simulation and detection

**requirements.txt**
- Scapy ≥ 2.6.1: Packet manipulation and capture
- NumPy ≥ 2.3.4: Statistical calculations for beacon detection

### Data Flow

```
┌─────────────────┐
│  Network        │
│  Interface      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐      ┌──────────────────┐
│  Packet         │      │  Existing        │
│  Capture        │◄─────┤  PCAP File       │
│  (Scapy)        │      │  (rdpcap)        │
└────────┬────────┘      └──────────────────┘
         │
         ▼
┌─────────────────┐
│  Protocol       │
│  Classification │
│  (Port-based)   │
└────────┬────────┘
         │
         ├─────────────────────────┐
         │                         │
         ▼                         ▼
┌─────────────────┐      ┌──────────────────┐
│  Unencrypted    │      │  Statistical     │
│  Traffic        │      │  Beacon          │
│  Analysis       │      │  Detection       │
└────────┬────────┘      └─────────┬────────┘
         │                         │
         ▼                         ▼
┌─────────────────┐      ┌──────────────────┐
│  Markdown       │      │  Console         │
│  Report         │      │  Output          │
│  Generation     │      │  (Interactive)   │
└─────────────────┘      └──────────────────┘
```

---

## 🤝 Contributing

We welcome contributions from the cybersecurity community! Here's how you can help:

### Areas for Contribution

1. **Detection Rules**: Add new protocol signatures and unencrypted service identification
2. **Statistical Models**: Improve beacon detection algorithms with ML/AI approaches
3. **Report Formats**: Support JSON, CSV, or HTML output in addition to Markdown
4. **Protocol Support**: Extend coverage to additional cleartext protocols
5. **Documentation**: Improve guides, add case studies, create video tutorials

### Development Workflow

```bash
# Fork repository and clone
git clone https://github.com/TachTech-Engineering/mlpcapanalyzer.git
cd mlPcapAnalyzer

# Create feature branch
git checkout -b feature/new-detection-rule

# Make changes and test
.venv/bin/python3 mlpcapanalyzer.py
.venv/bin/python3 quickstart_mlpcapanalyzer.py

# Commit with descriptive message
git commit -am "Add LDAP cleartext detection (port 389)"

# Push and create pull request
git push origin feature/new-detection-rule
```

### Code Standards

- **PEP 8 Compliance**: Follow Python style guidelines
- **Type Hints**: Use type annotations for function signatures
- **Docstrings**: Document all functions with purpose, parameters, and return values
- **Error Handling**: Implement try/except blocks for file I/O and network operations
- **Testing**: Include test cases for new detection rules

### Reporting Issues

Use GitHub Issues with the following template:

```
**Environment**:
- OS: Ubuntu 24.04
- Python: 3.12.1
- Scapy: 2.6.1

**Description**:
Beacon detection fails when...

**Steps to Reproduce**:
1. Run quickstart module 3
2. Set interval to 5 seconds
3. Generate 10 beacons

**Expected**: HIGH confidence detection
**Actual**: No beacons detected

**PCAP Sample**: [Attach sample file]
```

---

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 TachTech

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

## 📞 Contact

**TachTech Solutions**  
Boutique Cybersecurity Engineering for Fortune 200 Enterprises

- **Email**: kthompson@tachtech.net
- **GitHub**: [github.com/tachtech](https://github.com/tachtech)
- **LinkedIn**: [TachTech Solutions](https://linkedin.com/company/tachtech)

### Technical Support

For technical questions, bug reports, or feature requests:
- Open an issue on GitHub: [Issues](https://github.com/yourusername/mlPcapAnalyzer/issues)
- Email: support@tachtech.net

### Enterprise Services

TachTech offers professional services for enterprise security operations:
- **Threat Hunting Operations**: Advanced persistent threat detection
- **SIEM Implementation**: Google SecOps, Panther, Splunk migrations
- **Detection Engineering**: Custom rule development and tuning
- **Security Tool Optimization**: Cloudflare, CrowdStrike, Okta integrations

Contact us for consulting engagements and SOW development.

---

## 🎓 Educational Use

This toolkit is designed for **authorized security testing and educational purposes only**. Users are responsible for:

- Obtaining proper authorization before capturing network traffic
- Complying with local and federal laws regarding network monitoring
- Respecting privacy and data protection regulations (GDPR, CCPA, etc.)
- Using the tool ethically in professional security operations

**Disclaimer**: TachTech is not responsible for misuse of this software. Always obtain written permission before analyzing network traffic that you do not own or have explicit authorization to inspect.

---

## 🙏 Acknowledgments

- **Scapy Development Team**: For the incredible packet manipulation framework
- **SANS Institute**: For network forensics training methodologies
- **MITRE ATT&CK**: For C2 beaconing technique taxonomy (T1071, T1573)
- **Cybersecurity Community**: For continuous feedback and improvement suggestions

---

## 📚 Additional Resources

### Learning Materials

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Network Protocol Fundamentals](https://www.ietf.org/rfc.html)
- [SANS Network Forensics](https://www.sans.org/cyber-security-courses/network-forensics/)
- [MITRE ATT&CK - Command and Control](https://attack.mitre.org/tactics/TA0011/)

### Related Projects

- [NetworkMiner](https://www.netresec.com/?page=NetworkMiner): PCAP analysis and artifact extraction
- [Zeek](https://zeek.org/): Network security monitoring framework
- [Bro IDS](https://www.bro.org/): Network intrusion detection
- [Suricata](https://suricata.io/): Network threat detection engine

### TachTech Blog Posts

- "Detecting C2 Beacons with Statistical Analysis"
- "Hunting for Cleartext Credentials in Enterprise Networks"
- "Building a Containerized Threat Hunting Lab"
- "PCAP Analysis for SOC Analysts: A Practical Guide"

---

**Version**: 1.1.0  
**Last Updated**: November 2025  
**Maintained By**: Kyle Thompson, Solutions Architect @ TachTech

---

*Happy hunting! 🎯*
