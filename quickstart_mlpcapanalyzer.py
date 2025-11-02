#!/usr/bin/env python3
#!/created by kthompson@tachtech.net
"""
Scapy Quick Start Practice Script
Run this to immediately start learning PCAP analysis!

Usage:
    sudo python3 quick_start.py
"""

from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import Ether
from collections import Counter, defaultdict
import os
import sys

def print_banner():
    print("""
╔═══════════════════════════════════════════════════════════╗
║            TachTech Scapy PCAP                            ║
║          Interactive Analysis Tool                        ║
╚═══════════════════════════════════════════════════════════╝
    """)

def menu():
    print("\n" + "="*60)
    print("LEARNING MODULES")
    print("="*60)
    print("1. Capture Live Traffic (10 packets)")
    print("2. Analyze Existing PCAP")
    print("3. Create Test Beacon Traffic")
    print("4. Protocol Analysis Demo")
    print("5. DNS Analysis Demo")
    print("6. Simple Beacon Detection")
    print("7. Exit")
    print("="*60)
    
    choice = input("\nSelect module (1-7): ").strip()
    return choice

def module1_capture():
    """Module 1: Capture live traffic"""
    print("\n[Module 1: Live Capture]")
    print("-" * 60)
    
    count = input("How many packets to capture? (default: 10): ").strip()
    count = int(count) if count else 10
    
    print(f"\n[*] Capturing {count} packets...")
    print("[*] Generating some traffic (ping, DNS) will help!\n")
    
    try:
        packets = sniff(count=count, timeout=30)
        
        if len(packets) == 0:
            print("[!] No packets captured. Try generating some traffic.")
            return
        
        filename = "quick_capture.pcap"
        wrpcap(filename, packets)
        
        print(f"\n[+] Captured {len(packets)} packets")
        print(f"[+] Saved to: {filename}")
        
        # Show summary
        print("\n[*] Packet Summary:")
        packets.summary()
        
        # Protocol breakdown
        proto_count = Counter()
        for pkt in packets:
            if IP in pkt:
                proto = pkt[IP].proto
                if proto == 6:
                    proto_count['TCP'] += 1
                elif proto == 17:
                    proto_count['UDP'] += 1
                elif proto == 1:
                    proto_count['ICMP'] += 1
        
        print("\n[*] Protocol Distribution:")
        for proto, count in proto_count.items():
            print(f"    {proto}: {count}")
        
        input("\nPress Enter to continue...")
        
    except PermissionError:
        print("[!] Error: Need root privileges to capture traffic")
        print("[!] Run with: sudo python3 quick_start.py")
        input("\nPress Enter to continue...")

def module2_analyze():
    """Module 2: Analyze existing PCAP"""
    print("\n[Module 2: Analyze PCAP]")
    print("-" * 60)
    
    filename = input("Enter PCAP filename (or press Enter for quick_capture.pcap): ").strip()
    if not filename:
        filename = "quick_capture.pcap"
    
    if not os.path.exists(filename):
        print(f"[!] Error: File '{filename}' not found")
        print("[!] Try Module 1 first to create a capture")
        input("\nPress Enter to continue...")
        return
    
    print(f"\n[*] Analyzing {filename}...")
    packets = rdpcap(filename)
    
    print(f"[+] Loaded {len(packets)} packets\n")
    
    # Basic statistics
    print("="*60)
    print("BASIC STATISTICS")
    print("="*60)
    
    # Protocol distribution
    proto_count = Counter()
    ip_count = 0
    tcp_count = 0
    udp_count = 0
    
    for pkt in packets:
        if IP in pkt:
            ip_count += 1
            if TCP in pkt:
                tcp_count += 1
            elif UDP in pkt:
                udp_count += 1
            elif ICMP in pkt:
                proto_count['ICMP'] += 1
    
    proto_count['TCP'] = tcp_count
    proto_count['UDP'] = udp_count
    
    print(f"\nIP Packets: {ip_count}")
    for proto, count in proto_count.most_common():
        pct = (count / len(packets)) * 100 if len(packets) > 0 else 0
        print(f"  {proto:10s}: {count:5d} ({pct:5.1f}%)")
    
    # IP conversations
    print("\n" + "="*60)
    print("TOP CONVERSATIONS")
    print("="*60)
    
    convs = Counter()
    for pkt in packets:
        if IP in pkt:
            conv = f"{pkt[IP].src} → {pkt[IP].dst}"
            convs[conv] += 1
    
    print("\nTop 5:")
    for conv, count in convs.most_common(5):
        print(f"  {conv:40s}: {count:3d} packets")
    
    # DNS queries
    print("\n" + "="*60)
    print("DNS QUERIES")
    print("="*60)
    
    dns_queries = []
    for pkt in packets:
        if DNS in pkt and pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
            dns_queries.append(qname)
    
    if dns_queries:
        print(f"\nTotal queries: {len(dns_queries)}")
        print(f"Unique domains: {len(set(dns_queries))}")
        
        print("\nTop 5 queried domains:")
        dns_count = Counter(dns_queries)
        for domain, count in dns_count.most_common(5):
            print(f"  {domain:50s}: {count:3d}")
    else:
        print("\nNo DNS queries found")
    
    input("\nPress Enter to continue...")

def module3_beacon():
    """Module 3: Create test beacon traffic"""
    print("\n[Module 3: Create Test Beacon]")
    print("-" * 60)
    
    print("\nThis will create simulated beacon traffic for testing.")
    print("We'll create regular connection attempts to simulate C2 beaconing.")
    
    target = input("\nTarget IP (default: 8.8.8.8): ").strip()
    if not target:
        target = "8.8.8.8"
    
    interval = input("Interval in seconds (default: 5): ").strip()
    interval = int(interval) if interval else 5
    
    count = input("Number of beacons (default: 10): ").strip()
    count = int(count) if count else 10
    
    print(f"\n[*] Creating {count} beacon packets to {target}")
    print(f"[*] Interval: {interval}s")
    print("[*] Creating packets...\n")
    
    packets = []
    import time
    
    base_time = time.time()
    for i in range(count):
        # Create SYN packet with timestamp
        pkt = Ether()/IP(dst=target)/TCP(dport=443, flags='S')
        # Set timestamp to simulate regular intervals
        pkt.time = base_time + (i * interval)
        packets.append(pkt)
        print(f"  [{i+1:2d}/{count}] Beacon packet created (t={i*interval}s)")
    
    filename = "simulated_beacon.pcap"
    wrpcap(filename, packets)
    
    print(f"\n[+] Saved to: {filename}")
    print("\n[*] Now you can run Module 6 to detect this beacon!")
    
    input("\nPress Enter to continue...")

def module4_protocol_demo():
    """Module 4: Protocol analysis demo"""
    print("\n[Module 4: Protocol Analysis]")
    print("-" * 60)
    
    filename = input("Enter PCAP filename (or press Enter for quick_capture.pcap): ").strip()
    if not filename:
        filename = "quick_capture.pcap"
    
    if not os.path.exists(filename):
        print(f"[!] Error: File '{filename}' not found")
        input("\nPress Enter to continue...")
        return
    
    packets = rdpcap(filename)
    
    print("\n" + "="*60)
    print("DETAILED PROTOCOL ANALYSIS")
    print("="*60)
    
    # Layer analysis
    layer_count = Counter()
    port_count = Counter()
    
    for pkt in packets:
        # Count layers
        if Ether in pkt:
            layer_count['Ethernet'] += 1
        if IP in pkt:
            layer_count['IP'] += 1
        if TCP in pkt:
            layer_count['TCP'] += 1
            port_count[f"TCP:{pkt[TCP].dport}"] += 1
        if UDP in pkt:
            layer_count['UDP'] += 1
            port_count[f"UDP:{pkt[UDP].dport}"] += 1
        if ICMP in pkt:
            layer_count['ICMP'] += 1
        if DNS in pkt:
            layer_count['DNS'] += 1
    
    print("\nLayer Distribution:")
    for layer, count in layer_count.most_common():
        pct = (count / len(packets)) * 100
        print(f"  {layer:15s}: {count:5d} ({pct:5.1f}%)")
    
    print("\nTop Destination Ports:")
    for port, count in port_count.most_common(10):
        print(f"  {port:15s}: {count:5d}")
    
    # Show example packet details
    print("\n" + "="*60)
    print("EXAMPLE PACKET BREAKDOWN")
    print("="*60)
    
    if len(packets) > 0:
        print("\nFirst packet details:")
        pkt = packets[0]
        
        if Ether in pkt:
            print(f"\n  Ethernet Layer:")
            print(f"    Source MAC: {pkt[Ether].src}")
            print(f"    Dest MAC:   {pkt[Ether].dst}")
        
        if IP in pkt:
            print(f"\n  IP Layer:")
            print(f"    Source IP:  {pkt[IP].src}")
            print(f"    Dest IP:    {pkt[IP].dst}")
            print(f"    Protocol:   {pkt[IP].proto}")
            print(f"    TTL:        {pkt[IP].ttl}")
        
        if TCP in pkt:
            print(f"\n  TCP Layer:")
            print(f"    Source Port:  {pkt[TCP].sport}")
            print(f"    Dest Port:    {pkt[TCP].dport}")
            print(f"    Flags:        {pkt[TCP].flags}")
            print(f"    Seq:          {pkt[TCP].seq}")
        
        if UDP in pkt:
            print(f"\n  UDP Layer:")
            print(f"    Source Port:  {pkt[UDP].sport}")
            print(f"    Dest Port:    {pkt[UDP].dport}")
    
    input("\nPress Enter to continue...")

def module5_dns_demo():
    """Module 5: DNS analysis demo"""
    print("\n[Module 5: DNS Analysis]")
    print("-" * 60)
    
    filename = input("Enter PCAP filename (or press Enter for quick_capture.pcap): ").strip()
    if not filename:
        filename = "quick_capture.pcap"
    
    if not os.path.exists(filename):
        print(f"[!] Error: File '{filename}' not found")
        input("\nPress Enter to continue...")
        return
    
    packets = rdpcap(filename)
    
    print("\n" + "="*60)
    print("DNS ANALYSIS")
    print("="*60)
    
    queries = []
    query_types = Counter()
    
    for pkt in packets:
        if DNS in pkt and pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
            qtype = pkt[DNSQR].qtype
            
            queries.append(qname)
            
            # Map query type
            qtype_name = {1: 'A', 28: 'AAAA', 5: 'CNAME', 15: 'MX', 
                         16: 'TXT', 2: 'NS'}.get(qtype, f'Type-{qtype}')
            query_types[qtype_name] += 1
    
    print(f"\nTotal DNS Queries: {len(queries)}")
    print(f"Unique Domains: {len(set(queries))}")
    
    if queries:
        print("\nQuery Type Distribution:")
        for qtype, count in query_types.most_common():
            print(f"  {qtype:10s}: {count:5d}")
        
        print("\nTop 10 Queried Domains:")
        dns_count = Counter(queries)
        for domain, count in dns_count.most_common(10):
            print(f"  {domain:50s}: {count:3d}")
        
        # Look for suspicious patterns
        print("\n" + "="*60)
        print("SUSPICIOUS PATTERN DETECTION")
        print("="*60)
        
        suspicious = []
        
        for domain in set(queries):
            # Long domains (potential DGA)
            if len(domain) > 30:
                suspicious.append(('Long domain (DGA?)', domain))
            
            # Unusual TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                suspicious.append(('Suspicious TLD', domain))
            
            # High entropy (random-looking)
            if len(domain) > 15:
                # Simple entropy check: count unique chars
                unique_chars = len(set(domain.replace('.', '')))
                total_chars = len(domain.replace('.', ''))
                if total_chars > 0:
                    entropy_ratio = unique_chars / total_chars
                    if entropy_ratio > 0.7:  # High variety of characters
                        suspicious.append(('High entropy', domain))
        
        if suspicious:
            print("\nPotential Suspicious Domains:")
            for reason, domain in suspicious[:10]:
                print(f"  [{reason:20s}] {domain}")
        else:
            print("\nNo suspicious domains detected")
    else:
        print("\nNo DNS queries found in this capture")
    
    input("\nPress Enter to continue...")

def module6_beacon_detection():
    """Module 6: Simple beacon detection"""
    print("\n[Module 6: Beacon Detection]")
    print("-" * 60)
    
    filename = input("Enter PCAP filename (or 'simulated_beacon.pcap' for test): ").strip()
    if not filename:
        filename = "simulated_beacon.pcap"
    
    if not os.path.exists(filename):
        print(f"[!] Error: File '{filename}' not found")
        print("[!] Try Module 3 to create test beacon traffic first")
        input("\nPress Enter to continue...")
        return
    
    print(f"\n[*] Analyzing {filename} for beacons...")
    packets = rdpcap(filename)
    
    # Track connections by (src, dst, dport)
    connections = defaultdict(list)
    
    for pkt in packets:
        if TCP in pkt and IP in pkt:
            # Look for SYN packets
            if pkt[TCP].flags & 0x02 and not pkt[TCP].flags & 0x10:
                key = (pkt[IP].src, pkt[IP].dst, pkt[TCP].dport)
                timestamp = float(pkt.time)
                connections[key].append(timestamp)
    
    print(f"[+] Found {len(connections)} unique connection patterns\n")
    
    # Analyze each pattern
    print("="*60)
    print("BEACON ANALYSIS RESULTS")
    print("="*60)
    
    import numpy as np
    
    beacons = []
    
    for key, timestamps in connections.items():
        if len(timestamps) < 3:
            continue
        
        timestamps.sort()
        deltas = np.diff(timestamps)
        
        if len(deltas) == 0:
            continue
        
        mean_delta = np.mean(deltas)
        std_delta = np.std(deltas)
        
        if mean_delta == 0:
            continue
        
        # Coefficient of Variation
        cov = std_delta / mean_delta
        
        src, dst, port = key
        
        print(f"\n{src} → {dst}:{port}")
        print(f"  Connections: {len(timestamps)}")
        print(f"  Mean interval: {mean_delta:.2f}s")
        print(f"  Std deviation: {std_delta:.2f}s")
        print(f"  CoV: {cov:.3f}")
        
        # Classify beacon
        if cov < 0.1:
            print(f"  ⚠️  HIGH CONFIDENCE BEACON (very regular)")
            confidence = "HIGH"
        elif cov < 0.3:
            print(f"  ⚠️  MEDIUM CONFIDENCE BEACON (regular)")
            confidence = "MEDIUM"
        else:
            print(f"  ✓  Low confidence (irregular)")
            confidence = "LOW"
        
        if cov < 0.3:
            beacons.append({
                'src': src,
                'dst': dst,
                'port': port,
                'count': len(timestamps),
                'interval': mean_delta,
                'cov': cov,
                'confidence': confidence
            })
    
    # Summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    
    if beacons:
        print(f"\n⚠️  DETECTED {len(beacons)} POTENTIAL BEACON(S)\n")
        
        for beacon in sorted(beacons, key=lambda x: x['cov']):
            print(f"[{beacon['confidence']:6s}] {beacon['src']} → {beacon['dst']}:{beacon['port']}")
            print(f"          {beacon['count']} connections, ~{beacon['interval']:.1f}s interval")
    else:
        print("\n✓ No beaconing patterns detected")
    
    print("\n" + "="*60)
    print("\n💡 Understanding Results:")
    print("  - CoV < 0.1:  Very regular (HIGH confidence beacon)")
    print("  - CoV 0.1-0.3: Somewhat regular (MEDIUM confidence)")
    print("  - CoV > 0.3:  Irregular (LOW confidence / normal traffic)")
    
    input("\nPress Enter to continue...")

def main():
    print_banner()
    
    # Check if running with appropriate privileges
    if os.geteuid() != 0 and sys.platform != 'win32':
        print("⚠️  WARNING: Not running as root")
        print("   Live capture (Module 1) will require sudo\n")
    
    while True:
        choice = menu()
        
        if choice == '1':
            module1_capture()
        elif choice == '2':
            module2_analyze()
        elif choice == '3':
            module3_beacon()
        elif choice == '4':
            module4_protocol_demo()
        elif choice == '5':
            module5_dns_demo()
        elif choice == '6':
            module6_beacon_detection()
        elif choice == '7':
            print("\n👋 TachTech wishes you happy hunting! Contact us for new hunting techniques.")
            break
        else:
            print("\n[!] Invalid choice. Please select 1-7.")
            input("\nPress Enter to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[*] Interrupted by user")
        print("👋 Happy hunting from TachTech!")
        sys.exit(0)
