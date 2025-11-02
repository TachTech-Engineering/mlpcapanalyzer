#!/usr/bin/env python3
#kthompson@tachtech.net

import os
import sys
from datetime import datetime
from scapy.all import rdpcap, TCP, UDP, IP, DNS, Raw
from collections import defaultdict

# --- Configuration ---
PCAP_FILE = "scapy.pcap"

# Dictionary of common unencrypted protocols and their default ports
UNENCRYPTED_PORTS = {
    80: "HTTP",
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    110: "POP3",
    143: "IMAP"
}
# ---------------------

def analyze_and_save():
    # --- Setup Output File ---
    try:
        # Get the directory where the script is located
        script_dir = os.path.dirname(os.path.abspath(__file__))
    except NameError:
        # Fallback if __file__ is not defined (e.g., in an interactive shell)
        script_dir = os.getcwd()

    # Generate timestamp for filename
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{timestamp}_tachtech_scapy.md"
    filepath = os.path.join(script_dir, filename)

    # --- Counters ---
    flagged_count = 0
    protocol_port_counts = defaultdict(int)
    src_ip_counts = defaultdict(int)
    dst_ip_counts = defaultdict(int)
    dns_query_counts = defaultdict(int)

    total_protocol_port_counts = defaultdict(int)
    total_src_ip_counts = defaultdict(int)
    total_dst_ip_counts = defaultdict(int)
    total_dns_query_counts = defaultdict(int)

    other_packet_summaries = []

    try:
        # Open the file for writing.
        with open(filepath, 'w') as f:

            # --- NEW HELPER FUNCTION ---
            # This function will print to console AND write to the file
            def log(message=""):
                """Prints a message to the console and writes it to the file."""
                print(message)
                f.write(message + "\n")
            # ---------------------------

            try:
                packets = rdpcap(PCAP_FILE)

                log(f"# Analysis Report for `{PCAP_FILE}`")
                log(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                log("## Flagged Unencrypted Packet Details")
                log("\n```") # Start a code block

                # Loop through each packet
                for i, pkt in enumerate(packets):

                    if not pkt.haslayer(IP):
                        other_packet_summaries.append(pkt.summary())
                        continue

                    ip_layer = pkt[IP]

                    # --- TOTAL PCAP COUNTERS ---
                    total_src_ip_counts[ip_layer.src] += 1
                    total_dst_ip_counts[ip_layer.dst] += 1

                    total_proto_name = None
                    total_transport_layer = None
                    total_query_name = ""

                    if pkt.haslayer(TCP):
                        total_transport_layer = pkt[TCP]
                        total_proto_name = "TCP"
                    elif pkt.haslayer(UDP):
                        total_transport_layer = pkt[UDP]
                        total_proto_name = "UDP"
                    else:
                        try:
                            total_proto_name = ip_layer.summary().split()[4]
                        except:
                            total_proto_name = f"IP_Proto_{ip_layer.proto}"
                        # *** THIS IS THE CORRECTED LINE AREA ***
                        total_protocol_port_counts[total_proto_name] += 1
                        continue

                    total_proto_port_key = f"{total_proto_name} (Port {total_transport_layer.dport})"
                    total_protocol_port_counts[total_proto_port_key] += 1

                    if total_proto_name == "UDP" and (total_transport_layer.dport == 53 or total_transport_layer.sport == 53) and pkt.haslayer(DNS) and pkt[DNS].qd:
                        try:
                            total_query_name = pkt[DNS].qd.qname.decode('utf-8')
                            if total_query_name:
                                total_dns_query_counts[total_query_name] += 1
                        except Exception:
                            pass

                    # --- UNENCRYPTED PORT FILTER ---
                    protocol_name = None
                    target_port = 0

                    if total_transport_layer.sport in UNENCRYPTED_PORTS:
                        protocol_name = UNENCRYPTED_PORTS[total_transport_layer.sport]
                        target_port = total_transport_layer.sport
                    elif total_transport_layer.dport in UNENCRYPTED_PORTS:
                        protocol_name = UNENCRYPTED_PORTS[total_transport_layer.dport]
                        target_port = total_transport_layer.dport

                    # --- ANALYSIS & PRINTING (Only if unencrypted) ---
                    if protocol_name:
                        flagged_count += 1
                        log(f"--- [ Packet #{i+1}: Flagged {protocol_name} ] ---")
                        log(f"  [Header] Protocol: {protocol_name}")
                        log(f"  [Header] Source:      {ip_layer.src}:{total_transport_layer.sport}")
                        log(f"  [Header] Destination: {ip_layer.dst}:{total_transport_layer.dport}")

                        if protocol_name == "DNS" and total_query_name:
                            log(f"  [DNS Info] Query: {total_query_name}")

                        if protocol_name == "HTTP" and pkt.haslayer(Raw):
                            try:
                                payload = pkt[Raw].load.decode('utf-8').split('\n')[0]
                                log(f"  [HTTP Info] Data: {payload.strip()}")
                            except Exception as e:
                                log(f"  [HTTP Info] Could not decode HTTP payload.")

                        log("-" * (50 + len(protocol_name)))

                        # --- Update UNENCRYPTED Summary Counters ---
                        proto_port_key = f"{protocol_name} (Port {target_port})"
                        protocol_port_counts[proto_port_key] += 1
                        src_ip_counts[ip_layer.src] += 1
                        dst_ip_counts[ip_layer.dst] += 1
                        if protocol_name == "DNS" and total_query_name:
                            dns_query_counts[total_query_name] += 1

                log("```\n") # End the code block

                # ==========================================================
                # ---           PRINT FINAL SUMMARY TABLES               ---
                # ==========================================================

                # --- Section 1: UNENCRYPTED Summary ---
                log("\n\n" + "="*60)
                log("## [ UNENCRYPTED PACKET SUMMARY ]")
                log(f"**Total unencrypted packets flagged: {flagged_count}**")
                log("="*60)
                log("\n```") # Start code block

                if protocol_port_counts:
                    log("--- Summary by Protocol / Port ---")
                    sorted_protocols = sorted(protocol_port_counts.items(), key=lambda item: item[1], reverse=True)
                    for (proto_port, count) in sorted_protocols:
                        log(f"  {proto_port:<25} : {count} packets")

                if src_ip_counts:
                    log("\n--- Summary by Source IP ---")
                    sorted_src_ips = sorted(src_ip_counts.items(), key=lambda item: item[1], reverse=True)
                    for (ip, count) in sorted_src_ips:
                        log(f"  {ip:<25} : {count} packets")

                if dst_ip_counts:
                    log("\n--- Summary by Destination IP ---")
                    sorted_dst_ips = sorted(dst_ip_counts.items(), key=lambda item: item[1], reverse=True)
                    for (ip, count) in sorted_dst_ips:
                        log(f"  {ip:<25} : {count} packets")

                if dns_query_counts:
                    log("\n--- Summary by DNS Query ---")
                    sorted_dns = sorted(dns_query_counts.items(), key=lambda item: item[1], reverse=True)
                    for (query, count) in sorted_dns:
                        log(f"  {query:<40} : {count} queries")
                log("```") # End code block


                # --- Section 2: TOTAL PCAP Summary ---
                total_ip_packet_count = sum(total_src_ip_counts.values())

                log("\n\n" + "="*60)
                log("## [ ENTIRE PCAP FILE SUMMARY ]")
                log(f"**Total IP packets analyzed: {total_ip_packet_count} (out of {len(packets)} total packets)**")
                log("="*60)
                log("\n```") # Start code block

                if total_protocol_port_counts:
                    log("--- Summary by Protocol / Port (All Packets) ---")
                    sorted_protocols = sorted(total_protocol_port_counts.items(), key=lambda item: item[1], reverse=True)
                    for (proto_port, count) in sorted_protocols:
                        log(f"  {proto_port:<25} : {count} packets")

                if total_src_ip_counts:
                    log("\n--- Summary by Source IP (All Packets) ---")
                    sorted_src_ips = sorted(total_src_ip_counts.items(), key=lambda item: item[1], reverse=True)
                    for (ip, count) in sorted_src_ips:
                        log(f"  {ip:<25} : {count} packets")

                if total_dst_ip_counts:
                    log("\n--- Summary by Destination IP (All Packets) ---")
                    sorted_dst_ips = sorted(dst_ip_counts.items(), key=lambda item: item[1], reverse=True)
                    for (ip, count) in sorted_dst_ips:
                        log(f"  {ip:<25} : {count} packets")

                if total_dns_query_counts:
                    log("\n--- Summary by DNS Query (All Queries) ---")
                    sorted_dns = sorted(dns_query_counts.items(), key=lambda item: item[1], reverse=True)
                    for (query, count) in sorted_dns:
                        log(f"  {query:<40} : {count} queries")
                log("```") # End code block

                # --- Section 3: OTHER Non-IP Packet Summary ---
                if other_packet_summaries:
                    log("\n\n" + "="*60)
                    log("## [ OTHER NON-IP PACKET SUMMARY ]")
                    log(f"**Found {len(other_packet_summaries)} packets without an IPv4 layer (e.g., ARP, IPv6)**")
                    log("="*60)
                    log("\n```") # Start code block

                    log("--- Summary by Packet Type ---")
                    other_packet_counts = defaultdict(int)
                    for summary in other_packet_summaries:
                        other_packet_counts[summary] += 1

                    sorted_other = sorted(other_packet_counts.items(), key=lambda item: item[1], reverse=True)
                    for (summary, count) in sorted_other:
                        log(f"  {summary:<50} : {count} packets")
                    log("```") # End code block


            except FileNotFoundError:
                log(f"[!] Error: The file '{PCAP_FILE}' was not found.")
            except Exception as e:
                log(f"[!] An error occurred: {e}")

        # This print statement goes ONLY to the console, *not* the file
        print(f"\n[+] Analysis complete. Results saved to: {filepath}")

    except Exception as e:
        # This will catch errors in file creation and print to console
        print(f"[!] A critical error occurred while trying to create the report file: {e}", file=sys.stderr)
        sys.exit(1)

# --- Run the main function ---
if __name__ == "__main__":
    analyze_and_save()
