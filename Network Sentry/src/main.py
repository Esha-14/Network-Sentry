from collections import Counter
from datetime import datetime

from config import (
    PACKET_COUNT,
    CAPTURE_DIR,
    REPORT_DIR
)

from capture import PacketCapture
from analyzer import analyze_packet

from reporter import (
    generate_filename,
    save_pcap,
    save_csv
)


def print_banner():

    print("=" * 80)
    print("                    NETWORKSENTRY v1.0")
    print("              Network Sniffer & Packet Analyzer")
    print("=" * 80)


def print_packet_header():

    print()
    print(
        f"{'ID':<5}"
        f"{'TIME':<10}"
        f"{'SOURCE':<18}"
        f"{'DESTINATION':<18}"
        f"{'PROTO':<8}"
        f"{'PORTS':<16}"
        f"{'SIZE':<8}"
    )

    print("-" * 83)


def main():

    print_banner()

    print()
    print("[*] Configuration")
    print(f"    Packet Count : {PACKET_COUNT}")
    print(f"    PCAP Folder  : {CAPTURE_DIR}")
    print(f"    Report Folder: {REPORT_DIR}")

    capture = PacketCapture(PACKET_COUNT)

    try:

        packets = capture.start()

    except PermissionError:

        print("[!] Permission denied.")
        print("[!] Run Terminal or VS Code as Administrator.")
        return

    except KeyboardInterrupt:

        print()
        print("[!] Capture stopped by user.")
        return

    except Exception as error:

        print(f"[!] Capture error: {error}")
        return

    print()
    print(f"[+] Capture completed. Packets captured: {len(packets)}")

    records = []
    protocol_counter = Counter()

    print_packet_header()

    packet_id = 1

    for packet in packets:

        result = analyze_packet(
            packet,
            packet_id
        )

        if result is None:
            continue

        records.append(result)

        protocol_counter[result["protocol"]] += 1

        time_value = datetime.fromtimestamp(
            result["timestamp"]
        ).strftime("%H:%M:%S")

        ports = (
            f"{result['source_port']}"
            f" -> "
            f"{result['destination_port']}"
        )

        print(
            f"{result['id']:<5}"
            f"{time_value:<10}"
            f"{result['source_ip']:<18}"
            f"{result['destination_ip']:<18}"
            f"{result['protocol']:<8}"
            f"{ports:<16}"
            f"{result['length']:<8}"
        )

        packet_id += 1

    pcap_name = generate_filename(
        "capture",
        "pcap"
    )

    csv_name = generate_filename(
        "packet_report",
        "csv"
    )

    pcap_path = CAPTURE_DIR / pcap_name
    csv_path = REPORT_DIR / csv_name

    save_pcap(
        packets,
        pcap_path
    )

    save_csv(
        records,
        csv_path
    )

    print()
    print("=" * 80)
    print("                              SUMMARY")
    print("=" * 80)

    print(f"Total Packets Captured : {len(packets)}")
    print(f"IPv4 Packets Analyzed  : {len(records)}")

    print()
    print("Protocol Statistics:")

    for protocol, count in protocol_counter.items():

        print(f"    {protocol:<10}: {count}")

    print()
    print("[+] PCAP saved:")
    print(f"    {pcap_path}")

    print()
    print("[+] CSV report saved:")
    print(f"    {csv_path}")

    print()
    print("=" * 80)


if __name__ == "__main__":
    main()