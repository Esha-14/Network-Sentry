import csv
from datetime import datetime
from scapy.all import wrpcap


def generate_filename(prefix, extension):

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    return f"{prefix}_{timestamp}.{extension}"


def save_pcap(packets, output_path):

    wrpcap(str(output_path), packets)


def save_csv(records, output_path):

    if not records:
        return

    fields = [
        "id",
        "timestamp",
        "source_ip",
        "destination_ip",
        "protocol",
        "source_port",
        "destination_port",
        "length"
    ]

    with open(
        output_path,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fields
        )

        writer.writeheader()
        writer.writerows(records)