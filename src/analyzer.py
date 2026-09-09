from scapy.all import IP, TCP, UDP, ICMP


def get_protocol(packet):

    if TCP in packet:
        return "TCP"

    elif UDP in packet:
        return "UDP"

    elif ICMP in packet:
        return "ICMP"

    elif IP in packet:
        return "IP"

    return "OTHER"


def analyze_packet(packet, packet_id):

    if IP not in packet:
        return None

    source_port = "-"
    destination_port = "-"

    if TCP in packet:
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    return {
        "id": packet_id,
        "timestamp": float(packet.time),
        "source_ip": packet[IP].src,
        "destination_ip": packet[IP].dst,
        "protocol": get_protocol(packet),
        "source_port": source_port,
        "destination_port": destination_port,
        "length": len(packet)
    }
