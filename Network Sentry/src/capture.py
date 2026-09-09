from scapy.all import sniff

class PacketCapture:

    def __init__(self, packet_count):
        self.packet_count = packet_count

    def start(self):

        print()
        print("[+] Starting packet capture...")
        print(f"[+] Capturing {self.packet_count} packets...")
        print("[+] Press Ctrl+C to stop early.")
        print()

        packets = sniff(
            count=self.packet_count,
            store=True
        )

        return packets