from scapy.all import PcapReader


class CaptureReader:
    """
    Reads packets from Wireshark PCAP/PCAPNG files.

    This class is responsible only for reading packets.
    DNS parsing is handled separately.
    """

    def __init__(self, capture_file):
        self.capture_file = capture_file

    def read_packets(self):
        """
        Yield packets one at a time.
        """

        try:
            with PcapReader(self.capture_file) as reader:
                for packet in reader:
                    yield packet

        except FileNotFoundError:
            raise FileNotFoundError(
                f"Capture file not found: {self.capture_file}"
            )

    def __iter__(self):
        return self.read_packets()