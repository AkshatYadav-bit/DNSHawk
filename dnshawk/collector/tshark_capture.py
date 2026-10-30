import subprocess


class TSharkCapture:
    def __init__(self, interface, tshark_path="tshark"):
        self.interface = str(interface)
        self.tshark_path = tshark_path
        self.process = None

    def start(self):
        command = [
            self.tshark_path,

            # Flush stdout after every captured packet.
            "-l",

            "-i", self.interface,
            "-f", "udp port 53",

            "-T", "fields",

            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ipv6.src",
            "-e", "ip.dst",
            "-e", "ipv6.dst",
            "-e", "dns.qry.name",
            "-e", "dns.qry.type",
            "-e", "dns.flags.response",
            "-e", "dns.flags.rcode",
            "-e", "frame.len",

            "-E", "separator=|",
            "-E", "occurrence=f",
            "-E", "aggregator=,"
        ]

        self.process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        return self.process.stdout

    def stop(self):
        if self.process is not None:
            self.process.terminate()

            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()

            self.process = None