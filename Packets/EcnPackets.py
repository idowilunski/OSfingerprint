from scapy.all import *
from check import Check
from scapy.layers.inet import IP, TCP


# Sends an ECN packet according to the following documentation:
# https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
# Under : "TCP explicit congestion notification (ECN)"
class EcnPacket(Check):
    def __init__(self, target_ip, target_open_port):
        super().__init__(target_ip, target_open_port)

    def prepare_packet(self):
        # TCP options are WScale (10), NOP, MSS (1460), SACK permitted, NOP, NOP. The probe is sent to an open port.
        options = [
            (254, b'\x01\x01'),  # ECN CWR and ECE flags
            (3, b'\x03\x03\x0a'),  # WScale (10)
            (1, b'\x01'),  # NOP
            (2, b'\x04\x5b4'),  # MSS (1460)
            (4, b'\x00'),  # SACK permitted
            (1, b'\x01'),  # NOP
            (1, b'\x01')  # NOP
        ]

        # sequence number is random, window size field is three
        window_size = 3

        self._packet = IP(dst=self._target_ip) / TCP(dport=self._target_port, flags="S",
                                                     options=options,
                                                     window=window_size,
                                                     ack=0,
                                                     reserved=1,
                                                     urgptr=0xF7F5  # Urgent Pointer
                                                     )