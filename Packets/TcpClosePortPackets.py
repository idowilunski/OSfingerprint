import logging
from check import Check
from scapy.layers.inet import IP, TCP


# Prepares T5-T7 packets according to the following documentation, under "TCP (T2–T7)":
# https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
class TcpPacket5(Check):
    def __init__(self, target_ip, target_port):
        super().__init__(target_ip, target_port)

    # T5 sends a TCP SYN packet without IP DF and a window field of 31337 to a closed port.
    def prepare_packet(self):
        return IP(dst=self._target_ip) / TCP(dport=self._target_port, flags="S", window=31337,
                                             options=bytes.fromhex("03030A0102040109080AFFFFFFFF000000000402"))


class TcpPacket6(Check):
    def __init__(self, target_ip, target_port):
        super().__init__(target_ip, target_port)

    # T6 sends a TCP ACK packet with IP DF and a window field of 32768 to a closed port.
    def prepare_packet(self):
        return IP(dst=self._target_ip, flags="DF") / TCP(dport=self._target_port, flags="A", window=32768,
                                                         options=bytes.fromhex(
                                                             "03030A0102040109080AFFFFFFFF000000000402"))


class TcpPacket7(Check):
    def __init__(self, target_ip, target_port):
        super().__init__(target_ip, target_port)

    # T7 sends a TCP packet with the FIN, PSH, and URG flags set and a window field of 65535 to a closed port.
    # The IP DF bit is not set.
    # The exception is that T7 uses a Window scale value of 15 rather than 10
    def prepare_packet(self):
        return IP(dst=self._target_ip) / TCP(dport=self._target_port, flags="FPU", window=65535,
                                             # Note 03030F insteaf of 03030A - changes the window scale
                                             options=bytes.fromhex("03030F0102040109080AFFFFFFFF000000000402"))
