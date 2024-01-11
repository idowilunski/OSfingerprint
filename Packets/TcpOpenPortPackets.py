from check import Check
from scapy.layers.inet import IP, TCP


# Prepares T2-T4 packets according to the following documentation, under "TCP (T2–T7)":
# https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
class TcpPacket2(Check):
    def __init__(self, target_ip, target_port):
        super().__init__(target_ip, target_port)

    # T2 sends a TCP null (no flags set) packet with the IP DF bit set and a window field of 128 to an open port.
    # Those 20 bytes correspond to window scale (10), NOP, MSS (265), Timestamp
    # (TSval: 0xFFFFFFFF; TSecr: 0), then SACK permitted.
    def prepare_packet(self):
        self._packet = IP(dst=self._target_ip, flags="DF") / TCP(dport=self._target_port, window=128,
                                                                 options=[
                                                                     ("WScale", 10),
                                                                     ("NOP", ''),
                                                                     ("MSS", 265),
                                                                     ("Timestamp", (0xFFFFFFFF, 0)),
                                                                     ("SAck", '')
                                                                 ])


class TcpPacket3(Check):
    def __init__(self, target_ip, target_port):
        super().__init__(target_ip, target_port)

    # T3 sends a TCP packet with the SYN, FIN, URG,
    # and PSH flags set and a window field of 256 to an open port. The IP DF bit is not set.
    def prepare_packet(self):
        self._packet = IP(dst=self._target_ip) / TCP(dport=self._target_port, flags="SFUP", window=256,
                                                     options=[
                                                         ("WScale", 10),
                                                         ("NOP", ''),
                                                         ("MSS", 265),
                                                         ("Timestamp", (0xFFFFFFFF, 0)),
                                                         ("SAck", '')
                                                     ])


class TcpPacket4(Check):
    def __init__(self, target_ip, target_port):
        super().__init__(target_ip, target_port)

    # T4 sends a TCP ACK packet with IP DF and a window field of 1024 to an open port.
    def prepare_packet(self):
        self._packet = IP(dst=self._target_ip, flags="DF") / TCP(dport=self._target_port, flags="A", window=1024,
                                                                 options=[
                                                                     ("WScale", 10),
                                                                     ("NOP", ''),
                                                                     ("MSS", 265),
                                                                     ("Timestamp", (0xFFFFFFFF, 0)),
                                                                     ("SAck", '')
                                                                 ])
