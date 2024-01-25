from scapy.all import *
from check import Check
from scapy.layers.inet import IP, TCP


class ProbePacket6(Check):
    def __init__(self, target_ip, target_port):
        super().__init__(target_ip, target_port)

        # Construct a SYN packet for target IP and port according to the following NMAP documentation:
        # https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
        # Reference: Packet 6: MSS (265), SACK permitted, Timestamp (TSval: 0xFFFFFFFF; TSecr: 0). The window field
        # is 512.
        options = [
            ('MSS', 265),
            ('SAckOK', ''),  # SACK permitted
            ('Timestamp', (0xFFFFFFFF, 0)),  # TSVal- 0xFFFFFFFF, TSecr- 0
        ]
        window_size = 512

        self._packet = IP(dst=self._target_ip) / TCP(window=window_size, dport=self._target_port, flags="S",
                                                     seq=self._packet_seq_number, ack=self._packet_ack_number,
                                                     options=options)


class ProbePacket5(Check):
    def __init__(self, target_ip, target_port):
        super().__init__(target_ip, target_port)

        # Construct a SYN packet for target IP and port according to the following NMAP documentation:
        # https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
        # Reference: Packet 5: MSS (536), SACK permitted, Timestamp (TSval: 0xFFFFFFFF; TSecr: 0),
        # window scale (10), EOL. The window field is 16.
        options = [
            ('MSS', 536),
            ('SAckOK', ''),  # SACK permitted
            ('Timestamp', (0xFFFFFFFF, 0)),  # TSVal- 0xFFFFFFFF, TSecr- 0
            ('WScale', 10),  # Window scale
            ('EOL', '')
        ]
        window_size = 16

        self._packet = IP(dst=self._target_ip) / TCP(window=window_size, dport=self._target_port, flags="S",
                                                     seq=self._packet_seq_number, ack=self._packet_ack_number,
                                                     options=options)


class ProbePacket4(Check):
    def __init__(self, target_ip, target_port):
        super().__init__(target_ip, target_port)

        # Construct a SYN packet for target IP and port according to the following NMAP documentation:
        # https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
        # Reference: Packet 4:  SACK permitted, Timestamp (TSval: 0xFFFFFFFF; TSecr: 0),
        # window scale (10), EOL. The window field is 4.
        options = [
            ('SAckOK', ''),  # SACK permitted
            ('Timestamp', (0xFFFFFFFF, 0)),  # TSVal- 0xFFFFFFFF, TSecr- 0
            ('WScale', 10),  # Window scale
            ('EOL', '')
        ]
        window_size = 4

        self._packet = IP(dst=self._target_ip) / TCP(window=window_size, dport=self._target_port, flags="S",
                                                     seq=self._packet_seq_number, ack=self._packet_ack_number,
                                                     options=options)


class ProbePacket3(Check):
    def __init__(self, target_ip, target_port):
        super().__init__(target_ip, target_port)

        # Construct a SYN packet for target IP and port according to the following NMAP documentation:
        # https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
        # Reference: Packet 3:   Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), NOP,
        # NOP, window scale (5), NOP, MSS (640). The window field is 4.
        options = [
            ('Timestamp', (0xFFFFFFFF, 0)),  # TSVal- 0xFFFFFFFF, TSecr- 0
            ('NOP', None),
            ('NOP', None),
            ('WScale', 5),  # Window scale
            ('NOP', None),
            ('MSS', 640)
        ]
        window_size = 4

        self._packet = IP(dst=self._target_ip) / TCP(window=window_size, dport=self._target_port, flags="S",
                                                     seq=self._packet_seq_number, ack=self._packet_ack_number,
                                                     options=options)


class ProbePacket2(Check):
    def __init__(self, target_ip, target_port):
        super().__init__(target_ip, target_port)

        # Construct a SYN packet for target IP and port according to the following NMAP documentation:
        # https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
        # Reference: Packet 2:  MSS (1400), window scale (0), SACK permitted,
        # timestamp (TSval: 0xFFFFFFFF; TSecr: 0), EOL. The window field is 63.
        options = [
            ('MSS', 1400),
            ('WScale', 0),  # Window scale
            ('SAckOK', ''),  # SACK permitted
            ('Timestamp', (0xFFFFFFFF, 0)),  # TSVal- 0xFFFFFFFF, TSecr- 0
            ('EOL', '')  # End of options list
        ]
        window_size = 63

        self._packet = IP(dst=self._target_ip) / TCP(window=window_size, dport=self._target_port, flags="S",
                                                     seq=self._packet_seq_number, ack=self._packet_ack_number,
                                                     options=options)


class ProbePacket1(Check):
    def __init__(self, target_ip, target_port):
        super().__init__(target_ip, target_port)

        # Construct a SYN packet for target IP and port according to the following NMAP documentation:
        # https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
        # Reference: Packet 1: window scale (10), NOP, MSS (1460), timestamp (TSval: 0xFFFFFFFF; TSecr: 0),
        # SACK permitted. The window field is 1.
        options = [
            ('WScale', 10),  # Window scale
            ('NOP', None),
            ('MSS', 1460),
            ('Timestamp', (0xFFFFFFFF, 0)),  # TSVal- 0xFFFFFFFF, TSecr- 0
            ('SAckOK', '')  # SACK permitted
        ]
        window_size = 1

        self._packet = IP(dst=self._target_ip) / TCP(window=window_size, dport=self._target_port, flags="S",
                                                     seq=self._packet_seq_number, ack=self._packet_ack_number,
                                                     options=options)
