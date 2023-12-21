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
        #options = [
        #    ('WScale', 10),
        #    ('NOP', None),
        #    ('MSS', 1460),
        #    ('SAckOK', ''),  # SACK permitted
        #    ('NOP', None),
        #    ('NOP', None)
        #]

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
        #self._packet = IP(dst=self._target_ip) / TCP(dport=self._target_port, flags="S",
        #                                             options=options,
        #                                             window=window_size,
        #                                             #  ACK number is zero
        #                                             ack=0,
        #                                             # reserved bit which immediately precedes the CWR bit is set.
        #                                             reserved=1,
        #                                             # ECN CWR and ECE congestion control flags set.
        #                                             tcpflags="CE",
        #                                             # For an unrelated (to ECN) test, the urgent field value of 0xF7F5
        #                                             # is used even though the urgent flag is not set.
        #                                             urgptr=0xF7F5  # Urgent field value
        #                                             )

        #self._packet = IP(dst=self._target_ip) / TCP(dport=self._target_port, flags="S",
        #                                             options=options,
        #                                             window=window_size,
        #                                             ack=0,
        #                                             reserved=1,
        #                                             urgptr=0xF7F5  # Urgent Pointer
        #                                             )

        # Define the raw payload as bytes
        # Define the raw payload as bytes
        raw_payload = (
                b'\x45\x00\x00\x3c\x00\x00\x00\x00\x40\x06\x00\x00'
                b'\xc0\xa8\x01\x01' + self._target_ip.encode() +
                b'\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00\x00\x50'
                b'\x02\x03\x00\xf7\xf5\x00\x00\x02\x04\x03\x03\x0a'
                b'\x01\x01\x02\x04\x04\x5b\x04\x00\x01\x01\x01'
        )

        self._packet = IP(raw_payload)
        # TODO - found a bug in settings CE flag (ECN CWR and ECE congestion control flags)
        # Urgent field value
        # TODO - need to check if this makes sense
        #self._packet.getlayer(TCP).flags = 0x20  # 32