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
            ('WScale ', 10),
            ('NOP', None),
            ('MSS', 1460),
            ('SAckOK', ''),  # SACK permitted
            ('NOP', None),
            ('NOP', None)
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

        self._packet = IP(dst=self._target_ip) / TCP(dport=self._target_port, flags="S",
                                                     options=options,
                                                     window=window_size,
                                                     ack=0,
                                                     reserved=1,
                                                     #tcpflags="CE",
                                                     #urgptr=0xF7F5  # Urgent Pointer
                                                     )
        # TODO - found a bug in settings CE flag (ECN CWR and ECE congestion control flags)
        # Urgent field value
        # TODO - need to check if this makes sense
        self._packet.getlayer(TCP).flags = 0x20  # 32