from Packets.Check import Check
from scapy.layers.inet import IP, ICMP


class IcmpPacket1(Check):
    def __init__(self, target_ip, target_port):
        super().__init__(target_ip, target_port)
        # Prepare the first echo packet according to the following documentation:
        # https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
        # under "ICMP echo (IE)":
        # The first one has the IP DF bit set, a type-of-service (TOS) byte value of zero,
        # a code of nine (even though it should be zero), the sequence number 295,
        # a random IP ID and ICMP request identifier, and 120 bytes of 0x00 for the data payload.
        self._sent_packet = IP(dst=self._target_ip, flags="DF", tos=0, id=1234, ttl=0xFF) / \
                       ICMP(type=8, code=9, seq=295) / ( b'\x00' * 120)


class IcmpPacket2(Check):
    def __init__(self, target_ip, target_port):
        super().__init__(target_ip, target_port)

        ip_tos_reliability = 4
        # Prepare the first echo packet according to the following documentation:
        # https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
        # under "ICMP echo (IE)":
        # The second ping query is similar, except a TOS of four (IP_TOS_RELIABILITY) is used,
        # the code is zero, 150 bytes of data is sent,
        # and the ICMP request ID and sequence numbers are incremented by one from the previous query values.
        self._sent_packet = IP(dst=self._target_ip, tos=ip_tos_reliability, id=1235) / \
                       ICMP(type=8, code=0, seq=296) / ( b'\x00' * 150)
