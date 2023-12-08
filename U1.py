from scapy.layers.inet import IP, UDP, ICMP, RandNum
from CommonTests import *


# U1 probe is expected to receive in response an ICMP "port unreachable" message
class U1:
    def __init__(self, u1_check):
        self._df = CommonTests.calculate_dont_fragment(u1_check)
        self._t = None # TODO impl IP initial time-to-live (T)
        self._tg = None # TODO impl IP initial time-to-live guess (TG)
        self._ipl = self.calculate_ipl(u1_check)
        self._un = self.calculate_un(u1_check) # TODO
        self._ripl = None #TODO
        self._rid = None #TODO
        self._ripck = None # TODO
        self._ruck = self.calculate_ruck(u1_check)
        self._rud = self.calculate_rud(u1_check)

    @staticmethod
    def calculate_ruck(u1_check):
        request_chksm = u1_check.get_request_checksum()
        response_chksm = u1_check.get_response_checksum()
        if request_chksm == response_chksm:
            return 'G'
        return response_chksm

    @staticmethod
    def calculate_rud(u1_check):
        response = u1_check.get_response_packet()
        # Check the response
        if response and response.has_layer[UDP]:
            payload = response[UDP].load
            # G is recorded if all payload bytes are 'C' or payload is truncated to zero length
            if not payload or all(byte == ord('C') for byte in payload):
                return 'G'

        # I is recorded if payload is invalid
        return 'I'

    # Documentation reference: https://nmap.org/book/osdetect-methods.html#osdetect-tbl-o
    # Section - IP total length (IPL)
    @staticmethod
    def calculate_ipl(u1_check):
        # This test records the total length (in octets) of an IP packet
        # That length varies by implementation because they are allowed to choose
        # how much data from the original probe to include, as long as they meet the minimum RFC 1122 requirement.
        return len(u1_check.get_response_packet())

    # Documentation reference: https://nmap.org/book/osdetect-methods.html#osdetect-tbl-o
    # Section - Unused port unreachable field nonzero (UN)
    @staticmethod
    def calculate_un(u1_check):
        # An ICMP port unreachable message header is eight bytes long, but only the first four are used.
        # RFC 792 states that the last four bytes must be zero.
        # A few implementations (mostly ethernet switches and some specialized embedded devices) set it anyway.
        # The value of those last four bytes is recorded in this field.
        raw_icmp_header = bytes(u1_check.get_response_packet()[ICMP])
        return raw_icmp_header[-4:]



