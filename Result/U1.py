import logging

from scapy.layers.inet import IP, UDP, ICMP
from CommonTests import *


# U1 probe is expected to receive in response an ICMP "port unreachable" message
class U1:
    def __init__(self):
        self.r = None
        self.df = None
        self.t = None
        self.tg = None
        self.ipl = None
        self.un = None
        self.ripl = None
        self.rid = None
        self.ripck = None
        self.ruck = None
        self.rud = None


    def __eq__(self, other):
        if self.r != other.r:
            return False

        # If responsiveness test returned "no", then all values will be empty
        if self.r == 'N':
            return True

        if self.df != other.df:
            return False
        # T can either be a range, or value to compare
        if isinstance(self.t, tuple):
            # Check if it's a tuple, compare using the tuple values
            if self.t[1] > other.t[1] or self.t[0] < other.t[0]:
                return False
        else:
            # If it's not a tuple, perform a normal comparison
            if self.t != other.t:
                return False

        if self.tg != other.tg:
            return False
        if self.ipl != other.ipl:
            return False
        if self.un != other.un:
            return False
        if self.ripl != other.ripl:
            return False
        if self.rid != other.rid:
            return False
        if self.ripck != other.ripck:
            return False
        if self.ruck != other.ruck:
            return False
        if self.rud != other.rud:
            return False

        return True

    def init_from_response(self, udp_sender):
        u1_check = udp_sender.get_checks_list()[0]
        self.r = CommonTests.calculate_responsiveness(u1_check)
        self.df = CommonTests.calculate_dont_fragment(u1_check)
        self.t = CommonTests.calculate_ttl_diff(udp_sender)
        self.tg = CommonTests.calculate_ttl_guess(udp_sender)
        self.ipl = self.calculate_ipl(u1_check)
        self.un = self.calculate_un(u1_check)
        self.ripl = self.calculate_ripl(u1_check)
        self.rid = self.calculate_rid(u1_check)
        self.ripck = self.calculate_ripck(u1_check)
        self.ruck = self.calculate_ruck(u1_check)
        self.rud = self.calculate_rud(u1_check)

    def init_from_db(self, tests: dict):
        # If responsiveness result doesn't exist, it means responsiveness = Y
        self.r = tests.get('R', 'Y')

        if self.r == 'N':
            return

        self.df = tests.get('DF', '')

        t_value = tests.get('T', '')

        if '-' in t_value:
            t_range = t_value.split('-')
            # Convert hexadecimal strings to integers and create a tuple
            self.t = (int(t_range[0], 16), int(t_range[1], 16))
        else:
            self.t = t_value

        # Convert hexadecimal string to integer
        self.tg = int(tests.get('TG', ''), 16)
        self.ipl = int(tests.get('IPL', ''), 16)
        self.un = tests.get('UN', '')
        self.ripl = tests.get('RIPL', '')
        self.rid = tests.get('RID', '')
        self.ripck = tests.get('RIPCK', '')
        self.ruck = tests.get('RUCK', '')
        self.rud = tests.get('RUD', '')

    # Documentation reference: https://nmap.org/book/osdetect-methods.html#osdetect-tbl-o
    # Returned probe IP ID value (RID)
    # The U1 probe has a static IP ID value of 0x1042. If that value is returned in the port unreachable message,
    # the value G is stored for this test. Otherwise, the exact value returned is stored.
    @staticmethod
    def calculate_rid(u1_check):
        response_id = u1_check.get_response_ip_id()
        # TODO remove magic numbers
        if response_id == 0x1042:
            return 'G'

        return response_id

    # Documentation reference: https://nmap.org/book/osdetect-methods.html#osdetect-tbl-o
    # Integrity of returned probe IP checksum value (RIPCK)
    # The IP checksum is one value that we don't expect to remain the same when returned in a port unreachable message
    @staticmethod
    def calculate_ripck(u1_check):
        request_chksm = u1_check.get_request_checksum()
        response_chksm = u1_check.get_response_checksum()
        #  The checksum we receive should match the enclosing IP packet.
        #  If it does, the value G (good) is stored for this test.
        if request_chksm == response_chksm:
            return 'G'
        #  If the returned value is zero, then Z is stored.
        if response_chksm == 0:
            return 'Z'
        #  Otherwise the result is I (invalid).
        return 'I'

    @staticmethod
    def calculate_ripl(u1_check):
        return u1_check.get_response_ip_len()

    # Documentation reference: https://nmap.org/book/osdetect-methods.html#osdetect-tbl-o
    # Integrity of returned probe UDP checksum (RUCK)
    @staticmethod
    def calculate_ruck(u1_check):
        request_chksm = u1_check.get_request_checksum()
        response_chksm = u1_check.get_response_checksum()
        # The UDP header checksum value should be returned exactly as it was sent. If it is, G is recorded for this
        # test. Otherwise, the value actually returned is recorded.
        return 'G' if request_chksm == response_chksm else response_chksm

    @staticmethod
    def calculate_rud(u1_check):
        response = u1_check.get_response_packet()
        # Check the response
        if response and response.haslayer(UDP):
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
