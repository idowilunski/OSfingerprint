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

    def calculate_similarity_score(self, other):
        score = 0
        if self.r == other.r:
            score += 50
        if self.df == other.df:
            score += 20
        if isinstance(other.t, list):
            for t_tuple in other.t:
                if len(t_tuple) == 2 and t_tuple[0] <= self.t <= t_tuple[1]:
                    score += 15
                    break  # Break the loop if the score is within any tuple's range
        else:
            # Handle the case when other.t is not a list of tuples
            if self.t == other.t:
                score += 15

        if self.tg == other.t:
            score += 15
        if self.ipl == other.ipl:
            score += 100
        if self.un == other.un:
            score += 100
        if self.ripl == other.ripl:
            score += 100
        if self.rid == other.rid:
            score += 100
        if self.ripck == other.ripck:
            score += 100
        if self.ruck == other.ruck:
            score += 100
        if self.rud == other.rud:
            score += 100
        return score

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

        if '|' in t_value:
            # Handle multiple tuples separated by "|"
            tuple_strings = t_value.split('|')
            self.t = [tuple(map(int, t.split('-'))) for t in tuple_strings]
        elif '-' in t_value:
            # Handle a single tuple
            t_range = t_value.split('-')
            self.t = [[int(t_range[0], 16), int(t_range[1], 16)]]
        else:
            # Handle a single value
            self.t = int(t_value, 16)

        # Convert hexadecimal string to integer
        tg_value = tests.get('TG', '')

        if '|' in tg_value:
            # Handle multiple tuples separated by "|"
            tuple_strings = tg_value.split('|')
            self.tg = [tuple(map(int, t.split('-'))) for t in tuple_strings]
        elif '-' in tg_value:
            # Handle a single tuple
            t_range = tg_value.split('-')
            self.tg = [[int(t_range[0], 16), int(t_range[1], 16)]]
        else:
            # Handle a single value
            self.tg = int(tg_value, 16)

        ipl_value = tests.get('IPL', '')

        if '|' in ipl_value:
            # Handle multiple tuples separated by "|"
            tuple_strings = ipl_value.split('|')
            self.ipl = [tuple(map(int, t.split('-'))) for t in tuple_strings]
        elif '-' in ipl_value:
            # Handle a single tuple
            t_range = ipl_value.split('-')
            self.ipl = [[int(t_range[0], 16), int(t_range[1], 16)]]
        else:
            # Handle a single value
            self.ipl = int(ipl_value, 16)

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
