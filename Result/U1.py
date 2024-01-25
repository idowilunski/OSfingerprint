import logging
from scapy.layers.inet import UDP, ICMP

import PacketParsingUtils
from CommonTests import *
from PacketParsingUtils import *


class U1:
    """
    Represents the U1 probe, designed to receive an ICMP "port unreachable" message in response.

    This class includes methods for calculating similarity scores, initializing attributes from response packets or
    database records, and specific calculations related to the U1 probe.

    Attributes:
        r (str): Responsiveness result, 'Y' if responsive, 'N' if non-responsive.
        df (str): Don't Fragment (DF) bit value.
        t (int or list): Time-to-Live (TTL) value or a list of TTL tuples.
        tg (int or list): TTL guess value or a list of TTL guess tuples.
        ipl (int or list): IP total length (IPL) value or a list of IPL tuples.
        un (bytes): Unused port unreachable field value.
        ripl (int): Returned probe IP length (RIPL) value.
        rid (int or str): Returned probe IP ID (RID) value or 'G' for a static ID.
        ripck (str): Integrity of returned probe IP checksum (RIPCK) value ('G', 'Z', or 'I').
        ruck (str): Integrity of returned probe UDP checksum (RUCK) value ('G' or actual checksum).
        rud (str): Response UDP payload integrity (RUD) value ('G' or 'I').

    Methods:
        - calculate_similarity_score(other): Calculates a similarity score between two U1 instances based on attribute values.
        - init_from_response(udp_sender): Initializes attributes from a ProbeSender instance containing U1 probe response.
        - init_from_db(tests): Initializes attributes from a dictionary obtained from a database.
        - calculate_rid(u1_check): Calculates the Returned probe IP ID (RID) value.
        - calculate_ripck(u1_check): Calculates the Integrity of returned probe IP checksum (RIPCK) value.
        - calculate_ripl(u1_check): Calculates the Returned probe IP length (RIPL) value.
        - calculate_ruck(u1_check): Calculates the Integrity of returned probe UDP checksum (RUCK) value.
        - calculate_rud(u1_check): Calculates the Response UDP payload integrity (RUD) value.
        - calculate_ipl(u1_check): Calculates the IP total length (IPL) value.
        - calculate_un(u1_check): Calculates the Unused port unreachable field value.
    """
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
        """
        Calculate the similarity score between two U1 instances based on attribute values.

        The similarity score is calculated by comparing each attribute and assigning weights accordingly.

        Args:
            other (U1): Another U1 instance to compare with.

        Returns:
            int: The similarity score, ranging from 0 to 550.
        """
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
        attributes_to_compare = ['ipl', 'un', 'ripl', 'rid', 'ripck', 'ruck', 'rud']

        for attribute in attributes_to_compare:
            if getattr(self, attribute) == getattr(other, attribute):
                score += 100

        return score

    def init_from_response(self, packet_sender):
        """
        Initializes the attributes of the U1 class using information from a ProbeSender instance.

        Args:
            packet_sender (PacketSender): The PacketSender instance containing all responses to checks.

        Returns:
            None
        """
        u1_check = packet_sender.get_udp_checks_list()[0]
        self.r = CommonTests.calculate_responsiveness(u1_check)
        self.df = CommonTests.calculate_dont_fragment(u1_check)
        self.t = CommonTests.calculate_ttl_diff(u1_check)
        self.tg = CommonTests.calculate_ttl_guess(u1_check)
        self.ipl = self.calculate_ipl(u1_check)
        self.un = self.calculate_un(u1_check)
        self.ripl = self.calculate_ripl(u1_check)
        self.rid = self.calculate_rid(u1_check)
        self.ripck = self.calculate_ripck(u1_check)
        self.ruck = self.calculate_ruck(u1_check)
        self.rud = self.calculate_rud(u1_check)

    def init_from_db(self, tests: dict):
        """
        Initializes the attributes of the U1 class using information from a dictionary obtained from a database.

        Args:
            tests (dict): Dictionary containing information retrieved from a database.

        Returns:
            None
        """
        # If responsiveness result doesn't exist, it means responsiveness = Y
        self.r = tests.get('R', 'Y')
        self.df = tests.get('DF', '')

        t_value = tests.get('T', '')

        # This part handles the DB entry in case for t there are several optional values, or if value is a range
        # For example, T=B|16-21
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
            self.t = int(t_value, 16) if t_value != '' else ''

        # Convert hexadecimal string to integer
        tg_value = tests.get('TG', '')

        # This part handles the DB entry in case for tg there are several optional values, or if value is a range
        # For example, TG=B|16-21
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
            self.tg = int(tg_value, 16) if tg_value != '' else ''

        ipl_value = tests.get('IPL', '')

        # This part handles the DB entry in case for ipl there are several optional values, or if value is a range
        # For example, IPL=B|16-21
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
            self.ipl = int(ipl_value, 16) if ipl_value != '' else ''

        self.un = tests.get('UN', '')
        self.ripl = tests.get('RIPL', '')
        self.rid = tests.get('RID', '')
        self.ripck = tests.get('RIPCK', '')
        self.ruck = tests.get('RUCK', '')
        self.rud = tests.get('RUD', '')

    @staticmethod
    def calculate_rid(u1_check) -> str:
        """
        Calculates the Returned probe IP ID (RID) value.
        Documentation reference: https://nmap.org/book/osdetect-methods.html#osdetect-tbl-o

        Args:
            u1_check (U1): The U1 instance containing the response packet.

        Returns:
            str: 'G' if the static ID is returned, otherwise the exact value returned.
        """
        # The U1 probe has a static IP ID value of 0x1042. If that value is returned in the port unreachable message,
        # the value G is stored for this test. Otherwise, the exact value returned is stored.
        response_id = PacketParsingUtils.get_packet_ip_id(u1_check.get_response_packet())
        STATIC_IP_ID_OF_PROBE = 0x1042
        if response_id == STATIC_IP_ID_OF_PROBE:
            return 'G'

        return response_id

    @staticmethod
    def calculate_ripck(u1_check) -> str:
        """
        Calculates the Integrity of returned probe IP checksum (RIPCK) value.
        Documentation reference: https://nmap.org/book/osdetect-methods.html#osdetect-tbl-o

        The IP checksum is one value that we don't expect to remain the same when returned in a port unreachable message.

        Args:
            u1_check (U1): The U1 instance containing the response packet.

        Returns:
            str: 'G' for good if the checksum matches the enclosing IP packet,
            'Z' if the returned value is zero, 'I' otherwise.
        """
        request_chksm = PacketParsingUtils.get_ip_checksum(u1_check.get_sent_packet())
        response_chksm = PacketParsingUtils.get_ip_checksum(u1_check.get_response_packet())

        #  If the checksum we receive matches the enclosing IP packet - return 'G' (good).
        if response_chksm == request_chksm:
            return 'G'
        #  If the checksum we receive is zero, return 'Z' (zero).
        if response_chksm == 0:
            return 'Z'
        #  Otherwise, return I (invalid).
        return 'I'

    @staticmethod
    def calculate_ripl(u1_check) -> int:
        """
        Calculates the Returned probe IP length (RIPL) value.

        Args:
            u1_check (U1): The U1 instance containing the response packet.

        Returns:
            int: The length of the returned IP packet.
        """
        return PacketParsingUtils.get_packet_ip_len(u1_check.get_response_packet())

    @staticmethod
    def calculate_ruck(u1_check):
        """
        Calculates the Integrity of returned probe UDP checksum (RUCK) value.
        Documentation reference: https://nmap.org/book/osdetect-methods.html#osdetect-tbl-o

        Args:
            u1_check (U1): The U1 instance containing the response packet.

        Returns:
            str: 'G' for good if the UDP header checksum matches the sent value, otherwise the actual returned checksum.
        """
        request_chksm = PacketParsingUtils.get_ip_checksum(u1_check.get_sent_packet())
        response_chksm = PacketParsingUtils.get_ip_checksum(u1_check.get_response_packet())

        # If UDP header checksum is identcial to the sent checksum, return 'G' (good).
        # Otherwise, return actual checksum.
        return 'G' if request_chksm == response_chksm else response_chksm

    @staticmethod
    def calculate_rud(u1_check):
        """
        Calculates the Response UDP payload integrity (RUD) value.

        Args:
            u1_check (U1): The U1 instance containing the response packet.

        Returns:
            str: 'G' for good if all payload bytes are 'C' or payload is truncated to zero length,
            'I' if payload is invalid.
        """
        response = u1_check.get_response_packet()
        # verify packet validity
        if response and response.haslayer(UDP):
            payload = response[UDP].load
            # if all payload bytes are 'C' or payload size is zero - return 'G'
            if not payload or all(byte == ord('C') for byte in payload):
                return 'G'

        # Payload is invalid, return 'I'
        return 'I'

    @staticmethod
    def calculate_ipl(u1_check) -> int:
        """
        Calculates the IP total length (IPL) value.
        Documentation reference: https://nmap.org/book/osdetect-methods.html#osdetect-tbl-o

        This test records the total length (in octets) of an IP packet.

        Args:
            u1_check (U1): The U1 instance containing the response packet.

        Returns:
            int: The total length of the IP packet.
        """
        response = u1_check.get_response_packet()
        if response is None:
            return 0
        return len(response)

    @staticmethod
    def calculate_un(u1_check):
        """
        Calculates the Unused port unreachable field value.
        Documentation reference: https://nmap.org/book/osdetect-methods.html#osdetect-tbl-o
        Section - Unused port unreachable field nonzero (UN)

        Args:
            u1_check (U1): The U1 instance containing the response packet.

        Returns:
            bytes: The value of the last four bytes in the ICMP port unreachable header.
        """
        # An ICMP port unreachable message header is eight bytes long, but only the first four are used.
        # Last four bytes should be zero but some devices set it anyway, return them.
        if u1_check.get_response_packet() is None:
            return ""
        raw_icmp_header = bytes(u1_check.get_response_packet()[ICMP])
        return raw_icmp_header[-4:]
