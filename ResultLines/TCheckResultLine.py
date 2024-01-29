import PacketParsingUtils
from TestsCalculations import *
from ResultLines.IResultLine import *


class TCheckResultLine(IResultLine):
    """
    Represents a test check for the T (TCP) type of OS detection probes.

    Attributes:
        r (str): Responsiveness result ('Y', 'N', or '' if not applicable).
        df (str): Don't Fragment (DF) result.
        t (str): Time To Live (TTL) difference result.
        tg (str): Time To Live (TTL) guess result.
        w (list): List of window size values.
        s (str): Sequence number result.
        a (str): Acknowledgment number result.
        f (list): List of TCP flags.
        o (str): O value result.
        rd (str): RD (Router Advertisement) result.
        q (str): Quirks result.

    Methods:
        calculate_similarity_score(self, other): Calculates the similarity score between two TCheck instances.
        init_from_response(self, t_sender, check): Initializes attributes from a TSender and a check instance.
        init_from_db(self, tests: dict): Initializes attributes from a dictionary obtained from a database.
        calculate_ack_number(t_check): Calculates the acknowledgment number result.
        calculate_sequence_number(t_check): Calculates the sequence number result.
    """
    def __init__(self):
        self.r = None
        self.df = None
        self.t = None
        self.tg = None
        self.w = None
        self.s = None
        self.a = None
        self.f = None
        self.o = None
        self.rd = None
        self.q = None

    def calculate_similarity_score(self, other):
        """
        Calculates the similarity score between two TCheck instances.

        Args:
            other (TCheck): Another TCheck instance to compare.

        Returns:
            int: The similarity score between the two instances.
        """
        score = 0
        # TODO - for T2,T3,T7 has 80 score here
        if self.r == 'N':
            return 0
        if self.r == other.r:
            score += 100
        if self.t == other.t:
            score += 15
        if self.tg == other.tg:
            score += 15
        if other.w is not None:
            for window_size in other.w:
                if self.w == int(window_size, 16):
                    score += 25
        if other.f is not None:
            for flags_list in other.f:
                if sorted(self.f) == sorted(flags_list):
                    score += 30
        if self.o is not None and self.o == other.o:
            score += 10
        attributes_to_compare = ['q', 'rd', 'a', 's', 'df']

        for attribute in attributes_to_compare:
            if getattr(self, attribute) == getattr(other, attribute):
                score += 20
        return score

    def init_from_response(self, check):
        """
        Initializes TCheck attributes from a TSender and a check instance.

        Args:
            check (Check): The check instance containing relevant information.

        Returns:
            None
        """
        self.r = TestsCalculations.calculate_responsiveness(check)

        # If responsiveness test returned "no", no bother calculating, all values will be empty
        if self.r == 'N':
            return

        self.df = PacketParsingUtils.get_dont_fragment_bit_value(check.get_response_packet())
        self.t = TestsCalculations.calculate_ttl_diff(check)
        self.tg = TestsCalculations.calculate_ttl_guess(check)
        self.w = PacketParsingUtils.get_received_window_size(check.get_response_packet())
        self.s = self.calculate_sequence_number(check)
        self.a = self.calculate_ack_number(check)
        self.f = PacketParsingUtils.get_tcp_flags(check.get_response_packet())
        self.o = TestsCalculations.calculate_o(check)
        self.rd = TestsCalculations.calculate_rd(check)
        self.q = TestsCalculations.calculate_quirks(check)

    def init_from_db(self, tests: dict):
        """
        Initializes TCheck attributes from a dictionary obtained from the NMAP database.

        Args:
            tests (dict): Dictionary containing information retrieved from the NMAP database.

        Returns:
            None
        """
        self.r = tests.get('R', '')

        # If responsiveness test returned "no", no bother calculating, all values will be empty
        if self.r == 'N':
            return

        self.df = tests.get('DF', '')
        self.t = tests.get('T', '')
        self.tg = tests.get('TG', '')
        self.w = [entry for entry in tests.get('W', '').split('|') if entry]
        self.s = tests.get('S', '')
        self.a = tests.get('A', '')
        self.f = [list(entry) for entry in tests.get('F', '').split('|')]
        self.o = tests.get('O', '')
        self.rd = tests.get('RD', '')
        self.q = tests.get('Q', '')

    @staticmethod
    def calculate_ack_number(t_check):
        """
        Calculates the acknowledgment number result.
        According to documentation: TCP acknowledgment number (A):
        https://nmap.org/book/osdetect-methods.html#osdetect-tbl-o

        Args:
            t_check (TCheck): The TCheck instance containing the response packet.

        Returns:
            str: Acknowledgment number result ('Z', 'S', 'S+', or 'O'), how the acknowledgment number in the
            response compared to the sequence number in the respective probe.
        """
        response_packet = t_check.get_response_packet()
        response_ack_num = PacketParsingUtils.get_packet_ack_number(response_packet)
        probe_seq_num = PacketParsingUtils.get_sequence_number(response_packet)

        # Acknowledgment number is zero.
        if response_ack_num == 0:
            return 'Z'
        # Acknowledgment number is the same as the sequence number in the probe.
        if response_ack_num == probe_seq_num:
            return 'S'
        # Acknowledgment number is the same as the sequence number in the probe plus one
        if response_ack_num == (probe_seq_num + 1):
            return 'S+'
        # Acknowledgment number is something else (other).
        return 'O'

    @staticmethod
    def calculate_sequence_number(t_check):
        """
        Calculates the sequence number result.
        TCP sequence number (S) in documentation: https://nmap.org/book/osdetect-methods.html#osdetect-tbl-o

        Args:
            t_check (TCheck): The TCheck instance containing the response packet.

        Returns:
            str: Sequence number result ('Z', 'A', 'A+', or 'O'), , how the acknowledgment number in the
            probe compared to the sequence number in the respective response.
        """
        probe_ack_num = PacketParsingUtils.get_packet_ack_number(t_check.get_sent_packet())
        response_seq_num = PacketParsingUtils.get_packet_sequence_number(t_check.get_response_packet())

        # Sequence number is zero.
        if response_seq_num == 0:
            return 'Z'
        # Sequence number is the same as the acknowledgment number in the probe.
        if response_seq_num == probe_ack_num:
            return 'A'
        # Sequence number is the same as the acknowledgment number in the probe plus one
        if response_seq_num == (probe_ack_num + 1):
            return 'A+'
        # Sequence number is something else (other).
        return 'O'

