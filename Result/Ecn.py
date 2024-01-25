import CommonTests
from CommonTests import *


class Ecn:
    """
    Represents an ECN (Explicit Congestion Notification) test object.

    Attributes:
        r (str): Responsiveness result ('Y' for Yes, 'N' for No).
        df (str): Don't Fragment result ('Y' for Yes, 'N' for No).
        t (str): TTL Diff (Time To Live difference) result.
        tg (str): TTL Guess result.
        w (str): Window Size result.
        o (str): O Test result.
        cc (str): Congestion Notification result ('Y' for Yes, 'N' for No, 'S' for Echo, 'O' for Other).
        q (str): Quirks result.
    """

    def __init__(self):
        """
        Initializes an Ecn object with attributes representing ECN (Explicit Congestion Notification) test results.
        """
        self.r = None
        self.df = None
        self.t = None
        self.tg = None
        self.w = None
        self.o = None
        self.cc = None
        self.q = None

    def calculate_similarity_score(self, other) -> int:
        """
        Calculates the similarity score between two Ecn objects.

        Parameters:
            other (Ecn): The other Ecn object to compare.

        Returns:
            int: The similarity score between the two Ecn objects.
        """
        score = 0

        if not isinstance(other, Ecn):
            return score

        if self.r == 'N':
            return 0

        if self.r == other.r:
            score += 100
        if self.df == other.df:
            score += 20
        if self.t == other.t:
            score += 15
        if self.tg == other.tg:
            score += 15
        if other.w is not None:
            for window_size in other.w:
                if self.w == int(window_size, 16):
                    score += 15
        if self.o is not None and self.o == other.o:
            score += 15
        if self.cc == other.cc:
            score += 100
        if self.q == other.q:
            score += 20
        return score

    def init_from_response(self, ecn_sender):
        """
        Initializes the Ecn object attributes based on the response from the ECN sender.

        Parameters:
            ecn_sender (Sender): The sender object for the ECN test.
        """
        ecn_check = ecn_sender.get_checks_list()[0]
        self.r = CommonTests.calculate_responsiveness(ecn_check)

        # If responsiveness test returned "no", no bother calculating, all values will be empty
        if self.r == 'N':
            return

        self.df = CommonTests.calculate_dont_fragment(ecn_check)
        self.t = CommonTests.calculate_ttl_diff(ecn_sender.get_checks_list()[0])
        self.tg = CommonTests.calculate_ttl_guess(ecn_sender.get_checks_list()[0])
        self.w = CommonTests.calculate_window_size(ecn_check)
        self.o = CommonTests.calculate_o(ecn_check)
        if len(self.o) > 0:
            print( ''.join(self.o))
        self.cc = self.calculate_congestion_notification(ecn_check)
        self.q = CommonTests.calculate_quirks(ecn_check)

    def init_from_db(self, tests : dict):
        """
        Initializes the Ecn object attributes based on the values stored in the database.

        Parameters:
            tests (dict): Dictionary containing the test results retrieved from the database.
        """
        self.r = tests.get('R', '')

        # If responsiveness test returned "no", no bother calculating, all values will be empty
        if self.r == 'N':
            return

        self.df = tests.get('DF', '')
        self.t = tests.get('T', '')
        self.tg = tests.get('TG', '')
        self.w = [entry for entry in tests.get('W', '').split('|') if entry]
        self.o = tests.get('O', '')
        self.cc = tests.get('CC', '')
        self.q = tests.get('Q', '')

    @staticmethod
    def calculate_congestion_notification(ecn_packet):
        """
        Calculates the congestion notification result based on the ECN packet.

        Parameters:
            ecn_packet (Packet): The ECN packet from the test.

        Returns:
            str: The calculated congestion notification result ('Y', 'N', 'S', or 'O').
        """
        is_ece = PacketParsingUtils.is_ece_set(ecn_packet.get_response_packet())
        is_cwr = PacketParsingUtils.is_cwr_set(ecn_packet.get_response_packet())
        # Only the ECE bit is set (not CWR). This host supports ECN.
        if is_ece and not is_cwr:
            return 'Y'
        # Neither of these two bits is set. The target does not support ECN.
        if not is_ece and not is_cwr:
            return 'N'
        # Both bits are set. The target does not support ECN, but it echoes back what it thinks is a reserved bit.
        if is_ece and is_cwr:
            return 'S'
        # The one remaining combination of these two bits (other).
        return 'O'

