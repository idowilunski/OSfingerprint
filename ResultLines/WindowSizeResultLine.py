import logging
from ResultLines.IResultLine import *
import PacketParsingUtils


class WindowSizeResultLine(IResultLine):
    """
    Represents a class for handling and comparing TCP window size values.

    This class is designed to record and manage the 16-bit TCP window size values obtained from different probes.
    It includes methods for calculating a similarity score between two instances and initializing the class attributes
    from either response packets or database records.
    According to the following documentation, under "TCP initial window size (W, W1–W6)":
    https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq

    Attributes:
        w1 (int): 16-bit TCP window size value for probe W1.
        w2 (int): 16-bit TCP window size value for probe W2.
        w3 (int): 16-bit TCP window size value for probe W3.
        w4 (int): 16-bit TCP window size value for probe W4.
        w5 (int): 16-bit TCP window size value for probe W5.
        w6 (int): 16-bit TCP window size value for probe W6.

    Methods:
        - calculate_similarity_score(other): Calculates a similarity score between two WindowSize instances based on
          their window size values.
        - init_from_response(probe_sender): Initializes the class attributes using the window size values obtained
          from a ProbeSender instance.
        - init_from_db(tests): Initializes the class attributes using window size values from a dictionary obtained
          from a database.
    """
    def __init__(self):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        self.w1 = None
        self.w2 = None
        self.w3 = None
        self.w4 = None
        self.w5 = None
        self.w6 = None

    def calculate_similarity_score(self, other):
        """
        Calculate the similarity score between two WindowSize instances.

        The similarity score is calculated based on matching window size values between the two instances.

        Args:
            other (WindowSize): Another WindowSize instance to compare with.

        Returns:
            int: The similarity score, ranging from 0 to 90.
        """
        score = 0
        for attr in ['w1', 'w2', 'w3', 'w4', 'w5', 'w6']:
            if getattr(self, attr) == getattr(other, attr):
                score += 15
        return score

    def init_from_response(self, check_manager):
        """
        Initialize the class attributes from a ProbeSender instance.

        Args:
            check_manager (CheckManager): An instance of CheckManager containing response packets with window size values.
        """
        checks_list = check_manager.get_probe_checks_list()
        self.w1 = PacketParsingUtils.get_received_window_size(checks_list[0].get_response_packet())
        self.w2 = PacketParsingUtils.get_received_window_size(checks_list[1].get_response_packet())
        self.w3 = PacketParsingUtils.get_received_window_size(checks_list[2].get_response_packet())
        self.w4 = PacketParsingUtils.get_received_window_size(checks_list[3].get_response_packet())
        self.w5 = PacketParsingUtils.get_received_window_size(checks_list[4].get_response_packet())
        self.w6 = PacketParsingUtils.get_received_window_size(checks_list[5].get_response_packet())

    def init_from_db(self, tests: dict):
        """
        Initialize the class attributes from a dictionary obtained from the NMAP database parsed earlier.

        Args:
            tests (dict): A dictionary containing window size values for probes W1 to W6.

        Raises:
            Exception: If the input is not a dictionary.
        """
        if not isinstance(tests, dict):
            raise Exception("Init from DB called with a non dictionary object!")

        self.w1 = tests.get('W1', None)
        self.w2 = tests.get('W2', None)
        self.w3 = tests.get('W3', None)
        self.w4 = tests.get('W4', None)
        self.w5 = tests.get('W5', None)
        self.w6 = tests.get('W6', None)