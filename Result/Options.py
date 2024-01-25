from CommonTests import *


class Options:
    """
    Represents options obtained from a sequence of probes and provides methods for initialization
    and calculating similarity scores based on these options.

    Attributes:
        o1 (str): Option 1.
        o2 (str): Option 2.
        o3 (str): Option 3.
        o4 (str): Option 4.
        o5 (str): Option 5.
        o6 (str): Option 6.
    """

    def __init__(self):
        """
        Initializes an Options instance with attributes o1 to o6 set to None.
        """
        self.o1 = None
        self.o2 = None
        self.o3 = None
        self.o4 = None
        self.o5 = None
        self.o6 = None

    def calculate_similarity_score(self, other) -> int:
        """
        Calculates the similarity score between two Options instances based on attributes o1 to o6.

        Args:
            other (Options): Another Options instance to compare.

        Returns:
            int: The similarity score.
        """
        score = 0
        for attr in ['o1', 'o2', 'o3', 'o4', 'o5', 'o6']:
            if getattr(self, attr) == getattr(other, attr):
                score += 20
        return score

    def init_from_response(self, packet_sender):
        """
        Initializes options from a sequence of probe responses.

        Args:
            packet_sender (PacketSender): A PacketSender instance containing responses to all checks.
        """
        checks_list = packet_sender.get_probe_checks_list()
        self.o1 = CommonTests.calculate_o(checks_list[0])
        self.o2 = CommonTests.calculate_o(checks_list[1])
        self.o3 = CommonTests.calculate_o(checks_list[2])
        self.o4 = CommonTests.calculate_o(checks_list[3])
        self.o5 = CommonTests.calculate_o(checks_list[4])
        self.o6 = CommonTests.calculate_o(checks_list[5])

    def init_from_db(self, tests : dict):
        """
        Initializes options from a dictionary obtained from NMAP database.

        Args:
            tests (dict): A dictionary containing option values.
        """
        self.o1 = tests.get('O1', None)
        self.o2 = tests.get('O2', None)
        self.o3 = tests.get('O3', None)
        self.o4 = tests.get('O4', None)
        self.o5 = tests.get('O5', None)
        self.o6 = tests.get('O6', None)
