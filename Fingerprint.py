from ResultLines.SequenceResultLine import SequenceResultLine
from ResultLines.EcnResultLine import EcnResultLine
from ResultLines.OptionsResultLine import OptionsResultLine
from ResultLines.WindowSizeResultLine import WindowSizeResultLine
from ResultLines.TCheckResultLine import TCheckResultLine
from ResultLines.U1ResultLine import U1ResultLine
from ResultLines.IEResultLine import IEResultLine


class Fingerprint:
    """
    Class representing a network fingerprint with various test results.

    Attributes:
    - SEQ (Sequence): Sequence test result.
    - name (str): Name of the fingerprint.
    - CPE (str): Common Platform Enumeration identifier.
    - OPS (Options): Options test result.
    - WIN (WindowSize): Window Size test result.
    - ECN (Ecn): ECN test result.
    - T1 to T7 (TCheck): Test results for T1 to T7.
    - U1 (U1): U1 test result.
    - IE (IE): IE test result.
    """
    def __init__(self):
        """
            Initialize an instance of the Fingerprint class with default values.
        """
        self.SEQ = SequenceResultLine()
        self.name = "N/A"
        self.CPE = "N/A"
        self.OPS = OptionsResultLine()
        self.WIN = WindowSizeResultLine()
        self.ECN = EcnResultLine()
        self.T1 = TCheckResultLine()
        self.T2 = TCheckResultLine()
        self.T3 = TCheckResultLine()
        self.T4 = TCheckResultLine()
        self.T5 = TCheckResultLine()
        self.T6 = TCheckResultLine()
        self.T7 = TCheckResultLine()
        self.U1 = U1ResultLine()
        self.IE = IEResultLine()

    def init_from_response(self, packet_sender):
        """
        Initialize the Fingerprint instance from response data.

        Parameters:
        - packet_sender: Contains response data for all tests.
        """
        self.SEQ.init_from_response(packet_sender)
        self.OPS.init_from_response(packet_sender)
        self.WIN.init_from_response(packet_sender)
        self.ECN.init_from_response(packet_sender)
        self.T1.init_from_response(packet_sender, packet_sender.get_probe_checks_list()[0])
        self.T2.init_from_response(packet_sender, packet_sender.get_open_port_checks_list()[0])
        self.T3.init_from_response(packet_sender, packet_sender.get_open_port_checks_list()[1])
        self.T4.init_from_response(packet_sender, packet_sender.get_open_port_checks_list()[2])
        self.T5.init_from_response(packet_sender, packet_sender.get_close_port_checks_list()[0])
        self.T6.init_from_response(packet_sender, packet_sender.get_close_port_checks_list()[1])
        self.T7.init_from_response(packet_sender, packet_sender.get_close_port_checks_list()[2])
        self.U1.init_from_response(packet_sender)
        self.IE.init_from_response(packet_sender)

    def init_from_db(self, tests: dict):
        """
        Initialize the Fingerprint instance from a dictionary of test results, parsed earlier from NmapDB.

        Parameters:
        - tests (dict): Dictionary containing test results.
        """
        self.name = tests['Fingerprint']

        try:
            self.CPE = tests['CPE']
        except KeyError:
            pass

        self.SEQ.init_from_db(tests.get('SEQ'))
        self.OPS.init_from_db(tests.get('OPS'))
        self.WIN.init_from_db(tests.get('WIN'))
        self.ECN.init_from_db(tests.get('ECN'))
        self.T1.init_from_db(tests.get('T1'))
        self.T2.init_from_db(tests.get('T2'))
        self.T3.init_from_db(tests.get('T3'))
        self.T4.init_from_db(tests.get('T4'))
        self.T5.init_from_db(tests.get('T5'))
        self.T6.init_from_db(tests.get('T6'))
        self.T7.init_from_db(tests.get('T7'))
        self.U1.init_from_db(tests.get('U1'))
        self.IE.init_from_db(tests.get('IE'))

    def calculate_similarity_score(self, other_fingerprint):
        """
        Calculate the similarity score between two Fingerprint instances.

        Parameters:
        - other_fingerprint (Fingerprint): The other Fingerprint instance to compare with.

        Returns:
        The total similarity score between the two fingerprints.
        """
        seq_score = self.SEQ.calculate_similarity_score(other_fingerprint.SEQ)
        ops_score = self.OPS.calculate_similarity_score(other_fingerprint.OPS)
        win_score = self.WIN.calculate_similarity_score(other_fingerprint.WIN)
        ecn_score = self.ECN.calculate_similarity_score(other_fingerprint.ECN)
        t1_score = self.T1.calculate_similarity_score(other_fingerprint.T1)
        t2_score = self.T2.calculate_similarity_score(other_fingerprint.T2)
        t3_score = self.T3.calculate_similarity_score(other_fingerprint.T3)
        t4_score = self.T4.calculate_similarity_score(other_fingerprint.T4)
        t5_score = self.T5.calculate_similarity_score(other_fingerprint.T5)
        t6_score = self.T6.calculate_similarity_score(other_fingerprint.T6)
        t7_score = self.T7.calculate_similarity_score(other_fingerprint.T7)
        u1_score = self.U1.calculate_similarity_score(other_fingerprint.U1)
        ie_score = self.IE.calculate_similarity_score(other_fingerprint.IE)

        total_score = (
            seq_score + ops_score + win_score + ecn_score +
            t1_score + t2_score + t3_score + t4_score +
            t5_score + t6_score + t7_score + u1_score + ie_score
        )

        return total_score
