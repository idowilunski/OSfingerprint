import CommonTests
from CommonTests import *


class Ecn:
    def __init__(self):
        self.r = None
        self.df = None
        self.t = None # TODO
        self.tg = None #TODO impl
        self.w = None
        self.o = None
        self.cc = None
        self.q = None

    def __eq__(self, other):
        if not isinstance(other, Ecn):
            return False

        if self.r != other.r:
            return False
        if self.df != other.df:
            return False
        if self.t != other.t:
            return False
        if self.tg != other.tg:
            return False
        if self.w != other.w:
            return False
        if self.o != other.o:
            return False
        if self.cc != other.cc:
            return False
        if self.q != other.q:
            return False
        return True

    def init_from_response(self, ecn_sender):
        ecn_check = ecn_sender.get_checks_list()[0]
        self.r = CommonTests.calculate_responsiveness(ecn_check)
        self.df = CommonTests.calculate_dont_fragment(ecn_check)
        self.t = None  # TODO
        self.tg = None  # TODO impl
        self.w = CommonTests.calculate_window_size(ecn_check)
        self.o = CommonTests.calculate_o(ecn_check)
        self.cc = self.calculate_congestion_notification(ecn_check)
        self.q = CommonTests.calculate_quirks(ecn_check)

    def init_from_db(self, tests : dict):
        self.r = tests.get('R', '')
        self.df = tests.get('DF', '')
        self.t = tests.get('T', '')
        self.tg = tests.get('TG', '')
        self.w = tests.get('W', '')
        self.o = tests.get('O', '')
        self.cc = tests.get('CC', '')
        self.q = tests.get('Q', '')

    @staticmethod
    def calculate_congestion_notification(ecn_packet):
        is_ece = ecn_packet.is_response_ece_set()
        is_cwr = ecn_packet.is_response_cwr_set()
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

