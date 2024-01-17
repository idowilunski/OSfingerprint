import CommonTests
from CommonTests import *


class Ecn:
    def __init__(self):
        self.r = None
        self.df = None
        self.t = None
        self.tg = None
        self.w = None
        self.o = None
        self.cc = None
        self.q = None

    def calculate_similarity_score(self, other):
        score = 0

        if not isinstance(other, Ecn):
            return score

        if self.r == other.r:
            score += 100
        if self.df == other.df:
            score += 20
        if self.t == other.t:
            score += 15
        if self.tg == other.tg:
            score += 15
        if self.w == other.w:
            score += 15
        if self.o == other.o:
            score += 15
        if self.cc == other.cc:
            score += 100
        if self.q == other.q:
            score += 20
        return score

    def init_from_response(self, ecn_sender):
        ecn_check = ecn_sender.get_checks_list()[0]
        self.r = CommonTests.calculate_responsiveness(ecn_check)
        self.df = CommonTests.calculate_dont_fragment(ecn_check)
        self.t = CommonTests.calculate_ttl_diff(ecn_sender)
        self.tg = CommonTests.calculate_ttl_guess(ecn_sender)
        self.w = CommonTests.calculate_window_size(ecn_check)
        self.o = CommonTests.calculate_o(ecn_check)
        if len(self.o) > 0:
            print( ''.join(self.o))
        self.cc = self.calculate_congestion_notification(ecn_check)
        self.q = CommonTests.calculate_quirks(ecn_check)

    def init_from_db(self, tests : dict):
        self.r = tests.get('R', '')
        self.df = tests.get('DF', '')
        self.t = tests.get('T', '')
        self.tg = tests.get('TG', '')
        temp_w = tests.get('W', '')
        if temp_w == '':
            self.w = temp_w
        else:
            self.w = int(temp_w, 16)

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

