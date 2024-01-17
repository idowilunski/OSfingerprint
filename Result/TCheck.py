from CommonTests import *


class TCheck:
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
        score = 0
        # TODO - for T2,T3,T7 has 80 score here
        if self.r == other.r:
            score += 100
        if self.df == other.df:
            score += 20
        if self.t == other.t:
            score += 15
        if self.tg == other.tg:
            score += 15
        # TODO - T1 doesn't have matchpoint for W score!
        if self.w == other.w:
            score += 25
        if self.s == other.s:
            score += 20
        if self.a == other.a:
            score += 20
        if self.f == other.f:
            score += 30
        if self.o == other.o:
            score += 10
        if self.rd == other.rd:
            score += 20
        if self.q == other.q:
            score += 20
        return score

    def init_from_response(self, t_sender, check):
        self.r = CommonTests.calculate_responsiveness(check)
        self.df = CommonTests.calculate_dont_fragment(check)
        self.t = CommonTests.calculate_ttl_diff(t_sender)
        self.tg = CommonTests.calculate_ttl_guess(t_sender)
        self.w = CommonTests.calculate_window_size(check)
        self.s = self.calculate_sequence_number(check)
        self.a = self.calculate_ack_number(check)
        self.f = self.calculate_tcp_flags(check)
        self.o = CommonTests.calculate_o(check)
        self.rd = CommonTests.calculate_rd(t_sender)
        self.q = CommonTests.calculate_quirks(check)

    def init_from_db(self, tests: dict):
        self.r = tests.get('R', '')
        self.df = tests.get('DF', '')
        self.t = tests.get('T', '')
        self.tg = tests.get('TG', '')
        # TODO here there's a bug
        temp_w = tests.get('W', '')
        if temp_w == '':
            self.w = temp_w
        else:
            self.w = int(temp_w)
        self.s = tests.get('S', '')
        self.a = tests.get('A', '')
        self.f = tests.get('F', '')
        self.o = tests.get('O', '')
        self.rd = tests.get('RD', '')
        self.q = tests.get('Q', '')

    # TODO somehow consider the following:
    # To reduce this problem, reference fingerprints generally omit the R=Y test from the IE and U1 probes,
    # which are the ones most likely to be dropped. In addition, if Nmap is missing a closed TCP port for a target,
    # it will not set R=N for the T5, T6, or T7 tests even if the port it tries is non-responsive.
    # After all, the lack of a closed port may be because they are all filtered.

    @staticmethod
    def calculate_tcp_flags(t_check):
        return t_check.get_tcp_flags()

    @staticmethod
    # Tested according to TCP acknowledgment number (A)
    # in documentation: https://nmap.org/book/osdetect-methods.html#osdetect-tbl-o
    # This test is the same as S except that it tests how the acknowledgment number in the response compared
    # to the sequence number in the respective probe.
    def calculate_ack_number(t_check):
        response_ack_num = t_check.get_response_ack_number()
        probe_seq_num = t_check.get_probe_sequence_number()

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
    # Tested according to TCP sequence number (S)
    # in documentation: https://nmap.org/book/osdetect-methods.html#osdetect-tbl-o
    # This test examines the 32-bit sequence number field in the TCP header.
    # Rather than record the field value as some other tests do,
    # this one examines how it compares to the TCP acknowledgment number from the probe that elicited the response.
    def calculate_sequence_number(t_check):
        probe_ack_num = t_check.get_probe_ack_number()
        response_seq_num = t_check.get_response_sequence_number()

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


