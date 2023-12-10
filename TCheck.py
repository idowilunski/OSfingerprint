from CommonTests import *


class TCheck:
    def __init__(self):
        self.r = None
        self.df = None
        self.t = None
        self.tg = None # TODO impl IP initial time-to-live guess (TG)
        self.w = None
        self.s = None
        self.a = None
        self.f = None
        self.o = None
        self.rd = None
        self.q = None

    def __eq__(self, other):
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
        if self.s != other.s:
            return False
        if self.a != other.a:
            return False
        if self.f != other.f:
            return False
        if self.o != other.o:
            return False
        if self.rd != other.rd:
            return False
        if self.q != other.q:
            return False
        return True

    def init_from_response(self, t_check):
        self.r = CommonTests.calculate_responsiveness(t_check)
        self.df = CommonTests.calculate_dont_fragment(t_check)
        self.t = self.calculate_initial_ttl(t_check)
        self.tg = None  # TODO impl IP initial time-to-live guess (TG)
        self.w = CommonTests.calculate_window_size(t_check)
        self.s = self.calculate_sequence_number(t_check)
        self.a = self.calculate_ack_number(t_check)
        self.f = self.calculate_tcp_flags(t_check)
        self.o = CommonTests.calculate_o(t_check)
        self.rd = CommonTests.calculate_rd(t_check)
        self.q = CommonTests.calculate_quirks(t_check)

    def init_from_db(self, tests: dict):
        self.r = tests.get('R', '')
        self.df = tests.get('DF', '')
        self.t = tests.get('T', '')
        self.tg = tests.get('TG', '')
        self.w = tests.get('W', '')
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

    # Calculate IP initial time-to-live (T)
    # in documentation: https://nmap.org/book/osdetect-methods.html#osdetect-tbl-o
    # Nmap determines how many hops away it is from the target by examining the ICMP port unreachable response
    # to the U1 probe.
    # That response includes the original IP packet, including the already-decremented TTL field, received by the target
    # . By subtracting that value from our as-sent TTL, we learn how many hops away the machine is. Nmap then adds that
    # hop distance to the probe response TTL to determine what the initial TTL was when that ICMP probe response packet
    # was sent. That initial TTL value is stored in the fingerprint as the T result.
    # Even though an eight-bit field like TTL can never hold values greater than 0xFF, this test occasionally results in
    # values of 0x100 or higher. This occurs when a system (could be the source, a target, or a system in between)
    # corrupts or otherwise fails to correctly decrement the TTL. It can also occur due to asymmetric routes
    # Nmap can also learn from the system interface and routing tables when the hop distance is zero (localhost scan)
    # or one (on the same network segment). This value is used when Nmap prints the hop distance for the user,
    # but it is not used for T result computation.
    # TODO impl
    @staticmethod
    def calculate_initial_ttl(t_check):
        return ""

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


