from CommonTests import *


# TODO - somehow implement the same for t2, t3, ...t7 ?
# TODO - ECN looks the same but
class T1:
    # TODO - move optiosn, t1, etc to one folder and packets and sender to other folder
    # TODO - also add CTOR with values you can just add in, that way it'll come together with Ido's code of the db parsing
    def __init__(self, t1_check):
        self._r = CommonTests.calculate_responsiveness(t1_check)
        self._df = CommonTests.calculate_dont_fragment(t1_check)
        self._t = self.calculate_initial_ttl(t1_check)
        self._tg = None # TODO impl IP initial time-to-live guess (TG)
        self._w = CommonTests.calculate_window_size(t1_check)
        self._s = self.calculate_sequence_number(t1_check)
        self._a = self.calculate_ack_number(t1_check)
        self._f = self.calculate_tcp_flags(t1_check)
        self._o = None # TODO
        self._rd = CommonTests.calculate_rd(t1_check)
        self._q = self.calculate_quirks(t1_check)

    # TODO somehow consider the following:
    # To reduce this problem, reference fingerprints generally omit the R=Y test from the IE and U1 probes,
    # which are the ones most likely to be dropped. In addition, if Nmap is missing a closed TCP port for a target,
    # it will not set R=N for the T5, T6, or T7 tests even if the port it tries is non-responsive.
    # After all, the lack of a closed port may be because they are all filtered.

    # Calculate IP initial time-to-live (T)
    # in documentation: https://nmap.org/book/osdetect-methods.html#osdetect-tbl-o
    # Nmap determines how many hops away it is from the target by examining the ICMP port unreachable response to the U1 probe.
    # That response includes the original IP packet, including the already-decremented TTL field, received by the target. By subtracting that value from our as-sent TTL, we learn how many hops away the machine is. Nmap then adds that hop distance to the probe response TTL to determine what the initial TTL was when that ICMP probe response packet was sent. That initial TTL value is stored in the fingerprint as the T result.
    #
    # Even though an eight-bit field like TTL can never hold values greater than 0xFF, this test occasionally results in values of 0x100 or higher. This occurs when a system (could be the source, a target, or a system in between) corrupts or otherwise fails to correctly decrement the TTL. It can also occur due to asymmetric routes.
    #
    # Nmap can also learn from the system interface and routing tables when the hop distance is zero (localhost scan) or one (on the same network segment). This value is used when Nmap prints the hop distance for the user, but it is not used for T result computation.
    # TODO impl
    @staticmethod
    def calculate_initial_ttl(t1_check):
        return ""

    @staticmethod
    def calculate_tcp_flags(t1_check):
        return t1_check.get_tcp_flags()

    @staticmethod
    # Tested according to TCP acknowledgment number (A)
    # in documentation: https://nmap.org/book/osdetect-methods.html#osdetect-tbl-o
    # This test is the same as S except that it tests how the acknowledgment number in the response compared
    # to the sequence number in the respective probe.
    def calculate_ack_number(t1_check):
        response_ack_num = t1_check.get_response_ack_number()
        probe_seq_num = t1_check.get_probe_sequence_number()

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
    def calculate_sequence_number(t1_check):
        probe_ack_num = t1_check.get_probe_ack_number()
        response_seq_num = t1_check.get_response_sequence_number()

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

    # TCP miscellaneous quirks (Q)
    # Implemented according to matching nmap documentation : https://nmap.org/book/osdetect-methods.html#osdetect-tbl-o
    @staticmethod
    def calculate_quirks(t1_check):
        # The Q string must always be generated in alphabetical order. If no quirks are present,
        # the Q test is empty but still shown.
        q_result = ""
        #  The first is that the reserved field in the TCP header (right after the header length) is nonzero.
        #  This is particularly likely to happen in response to the ECN test as that one sets a reserved bit
        #  in the probe.
        #  If this is seen in a packet, an “R” is recorded in the Q string.
        if t1_check.is_response_reserved_bit_set():
            q_result += "R"
        # Check for nonzero urgent pointer field value when the URG flag is not set.
        # This is also particularly likely to be seen in response to the ECN probe, which sets a non-zero urgent field.
        # A “U” is appended to the Q string when this is seen.
        if t1_check.is_urgent_bit_set():
            q_result += "U"

        return q_result


