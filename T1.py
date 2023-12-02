# TODO - somehow implement the same for t2, t3, ...t7 ?
# TODO - ECN looks the same but
class T1:
    def __init__(self, t1_check):
        self._r = None #TODO impl responsiveness test
        self._df = self.calculate_dont_fragment(t1_check)
        self._w = None # TODO 
        self._t = None # TODO impl IP initial time-to-live (T)
        self._tg = None # TODO impl IP initial time-to-live guess (TG)
        self._s = self.calculate_sequence_number(t1_check)
        self._a = self.calculate_ack_number(t1_check)
        self._f = self.calculate_tcp_flags(t1_check)
        self._rd = None # TODO impl TCP RST data checksum (RD)
        self._q = self.calculate_quirks(t1_check)

    @staticmethod
    def calculate_tcp_flags(t1_check):
        return t1_check.get_tcp_flags()

    # TODO impl
    @staticmethod
    def calculate_ip_dont_fragment(t1_check):
        pass
    # TODO get is_dont_fragment_bit_set from the checks[0]...[-1]

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


