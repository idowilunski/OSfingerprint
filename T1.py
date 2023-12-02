class T1:
    def __init__(self, t1_check):
        self._r = None
        self._df = None
        self._t = None
        self._tg = None
        self._s = None
        self._a = None
        self._f = None
        self._rd = None
        self._q = self.calculate_quirks(t1_check)

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


