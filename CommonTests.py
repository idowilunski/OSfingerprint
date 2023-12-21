import binascii


class CommonTests:
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
        if t1_check.is_response_urgent_bit_set():
            q_result += "U"

        return q_result

    # According to the following documentation, under "TCP options (O, O1–O6)":
    # https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
    #  If there are no TCP options in a response, the test will exist but the value string will be empty.
    #  If no probe was returned, the test is omitted.
    @staticmethod
    def calculate_o(check):
        if not check.is_response_packet_empty():
            return ''.join(
                [CommonTests.format_option(opt) for opt in check.get_received_tcp_options()])

    @staticmethod
    def format_option(option):
        option_type, option_value = option
        if option_type == "EOL":
            return "L"
        elif option_type == "NOP":
            return "N"
        elif option_type == "MSS":
            return f"M{option_value:04X}"
        elif option_type == "WScale":
            return f"W{option_value}"
        elif option_type == "TS":
            ts_val, ts_ecr = option_value
            return f"T{int(ts_val != 0)}{int(ts_ecr != 0)}"
        elif option_type == "SAckOK":
            return "S"
        else:
            return f"Unknown Option - Type: {option_type}, Value: {option_value}"

    @staticmethod
    def calculate_window_size(check):
        return check.get_received_window_size()

    @staticmethod
    # TODO add calc that if responsiveness is 'N' don't compare the rest...?
    def calculate_responsiveness(check):
        if check.is_response_packet_empty():
            return 'N'
        return 'Y'

    @staticmethod
    # TODO - I'm not sure when we encounter RST packets ? what's the probe sender here, the closed ports?
    # Calculate te RD - TCP RST data checksum (RD)
    # According to the following documentation, under "TCP RST data checksum (RD)" :
    # https://nmap.org/book/osdetect-methods.html#osdetect-tbl-o
    # RST segment could contain ASCII text that encoded and explained the cause of the RST.
    # No standard has yet been established for such data.
    # Do CRC32 checksum and set RD
    def calculate_rd(probe_sender):
        response_data = probe_sender.get_checks_list[0].get_data()
        if len(response_data) == 0:
            return 0
        return binascii.crc32(response_data)

    @staticmethod
    def calculate_dont_fragment(check):
        return check.is_dont_fragment_bit_set()
