
class Options:
    def __init__(self, probe_sender):
        self._o1 = None
        self._o2 = None
        self._o3 = None
        self._o4 = None
        self._o5 = None
        self._o6 = None
        self.calculate_o(probe_sender)

    # According to the following documentation, under "TCP options (O, O1–O6)":
    # https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
    def calculate_o(self, probe_sender):
        #  If there are no TCP options in a response, the test will exist but the value string will be empty.
        #  If no probe was returned, the test is omitted.
        checks_list = probe_sender.get_checks_list()
        if not checks_list[0].is_response_packet_empty():
            self._o1 = ''.join(
                [self.format_option(opt) for opt in checks_list[0].get_received_tcp_options()])
        if not checks_list[1].is_response_packet_empty():
            self._o2 = ''.join(
                [self.format_option(opt) for opt in checks_list[1].get_received_tcp_options()])
        if not checks_list[2].is_response_packet_empty():
            self._o3 = ''.join(
                [self.format_option(opt) for opt in checks_list[2].get_received_tcp_options()])
        if not checks_list[3].is_response_packet_empty():
            self._o4 = ''.join(
                [self.format_option(opt) for opt in checks_list[3].get_received_tcp_options()])
        if not checks_list[4].is_response_packet_empty():
            self._o5 = ''.join(
                [self.format_option(opt) for opt in checks_list[4].get_received_tcp_options()])
        if not checks_list[5].is_response_packet_empty():
            self._o6 = ''.join(
                [self.format_option(opt) for opt in checks_list[5].get_received_tcp_options()])

    @staticmethod
    def format_option(option):
        option_type, option_value = option
        if option_type == "EOL":
            return "L"
        elif option_type == "NOP":
            return "N"
        elif option_type == "MSS":
            return f"M{option_value:04X}"
        elif option_type == "WS":
            return f"W{option_value}"
        elif option_type == "TS":
            ts_val, ts_ecr = option_value
            return f"T{int(ts_val != 0)}{int(ts_ecr != 0)}"
        elif option_type == "SACK":
            return "S"
        else:
            return f"Unknown Option - Type: {option_type}, Value: {option_value}"
