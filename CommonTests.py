import binascii

import PacketParsingUtils


class CommonTests:
    """
        Class containing common tests and calculations for our network fingerprints tests, used in several classes.
    """

    @staticmethod
    def calculate_quirks(check):
        """
                Calculate TCP miscellaneous quirks (Q) based on the response of the input check.
                Implemented according to matching nmap documentation :
                https://nmap.org/book/osdetect-methods.html#osdetect-tbl-o

                Parameters:
                - check: An instance of Check representing the check's response.

                Returns:
                A string representing the calculated quirks (Q). Generated in alphabetical order,
                if no quirks are present - empty string (but still shown).
        """
        q_result = ""
        response_packet = check.get_response_packet()
        #  Add "R" if reserved field is set in the TCP header
        #  (likely to happen in response to the ECN test as that one sets a reserved bit in the probe).
        if PacketParsingUtils.is_reserved_bit_set(response_packet):
            q_result += "R"

        # Add "U" if urgent pointer is nonzero when the URG flag is not set.
        # (likely to be seen in response to the ECN test as that one sets a non-zero urgent field).
        if PacketParsingUtils.is_urgent_bit_set(response_packet):
            q_result += "U"

        return q_result

    @staticmethod
    def calculate_o(check):
        """
        Calculate TCP options (O, O1-O6) based on the response of a check.
        According to the following documentation, under "TCP options (O, O1–O6)":
        https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq

        Parameters:
        - check: An instance of TCheck representing the response of a check.

        Returns:
        A string representing the calculated TCP options.
        If there are no TCP options in a response, the test will exist but the value string will be empty.
        If no probe was returned, the test is omitted.
        """
        return ''.join(
                [CommonTests.format_option(opt) for opt in
                 PacketParsingUtils.get_packet_tcp_options(check.get_response_packet())])

    @staticmethod
    def format_option(option):
        """
            Format a single TCP option for inclusion in the calculated options string.

            Parameters:
            - option: A tuple representing the TCP option (type, value).

            Returns:
            A string representing the formatted TCP option.
        """
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
        """
            Calculate the TCP window size based on the response of a check.

            Parameters:
            - check: An instance of Check representing the response of a check.

            Returns:
            The calculated TCP window size.
        """
        return PacketParsingUtils.get_received_window_size(check.get_response_packet())

    @staticmethod
    def calculate_responsiveness(check):
        """
        Calculate the responsiveness (Y/N) based on the response of a check.

        Parameters:
        - check: An instance of Check representing the response of a check.

        Returns:
        A string representing the calculated responsiveness (Y/N).
        """
        return 'Y' if check.get_response_packet() is not None else 'N'

    @staticmethod
    def calculate_rd(probe_sender):
        """
        Calculate the TCP RST data checksum (RD) based on the response of a probe sender.
        According to the following NMAP documentation, under "TCP RST data checksum (RD)" :
        https://nmap.org/book/osdetect-methods.html#osdetect-tbl-o
        There's no standard for the ASCII text of the RST, it can contain an explanation of the cause

        Parameters:
        - probe_sender: An instance of a probe sender.

        Returns:
        The calculated TCP RST data checksum (RD).
        """
        response_data = probe_sender.get_checks_list()[0].get_response_packet()
        return binascii.crc32(response_data.original) if response_data else 0

    @staticmethod
    def calculate_dont_fragment(check):
        """
        Calculate the value of the Don't Fragment (DF) bit based on the response of a check.

        Parameters:
        - check: An instance of Check representing the response of a check.

        Returns:
        The value of the Don't Fragment (DF) bit.
        """
        return PacketParsingUtils.get_dont_fragment_bit_value(check.get_response_packet())

    @staticmethod
    def calculate_ttl_diff(check):
        """
        Calculate the Time-to-Live (TTL) difference based on the response of a check.

        Parameters:
        - check: An instance of Check representing the response of a check.

        Returns:
        The calculated TTL difference.
        """
        return 0XFF - PacketParsingUtils.get_packet_ttl(check.get_response_packet())

    @staticmethod
    def calculate_ttl_guess(check):
        """
        Calculate the guessed TTL value based on the response of a check.

        Parameters:
        - check: An instance of Check representing the response of a check.

        Returns:
        The calculated guessed TTL value.
        """
        return CommonTests.round_up_to_nearest(0XFF - PacketParsingUtils.get_packet_ttl(check.get_response_packet()))

    @staticmethod
    def round_up_to_nearest(value):
        """
        Round up a value to the nearest possible value from a predefined list from nmap documentation.

        Parameters:
        - value: The value to round up.

        Returns:
        The rounded-up value.
        """
        possible_values = [32, 64, 128, 255]

        # Find the next highest value
        return min(possible_values, key=lambda x: (x - value) if x >= value else float('inf'))
