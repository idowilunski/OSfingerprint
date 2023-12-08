import binascii


class CommonTests:
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
