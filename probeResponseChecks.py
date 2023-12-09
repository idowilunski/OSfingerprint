import math
from probesSender import *
from math import gcd, sqrt, log2
import logging

# TODO add classes for ECN, T1..T7 (maybe inheritance? think afterwards), U1, IE with format
# TODO think maybe to inherit the format function as abc ?


# This class is used for running all the tests on received packets and storing the results in the class variables
class ResponseChecker:
    def __init__(self):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        self._dfi = None
        self._cc = None
        self._q = None
        # TODO - combine these values somehow with Ido's fingerprint class

    # TODO maybe move this out?
    # runs the sequence (SEQ) check -
    # According to the following documentation: https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
    # The SEQ test sends six TCP SYN packets to an open port of the target machine and collects SYN/ACK packets back
    # This function runs all the tests on the 6 TCP probes sent to the open port and parses the results
    def run_check(self, probe_sender, icmp_sender, tcp_open_port_sender, tcp_close_port_sender, ecn_sender):
        min_responses_num_ci = 2
        self.calculate_ti_ci_ii(tcp_close_port_sender, min_responses_num_ci)

        # TODO here also IP initial time-to-live (T) and IP initial time-to-live guess (TG)
        self.calculate_congestion_notification(ecn_sender)

    def calculate_congestion_notification(self, ecn_sender):
        ecn_check = ecn_sender.get_checks_list()[0]
        is_ece = ecn_check.is_response_ece_set()
        is_cwr = ecn_check.is_response_cwr_set()
        # Only the ECE bit is set (not CWR). This host supports ECN.
        if is_ece and not is_cwr:
            self._cc = 'Y'
            return
        # Neither of these two bits is set. The target does not support ECN.
        if not is_ece and not is_cwr:
            self._cc = 'N'
            return
        # Both bits are set. The target does not support ECN, but it echoes back what it thinks is a reserved bit.
        if is_ece and is_cwr:
            self._cc = 'S'
            return
        # The one remaining combination of these two bits (other).
        return 'O'

    def calculate_responsiveness(self, probe_sender):
        pass
    # TODO - impl and document according to Responsiveness (R)

    @staticmethod
    # Calculate the TI/CI/II results
    # According to the following documentation, under "IP ID sequence generation algorithm (TI, CI, II)" :
    # https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
    # TODO - Note that difference values assume that the counter can wrap.
    #  So the difference between an IP ID of 65,100 followed by a value of 700 is 1,136.
    #  The difference between 2,000 followed by 1,100 is 64,636. Here are the calculation details:
    #  we still didn't treat this case in our code
    def calculate_ti_ci_ii(probe_sender, min_responses_num):
        count_non_empty_responses = sum(not check.is_response_packet_empty() for check in probe_sender.get_checks_list())

        #  at least three responses must be received for the test to be included for TI,
        # at least 2 for CI, and 2 for II
        if count_non_empty_responses < min_responses_num:
            raise f"Not enough responses were received: {count_non_empty_responses}"

        all_zero_ids = all(check.get_ip_id() != 0 for check in probe_sender.get_checks_list())
        if all_zero_ids:
            return 'Z'

        max_difference = 0

        for i in range(len(probe_sender.get_checks_list()) - 1):
            difference = abs(probe_sender.get_checks_list()[i + 1] - probe_sender.get_checks_list()[i])
            max_difference = max(max_difference, difference)

        # TODO - make sure for ii it can't be returned.
        if max_difference >= 20000:
            return 'RD' # Random

        # If all of the IP IDs are identical, the test is set to that value in hex.
        are_all_identical = all(x == probe_sender.get_checks_list()[0] for x in probe_sender.get_checks_list())
        if are_all_identical:
            return hex(probe_sender.get_checks_list()[0])

        for i in range(len(probe_sender.get_checks_list()) - 1):
            difference = abs(probe_sender.get_checks_list()[i + 1] - probe_sender.get_checks_list()[i])

            # If any of the differences between two consecutive IDs exceeds 1,000, and is not evenly divisible by 256,
            # the test's value is RI (random positive increments)
            if difference > 1000 and difference % 256 != 0:
                return 'RI'
            # If the difference is evenly divisible by 256, it must be at least 256,000 to cause this RI result.
            elif difference % 256 == 0 and difference >= 256000:
                return 'RI'

            # TODO - how do we verify if documentation means consecutive differences here or not?

        # If all of the differences are divisible by 256 and no greater than 5,120, the test is set to BI
        # (broken increment).
        # This happens on systems like Microsoft Windows where the IP ID is sent in host byte order rather
        # than network byte order. It works fine and isn't any sort of RFC violation,
        # though it does give away host architecture details which can be useful to attackers.
        all_divisible_by_256 = all(
            abs(probe_sender.get_checks_list()[i + 1] - probe_sender.get_checks_list()[i]) % 256 == 0
            for i in range(len(probe_sender.get_checks_list()) - 1))

        if all_divisible_by_256 and max_difference < 5120:
            return 'BI'

        # If all of the differences are less than ten, the value is I (incremental). We allow difference up to ten here
        # (rather than requiring sequential ordering) because traffic from other hosts can cause sequence gaps.
        all_less_than_ten = all(abs(probe_sender.get_checks_list()[i + 1] - probe_sender.get_checks_list()[i]) < 10
                                for i in range(len(probe_sender.get_checks_list()) - 1))
        if all_less_than_ten:
            return 'I'

        # If none of the previous steps identify the generation algorithm, the test is omitted from the fingerprint.
        return None

    # TODO - CI is from the responses to the three TCP probes sent to a closed port: T5, T6, and T7.
    #  II comes from the ICMP responses to the two IE ping probes
