import math
from probesSender import *
from math import gcd, sqrt, log2
import logging


class ProbeResponseChecker:
    def __init__(self):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        self._gcd_value = 0
        self._seq_rates = []
        self._diff1 = [] # Differences list, diff1 is the name in the nmap documentation reference
        self._isr = None
        self._sp = None
        self._ss = None
        self._ts = None

    @staticmethod
    def find_gcd_of_list(num_list):
        if not num_list:
            return None  # Handle empty list case

        result_gcd = num_list[0]

        for num in num_list[1:]:
            result_gcd = math.gcd(result_gcd, num)

        return result_gcd

    # runs the sequence (SEQ) check -
    # According to the following documentation: https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
    # The SEQ test sends six TCP SYN packets to an open port of the target machine and collects SYN/ACK packets back
    # This function runs all the tests on the 6 TCP probes sent to the open port and parses the results
    def run_check(self, probe_sender):
        # TODO - for II and CI it will be 2
        min_responses_num = 3
        self.calculate_gcd(probe_sender)
        self.calculate_isr(probe_sender)
        self.calculate_sp(probe_sender)
        self.calculate_ss()
        self.calculate_ts(probe_sender)
        self.calculate_ti_ci_ii(probe_sender, min_responses_num)

    # Calculate the TS - TCP timestamp option algorithm (TS) (TS)
    # According to the following documentation, under "TCP timestamp option algorithm (TS)" :
    # https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
    def calculate_ts(self, probe_sender):
        timestamp_increments_per_sec = []
        # This one looks at the TCP timestamp option (if any) in responses to the SEQ probes.
        # It examines the TSval (first four bytes of the option) rather than the echoed TSecr (last four bytes) value.

        for i in range(len(probe_sender.get_checks_list()) - 1):
            first_timestamp = probe_sender.get_checks_list()[i].get_send_time()
            if not first_timestamp:
                raise
            second_timestamp = probe_sender.get_checks_list()[i + 1].get_send_time()
            if not second_timestamp:
                raise

            # Since we're going by order, second send time is always after the first
            if not second_timestamp > first_timestamp:
                raise

            first_tsval = probe_sender.get_checks_list()[i].get_response_tsval()
            second_tsval = probe_sender.get_checks_list()[i + 1].get_response_tsval()

            # If any of the responses have no timestamp option, TS is set to U (unsupported).
            if not first_tsval or not second_tsval:
                self._ts = "U"
                self.logger.info(f"TS: {self._ts}")
                return

            # If any of the timestamp values are zero, TS is set to 0.
            if first_tsval == 0 or second_tsval == 0:
                self._ts = 0
                self.logger.info(f"TS: {self._ts}")
                return


            # TODO - this is code duplication from isr calc, consider adding timestamp sending diff list in "self"
            time_difference = (second_timestamp - first_timestamp).total_seconds()
            tsval_difference = (second_tsval - first_tsval)

            # It takes the difference between each consecutive TSval and divides that by the amount
            # of time elapsed between Nmap sending the two probes which generated those responses
            timestamp_increments_per_sec.append(tsval_difference / float(time_difference))

        # The resultant value gives a rate of timestamp increments per second,
        # Nmap computes the average increments per second over all consecutive probes
        average_value = sum(timestamp_increments_per_sec) / len(timestamp_increments_per_sec)

        # The following ranges get special treatment because they correspond to the 2 Hz, 100 Hz, and 200 Hz frequencies
        # If the average increments per second falls within the range 0-5, TS is set to 1.
        if 0 <= average_value <= 5.66:
            self._ts = 1
            self.logger.info(f"TS: {self._ts}")
            return
        elif 70 <= average_value <= 150:
            self._ts = 7
            self.logger.info(f"TS: {self._ts}")
            return
        elif 150 <= average_value <= 350:
            self._ts = 8
            self.logger.info(f"TS: {self._ts}")
            return

        # In all other cases, Nmap records the binary logarithm of the average increments per second,
        # rounded to the nearest integer. Since most hosts use 1,000 Hz frequencies, A is a common result.
        binary_log = math.log2(average_value)
        self._ts = round(binary_log)
        self.logger.info(f"TS: {self._ts}")

    # Calculate the TI/CI/II results
    # According to the following documentation, under "IP ID sequence generation algorithm (TI, CI, II)" :
    # https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
    # TODO - Note that difference values assume that the counter can wrap.
    #  So the difference between an IP ID of 65,100 followed by a value of 700 is 1,136.
    #  The difference between 2,000 followed by 1,100 is 64,636. Here are the calculation details:
    #  we still didn't treat this case in our code
    def calculate_ti_ci_ii(self, probe_sender, min_responses_num):
        count_non_empty_responses = sum(not check.is_response_packet_empty() for check in probe_sender.get_checks_list())

        #  at least three responses must be received for the test to be included for TI,
        # at least 2 for CI, and 2 for II
        if count_non_empty_responses < min_responses_num:
            self.logger.info(f"Not enough responses were received: {count_non_empty_responses}")
            return

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

    # TODO - write the same function for the ICMP packet and the TCP probes t5-t7
    # TODO - CI is from the responses to the three TCP probes sent to a closed port: T5, T6, and T7.
    #  for CI, at least two responses are required; and for II, both ICMP responses must be received.
    #  II comes from the ICMP responses to the two IE ping probes



    # Calculate the SS - Shared IP ID sequence Boolean (SS)
    # According to the following documentation, under "Shared IP ID sequence Boolean (SS)" :
    # https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
    def calculate_ss(self):
        pass
        # TODO - can't implement this yet since I didn't implement the ICMP requests

    # Calculate the GCD (the greatest common divisor) from the 32-bit ISN
    # According to the following documentation, under "TCP ISN greatest common divisor (GCD)":
    # https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
    # This test attempts to determine the smallest number by which the target host increments these values.
    def calculate_gcd(self, probeSender):
        # TODO - make sure we've received here a non-empty response, and only if so, add it in the calculation?
        for i in range(len(probeSender.get_checks_list()) - 1):
            first_isn = probeSender.get_checks_list()[i].get_isn()
            if not first_isn:
                raise
            second_isn = probeSender.get_checks_list()[i + 1].get_isn()
            if not second_isn:
                raise

            # If an ISN is lower than the previous one, Nmap looks at both the number of values it would have to
            # subtract from the first value to obtain the second, and the number of values it would have to count up
            # (including wrapping the 32-bit counter back to zero). The smaller of those two values is stored in diff1.

            # Calculate the absolute difference
            absolute_difference = abs(first_isn - second_isn)

            # Check if the ISN wrapped around
            wrapped_around_difference = (1 << 32) - absolute_difference

            # Choose the smaller of the two differences
            final_difference = min(absolute_difference, wrapped_around_difference)

            self.logger.debug(f"Appending diff between {first_isn} and {second_isn}: {final_difference}")
            self._diff1.append(final_difference)

        # Note: before python 3.9 usage of list in gcd function won't be supported, make sure you've installed the
        # environment from the requirements.txt
        # TODO make it work somehow either with 3.7 or download 3.9
        if len(self._diff1) > 0:
            self._gcd_value = ProbeResponseChecker.find_gcd_of_list(self._diff1)
            self.logger.info(f"GCD: {self._gcd_value}")

        # TODO add UT that does the following:
        #  So the difference between 0x20000 followed by 0x15000 is 0xB000.
        #  The difference between 0xFFFFFF00 and 0xC000 is 0xC0FF.
        #  This test value then records
        #  the greatest common divisor of all those elements. This GCD is also used for calculating the SP result.

    # Calculate ISR (ISN counter rate)
    # # According to the following documentation, under "TCP ISN counter rate (ISR)":
    # https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
    # This value reports the average rate of increase for the returned TCP initial sequence number.
    def calculate_isr(self, probeSender):
        for i in range(len(probeSender.get_checks_list()) - 1):
            first_timestamp = probeSender.get_checks_list()[i].get_send_time()
            if not first_timestamp:
                raise
            second_timestamp = probeSender.get_checks_list()[i + 1].get_send_time()
            if not second_timestamp:
                raise

            # Since we're going by order, second send time is always after the first
            if not second_timestamp > first_timestamp:
                raise

            time_difference = (second_timestamp - first_timestamp).total_seconds()

            #  Those differences are each divided by the amount of time elapsed
            #  (in seconds—will generally be about 0.1) between sending the two probes which generated them.
            #  The result is an array, which we'll call seq_rates,
            #  containing the rates of ISN counter increases per second.

            self._seq_rates.append(self._diff1[i] / float(time_difference))

        # Calculate the average of self._seq_rates
        average_value = sum(self._seq_rates) / len(self._seq_rates)

        # Determine ISR based on the average value
        if average_value < 1:
            self._isr = 0
        else:
            self._isr = round(8 * math.log2(average_value))

        self.logger.info(f"ISR: {self._isr}")

    # Calculate SP (sequence predictability)
    # # According to the following documentation, under "TCP ISN sequence predictability index (SP)":
    # https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
    # estimates how difficult it would be to predict the next ISN from the
    # known sequence of six probe responses
    def calculate_sp(self, probeSender):
        count_non_empty_responses = sum(not check.is_response_packet_empty() for check in probeSender.get_checks_list())

        # This test is only performed if at least four responses were seen.
        if count_non_empty_responses < 4:
            return None

        # TODO remove magic numbers

        #  If the previously computed GCD value is greater than nine,
        #  the elements of the previously computed seq_rates array are divided by that value.
        #  We don't do the division for smaller GCD values because those are usually caused by chance.
        if self._gcd_value and self._gcd_value > 9:
            # Divide elements of seq_rates by the GCD value
            normalized_seq_rates = [rate / self._gcd_value for rate in self._seq_rates]

            # Calculate the standard deviation of the normalized_seq_rates
            std_dev = math.sqrt(sum(
                (x - sum(normalized_seq_rates) / len(normalized_seq_rates)) ** 2 for x in normalized_seq_rates) / len(
                normalized_seq_rates))

            # Check if the standard deviation is one or less
            if std_dev <= 1:
                self._sp = 0
                self.logger.info(f"SP: {self._sp}")
            else:
                # Compute the binary logarithm of the standard deviation
                log_std_dev = math.log2(std_dev)

                # Multiply by eight, round to the nearest integer, and store as SP
                self._sp = round(log_std_dev * 8)
                self.logger.info(f"SP: {self._sp}")



