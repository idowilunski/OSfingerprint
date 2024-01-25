import logging
import math
from ResultLines.IResultLine import *
import PacketParsingUtils
from CommonTests import *


class Sequence(IResultLine):
    """
    Represents the sequence (SEQ) check according to the documentation:
    https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
    The SEQ test sends six TCP SYN packets to an open port of the target machine and collects SYN/ACK packets back

    Attributes:
        seq_rates (list): List to store rates of ISN (Initial Sequence Number) counter increases per second.
        diff1 (list): Differences list for GCD calculation.
        sp: Sequence Predictability result.
        gcd: Greatest Common Divisor (GCD) result.
        isr: ISN counter rate result.
        ti: IP ID sequence generation algorithm result for TCP.
        rd: Router Advertisement (RD) result.
        ci: IP ID sequence generation algorithm result for closed port TCP probes.
        ii: IP ID sequence generation algorithm result for ICMP responses.
        ss: Shared IP ID sequence Boolean result.
        ts: TCP timestamp option algorithm result.

    Methods:
        calculate_similarity_score(self, other) -> int: Calculates the similarity score between two Sequence instances.
        init_from_response(self, packet_sender): Initializes attributes from responses.
        init_from_db(self, tests: dict): Initializes attributes from a dictionary obtained from a database.
        calculate_ts(packet_sender): Calculates the TCP timestamp option algorithm (TS).
        calculate_ss(packet_sender): Calculates the Shared IP ID sequence Boolean (SS).
        find_gcd_of_list(num_list): Finds the Greatest Common Divisor (GCD) of a list of numbers.
        calculate_sp(self, packet_sender): Calculates the Sequence Predictability (SP).
        calculate_gcd(self, packet_sender): Calculates the Greatest Common Divisor (GCD) from the 32-bit ISN.
        calculate_ti_ci_ii(packet_sender, min_responses_num): Calculates the TI/CI/II results.
        calculate_isr(self, packet_sender): Calculates the ISN counter rate (ISR).
    """
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.seq_rates = []
        self.diff1 = []  # Differences list, diff1 is the name in the nmap documentation reference
        self.sp = None
        self.gcd = None
        self.isr = None
        self.ti = None
        self.rd = None
        self.ci = None
        self.ii = None
        self.ss = None
        self.ts = None

    def calculate_similarity_score(self, other) -> int:
        """
        Calculates the similarity score between two Sequence instances.

        Args:
            other (Sequence): Another Sequence instance to compare.

        Returns:
            int: The similarity score between the two instances.
        """
        score = 0
        if self.sp == other.sp:
            score += 25
        if self.gcd == other.gcd:
            score += 75
        if self.isr == other.isr:
            score += 25
        if self.ti == other.ti:
            score += 100
        if self.ci == other.ci:
            score += 50
        if self.ii == other.ii:
            score += 100
        if self.ss == other.ss:
            score += 80
        if self.ts == other.ts:
            score += 100
        return score

    def init_from_response(self, packet_sender):
        """
        Initializes Sequence attributes from Senders instances.

        Args:
            packet_sender (TSender): instance containing responses to the checks.

        Returns:
            None
        """
        self.sp = self.calculate_sp(packet_sender)
        self.gcd = self.calculate_gcd(packet_sender)
        self.isr = self.calculate_isr(packet_sender)
        self.ti = self.calculate_ti_ci_ii(packet_sender.get_probe_checks_list(), 3)
        self.rd = CommonTests.calculate_rd(packet_sender.get_probe_checks_list()[0])
        self.ci = self.calculate_ti_ci_ii(packet_sender.get_close_port_checks_list(), 2)
        self.ii = self.calculate_ti_ci_ii(packet_sender.get_icmp_checks_list(), 2)
        self.ss = self.calculate_ss(packet_sender)
        self.ts = self.calculate_ts(packet_sender)

    def init_from_db(self, tests: dict):
        """
        Initializes Sequence attributes from a dictionary obtained from the NMAP database.

        Args:
            tests (dict): Dictionary containing information retrieved from the NMAP database.

        Returns:
            None
        """
        self.sp = tests.get('SP', None)
        self.gcd = tests.get('GCD', None)
        self.isr = tests.get('ISR', None)
        self.ti = tests.get('TI', None)
        self.rd = tests.get('RD', None)
        self.ci = tests.get('CI', None)
        self.ii = tests.get('II', None)
        self.ss = tests.get('SS', None)
        self.ts = tests.get('TS', None)

    @staticmethod
    def calculate_ts(packet_sender):
        """
        Calculates the TCP timestamp option algorithm (TS).
        According to the following documentation, under "TCP timestamp option algorithm (TS)" :
        https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq

        Args:
            packet_sender (TSender): TSender instance containing responses to all checks.

        Returns:
            int or str: ResultLines of the TCP timestamp option algorithm.
        """
        timestamp_increments_per_sec = []
        for i in range(len(packet_sender.get_probe_checks_list()) - 1):
            # Verify both timestamp were recorded upon send
            first_timestamp = packet_sender.get_probe_checks_list()[i].get_send_time()
            second_timestamp = packet_sender.get_probe_checks_list()[i + 1].get_send_time()
            if not first_timestamp or not second_timestamp:
                raise

            # Since we're going by order, second send time is always after the first
            if not second_timestamp > first_timestamp:
                raise

            first_tsval = PacketParsingUtils.get_packet_tsval(packet_sender.get_probe_checks_list()[i].get_response_packet())
            second_tsval = PacketParsingUtils.get_packet_tsval(packet_sender.get_probe_checks_list()[i + 1].get_response_packet())

            # If any of the responses have no timestamp option, TS is set to U (unsupported).
            if not first_tsval or not second_tsval:
                return "U"

            # If any of the timestamp values are zero, TS is set to 0.
            if first_tsval == 0 or second_tsval == 0:
                return 0

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
            return 1
        if 70 <= average_value <= 150:
            return 7
        if 150 <= average_value <= 350:
            return 8

        # In all other cases, Nmap records the binary logarithm of the average increments per second,
        # rounded to the nearest integer. Since most hosts use 1,000 Hz frequencies, A is a common result.
        binary_log = math.log2(average_value)
        return round(binary_log)

    @staticmethod
    def calculate_ss(packet_sender):
        """
        Calculates the Shared IP ID sequence Boolean (SS).
        According to the following documentation, under "Shared IP ID sequence Boolean (SS)" :
        https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq

        Args:
            packet_sender: TSender instance containing responses to all checks.

        Returns:
            str: ResultLines of the Shared IP ID sequence Boolean
            (whether the target shares its IP ID sequence between the TCP and ICMP protocols).
        """
        probes_checks = packet_sender.get_probe_checks_list()
        icmp_checks = packet_sender.get_icmp_checks_list()

        avg = (PacketParsingUtils.get_packet_ip_id(probes_checks[-1].get_response_packet())
               - PacketParsingUtils.get_packet_ip_id(probes_checks[0].get_response_packet())) / (6-1)

        # If the first ICMP echo response IP ID is less than the final TCP sequence response IP ID plus three times avg,
        # the SS result is S. Otherwise it is O.
        if PacketParsingUtils.get_packet_ip_id(icmp_checks[0].get_response_packet()) < \
                (PacketParsingUtils.get_packet_ip_id(probes_checks[-1].get_response_packet()) + (3 * avg)):
            return 'S'
        return '0'

    @staticmethod
    def find_gcd_of_list(num_list):
        """
        Finds the Greatest Common Divisor (GCD) of a list of numbers.

        Args:
            num_list (list): List of numbers.

        Returns:
            int or None: Resulting GCD or None if the list is empty.
        """
        if not num_list:
            return None  # Handle empty list case

        result_gcd = num_list[0]

        for num in num_list[1:]:
            result_gcd = math.gcd(result_gcd, num)

        return result_gcd

    def calculate_sp(self, packet_sender):
        """
        Calculates the Sequence Predictability (SP).
        Estimates how difficult it would be to predict the next ISN from the known sequence of six probe responses
        According to the following documentation, under "TCP ISN sequence predictability index (SP)":
        https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq

        Args:
            packet_sender (TSender): TSender instance containing T all responses to checks.

        Returns:
            int or None: ResultLines of the Sequence Predictability.
        """
        count_non_empty_responses = sum(check.get_response_packet() is not None for check in packet_sender.get_probe_checks_list())

        # This test is only performed if at least four responses were seen.
        if count_non_empty_responses < 4:
            return None

        #  If the previously computed GCD value is greater than nine,
        #  the elements of the previously computed seq_rates array are divided by that value.
        #  We don't do the division for smaller GCD values because those are usually caused by chance.
        if self.gcd and self.gcd > 9:
            # Divide elements of seq_rates by the GCD value
            normalized_seq_rates = [rate / self.gcd for rate in self.seq_rates]

            # Calculate the standard deviation of the normalized_seq_rates
            std_dev = math.sqrt(sum(
                (x - sum(normalized_seq_rates) / len(normalized_seq_rates)) ** 2 for x in normalized_seq_rates) / len(
                normalized_seq_rates))

            # Check if the standard deviation is one or less
            if std_dev <= 1:
                return 0
            else:
                # Compute the binary logarithm of the standard deviation
                log_std_dev = math.log2(std_dev)

                # Multiply by eight, round to the nearest integer, and store as SP
                return round(log_std_dev * 8)

    def calculate_gcd(self, packet_sender):
        """
        Calculates the Greatest Common Divisor (GCD) from the 32-bit ISN.
        According to the following documentation, under "TCP ISN greatest common divisor (GCD)":
        https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
        Attempts to determine the smallest number by which the target host increments these values.

        Args:
            packet_sender (TSender): TSender instance containing all responses to checks.

        Returns:
            int or None: Resulting GCD or None if there are no valid differences.
        """
        for i in range(len(packet_sender.get_probe_checks_list()) - 1):
            # Verify both ISNs are present
            first_isn = PacketParsingUtils.get_packet_sequence_number(packet_sender.get_probe_checks_list()[i].get_response_packet())
            second_isn = PacketParsingUtils.get_packet_sequence_number(packet_sender.get_probe_checks_list()[i+1].get_response_packet())
            if not first_isn or not second_isn:
                self.logger.error("First or second ISN is empty")

            # Calculate the absolute difference
            absolute_difference = abs(first_isn - second_isn)

            # Check if the ISN wrapped around
            wrapped_around_difference = (1 << 32) - absolute_difference

            # Choose the smaller of the two differences
            final_difference = min(absolute_difference, wrapped_around_difference)

            self.diff1.append(final_difference)

        # Note: before python 3.9 usage of list in gcd function won't be supported, make sure you've installed the
        # correct python env
        if len(self.diff1) > 0:
            return Sequence.find_gcd_of_list(self.diff1)

    def calculate_ti_ci_ii(self, checks_list, min_responses_num):
        """
        Calculates the TI/CI/II results.
        According to the following documentation, under "IP ID sequence generation algorithm (TI, CI, II)" :
        https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq

        Args:
            checks_list: List of checks containing responses.
            min_responses_num (int): Minimum number of responses required for the test.

        Returns:
            str or None: ResultLines of the TI/CI/II test or None if not enough responses are available.
        """
        count_non_empty_responses = sum(check.get_response_packet() is not None for check in checks_list)

        #  at least three responses must be received for the test to be included for TI,
        # at least 2 for CI, and 2 for II
        if count_non_empty_responses < min_responses_num:
            self.logger.error(f"Not enough responses were received: {count_non_empty_responses}")

        all_zero_ids = all(PacketParsingUtils.get_packet_ip_id(check.get_response_packet()) != 0 for check in checks_list)
        if all_zero_ids:
            return 'Z'

        max_difference = 0

        for i in range(len(checks_list) - 1):
            isn_first = checks_list[i + 1].get_response_sequence_number()
            isn_second = checks_list[i].get_response_sequence_number()
            difference = abs(isn_first - isn_second)
            max_difference = max(max_difference, difference)

        if max_difference >= 20000:
            return 'RD' # Random

        # If all of the IP IDs are identical, the test is set to that value in hex.
        are_all_identical = all(x == checks_list[0] for x in checks_list)
        if are_all_identical:
            return hex(checks_list[0])

        isn_first = checks_list[i + 1].get_response_sequence_number()
        isn_second = checks_list[i].get_response_sequence_number()
        for i in range(len(checks_list) - 1):
            difference = abs(isn_first - isn_second)

            # If any of the differences between two consecutive IDs exceeds 1,000, and is not evenly divisible by 256,
            # the test's value is RI (random positive increments)
            if difference > 1000 and difference % 256 != 0:
                return 'RI'
            # If the difference is evenly divisible by 256, it must be at least 256,000 to cause this RI result.
            elif difference % 256 == 0 and difference >= 256000:
                return 'RI'

        # If all of the differences are divisible by 256 and no greater than 5,120, the test is set to BI
        # (broken increment).
        # This happens on systems like Microsoft Windows where the IP ID is sent in host byte order rather
        # than network byte order. It works fine and isn't any sort of RFC violation,
        # though it does give away host architecture details which can be useful to attackers.
        all_divisible_by_256 = all(
            abs(isn_first - isn_second) % 256 == 0
            for i in range(len(checks_list) - 1))

        if all_divisible_by_256 and max_difference < 5120:
            return 'BI'

        # If all of the differences are less than ten, the value is I (incremental). We allow difference up to ten here
        # (rather than requiring sequential ordering) because traffic from other hosts can cause sequence gaps.
        all_less_than_ten = all(abs(isn_first - isn_second) < 10
                                for i in range(len(checks_list) - 1))
        if all_less_than_ten:
            return 'I'

        # If none of the previous steps identify the generation algorithm, the test is omitted from the fingerprint.
        return None

    def calculate_isr(self, packet_sender):
        """
        Calculates the ISN counter rate (ISR).
        According to the following documentation, under "TCP ISN counter rate (ISR)":
        https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
        This value reports the average rate of increase for the returned TCP initial sequence number.

        Args:
            packet_sender (TSender): TSender instance containing all responses to checks.

        Returns:
            None
        """
        for i in range(len(packet_sender.get_probe_checks_list()) - 1):
            first_timestamp = packet_sender.get_probe_checks_list()[i].get_send_time()
            if not first_timestamp:
                raise
            second_timestamp = packet_sender.get_probe_checks_list()[i + 1].get_send_time()
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

            self.seq_rates.append(self.diff1[i] / float(time_difference))

        # Calculate the average of self.seq_rates
        average_value = sum(self.seq_rates) / len(self.seq_rates)

        # Determine ISR based on the average value
        if average_value < 1:
            self.isr = 0
        else:
            self.isr = round(8 * math.log2(average_value))
