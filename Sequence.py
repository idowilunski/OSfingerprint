from probeResponseChecks import *
from CommonTests import *


# runs the sequence (SEQ) check -
# According to the following documentation: https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
# The SEQ test sends six TCP SYN packets to an open port of the target machine and collects SYN/ACK packets back
# This function runs all the tests on the 6 TCP probes sent to the open port and parses the results
class Sequence:
    def __init__(self, probe_sender, icmp_sender, close_ports_sender):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        self._seq_rates = []
        self._diff1 = [] # Differences list, diff1 is the name in the nmap documentation reference
        self._sp = self.calculate_sp(probe_sender)
        self._gcd = self.calculate_gcd(probe_sender)
        self._isr = self.calculate_isr(probe_sender)
        self._ti = self.calculate_ti_ci_ii(probe_sender, 3)
        self._rd = CommonTests.calculate_rd(probe_sender)
        self._ci = self.calculate_ti_ci_ii(close_ports_sender, 2)
        self._ii = self.calculate_ti_ci_ii(icmp_sender, 2)
        self._ss = self.calculate_ss(probe_sender, icmp_sender)
        self._ts = self.calculate_ts(probe_sender)

    @staticmethod
    # Calculate the TS - TCP timestamp option algorithm (TS) (TS)
    # According to the following documentation, under "TCP timestamp option algorithm (TS)" :
    # https://nmap.org/book/osdetect-methods.html#osdetect-p    robes-seq
    def calculate_ts(probe_sender):
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
                return "U"

            # If any of the timestamp values are zero, TS is set to 0.
            if first_tsval == 0 or second_tsval == 0:
                return 0

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
    # Calculate the SS - Shared IP ID sequence Boolean (SS)
    # According to the following documentation, under "Shared IP ID sequence Boolean (SS)" :
    # https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
    def calculate_ss(probe_sender, icmp_sender):
        # This Boolean value records whether the target shares its IP ID sequence between the TCP and ICMP protocols.
        # This test is only included if II is RI, BI, or I and TI is the same. If SS is included,
        # the result is S if the sequence is shared and O (other) if it is not.
        # That determination is made by the following algorithm:
        # Let avg be the final TCP sequence response IP ID minus the first TCP sequence response IP ID,
        # divided by the difference in probe numbers.
        # TODO add UT for avg: If probe #1 returns an IP ID of 10,000 and probe #6 returns 20,000,
        #  avg would be (20,000 − 10,000) / (6 − 1), which equals 2,000.
        probes_checks = probe_sender.get_checks_list()
        icmp_checks = icmp_sender.get_checks_list()

        avg = (probes_checks[-1].get_ip_id() - probes_checks[0].get_ip_id()) / (6-1)

        # If the first ICMP echo response IP ID is less than the final TCP sequence response IP ID plus three times avg,
        # the SS result is S. Otherwise it is O.
        if icmp_checks[0].get_ip_id() < (probes_checks[-1].get_ip_id() + (3 * avg)):
            return 'S'
        return '0'

    @staticmethod
    def find_gcd_of_list(num_list):
        if not num_list:
            return None  # Handle empty list case

        result_gcd = num_list[0]

        for num in num_list[1:]:
            result_gcd = math.gcd(result_gcd, num)

        return result_gcd

    # Calculate SP (sequence predictability)
    # # According to the following documentation, under "TCP ISN sequence predictability index (SP)":
    # https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
    # estimates how difficult it would be to predict the next ISN from the
    # known sequence of six probe responses
    def calculate_sp(self, probe_sender):
        count_non_empty_responses = sum(not check.is_response_packet_empty() for check in probe_sender.get_checks_list())

        # This test is only performed if at least four responses were seen.
        if count_non_empty_responses < 4:
            return None

        # TODO remove magic numbers

        #  If the previously computed GCD value is greater than nine,
        #  the elements of the previously computed seq_rates array are divided by that value.
        #  We don't do the division for smaller GCD values because those are usually caused by chance.
        if self._gcd and self._gcd > 9:
            # Divide elements of seq_rates by the GCD value
            normalized_seq_rates = [rate / self._gcd for rate in self._seq_rates]

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

    # Calculate the GCD (the greatest common divisor) from the 32-bit ISN
    # According to the following documentation, under "TCP ISN greatest common divisor (GCD)":
    # https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
    # This test attempts to determine the smallest number by which the target host increments these values.
    def calculate_gcd(self, probe_sender):
        # TODO - make sure we've received here a non-empty response, and only if so, add it in the calculation?
        for i in range(len(probe_sender.get_checks_list()) - 1):
            first_isn = probe_sender.get_checks_list()[i].get_isn()
            if not first_isn:
                raise
            second_isn = probe_sender.get_checks_list()[i + 1].get_isn()
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
            return Sequence.find_gcd_of_list(self._diff1)

        # TODO add UT that does the following:
        #  So the difference between 0x20000 followed by 0x15000 is 0xB000.
        #  The difference between 0xFFFFFF00 and 0xC000 is 0xC0FF.
        #  This test value then records
        #  the greatest common divisor of all those elements. This GCD is also used for calculating the SP result.

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

    # Calculate ISR (ISN counter rate)
    # # According to the following documentation, under "TCP ISN counter rate (ISR)":
    # https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
    # This value reports the average rate of increase for the returned TCP initial sequence number.
    def calculate_isr(self, probe_sender):
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
