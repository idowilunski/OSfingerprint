import math
from math import gcd, sqrt, log2
import logging


class Sequence:
    def __init__(self, probe_sender, icmp_sender):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        self._seq_rates = []
        self._diff1 = [] # Differences list, diff1 is the name in the nmap documentation reference
        self._sp = self.calculate_sp(probe_sender)
        self._gcd = self.calculate_gcd(probe_sender)
        self._isr = self.calculate_isr(probe_sender)
#        self._ti = calculate_ti()
#        self._ii = calculate_ii()
        #TODO make it somehow more generic so we can call it here?
        self._ss = self.calculate_ss(probe_sender, icmp_sender)
        self._ts = self.calculate_ts(probe_sender)

    def format(self):
        # TODO add here formatting func to format it like this: SEQ(SP=75-9B%GCD=1-6%ISR=92-9C%TI=I%II=I%SS=S%TS=0)
        pass

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

    # Calculate the SS - Shared IP ID sequence Boolean (SS)
    # According to the following documentation, under "Shared IP ID sequence Boolean (SS)" :
    # https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
    def calculate_ss(self, probe_sender, icmp_sender):
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
            self._gcd_value = Sequence.find_gcd_of_list(self._diff1)
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
