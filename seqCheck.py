import math

from seqProbes import ProbePacket1, ProbePacket2, ProbePacket3, ProbePacket4, ProbePacket5, ProbePacket6
from math import gcd, sqrt, log2
import logging

# TODO - impl also ICMP probes and TCP requests 1-7 sent to a close port and the response analysis
#  in general, implement the entire section : IP ID sequence generation algorithm (TI, CI, II)
# also this Shared IP ID sequence Boolean (SS)

class SeqCheck:
    def __init__(self, target_ip, target_port):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        self._target_ip = target_ip
        self._target_port = target_port
        self._packet1 = ProbePacket1(target_ip, target_port)
        self._packet2 = ProbePacket2(target_ip, target_port)
        self._packet3 = ProbePacket3(target_ip, target_port)
        self._packet4 = ProbePacket4(target_ip, target_port)
        self._packet5 = ProbePacket5(target_ip, target_port)
        self._packet6 = ProbePacket6(target_ip, target_port)

        self._checks_list = [self._packet1, self._packet2, self._packet3, self._packet4, self._packet5, self._packet6]
        self._gcd_value = 0
        self._seq_rates = []
        self._diff1 = [] # Differences list, diff1 is the name in the nmap documentation reference
        self._isr = None
        self._sp = None

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
    def run_check(self):
        # Iterate over checks set, and for each - prepare a test probe, send it and analyze the output
        for check in self._checks_list:
            check.prepare_probe_packet()
            check.send_packet()
            check.analyze_response_packet()

        self.calculate_gcd()
        self.calculate_isr()
        self.calculate_sp()

    # Calculate the GCD (the greatest common divisor) from the 32-bit ISN
    # According to the following documentation, under "TCP ISN greatest common divisor (GCD)":
    # https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
    # This test attempts to determine the smallest number by which the target host increments these values.
    def calculate_gcd(self):
        # TODO - make sure we've received here a non-empty response, and only if so, add it in the calculation?
        for i in range(len(self._checks_list) - 1):
            first_isn = self._checks_list[i].get_isn()
            if not first_isn:
                raise
            second_isn = self._checks_list[i + 1].get_isn()
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
            self._gcd_value = SeqCheck.find_gcd_of_list(self._diff1)
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
    def calculate_isr(self):
        for i in range(len(self._checks_list) - 1):
            first_timestamp = self._checks_list[i].get_send_time()
            if not first_timestamp:
                raise
            second_timestamp = self._checks_list[i + 1].get_send_time()
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
    def calculate_sp(self):
        # TODO make it one-liner
        count_non_empty_responses = 0
        for i in range(len(self._checks_list)):
            count_non_empty_responses += not self._checks_list[i].is_response_packet_empty()

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



