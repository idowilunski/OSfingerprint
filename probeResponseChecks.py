import math
from probesSender import *
from math import gcd, sqrt, log2
import logging


# This class is used for running all the tests on received packets and storing the results in the class variables
class ResponseChecker:
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
        self._o1 = None
        self._o2 = None
        self._o3 = None
        self._o4 = None
        self._o5 = None
        self._o6 = None
        self._w1 = None
        self._w2 = None
        self._w3 = None
        self._w4 = None
        self._w5 = None
        self._w6 = None
        self._dfi = None
        self._cc = None
        self._q = None
        # TODO - combine these values somehow with Ido's fingerprint class

    @staticmethod
    def find_gcd_of_list(num_list):
        if not num_list:
            return None  # Handle empty list case

        result_gcd = num_list[0]

        for num in num_list[1:]:
            result_gcd = math.gcd(result_gcd, num)

        return result_gcd

    # TODO maybe move this out?
    # runs the sequence (SEQ) check -
    # According to the following documentation: https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
    # The SEQ test sends six TCP SYN packets to an open port of the target machine and collects SYN/ACK packets back
    # This function runs all the tests on the 6 TCP probes sent to the open port and parses the results
    def run_check(self, probe_sender, icmp_sender, tcp_open_port_sender, tcp_close_port_sender, ecn_sender):
        self.calculate_gcd(probe_sender)
        self.calculate_isr(probe_sender)
        self.calculate_sp(probe_sender)
        self.calculate_ts(probe_sender)

        min_responses_num_ti = 3
        self.calculate_ti_ci_ii(probe_sender, min_responses_num_ti)
        min_responses_num_ii = 2
        self.calculate_ti_ci_ii(icmp_sender, min_responses_num_ii)
        min_responses_num_ci = 2
        self.calculate_ti_ci_ii(tcp_close_port_sender, min_responses_num_ci)

        self.calculate_ss(probe_sender, icmp_sender)
        self.calculate_o(probe_sender)
        self.calculate_w(probe_sender)
        self.calculate_responsiveness(probe_sender)
        self.calculate_ip_dont_fragment(probe_sender)
        self.calculate_dont_fragment_icmp(probe_sender)

        # TODO here also IP initial time-to-live (T) and IP initial time-to-live guess (TG)
        self.calculate_congestion_notification(ecn_sender)
        self.calculate_quirks(ecn_sender)

    def calculate_quirks(self, ecn_sender):
        # TODO - seems like Q is calculated for each TCP packet, change impl to multiple
        ecn_check = ecn_sender.get_checks_list()[0]
        ecn_check.is_response_reserved_bit_set()
        # TODO finish test according to TCP miscellaneous quirks (Q)

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


    def calculate_dont_fragment_icmp(self, icmp_sender):
        # This is simply a modified version of the DF test that is used for the special IE probes. It compares results of the don't fragment bit for the two ICMP echo request probes sent. It has four possible values
        checks_list = icmp_sender.get_checks_list()
        if not checks_list[0].is_dont_fragment_bit_set() and not checks_list[1].is_dont_fragment_bit_set():
            self._dfi = 'N'
            return
        # TODO get the probe values and not only the response values and compare to test "	Both responses echo the DF value of the probe." and return 'S'
        # 	Both of the response DF bits are set. - 'Y'
        if checks_list[0].is_dont_fragment_bit_set() and checks_list[1].is_dont_fragment_bit_set():
            self._dfi = 'Y'
            return

        # The one remaining other combination—both responses have the DF bit toggled.
        self._dfi = 'O'
        return

    def calculate_responsiveness(self, probe_sender):
        pass
    # TODO - impl and document according to Responsiveness (R)

    def calculate_ip_dont_fragment(self, probe_sender):
        # TODO need to change how I define stuff, it needs to be per line somehow...
    # Checked in the DB - seems like it's documented per packet of the T1...T7 packets, same for icmp
        pass
    # TODO get is_dont_fragment_bit_set from the checks[0]...[-1]

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

    # According to the following documentation, under "TCP initial window size (W, W1–W6)":
    # https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
    def calculate_w(self, probe_sender):
        #  This test simply records the 16-bit TCP window size of the received packet
        # While this test is generally named W, the six probes sent for sequence generation purposes are a special case.
        # Those are inserted into a special WIN test line and take the names W1 through W6. The window size is recorded
        # for all the sequence number probes because they differ in TCP MSS option values,
        # which causes some operating systems to advertise a different window size.
        # Despite the different names, each test is processed exactly the same way.
        checks_list = probe_sender.get_checks_list()
        self._w1 = checks_list[0].get_received_window_size()
        self._w2 = checks_list[1].get_received_window_size()
        self._w3 = checks_list[2].get_received_window_size()
        self._w4 = checks_list[3].get_received_window_size()
        self._w5 = checks_list[4].get_received_window_size()
        self._w6 = checks_list[5].get_received_window_size()

    # According to the following documentation, under "TCP options (O, O1–O6)":
    # https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
    def calculate_o(self, probe_sender):
        #  If there are no TCP options in a response, the test will exist but the value string will be empty.
        #  If no probe was returned, the test is omitted.
        checks_list = probe_sender.get_checks_list()
        if not checks_list[0].is_response_packet_empty():
            self._o1 = ''.join(
                [ResponseChecker.format_option(opt) for opt in checks_list[0].get_received_tcp_options()])
        if not checks_list[1].is_response_packet_empty():
            self._o2 = ''.join(
                [ResponseChecker.format_option(opt) for opt in checks_list[1].get_received_tcp_options()])
        if not checks_list[2].is_response_packet_empty():
            self._o3 = ''.join(
                [ResponseChecker.format_option(opt) for opt in checks_list[2].get_received_tcp_options()])
        if not checks_list[3].is_response_packet_empty():
            self._o4 = ''.join(
                [ResponseChecker.format_option(opt) for opt in checks_list[3].get_received_tcp_options()])
        if not checks_list[4].is_response_packet_empty():
            self._o5 = ''.join(
                [ResponseChecker.format_option(opt) for opt in checks_list[4].get_received_tcp_options()])
        if not checks_list[5].is_response_packet_empty():
            self._o6 = ''.join(
                [ResponseChecker.format_option(opt) for opt in checks_list[5].get_received_tcp_options()])

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

    # TODO - CI is from the responses to the three TCP probes sent to a closed port: T5, T6, and T7.
    #  II comes from the ICMP responses to the two IE ping probes

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
            self._ss = 'S'
        else:
            self._ss = '0'

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
            self._gcd_value = ResponseChecker.find_gcd_of_list(self._diff1)
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



