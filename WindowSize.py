import logging


#  This test simply records the 16-bit TCP window size of the received packet
# According to the following documentation, under "TCP initial window size (W, W1–W6)":
# https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq

# "While this test is generally named W, the six probes sent for sequence generation purposes are a special case.
# Those are inserted into a special WIN test line and take the names W1 through W6. The window size is recorded
# for all the sequence number probes because they differ in TCP MSS option values,
# which causes some operating systems to advertise a different window size.
# Despite the different names, each test is processed exactly the same way."
class WindowSize:
    def __init__(self, probe_sender):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        checks_list = probe_sender.get_checks_list()
        self._w1 = self.calculate_w(checks_list[0])
        self._w2 = self.calculate_w(checks_list[1])
        self._w3 = self.calculate_w(checks_list[2])
        self._w4 = self.calculate_w(checks_list[3])
        self._w5 = self.calculate_w(checks_list[4])
        self._w6 = self.calculate_w(checks_list[5])

    @staticmethod
    def calculate_w(check):
        return check.get_received_window_size()
