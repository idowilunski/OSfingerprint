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
    def __init__(self):

        self.w1 = None
        self.w2 = None
        self.w3 = None
        self.w4 = None
        self.w5 = None
        self.w6 = None

    def __eq__(self, other):
        if self.w1 != other.w1:
            return False
        if self.w2 != other.w2:
            return False
        if self.w3 != other.w3:
            return False
        if self.w4 != other.w4:
            return False
        if self.w5 != other.w5:
            return False
        if self.w6 != other.w6:
            return False

        return True

    def init_from_response(self, probe_sender):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        checks_list = probe_sender.get_checks_list()
        self.w1 = self.calculate_w(checks_list[0])
        self.w2 = self.calculate_w(checks_list[1])
        self.w3 = self.calculate_w(checks_list[2])
        self.w4 = self.calculate_w(checks_list[3])
        self.w5 = self.calculate_w(checks_list[4])
        self.w6 = self.calculate_w(checks_list[5])

    def init_from_db(self, tests: dict):
        self.w1 = tests.get('W1', None)
        self.w2 = tests.get('W2', None)
        self.w3 = tests.get('W3', None)
        self.w4 = tests.get('W4', None)
        self.w5 = tests.get('W5', None)
        self.w6 = tests.get('W6', None)

    @staticmethod
    def calculate_w(check):
        return check.get_received_window_size()
