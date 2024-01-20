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
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        self.w1 = None
        self.w2 = None
        self.w3 = None
        self.w4 = None
        self.w5 = None
        self.w6 = None

    def calculate_similarity_score(self, other):
        score = 0
        for attr in ['w1', 'w2', 'w3', 'w4', 'w5', 'w6']:
            if getattr(self, attr) == getattr(other, attr):
                score += 15
        return score

    def init_from_response(self, probe_sender):
        checks_list = probe_sender.get_checks_list()
        self.w1 = checks_list[0].check.get_received_window_size()
        self.w2 = checks_list[1].check.get_received_window_size()
        self.w3 = checks_list[2].check.get_received_window_size()
        self.w4 = checks_list[3].check.get_received_window_size()
        self.w5 = checks_list[4].check.get_received_window_size()
        self.w6 = checks_list[5].check.get_received_window_size()

    def init_from_db(self, tests: dict):
        if not isinstance(tests, dict):
            raise Exception("Init from DB called with a non dictionary object!")

        self.w1 = tests.get('W1', None)
        self.w2 = tests.get('W2', None)
        self.w3 = tests.get('W3', None)
        self.w4 = tests.get('W4', None)
        self.w5 = tests.get('W5', None)
        self.w6 = tests.get('W6', None)

