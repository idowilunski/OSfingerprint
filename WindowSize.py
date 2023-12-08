import logging


class WindowSize:
    def __init__(self, probe_sender):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        self._w1 = None
        self._w2 = None
        self._w3 = None
        self._w4 = None
        self._w5 = None
        self._w6 = None

        self.calculate_w(probe_sender)

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