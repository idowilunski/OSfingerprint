from CommonTests import *


class Options:
    def __init__(self, probe_sender):
        checks_list = probe_sender.get_checks_list()
        self._o1 = CommonTests.calculate_o(checks_list[0])
        self._o2 = CommonTests.calculate_o(checks_list[1])
        self._o3 = CommonTests.calculate_o(checks_list[2])
        self._o4 = CommonTests.calculate_o(checks_list[3])
        self._o5 = CommonTests.calculate_o(checks_list[4])
        self._o6 = CommonTests.calculate_o(checks_list[6])
