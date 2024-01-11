from CommonTests import *


class Options:
    def __init__(self):
        self.o1 = None
        self.o2 = None
        self.o3 = None
        self.o4 = None
        self.o5 = None
        self.o6 = None

    def calculate_similarity_score(self, other):
        score = 0
        if self.o1 == other.o1:
            score += 20
        if self.o2 == other.o2:
            score += 20
        if self.o3 == other.o3:
            score += 20
        if self.o4 == other.o4:
            score += 20
        if self.o5 == other.o5:
            score += 20
        if self.o6 == other.o6:
            score += 20
        return score

    def init_from_response(self, probe_sender):
        checks_list = probe_sender.get_checks_list()
        self.o1 = CommonTests.calculate_o(checks_list[0])
        self.o2 = CommonTests.calculate_o(checks_list[1])
        self.o3 = CommonTests.calculate_o(checks_list[2])
        self.o4 = CommonTests.calculate_o(checks_list[3])
        self.o5 = CommonTests.calculate_o(checks_list[4])
        self.o6 = CommonTests.calculate_o(checks_list[5])

    def init_from_db(self, tests : dict):
        self.o1 = tests.get('O1', None)
        self.o2 = tests.get('O2', None)
        self.o3 = tests.get('O3', None)
        self.o4 = tests.get('O4', None)
        self.o5 = tests.get('O5', None)
        self.o6 = tests.get('O6', None)
