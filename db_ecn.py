import commonFuncs
from commonFuncs import *


class db_ecn:
    def __init__(self, tests):
        self.R = tests.get('R', '')
        self.DF = tests.get('DF', '')
        self.T = tests.get('T', '')
        self.TG = tests.get('TG', '')
        self.W = tests.get('W', '')
        self.O = tests.get('O', '')
        self.CC = tests.get('CC', '')
        self.Q = tests.get('Q', '')

#        commonFuncs.print_items(self.__dict__.items())