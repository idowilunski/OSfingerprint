class db_t:
    def __init__(self, tests):
        self.R = tests.get('R', '')
        self.DF = tests.get('DF', '')
        self.T = tests.get('T', '')
        self.TG = tests.get('TG', '')
        self.W = tests.get('W', '')
        self.S = tests.get('S', '')
        self.A = tests.get('A', '')
        self.F = tests.get('F', '')
        self.O = tests.get('O', '')
        self.RD = tests.get('RD', '')
        self.Q = tests.get('Q', '')
