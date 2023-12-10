class db_ie:
    def __init__(self, tests):
        self.R = tests.get('R', '')
        self.DFI = tests.get('DFI', '')
        self.CD = tests.get('CD', '')
        self.T = tests.get('T', '')
        self.TG = tests.get('TG', '')