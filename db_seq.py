# TODO replace all '' with None

class DbSeq:
    def __init__(self, tests):
        self.SP = tests.get('SP', '')
        self.GCD = tests.get('GCD', '')
        self.ISR = tests.get('ISR', '')
        self.TI = tests.get('TI', '')
        self.RD = tests.get('RD', '')
        self.CI = tests.get('CI', '')
        self.II = tests.get('II', '')
        self.SS = tests.get('SS', '')
        self.TS = tests.get('TS', '')
