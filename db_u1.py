class db_u1:
    def __init__(self, tests):
        self._r = tests.get('R', '')
        self._df = tests.get('DF', '')
        self._t = tests.get('T', '')
        self._tg = tests.get('TG', '')
        self._ipl = tests.get('IPL', '')
        self._un = tests.get('UN', '')
        self._ripl = tests.get('RIPL', '')
        self._rid = tests.get('RID', '')
        self._ripck = tests.get('RIPCK', '')
        self._ruck = tests.get('RUCK', '')
        self._rud = tests.get('RUD', '')
