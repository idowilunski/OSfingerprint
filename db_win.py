# TODO - make sure we keep conventions together (for example, in my files the convention is self._w1)

class DbWin:
    def __init__(self, tests):
        self._w1 = tests.get('W1', '')
        self._w2 = tests.get('W2', '')
        self._w3 = tests.get('W3', '')
        self._w4 = tests.get('W4', '')
        self._w5 = tests.get('W5', '')
        self._w6 = tests.get('W6', '')
