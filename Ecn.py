from CommonTests import *


class Ecn:
    def __init__(self, ecn_sender):
        self._r = CommonTests.calculate_responsiveness(ecn_sender)
        self._df = CommonTests.calculate_dont_fragment(ecn_sender)
        self._t = None # TODO
        self._tg = None #TODO impl
        self._w = CommonTests.calculate_window_size(ecn_sender)
        self._o = None # TODO
        self._cc =None # TODO
        self._q = None # TOOD
