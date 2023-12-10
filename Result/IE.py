from CommonTests import *

class IE:
    def __init__(self):
        self.r = None
        self.dfi = None
        self.cd = None
        self.t = None #TODO impl
        self.tg = None  # TODO impl IP initial time-to-live guess (TG)

    def __eq__(self, other):
        if self.r != other.r:
            return False
        if self.dfi != other.dfi:
            return False
        if self.cd != other.cd:
            return False
        if self.t != other.t:
            return False
        if self.tg != other.tg:
            return False
        return True

    def init_from_response(self, icmp_sender):
        self.r = CommonTests.calculate_responsiveness(icmp_sender)
        self.dfi = self.calculate_dont_fragment_icmp(icmp_sender)
        self.cd = self.calculate_cd(icmp_sender)
        self.t = None #TODO impl
        self.tg = None  # TODO impl IP initial time-to-live guess (TG)

    def init_from_db(self, tests : dict):
        self.r = tests.get('R', '')
        self.dfi = tests.get('DFI', '')
        self.cd = tests.get('CD', '')
        self.t = tests.get('T', '')
        self.tg = tests.get('TG', '')

    @staticmethod
    def calculate_cd(icmp_sender):
        # Both code values are zero.
        if icmp_sender[0].is_icmp_response_code_zero() && icmp_sender[1].is_icmp_response_code_zero():
            return 'Z'
        # TODO check 	Both code values are the same as in the corresponding probe. and return 'S'
        # TODO check When they both use the same non-zero number, it is shown here. <NN>
        return 'O' # Any other combination

    @staticmethod
    def calculate_dont_fragment_icmp(icmp_sender):
        # This is simply a modified version of the DF test that is used for the special IE probes. It compares results of the don't fragment bit for the two ICMP echo request probes sent. It has four possible values
        checks_list = icmp_sender.get_checks_list()
        if not checks_list[0].is_dont_fragment_bit_set() and not checks_list[1].is_dont_fragment_bit_set():
            return 'N'
        # TODO get the probe values and not only the response values and compare to test "	Both responses echo the DF value of the probe." and return 'S'
        # 	Both of the response DF bits are set. - 'Y'
        if checks_list[0].is_dont_fragment_bit_set() and checks_list[1].is_dont_fragment_bit_set():
            return 'Y'

        # The one remaining other combination—both responses have the DF bit toggled.
        return 'O'

