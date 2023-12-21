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

        # If responsiveness test returned "no", then all values will be empty
        if self.r == 'N':
            return True

        if self.dfi != other.dfi:
            return False
        if self.cd != other.cd:
            return False
        if self.t > other.t[1] or self.t < other.t[0]:
            return False
        if self.tg != other.tg:
            return False
        return True

    def init_from_response(self, icmp_sender):
        icmp_check = icmp_sender.get_checks_list()[0]
        self.r = CommonTests.calculate_responsiveness(icmp_check)

        # If responsiveness test returned "no", no bother calculating, all values will be empty
        if self.r == 'N':
            return

        self.dfi = self.calculate_dont_fragment_icmp(icmp_sender)
        self.cd = self.calculate_cd(icmp_sender)
        self.t = self.calculate_ttl_diff(icmp_sender)
        self.tg = None  # TODO impl IP initial time-to-live guess (TG)

    @staticmethod
    def calculate_ttl_diff(icmp_sender):
        icmp_checks_list = icmp_sender.get_checks_list()
        return 0XFF - icmp_checks_list[0].get_response_ttl()

    def init_from_db(self, tests : dict):
        # If responsiveness result doesn't exist, it means responsiveness = Y
        self.r = tests.get('R', 'Y')

        if self.r == 'N':
            return

        self.dfi = tests.get('DFI', '')
        self.cd = tests.get('CD', '')

        # T value is a hexadecimal range so we need to parse it, and create a tuple
        t_range = tests.get('T', '')
        t_values = t_range.split('-')

        # Convert hexadecimal strings to integers
        start_value = int(t_values[0], 16)
        end_value = int(t_values[1], 16)

        # Create a tuple of start and end values
        self.t = (start_value, end_value)
        self.tg = tests.get('TG', '')

    @staticmethod
    def calculate_cd(icmp_sender):
        # Both code values are zero.
        icmp_checks_list = icmp_sender.get_checks_list()
        if icmp_checks_list[0].is_icmp_response_code_zero() and icmp_checks_list[1].is_icmp_response_code_zero():
            return 'Z'
        # TODO check 	Both code values are the same as in the corresponding probe. and return 'S'
        # TODO check When they both use the same non-zero number, it is shown here. <NN>
        return 'O' # Any other combination

    @staticmethod
    def calculate_dont_fragment_icmp(icmp_sender):
        # This is simply a modified version of the DF test that is used for the special IE probes.
        # It compares results of the don't fragment bit for the two ICMP echo request probes sent.
        # It has four possible values
        checks_list = icmp_sender.get_checks_list()
        df_value_0 = checks_list[0].get_dont_fragment_bit_value()
        df_value_1 = checks_list[1].get_dont_fragment_bit_value()
        if df_value_0 == 'N' and df_value_1 == 'N':
            return 'N'
        # TODO get the probe values and not only the response values and compare to test "	Both responses echo the DF value of the probe." and return 'S'
        # 	Both of the response DF bits are set. - 'Y'
        if df_value_0 == 'Y' and df_value_1 == 'Y':
            return 'Y'

        # The one remaining other combination—both responses have the DF bit toggled.
        return 'O'

