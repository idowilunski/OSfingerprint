from CommonTests import *


class IE:
    def __init__(self):
        self.r = None
        self.dfi = None
        self.cd = None
        self.t = None
        self.tg = None

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

        # T can either be a range, or value to compare
        if isinstance(other.t, tuple):
            # Check if it's a tuple, compare using the tuple values
            if not (other.t[0] < self.t < other.t[1]):
                return False
        else:
            # If it's not a tuple, perform a normal comparison
            if self.t != other.t:
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
        self.t = CommonTests.calculate_ttl_diff(icmp_sender)
        self.tg = CommonTests.calculate_ttl_guess(icmp_sender)


    def init_from_db(self, tests : dict):
        # If responsiveness result doesn't exist, it means responsiveness = Y
        self.r = tests.get('R', 'Y')

        if self.r == 'N':
            return

        self.dfi = tests.get('DFI', '')
        self.cd = tests.get('CD', '')

        # T value is a hexadecimal range so we need to parse it, and create a tuple
        t_value = tests.get('T', '')

        if '-' in t_value:
            t_range = t_value.split('-')
            # Convert hexadecimal strings to integers and create a tuple
            self.t = (int(t_range[0], 16), int(t_range[1], 16))
        else:
            self.t = t_value

        # Convert hexadecimal string to integer
        self.tg = int(tests.get('TG', ''), 16)

    # The T, and CD values are for the response to the first probe only, since they are highly unlikely to differ.
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
        # TODO get the probe values and not only the response values and compare to test "
        #  Both responses echo the DF value of the probe." and return 'S'
        # 	Both of the response DF bits are set. - 'Y'
        if df_value_0 == 'Y' and df_value_1 == 'Y':
            return 'Y'

        # The one remaining other combination—both responses have the DF bit toggled.
        return 'O'

