from CommonTests import *


class IE:
    def __init__(self):
        self.r = None
        self.dfi = None
        self.cd = None
        self.t = None
        self.tg = None

    def calculate_similarity_score(self, other):
        score = 0
        if self.r == 'N':
            return 0

        if self.r == other.r:
            score += 50

        if self.dfi == other.dfi:
            score += 40
        if self.cd == other.cd:
            score += 100

        # T can either be a range, or value to compare
        if isinstance(other.t, list):
            for t_tuple in other.t:
                if len(t_tuple) == 2 and t_tuple[0] <= self.t <= t_tuple[1]:
                    score += 15
                    break  # Break the loop if the score is within any tuple's range
        else:
            # If it's not a tuple, perform a normal comparison
            if self.t == other.t:
                score += 15

        if self.tg == other.tg:
            score += 15
        return score

    def init_from_response(self, icmp_sender):
        icmp_check = icmp_sender.get_checks_list()[0]
        self.r = CommonTests.calculate_responsiveness(icmp_check)

        # If responsiveness test returned "no", no bother calculating, all values will be empty
        if self.r == 'N':
            return

        self.dfi = self.calculate_dont_fragment_icmp(icmp_sender)
        self.cd = self.calculate_cd(icmp_sender)
        self.t = CommonTests.calculate_ttl_diff(icmp_sender.get_checks_list()[0])
        self.tg = CommonTests.calculate_ttl_guess(icmp_sender.get_checks_list()[0])


    def init_from_db(self, tests : dict):
        # If responsiveness result doesn't exist, it means responsiveness = Y
        self.r = tests.get('R', 'Y')

        if self.r == 'N':
            return

        self.dfi = tests.get('DFI', '')
        self.cd = tests.get('CD', '')

        # T value is a hexadecimal range so we need to parse it, and create a tuple
        t_value = tests.get('T', '')

        #if '-' in t_value:
        #    t_range = t_value.split('-')
            # Convert hexadecimal strings to integers and create a tuple
        #     self.t = (int(t_range[0], 16), int(t_range[1], 16))
        #else:
        #    self.t = t_value

        # Check if "|" exists
        if '|' in t_value:
            # Split by "|"
            parts = t_value.split('|')
            # Process each part separately
            processed_parts = []
            self.t = []
            for part in parts:
                # Check if "-" exists in the part
                if '-' in part:
                    # Split by "-"
                    sub_parts = part.split('-')
                    # Convert each sub-part to a tuple of integers
                    processed_sub_parts = tuple(int(part, 16) for part in sub_parts)
                    self.t.append(processed_sub_parts)
                else:
                    # Convert the part to an integer
                    self.t.append(int(part, 16))
        else:
            # If "|" doesn't exist, check if "-" exists
            if '-' in t_value:
                # Split by "-"
                parts = t_value.split('-')
                # Convert each part to a tuple of integers
                self.t = tuple(int(part, 16) for part in parts)
            else:
                # Convert the entire value to an integer
                self.t = int(t_value, 16)

        # Check if "|" exists
        if '|' in t_value:
            # Split by "|"
            parts = t_value.split('|')
            # Process each part separately
            processed_parts = []
            self.tg = []
            for part in parts:
                # Check if "-" exists in the part
                if '-' in part:
                    # Split by "-"
                    sub_parts = part.split('-')
                    # Convert each sub-part to a tuple of integers
                    processed_sub_parts = tuple(int(sub_part, 16) for sub_part in sub_parts)
                    self.tg.append(processed_sub_parts)
                else:
                    # Convert the part to an integer
                    self.tg.append(int(part, 16))
        else:
            # If "|" doesn't exist, check if "-" exists
            if '-' in t_value:
                # Split by "-"
                parts = t_value.split('-')
                # Convert each part to a tuple of integers
                self.tg = tuple(int(part, 16) for part in parts)
            else:
                # Convert the entire value to an integer
                self.tg = int(t_value, 16)

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

