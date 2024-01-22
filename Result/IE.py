from CommonTests import *
from scapy.layers.inet import ICMP

class IE:
    """
    Represents information extracted from ICMP Echo probes (IE probes) and provides methods for initialization
    and calculating similarity scores based on these probe results.

    Attributes:
        r (str): Responsiveness, indicating whether the target host responds to ICMP Echo probes (Y/N).
        dfi (str): Don't Fragment ICMP, indicating the behavior of the Don't Fragment bit in ICMP echo request probes.
        cd (str): Comparison of ICMP Echo response code values from two probes (Z, S, or O).
        t (int or list of tuples): Time-to-Live (TTL) value(s) or range(s) from the first IE probe response.
        tg (int or list of tuples): TTL Guess value(s) or range(s) from the first IE probe response.
    """

    def __init__(self):
        """
        Initializes an IE instance with attributes r, dfi, cd, t, and tg set to None.
        """
        self.r = None
        self.dfi = None
        self.cd = None
        self.t = None
        self.tg = None

    def calculate_similarity_score(self, other)-> int:
        """
        Calculates the similarity score between two IE instances based on their attributes.

        Args:
            other (IE): Another IE instance to compare.

        Returns:
            int: The similarity score.
        """
        score = 0

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
        """
        Initializes IE attributes from ICMP Echo probe responses.

        Args:
            icmp_sender (ICMPSender): An ICMPSender instance containing ICMP Echo probe responses.
        """
        icmp_check = icmp_sender.get_checks_list()[0]
        self.r = CommonTests.calculate_responsiveness(icmp_check)
        self.dfi = self.calculate_dont_fragment_icmp(icmp_sender)
        self.cd = self.calculate_cd(icmp_sender)
        self.t = CommonTests.calculate_ttl_diff(icmp_sender.get_checks_list()[0])
        self.tg = CommonTests.calculate_ttl_guess(icmp_sender.get_checks_list()[0])

    def init_from_db(self, tests : dict):
        """
        Initializes IE attributes from a dictionary obtained from the NMAP database.

        Args:
            tests (dict): A dictionary containing IE attribute values.
        """
        # If responsiveness result doesn't exist, it means responsiveness = Y
        self.r = tests.get('R', 'Y')
        self.dfi = tests.get('DFI', '')
        self.cd = tests.get('CD', '')

        # T value is a hexadecimal range so we need to parse it, and create a tuple
        t_value = tests.get('T', '')

        # This part handles the DB entry in case for t there are several optional values, or if value is a range
        # For example, T=B|16-21
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
                self.t = int(t_value, 16) if t_value != '' else ''

        tg_value = tests.get('TG', '')
        # This part handles the DB entry in case for tg there are several optional values, or if value is a range
        # For example, T=B|16-21
        if '|' in tg_value:
            # Split by "|"
            parts = tg_value.split('|')
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
            if '-' in tg_value:
                # Split by "-"
                parts = tg_value.split('-')
                # Convert each part to a tuple of integers
                self.tg = tuple(int(part, 16) for part in parts)
            else:
                # Convert the entire value to an integer
                self.tg = int(tg_value, 16) if tg_value != '' else ''

    @staticmethod
    def calculate_cd(icmp_sender):
        """
        Calculates the comparison of ICMP Echo response code values from two probes (Z, S, or O).

        Args:
            icmp_sender (ICMPSender): An ICMPSender instance containing ICMP Echo probe responses.

        Returns:
            str: The CD value (Z, S, or O).
        """
        # IF both code values are zero, return 'Z'
        icmp_checks_list = icmp_sender.get_checks_list()
        if icmp_checks_list[0].is_icmp_response_code_zero() and icmp_checks_list[1].is_icmp_response_code_zero():
            return 'Z'
        sent_type0 = icmp_checks_list[0].get_sent_packet()[ICMP].type
        sent_type1 = icmp_checks_list[1].get_sent_packet()[ICMP].type
        if icmp_checks_list[0].get_response_packet() is None or icmp_checks_list[1].get_response_packet() is None:
            return '0'
        response_type0 = icmp_checks_list[0].get_response_packet()[ICMP].type
        response_type1 = icmp_checks_list[1].get_response_packet()[ICMP].type

        # Both code values are the same as in the corresponding probe - return 'S'
        if sent_type0 == response_type0 and sent_type1 == response_type1:
            return 'S'
        # Both use the same non-zero number-  return <NN>
        if response_type0 == response_type1 and response_type1 != 0:
            return f"<{response_type0}{response_type1}>"
        # Any other combination - return 'O'
        return 'O'

    @staticmethod
    def calculate_dont_fragment_icmp(icmp_sender):
        """
        Calculates the behavior of the Don't Fragment bit in ICMP echo request probes (N, Y, S or O).

        Args:
            icmp_sender (ICMPSender): An ICMPSender instance containing ICMP Echo probe responses.

        Returns:
            str: The DFI value (N, Y, S, or O).
        """
        checks_list = icmp_sender.get_checks_list()
        df_value_0 = checks_list[0].get_dont_fragment_bit_value()
        df_value_1 = checks_list[1].get_dont_fragment_bit_value()
        # Both of the response DF bits are not set. - 'N'
        if df_value_0 == 'N' and df_value_1 == 'N':
            return 'N'
        df_probe_value0 = checks_list[0].get_sent_packet()[ICMP].type
        df_probe_value1 = checks_list[1].get_sent_packet()[ICMP].type
        # Both of the response DF bits are set. - 'Y'
        if df_value_0 == 'Y' and df_value_1 == 'Y':
            return 'Y'
        # Both responses echo the DF value of the probe- return 'S'
        if df_value_0 == df_probe_value0 and df_value_1 == df_probe_value1:
            return 'S'
        # Both responses have the DF bit toggled- return '0'
        return 'O'

