from Result.Sequence import Sequence
from Result.Ecn import Ecn
from Result.Options import Options
from Result.WindowSize import WindowSize
from Result.TCheck import TCheck
from Result.U1 import U1
from Result.IE import IE


class Fingerprint:

    def __init__(self):
        self.SEQ = Sequence()
        self.name = "N/A"
        self.CPE = "N/A"
        self.OPS = Options()
        self.WIN = WindowSize()
        self.ECN = Ecn()
        self.T1 = TCheck()
        self.T2 = TCheck()
        self.T3 = TCheck()
        self.T4 = TCheck()
        self.T5 = TCheck()
        self.T6 = TCheck()
        self.T7 = TCheck()
        self.U1 = U1()
        self.IE = IE()

    def init_from_response(self, ecn_sender, open_ports_sender, udp_sender, icmp_sender, probe_sender,
                           close_ports_sender):
        self.SEQ.init_from_response(probe_sender, close_ports_sender, icmp_sender)
        self.OPS.init_from_response(probe_sender)
        self.WIN.init_from_response(probe_sender)
        self.ECN.init_from_response(ecn_sender)
        self.T1.init_from_response(probe_sender, probe_sender.get_checks_list()[0])
        self.T2.init_from_response(open_ports_sender, open_ports_sender.get_checks_list()[0])
        self.T3.init_from_response(open_ports_sender, open_ports_sender.get_checks_list()[1])
        self.T4.init_from_response(open_ports_sender, open_ports_sender.get_checks_list()[2])
        self.T5.init_from_response(close_ports_sender, close_ports_sender.get_checks_list()[0])
        self.T6.init_from_response(close_ports_sender, close_ports_sender.get_checks_list()[1])
        self.T7.init_from_response(close_ports_sender, close_ports_sender.get_checks_list()[2])
        self.U1.init_from_response(udp_sender)
        self.IE.init_from_response(icmp_sender)

    def init_from_db(self, tests: dict):
        self.name = tests['Fingerprint']
        self.CPE = tests['CPE']
        self.SEQ.init_from_db(tests.get('SEQ'))
        self.OPS.init_from_db(tests.get('OPS'))
        self.WIN.init_from_db(tests.get('WIN'))
        self.ECN.init_from_db(tests.get('ECN'))
        self.T1.init_from_db(tests.get('T1'))
        self.T2.init_from_db(tests.get('T2'))
        self.T3.init_from_db(tests.get('T3'))
        self.T4.init_from_db(tests.get('T4'))
        self.T5.init_from_db(tests.get('T5'))
        self.T6.init_from_db(tests.get('T6'))
        self.T7.init_from_db(tests.get('T7'))
        self.U1.init_from_db(tests.get('U1'))
        self.IE.init_from_db(tests.get('IE'))

    def calculate_similarity_score(self, other_fingerprint):
        # Perform similarity score calculations for each member
        seq_score = self.SEQ.calculate_similarity_score(other_fingerprint.SEQ)
        ops_score = self.OPS.calculate_similarity_score(other_fingerprint.OPS)
        win_score = self.WIN.calculate_similarity_score(other_fingerprint.WIN)
        ecn_score = self.ECN.calculate_similarity_score(other_fingerprint.ECN)
        t1_score = self.T1.calculate_similarity_score(other_fingerprint.T1)
        t2_score = self.T2.calculate_similarity_score(other_fingerprint.T2)
        t3_score = self.T3.calculate_similarity_score(other_fingerprint.T3)
        t4_score = self.T4.calculate_similarity_score(other_fingerprint.T4)
        t5_score = self.T5.calculate_similarity_score(other_fingerprint.T5)
        t6_score = self.T6.calculate_similarity_score(other_fingerprint.T6)
        t7_score = self.T7.calculate_similarity_score(other_fingerprint.T7)
        u1_score = self.U1.calculate_similarity_score(other_fingerprint.U1)
        ie_score = self.IE.calculate_similarity_score(other_fingerprint.IE)

        # Do something with the individual scores, e.g., sum them up
        total_score = (
            seq_score + ops_score + win_score + ecn_score +
            t1_score + t2_score + t3_score + t4_score +
            t5_score + t6_score + t7_score + u1_score + ie_score
        )

        return total_score
