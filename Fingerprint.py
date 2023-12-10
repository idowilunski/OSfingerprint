class Fingerprint:
    def __init__(self, FINGERPRINT, CPE, SEQ, OPS, WIN, ECN, T1, T2, T3, T4, T5, T6, T7, U1, IE):
        self.FINGERPRINT = FINGERPRINT
        self.CPE = CPE
        self.SEQ = db_seq(SEQ)
        self.OPS = db_ops(OPS)
        self.WIN = db_win(WIN)
        self.ECN = db_ecn(ECN)
        self.T1 = db_t(T1)
        self.T2 = db_t(T2)
        self.T3 = db_t(T3)
        self.T4 = db_t(T4)
        self.T5 = db_t(T5)
        self.T6 = db_t(T6)
        self.T7 = db_t(T7)
        self.U1 = db_u1(U1)
        self.IE = db_ie(IE)

    def print(self):
        self.SEQ.print()
        self.OPS.print()
        self.WIN.print()
        self.ECN.print()