
class db_seq:
    def __init__(self, tests):
        self.SP = tests.get('SP', '')
        self.GCD = tests.get('GCD', '')
        self.ISR = tests.get('ISR', '')
        self.TI = tests.get('TI', '')
        self.RD = tests.get('RD', '')
        self.CI = tests.get('CI', '')
        self.II = tests.get('II', '')
        self.SS = tests.get('SS', '')
        self.TS = tests.get('TS', '')

    def print(self):
        for attribute, value in self.__dict__.items():
            print(f"{attribute}: {value}", end=' ')

class db_win:
    def __init__(self, tests):
        self.W1 = tests.get('W1', '')
        self.W2 = tests.get('W2', '')
        self.W3 = tests.get('W3', '')
        self.W4 = tests.get('W4', '')
        self.W5 = tests.get('W5', '')
        self.W6 = tests.get('W6', '')

    def print(self):
        for attribute, value in self.__dict__.items():
            print(f"{attribute}: {value}", end=' ')
class db_ecn:
    def __init__(self, tests):
        self.R = tests.get('R', '')
        self.DF = tests.get('DF', '')
        self.T = tests.get('T', '')
        self.TG = tests.get('TG', '')
        self.W = tests.get('W', '')
        self.O = tests.get('O', '')
        self.CC = tests.get('CC', '')
        self.Q = tests.get('Q', '')
    def print(self):
        for attribute, value in self.__dict__.items():
            print(f"{attribute}: {value}", end=' ')

class db_ops:
    def __init__(self, tests):
        self._o1 = tests.get('O1', '')
        self._o2 = tests.get('O2', '')
        self._o3 = tests.get('O3', '')
        self._o4 = tests.get('O4', '')
        self._o5 = tests.get('O5', '')
        self._o6 = tests.get('O6', '')

    def print(self):
        for attribute, value in self.__dict__.items():
            print(f"{attribute}: {value}", end=' ')

class db_ie:
    def __init__(self, tests):
        self.R = tests.get('R', '')
        self.DFI = tests.get('DFI', '')
        self.CD = tests.get('CD', '')
        self.T = tests.get('T', '')
        self.TG = tests.get('TG', '')

    def print(self):
        for attribute, value in self.__dict__.items():
            print(f"{attribute}: {value}", end=' ')

class db_u1:
    def __init__(self, tests):
        self.R = tests.get('R', '')
        self.DF = tests.get('DF', '')
        self.T = tests.get('T', '')
        self.TG = tests.get('TG', '')
        self.IPL = tests.get('IPL', '')
        self.UN = tests.get('UN', '')
        self.RIPL = tests.get('RIPL', '')
        self.RID = tests.get('RID', '')
        self.RIPCK = tests.get('RIPCK', '')
        self.RUCK = tests.get('RUCK', '')
        self.RUD = tests.get('RUD', '')

class db_t:
    def __init__(self, tests):
        self.R = tests.get('R', '')
        self.DF = tests.get('DF', '')
        self.T = tests.get('T', '')
        self.TG = tests.get('TG', '')
        self.W = tests.get('W', '')
        self.S = tests.get('S', '')
        self.A = tests.get('A', '')
        self.F = tests.get('F', '')
        self.O = tests.get('O', '')
        self.RD = tests.get('RD', '')
        self.Q = tests.get('Q', '')

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


def parse_tests(tests_str):
    # Splitting the input string by '%'
    substrings = tests_str.split('%')

    # Creating a dictionary from the substrings
    result_dict = {}
    for substring in substrings:
        if '=' in substring:
            key, value = substring.split('=')
            result_dict[key] = value

    return result_dict

class DatabaseParser:
    def __init__(self, db_path):
        self.db_path = db_path
        self.fingerprints = []

    def parse_entry(self, entry):
        lines = entry.split('\n')
        entry_data = {}
        for line in lines:
            # skip irrelevant lines
            if not line or line[0] == '#' or line.strip().startswith('Class'):
                continue

            # CPE line needs different handling
            if line.strip().startswith('CPE') or line.strip().startswith('Fingerprint'):
                key, value = line.split(' ', 1)
                entry_data[key] = value.strip()

            # all other lines
            else:
                key, value = line.split('(', 1)
                entry_data[key] = parse_tests(value.rstrip(')'))

        return entry_data

    def read_database(self):
        with open(self.db_path, 'r', encoding='utf-8', errors='ignore') as file:
            count = 0
            entries = file.read().split('\n\n')
            for entry in entries:
                if count < 2:
                    count += 1
                    continue

                entry_data = self.parse_entry(entry)
                fingerprint = Fingerprint(
                    entry_data.get('Fingerprint', ''),
                    entry_data.get('CPE', ''),
                    entry_data.get('SEQ', ''),
                    entry_data.get('OPS', ''),
                    entry_data.get('WIN', ''),
                    entry_data.get('ECN', ''),
                    entry_data.get('T1', ''),
                    entry_data.get('T2', ''),
                    entry_data.get('T3', ''),
                    entry_data.get('T4', ''),
                    entry_data.get('T5', ''),
                    entry_data.get('T6', ''),
                    entry_data.get('T7', ''),
                    entry_data.get('U1', ''),
                    entry_data.get('IE', '')
                    )
                self.fingerprints.append(fingerprint)
                print(entry_data)

    def get_fingerprints(self):
        return self.fingerprints



def main():
    db_path = 'C:\\Users\\idowi\\Desktop\\OSfingerprint\\DB_example.txt'
    parser = DatabaseParser(db_path)
    parser.read_database()
    fingerprints = parser.get_fingerprints()
    for fingerprint in fingerprints:
        print(fingerprint)
        fingerprint.print()




#main

if __name__ == "__main__":
    main()
