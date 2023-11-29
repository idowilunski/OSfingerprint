class Fingerprint:
    def __init__(self, FINGERPRINT, CPE, SEQ, OPS, WIN, ECN, T1, T2, T3, T4, T5, T6, T7, U1, IE):
        self.FINGERPRINT = FINGERPRINT
        self.CPE = CPE
        self.SEQ = SEQ
        self.OPS = OPS
        self.WIN = WIN
        self.ECN = ECN
        self.T1 = T1
        self.T2 = T2
        self.T3 = T3
        self.T4 = T4
        self.T5 = T5
        self.T6 = T6
        self.T7 = T7
        self.U1 = U1
        self.IE = IE


class DatabaseParser:
    def __init__(self, db_path):
        self.db_path = db_path
        self.fingerprints = []

    def parse_entry(self, entry):
        lines = entry.split('\n')
        entry_data = {}
        for line in lines:
            print(line + '\n')
            # skip irrelevant lines
            if line[0] == '#' or line.strip().startswith('Class'):
                continue

            # CPE line needs different handling
            if line.strip().startswith('CPE') or line.strip().startswith('Fingerprint'):
                key, value = line.split(' ', 1)
                entry_data[key] = value.strip()
                print(entry_data)

            # all other lines
            else:
                key, value = line.split('(', 1)
                entry_data[key] = value.rstrip(')')
        return entry_data

    def read_database(self):
        with open(self.db_path, 'r') as file:
            entries = file.read().split('\n\n')
            for entry in entries:
                if entry:
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

    def get_fingerprints(self):
        return self.fingerprints


def main():
    db_path = 'C:\\Users\\idowi\\Desktop\\OSfingerprint\\DB_example.txt'
    parser = DatabaseParser(db_path)
    parser.read_database()
    fingerprints = parser.get_fingerprints()

    # Print the list of fingerprints
    for fingerprint in fingerprints:
        print(vars(fingerprint))


if __name__ == "__main__":
    main()
