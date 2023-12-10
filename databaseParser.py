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


