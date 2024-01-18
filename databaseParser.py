from Fingerprint import *


class DatabaseParser:
    def __init__(self, db_path):
        self.db_path = db_path
        self.fingerprints = []

    @staticmethod
    def parse_entry(entry):
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
                entry_data[key] = DatabaseParser.parse_tests(value.rstrip(')'))

        return entry_data

    @staticmethod
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

    def read_database_and_get_all_entries(self):
        list_of_entries = []
        with open(self.db_path, 'r', encoding='utf-8', errors='ignore') as file:
            count = 0
            entries = file.read().split('\n\n')
            for entry in entries:
                if count < 2:
                    count += 1
                    continue

                entry_data = self.parse_entry(entry)
                list_of_entries.append(entry_data)

        return list_of_entries

    def get_fingerprints(self):
        return self.fingerprints


