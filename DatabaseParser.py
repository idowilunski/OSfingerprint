class DatabaseParser:
    """
    Class for parsing the NMAP database file containing fingerprint entries.

    Attributes:
    - db_path (str): Path to the database file.
    """

    """
    Initialize an instance of the DatabaseParser class.

    Parameters:
    - db_path (str): Path to the database file.
    """
    def __init__(self, db_path):
        self.db_path = db_path

    @staticmethod
    def parse_entry(entry):
        """
        Parse a single entry from the database.

        Parameters:
        - entry (str): Entry string from the database.

        Returns:
        A dictionary containing parsed data from the entry.
        """
        lines = entry.split('\n')
        entry_data = {}
        for line in lines:
            # skip irrelevant lines (comments, or "class" that's unneeded for our parsing)
            if not line or line[0] == '#' or line.strip().startswith('Class'):
                continue

            # Handle CPE line
            if line.strip().startswith('CPE') or line.strip().startswith('Fingerprint'):
                key, value = line.split(' ', 1)
                entry_data[key] = value.strip()

            # Handle all other lines
            else:
                key, value = line.split('(', 1)
                entry_data[key] = DatabaseParser.parse_tests(value.rstrip(')'))

        return entry_data

    @staticmethod
    def parse_tests(tests_str):
        """
        Parse the tests data from a string.

        Parameters:
        - tests_str (str): String containing tests data.

        Returns:
        A dictionary containing parsed tests data.
        """

        # Find "%" that separates the tests' results in the entry line (For example, IE(DFI=N%T=FA-104%TG=FF%CD=S))
        substrings = tests_str.split('%')

        # Create a dictionary from the substrings (For example, W1=8000 will become {"W1":8000})
        result_dict = {}
        for substring in substrings:
            if '=' in substring:
                key, value = substring.split('=')
                result_dict[key] = value

        return result_dict

    def read_database_and_get_all_entries(self):
        """
        Read the database file and return a list of all entries.

        Returns:
        A list of dictionaries, each representing a parsed entry from the database.
        """
        list_of_entries = []
        # Open and parse db file
        with open(self.db_path, 'r', encoding='utf-8', errors='ignore') as file:
            count = 0
            # Verify we've reached a new entry, as it's separate with an empty line from the next
            entries = file.read().split('\n\n')
            for entry in entries:
                # Skip the first 2 lines of each entry as their info shouldn't be parsed
                if count < 2:
                    count += 1
                    continue
                entry_data = self.parse_entry(entry)
                list_of_entries.append(entry_data)

        # Return a list of dictionaries with all the parsed parameters
        return list_of_entries


