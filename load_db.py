
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

#def main():
#    db_path = 'C:\\Users\\idowi\\Desktop\\OSfingerprint\\DB_example.txt'
#    parser = DatabaseParser(db_path)
#    parser.read_database()
#    fingerprints = parser.get_fingerprints()
#    for fingerprint in fingerprints:
#        print(fingerprint)
#        fingerprint.print()




#main

if __name__ == "__main__":
    main()
