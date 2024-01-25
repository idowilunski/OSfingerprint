from PortScanner import PortScanner
from DatabaseParser import *
from Fingerprint import Fingerprint
import shutil
import os
import sys
from CheckManager import CheckManager


def print_usage():
    print("Usage: py main.py <ip_address>")
    sys.exit(1)


def find_nmap_directory():
    nmap_path = shutil.which('nmap')

    if nmap_path:
        nmap_directory = os.path.dirname(nmap_path)
        return nmap_directory
    else:
        return None


if __name__ == '__main__':
    # Check if the user provided an IP address
    if len(sys.argv) != 2:
        print("Error: Please provide an IP address.")
        print_usage()

    ip_addr = sys.argv[1]
    port_scanner = PortScanner()
    open_port, close_port = port_scanner.perform_port_scan(ip_addr)

    db_path = "C:\\Program Files (x86)\\Nmap\\nmap-os-db"
    parser = DatabaseParser(db_path)

    list_of_entries = parser.read_database_and_get_all_entries()

    # TODO - go over each port and detect / get it from commandline

#    ip_addr = "45.33.32.156"
    #open_port = 150
    #close_port = 150
    check_manager = CheckManager(ip_addr, open_port, close_port)
    check_manager.send_packets()

    response_fingerprint = Fingerprint()
    response_fingerprint.init_from_response(check_manager)

# port 19575 is also open and 19576 and 19577
    max_score = -1  # Set an initial value lower than any possible score
    best_result = None

    for entry in list_of_entries:
        curr_entry = Fingerprint()
        curr_entry.init_from_db(entry)

        # Calculate the similarity score
        score = response_fingerprint.calculate_similarity_score(curr_entry)

        # Check if the current score is higher than the maximum
        if score > max_score:
            max_score = score
            best_result = curr_entry

    print(f"DONE! Max score is: {best_result.name}")
