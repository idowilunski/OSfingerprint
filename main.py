# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import PacketSenders
from Result import Ecn
from PacketSenders import *
import PacketSenders.EcnSender, PacketSenders.EchoSender
import Result.Ecn, Result.IE
from databaseParser import *

# my computer result by nmap is : Microsoft Windows 10 1809 - 2004
# ECN(R=Y%DF=Y%T=7B-85%TG=80%W=FFFF%O=MFFD7NW8NNS%CC=N%Q=)
# Press the green button in the gutter to run the script.
if __name__ == '__main__':

    # TODO call ido's functions
    db_path = 'DB_example.txt'
    parser = DatabaseParser(db_path)
    #parser.read_database()

    list_of_ie = parser.read_database_and_get_all_ie()

    # TODO - go over each port and detect / get it from commandline
    # nmap result -
#Discovered open port 445/tcp on 127.0.0.1
#Discovered open port 135/tcp on 127.0.0.1
#Discovered open port 902/tcp on 127.0.0.1
#Discovered open port 912/tcp on 127.0.0.1
#Discovered open port 49160/tcp on 127.0.0.1
#Discovered open port 4001/tcp on 127.0.0.1
#Discovered open port 6881/tcp on 127.0.0.1

    #ecn_sender = PacketSenders.EcnSender.EcnSender("127.0.0.1", 445)
# port 19575 is also open and 19576 and 19577
    for port in range(1, 2):
            # tested until 13704
            ie_sender = PacketSenders.EchoSender.EchoSender("127.0.0.1", 19576)
        # Call the function or perform any other actions here
        # For example, ecn_sender.some_function()

        # Print the port number and any relevant information
            print(f"Trying port {port}...")
            ie_sender.prepare_packets()
            ie_sender.send_packets()
            ie_sender.parse_response_packets()

            response_ie = Result.IE.IE()
            response_ie.init_from_response(ie_sender)

            for ie_dict in list_of_ie:
                curr_ie = Result.IE.IE()
                curr_ie.init_from_db(ie_dict)
                if response_ie == curr_ie:
                    print("YAY")

    print("DONE")

    #    fingerprints = parser.get_fingerprints()
    #    for fingerprint in fingerprints:
    #        print(fingerprint)
    #        fingerprint.print()
    #ecn.init_from_db(tests)

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
