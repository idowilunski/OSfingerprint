# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import PacketSenders
from Result import Ecn
from PacketSenders import *
import PacketSenders.EcnSender, PacketSenders.EchoSender, PacketSenders.UdpSender
import Result.Ecn, Result.IE, Result.U1
from databaseParser import *

# my computer result by nmap is : Microsoft Windows 10 1809 - 2004
# ECN(R=Y%DF=Y%T=7B-85%TG=80%W=FFFF%O=MFFD7NW8NNS%CC=N%Q=)
# Press the green button in the gutter to run the script.
if __name__ == '__main__':

    # TODO call ido's functions
    db_path = 'DB_example.txt'
    parser = DatabaseParser(db_path)
    #parser.read_database()

    list_of_u1s = parser.read_database_and_get_all_u1()

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
            udp_sender = PacketSenders.UdpSender.UdpSender("127.0.0.1", 7772)
        # Call the function or perform any other actions here
        # For example, ecn_sender.some_function()

        # Print the port number and any relevant information
            print(f"Trying port {port}...")
            udp_sender.prepare_packets()
            udp_sender.send_packets()
            udp_sender.parse_response_packets()

            response_u1 = Result.U1.U1()
            response_u1.init_from_response(udp_sender)

            for u1_dict in list_of_u1s:
                curr_u1 = Result.U1.U1()
                curr_u1.init_from_db(u1_dict)
                if response_u1 == curr_u1:
                    print("YAY")

    print("DONE")

    #    fingerprints = parser.get_fingerprints()
    #    for fingerprint in fingerprints:
    #        print(fingerprint)
    #        fingerprint.print()
    #ecn.init_from_db(tests)

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
