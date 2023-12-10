# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import PacketSenders
from Result import Ecn
from PacketSenders import *
import PacketSenders.EcnSender
import Result.Ecn
from databaseParser import *

# Press the green button in the gutter to run the script.
if __name__ == '__main__':

    # TODO call ido's functions
    db_path = 'DB_example.txt'
    parser = DatabaseParser(db_path)
    #parser.read_database()

    list_of_ecns = parser.read_database_and_get_all_ecns()

    # TODO - go over each port and detect / get it from commandline
    ecn_sender = PacketSenders.EcnSender.EcnSender("127.0.0.1", 63342)

    ecn_sender.prepare_packets()
    ecn_sender.send_packets()
    ecn_sender.parse_response_packets()

    response_ecn = Result.Ecn.Ecn()
    response_ecn.init_from_response(ecn_sender)

    for ecn_dict in list_of_ecns:
        curr_ecn = Result.Ecn.Ecn()
        curr_ecn.init_from_db(ecn_dict)
        if response_ecn == curr_ecn:
            print("YAY")

    print("DONE")

    #    fingerprints = parser.get_fingerprints()
    #    for fingerprint in fingerprints:
    #        print(fingerprint)
    #        fingerprint.print()
    #ecn.init_from_db(tests)

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
