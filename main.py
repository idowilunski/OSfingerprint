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
    db_path = 'C:\\Users\\idowi\\Desktop\\OSfingerprint\\DB_example.txt'
    parser = DatabaseParser(db_path)
    parser.read_database()

    # TODO - go over each port and detect / get it from commandline
    ecn_sender = PacketSenders.EcnSender.EcnSender("127.0.0.1", 63342)

    ecn_sender.prepare_packets()
    ecn_sender.send_packets()
    ecn_sender.parse_response_packets()

    ecn = Result.Ecn.Ecn()
    ecn.init_from_response(ecn_sender)

    #    fingerprints = parser.get_fingerprints()
    #    for fingerprint in fingerprints:
    #        print(fingerprint)
    #        fingerprint.print()
    ecn.init_from_db(tests)

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
