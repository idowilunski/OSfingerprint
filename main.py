# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import Fingerprint
import PacketSenders
from Result import Ecn
from PacketSenders import *
import PacketSenders.EcnSender, PacketSenders.EchoSender, PacketSenders.UdpSender, PacketSenders.probesSender, \
    PacketSenders.TcpClosePortSender, PacketSenders.TcpOpenPortSender
import Result.Ecn, Result.IE, Result.U1
from databaseParser import *
from Fingerprint import Fingerprint

# my computer result by nmap is : Microsoft Windows 10 1809 - 2004
# ECN(R=Y%DF=Y%T=7B-85%TG=80%W=FFFF%O=MFFD7NW8NNS%CC=N%Q=)
# Press the green button in the gutter to run the script.
if __name__ == '__main__':

    # TODO call ido's functions
    db_path = "C:\\Program Files (x86)\\Nmap\\nmap-os-db"
    parser = DatabaseParser(db_path)
    #parser.read_database()

    list_of_entries = parser.read_database_and_get_all_entries()

    # TODO - go over each port and detect / get it from commandline
    # nmap result -
#Discovered open port 445/tcp on 127.0.0.1
#Discovered open port 135/tcp on 127.0.0.1
#Discovered open port 902/tcp on 127.0.0.1
#Discovered open port 912/tcp on 127.0.0.1
#Discovered open port 49160/tcp on 127.0.0.1
#Discovered open port 4001/tcp on 127.0.0.1
#Discovered open port 6881/tcp on 127.0.0.1

    udp_sender = PacketSenders.UdpSender.UdpSender("127.0.0.1", 7772)
    ecn_sender = PacketSenders.EcnSender.EcnSender("127.0.0.1", 7772)
    icmp_sender = PacketSenders.EchoSender.EchoSender("127.0.0.1", 7772)
    probe_sender = PacketSenders.probesSender.ProbesSender("127.0.0.1", 7772)
    tcp_open_port_sender = PacketSenders.TcpOpenPortSender.TcpOpenPortSender("127.0.0.1", 7772)
    tcp_close_port_sender = PacketSenders.TcpClosePortSender.TcpClosePortSender("127.0.0.1", 1)

    udp_sender.prepare_packets()
    ecn_sender.prepare_packets()
    icmp_sender.prepare_packets()
    probe_sender.prepare_packets()
    tcp_open_port_sender.prepare_packets()
    tcp_close_port_sender.prepare_packets()

    udp_sender.send_packets()
    ecn_sender.send_packets()
    icmp_sender.send_packets()
    probe_sender.send_packets()
    tcp_open_port_sender.send_packets()
    tcp_close_port_sender.send_packets()

    udp_sender.parse_response_packets()
    ecn_sender.parse_response_packets()
    icmp_sender.parse_response_packets()
    probe_sender.parse_response_packets()
    tcp_open_port_sender.parse_response_packets()
    tcp_close_port_sender.parse_response_packets()

    response_fingerprint = Fingerprint()
    response_fingerprint.init_from_response(ecn_sender, tcp_open_port_sender, udp_sender, icmp_sender, probe_sender,
                           tcp_close_port_sender)

# port 19575 is also open and 19576 and 19577
    max_score = -1  # Set an initial value lower than any possible score
    best_u1_result = None

    for entry in list_of_entries:
        curr_entry = Fingerprint()
        curr_entry.init_from_db(entry)

        # Calculate the similarity score
        score = response_fingerprint.calculate_similarity_score(curr_entry)

        print(f"Score is {score} and fingerprint is: {curr_entry.name}")
        # Check if the current score is higher than the maximum
        if score > max_score:
            max_score = score
            best_u1_result = curr_entry


    print(f"DONE! Max score is: {best_u1_result.name}")

    #    fingerprints = parser.get_fingerprints()
    #    for fingerprint in fingerprints:
    #        print(fingerprint)
    #        fingerprint.print()
    #ecn.init_from_db(tests)

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
