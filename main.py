import PacketSenders.EcnSender, PacketSenders.EchoSender, PacketSenders.UdpSender, PacketSenders.probesSender, \
    PacketSenders.TcpClosePortSender, PacketSenders.TcpOpenPortSender
from PortScanner import perform_port_scan
from databaseParser import *
from Fingerprint import Fingerprint
import shutil
import os
import sys


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
    open_port, close_port = perform_port_scan(ip_addr)

    db_path = find_nmap_directory() + "\\nmap-os-db"
    parser = DatabaseParser(db_path)

    list_of_entries = parser.read_database_and_get_all_entries()

    # TODO - go over each port and detect / get it from commandline

#    ip_addr = "45.33.32.156"
#    open_port = 80
#    close_port = 150
    udp_sender = PacketSenders.UdpSender.UdpSender(ip_addr, close_port)
    ecn_sender = PacketSenders.EcnSender.EcnSender(ip_addr, open_port)
    icmp_sender = PacketSenders.EchoSender.EchoSender(ip_addr, open_port)
    probe_sender = PacketSenders.probesSender.ProbesSender(ip_addr, open_port)
    tcp_open_port_sender = PacketSenders.TcpOpenPortSender.TcpOpenPortSender(ip_addr, open_port)
    tcp_close_port_sender = PacketSenders.TcpClosePortSender.TcpClosePortSender(ip_addr, close_port)

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
    response_fingerprint.init_from_response(ecn_sender, tcp_open_port_sender,
                                            udp_sender, icmp_sender, probe_sender,
                                            tcp_close_port_sender)

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
