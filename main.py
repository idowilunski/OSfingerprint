from probesSender import ProbesSender
from TCheck import *
from EchoSender import *
from EcnSender import *
from TcpOpenPortSender import *
from TcpClosePortSender import *
from UdpSender import *
from U1 import *
from Sequence import *
from Options import *
from Ecn import *
from WindowSize import *
from IE import *

if __name__ == '__main__':
    # TODO add code documentation for all classes
    #  packets. consider even removing prepare_packets call from outside, and call it in the init, in RAII

    # runs the sequence (SEQ) check -
    # According to the following documentation: https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
    # The SEQ test sends six TCP SYN packets to an open port of the target machine and collects SYN/ACK packets back
    probe_sender = ProbesSender("127.0.0.1", 63342)
    probe_sender.prepare_packets()

    icmp_sender = EchoSender("127.0.0.1", 63342)
    icmp_sender.prepare_packets()

    ecn_sender = EcnSender("127.0.0.1", 63342)
    ecn_sender.prepare_packets()

    udp_sender = UdpSender("127.0.0.1", 22, 63342)
    udp_sender.prepare_packets()

    tcp_open_port_sender = TcpOpenPortSender("127.0.0.1", 63342)
    tcp_open_port_sender.prepare_packets()

    tcp_close_port_sender = TcpClosePortSender("127.0.0.1", 22)
    tcp_close_port_sender.prepare_packets()

    probe_sender.send_packets()
    # These ICMP probes follow immediately after the TCP sequence probes to ensure valid results
    # of the shared IP ID sequence number test (see the section called “Shared IP ID sequence Boolean (SS)”).
    icmp_sender.send_packets()
    ecn_sender.send_packets()
    tcp_open_port_sender.send_packets()
    tcp_close_port_sender.send_packets()
    udp_sender.send_packets()

    probe_sender.parse_response_packets()
    tcp_open_port_sender.parse_response_packets()
    tcp_close_port_sender.parse_response_packets()
    ecn_sender.parse_response_packets()
    icmp_sender.parse_response_packets()
    udp_sender.parse_response_packets()

    # TODO print lines:
    seq = Sequence(probe_sender, icmp_sender, tcp_close_port_sender)
    ops = Options(probe_sender)
    t1 = TCheck(tcp_open_port_sender.get_checks_list()[0])
    t2 = TCheck(tcp_open_port_sender.get_checks_list()[1])
    t3 = TCheck(tcp_open_port_sender.get_checks_list()[2])
    t4 = TCheck(tcp_open_port_sender.get_checks_list()[3])
    t5 = TCheck(tcp_close_port_sender.get_checks_list()[0])
    t6 = TCheck(tcp_close_port_sender.get_checks_list()[1])
    t7 = TCheck(tcp_close_port_sender.get_checks_list()[2])
    u1 = U1(udp_sender.get_checks_list()[0])
    w = WindowSize(probe_sender)
    ecn = Ecn(ecn_sender)
    ie = IE(icmp_sender)
    # ("scanme.nmap.org", 22)
    # TODO - now print all responses

# TODO - The probes are sent exactly 100 milliseconds apart so the total time taken is 500 ms
# TODO - if we'll do the sending in one thread it'll do it better than current that waits for the response?
