from probesSender import ProbesSender
from probeResponseChecks import ResponseChecker
from EchoSender import *
from EcnSender import *
from TcpSender import *

if __name__ == '__main__':
    # TODO add code documentation for all classes
    # TODO - go over documentation make sure we CTOR and prepare_packets for all
    #  packets. consider even removing prepare_packets call from outside, and call it in the init, in RAII

    # runs the sequence (SEQ) check -
    # According to the following documentation: https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
    # The SEQ test sends six TCP SYN packets to an open port of the target machine and collects SYN/ACK packets back
    probe_sender = ProbesSender("127.0.0.1", 63342)
    probe_sender.prepare_packets()

    echo_sender = EchoSender("127.0.0.1", 63342)
    echo_sender.prepare_packets()

    ecn_sender = EcnSender("127.0.0.1", 63342)
    ecn_sender.prepare_packets()

    tcp_sender = TcpSender("127.0.0.1", 63342, 22)
    tcp_sender.prepare_packets()

    probe_sender.send_packets()
    # These ICMP probes follow immediately after the TCP sequence probes to ensure valid results
    # of the shared IP ID sequence number test (see the section called “Shared IP ID sequence Boolean (SS)”).
    echo_sender.send_packets()
    ecn_sender.send_packets()
    tcp_sender.send_packets()

    probe_sender.parse_response_packets()
    tcp_sender.parse_response_packets()
    ecn_sender.parse_response_packets()
    echo_sender.parse_response_packets()

    # Calculates GCD, SP, ISR, TS
    probe_response_checker = ResponseChecker()
    probe_response_checker.run_check(probe_sender, echo_sender, tcp_sender)
    #TODO - calculate SS, II

#    optChecks = OptionsChecks()
#    optChecks.run_check(sender)

# TODO - if response is received for ecn, run tests:
#  If a response is received, the R, DF, T, TG, W, O, CC, and Q tests are performed and recorded.










#    probe_response_checker = Packet4("scanme.nmap.org", 22)

# TODO - The probes are sent exactly 100 milliseconds apart so the total time taken is 500 ms
# TODO - if we'll do the sending in one thread it'll do it better than current that waits for the response?
# TODO - restart my computer after the firewall changes and see if loopback now works

# TODO also still missing:
# TI, II, TS, and SS. The next line, OPS contains the TCP options received for each of the probes (the test names are O1 through 06). Similarly, the WIN line contains window sizes for the probe responses (named W1 through W6). The final line related to these probes, T1, contains various test values for packet #1. Those results are for the R, DF, T, TG, W, S, A, F, O, RD, and Q tests. These tests are only reported for the first probe since they are almost always the same for each probe.
#    for i in range(1,9000):
#        print(i)
#        probe_response_checker = ResponseChecker("127.0.0.1", 63342)
# probe_response_checker = ResponseChecker("scanme.nmap.org", 22)
#        probe_response_checker.run_check()
