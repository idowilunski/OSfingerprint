from probesSender import ProbesSender
from seqCheck import SequenceCheck

if __name__ == '__main__':
    # runs the sequence (SEQ) check -
    # According to the following documentation: https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
    # The SEQ test sends six TCP SYN packets to an open port of the target machine and collects SYN/ACK packets back
    sender = ProbesSender("127.0.0.1", 63342)
    sender.prepare_probes()
    sender.send_probes()
    sender.parse_response_packets()

    seqCheck = SequenceCheck()
    seqCheck.run_check(sender)










#    seqCheck = Packet4("scanme.nmap.org", 22)
#    seqCheck.prepare_probe_packet()
#    seqCheck.send_packet()
#    seqCheck.analyze_response_packet()

# TODO - The probes are sent exactly 100 milliseconds apart so the total time taken is 500 ms
# TODO - if we'll do the sending in one thread it'll do it better than current that waits for the response?
# TODO - restart my computer after the firewall changes and see if loopback now works

# TODO also still missing:
# TI, II, TS, and SS. The next line, OPS contains the TCP options received for each of the probes (the test names are O1 through 06). Similarly, the WIN line contains window sizes for the probe responses (named W1 through W6). The final line related to these probes, T1, contains various test values for packet #1. Those results are for the R, DF, T, TG, W, S, A, F, O, RD, and Q tests. These tests are only reported for the first probe since they are almost always the same for each probe.
#    for i in range(1,9000):
#        print(i)
#        seqCheck = SeqCheck("127.0.0.1", 63342)
# seqCheck = SeqCheck("scanme.nmap.org", 22)
#        seqCheck.run_check()
