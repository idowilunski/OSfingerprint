
#from seqProbes import Packet1, Packet2, Packet3, Packet4, Packet5
from seqCheck import SeqCheck

if __name__ == '__main__':
#    seqCheck = Packet4("scanme.nmap.org", 22)
#    seqCheck.prepare_probe_packet()
#    seqCheck.send_packet()
#    seqCheck.analyze_response_packet()

    # TODO - restart my computer after the firewall changes and see if loopback now works
#    for i in range(1,9000):
#        print(i)
        seqCheck = SeqCheck("127.0.0.1", 63342)
    #seqCheck = SeqCheck("scanme.nmap.org", 22)
        seqCheck.run_check()

