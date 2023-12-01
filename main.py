
from seqCheck import SeqCheck

if __name__ == '__main__':
    seqCheck = SeqCheck("scanme.nmap.org", 22)
    seqCheck.prepare_packet()
    seqCheck.send_packet()
    seqCheck.analyze_response_packet()
