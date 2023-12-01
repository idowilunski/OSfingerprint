import logging
from scapy.all import *
from check import Check
from TcpFlags import TCPFlags
from scapy.layers.inet import IP, TCP


class SeqCheck(Check):
    def __init__(self, target_ip, target_port):
        super().__init__(target_ip, target_port)

    def prepare_packet(self):
        # Construct a SYN packet for target IP and port according to the following NMAP documentation:
        # https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
        # Reference: Packet 1: window scale (10), NOP, MSS (1460), timestamp (TSval: 0xFFFFFFFF; TSecr: 0),
        # SACK permitted. The window field is 1.
        options = [
            ('WScale', 10), # Window scale
            ('NOP', None),
            ('MSS', 1460),
            ('Timestamp', (0xFFFFFFFF, 0)), # TSVal- 0xFFFFFFFF, TSecr- 0
            ('SAckOK', '') # SACK permitted
        ]
        self._packet = IP(dst=self._target_ip) / TCP(window=1, dport=self._target_port, flags="S", options=options)

    def send_packet(self):
        try:
            self._response_packet = sr1(self._packet, verbose=0, timeout=3)
        except Exception as e:
            self.logger.error(f"Error sending request: {e}")
            raise

    def analyze_response_packet(self):
        if not self._response_packet:
            self.logger.error("Response packet is empty")
            # TODO - what exception to raise?
            raise
        if not self._response_packet.haslayer(TCP):
            self.logger.error("Response is not a TCP packet")
            # TODO - what exception to raise?
            raise
        if TCPFlags.SYN | TCPFlags.ACK == self._response_packet[TCP].flags:
            seq_number = self._response_packet[TCP].seq
            self.logger.info(f"Port {self._target_port} is open")
        elif TCPFlags.RST | TCPFlags.ACK == self._response_packet[TCP].flags:
            self.logger.info(f"Port {self._target_port} is closed")
            # TODO - isn't this an error? or is it ok for nmap detection ?
        else:
            self.logger.error("Unexpected response")
            # TODO - what exception to raise?
            raise
