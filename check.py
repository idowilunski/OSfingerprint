from abc import ABC, abstractmethod
import logging
from scapy.all import *
from TcpFlags import TCPFlags
from scapy.layers.inet import IP, TCP
from datetime import datetime

# Check is an abstract base class representing the interface for a "check" in OS-detection
# Usage of inheriting class is expected to be: prepare_packet, send_packet, and analyze_response.
class Check:
    def __init__(self, target_ip, target_port):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        self._packet = None
        self._response_packet = None
        self._target_ip = target_ip
        self._target_port = target_port
        self._isn = None
        self._send_timestamp = None
        self._response_tsval = None

    def get_response_tsval(self):
        return self._response_tsval

    def is_response_packet_empty(self) -> bool:
        return not self._response_packet

    def get_isn(self):
        return self._isn

    def get_send_time(self):
        return self._send_timestamp

    @abstractmethod
    def prepare_packet(self):
        pass

    def send_packet(self):
        try:
            self._send_timestamp = datetime.now()
            self._response_packet = sr1(self._packet, verbose=0, timeout=10)
        except Exception as e:
            self.logger.error(f"Error sending request: {e}")
            raise

    def parse_response_packet(self):
        if not self._response_packet:
            self.logger.error("Response packet is empty")
            return
            # This is not an error, according to documentation it's expected to sometimes happen and should
            # be treated downstream
        if not self._response_packet.haslayer(TCP):
            self.logger.error("Response is not a TCP packet")
            # TODO - what exception to raise?
            raise
        if TCPFlags.SYN | TCPFlags.ACK == self._response_packet[TCP].flags:
            self._isn = self._response_packet[TCP].seq # ISN - Initial sequence number
            # TODO - add verification seq number makes sense? 32-bit number?
            self.logger.info(f"Port {self._target_port} is open, ISN is: {self._isn}")
        elif TCPFlags.RST | TCPFlags.ACK == self._response_packet[TCP].flags:
            self.logger.info(f"Port {self._target_port} is closed")
        else:
                self.logger.error("Unexpected response")

        # TODO remove magic numbers here
        # Check if the TCP layer has the Timestamp option (8)
        # TODO - wasn't tested since I

        matching_tuple = next((option for option in self._response_packet[TCP].options if option[0] == "Timestamp"), None)
        if matching_tuple:
            self._response_tsval = matching_tuple[1][0]
