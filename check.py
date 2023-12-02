from abc import ABC, abstractmethod
import logging
from scapy.all import *
from TcpFlags import TCPFlags
from scapy.layers.inet import IP, TCP, ICMP
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
        self._ip_id = None
        self._window_size = None
        self.is_dont_fragment_bit_set = None
        self._response_ece = None
        self._response_cwr = None
        self._response_is_reserved = False

    def is_response_reserved_bit_set(self) -> bool:
        return self._response_is_reserved

    def is_response_ece_set(self):
        return self._response_ece

    def is_response_cwr_set(self):
        return self._response_cwr

    def get_response_tsval(self):
        return self._response_tsval

    def is_response_packet_empty(self) -> bool:
        return not self._response_packet

    def is_dont_fragment_bit_set(self):
        return self.is_dont_fragment_bit_set

    def get_ip_id(self):
        return self._ip_id

    def get_isn(self):
        return self._isn

    def get_received_window_size(self):
        return self._window_size

    def get_received_tcp_options(self):
        try:
            return self._response_packet[TCP].options
        except Exception:
            self.logger.error("This is not a TCP packet, cannot extract options!")
            return None

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
        if not self._response_packet.haslayer(TCP) and not self._response_packet.haslayer(ICMP):
            self.logger.error("Response is not a TCP or ICMP packet")
            # TODO - what exception to raise?
            raise
        if self._response_packet.haslayer(TCP):
            if TCPFlags.SYN | TCPFlags.ACK == self._response_packet[TCP].flags:
                self._isn = self._response_packet[TCP].seq  # ISN - Initial sequence number
                # TODO - add verification seq number makes sense? 32-bit number?
                self.logger.info(f"Port {self._target_port} is open, ISN is: {self._isn}")
            elif TCPFlags.RST | TCPFlags.ACK == self._response_packet[TCP].flags:
                self.logger.info(f"Port {self._target_port} is closed")
            else:
                self.logger.error("Unexpected response")

            matching_tuple = next((option for option in self._response_packet[TCP].options if option[0] == "Timestamp"),
                                  None)
            if matching_tuple:
                self._response_tsval = matching_tuple[1][0]

            self._window_size = packet[TCP].window
            self.logger.info(f"Window size: {self._window_size}")

            self.is_dont_fragment_bit_set = bool(self._response_packet[IP].flags.DF)
            self.logger.info(f"Dont fragment bit: {self.is_dont_fragment_bit_set}")

            # Read the CWR and ECE flags from the TCP packet
            self._response_cwr = bool(self._response_packet[TCP].flags & 0x80)  # 0x80 is the CWR flag
            self._response_ece = bool(self._response_packet[TCP].flags & 0x40)  # 0x40 is the ECE flag

            # Read the reserved field from the TCP packet
            self._response_is_reserved = bool(self._response_packet[TCP].res)

        # TODO remove magic numbers here

        fragmentation_needed = 3
        if self._response_packet.haslayer(ICMP):
            self.is_dont_fragment_bit_set = bool(self._response_packet[ICMP].type == fragmentation_needed)

        # Common for both ICMP and TCP:
        self._ip_id = self._response_packet[IP].id
        self.logger.info(f"IP ID: {self._ip_id}")

