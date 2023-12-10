from abc import ABC, abstractmethod
from scapy.all import *
from TcpFlags import TCPFlags
from scapy.layers.inet import IP, TCP, ICMP, UDP, RandNum
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
        self._packet_seq_number = RandNum(0, 5000)
        self._send_timestamp = None
        self._packet_ack_number = RandNum(0, 5000)

    def get_response_ip_len(self):
        if not self._response_packet.haslayer[IP]:
            raise "This function was incorrectly called on a non IP packet"

        return self._response_packet[IP].len

    def get_response_ip_id(self):
        if not self._response_packet.haslayer[IP]:
            raise "This function was incorrectly called on a non IP packet"

        return self._response_packet[IP].id

    def get_request_checksum(self):
        return self.calculate_udp_checksum(self._packet)

    def get_response_checksum(self):
        if not self._response_packet.haslayer(UDP):
            raise "This function was incorrectly called on a non UDP packet"

        return self._response_packet[UDP].chksum

    def is_icmp_response_code_zero(self):
        if not self._response_packet.haslayer[ICMP]:
            raise "This function was incorrectly called on a non ICMP packet"

        return self._response_packet[ICMP].type == 0

    def get_tcp_flags(self):
        if not self._response_packet.haslayer[TCP]:
            raise "This function was incorrectly called on a non TCP packet"

        return self._response_packet[TCP].flags

    def is_response_urgent_bit_set(self) -> bool:
        if not self._response_packet.haslayer[TCP]:
            raise "This function was incorrectly called on a non TCP packet"

        # Read the urgent field from the TCP packet
        return bool(self._response_packet[TCP].urg)

    def is_response_reserved_bit_set(self) -> bool:
        if not self._response_packet.haslayer[TCP]:
            raise "This function was incorrectly called on a non TCP packet"

        # Read the reserved field from the TCP packet
        return bool(self._response_packet[TCP].res)

    def is_response_ece_set(self):
        if not self._response_packet.haslayer[TCP]:
            raise "This function was incorrectly called on a non TCP packet"

        return bool(self._response_packet[TCP].flags & 0x40) # 0x40 is the ECE flag

    def is_response_cwr_set(self):
        if not self._response_packet.haslayer[TCP]:
            raise "This function was incorrectly called on a non TCP packet"

        return bool(self._response_packet[TCP].flags & 0x80) # 0x80 is the CWR flag

    def get_response_tsval(self):
        if not self._response_packet.haslayer[TCP]:
            raise "This function was incorrectly called on a non TCP packet"

        matching_tuple = next((option for option in self._response_packet[TCP].options if option[0] == "Timestamp"),
                              None)
        if matching_tuple:
            return matching_tuple[1][0]

    def is_response_packet_empty(self) -> bool:
        return not self._response_packet

    def is_dont_fragment_bit_set(self):
        if not self._response_packet.haslayer(ICMP) and not self._response_packet.haslayer[IP]:
            raise "This function was incorrectly called on a non IP, and non ICMP packet"

        # TODO remove magic numbers here
        fragmentation_needed = 3
        if self._response_packet.haslayer(ICMP):
            return bool(self._response_packet[ICMP].type == fragmentation_needed)

        if self._response_packet.haslayer(IP):
            return bool(self._response_packet[IP].flags.DF)

    def get_ip_id(self):
        if not self._response_packet.haslayer(IP):
            raise "This function was incorrectly called on a non IP packet"

        return self._response_packet[IP].id

    def get_response_ack_number(self):
        if not self._response_packet.haslayer[TCP]:
            raise "This function was incorrectly called on a non TCP packet"
        return self._response_packet[TCP].ack

    def get_probe_ack_number(self):
        return self._packet_ack_number

    def get_probe_sequence_number(self):
        return self._packet_seq_number

    def get_response_sequence_number(self):
        # TODO - add verification seq number makes sense? 32-bit number?
        if not self._response_packet.haslayer(TCP):
            raise "This function was incorrectly called on a non TCP packet"

        if TCPFlags.SYN | TCPFlags.ACK != self._response_packet[TCP].flags:
            raise "This function was incorrectly called on a TCP packet returned to a non-open port"

        return self._response_packet[TCP].seq  # ISN - Initial sequence number

    def get_received_window_size(self):
        if not self._response_packet.haslayer[TCP]:
            raise "This function was incorrectly called on a non TCP packet"

        return self._response_packet[TCP].window

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

    # TODO - not sure if this func makes sense
    @staticmethod
    def calculate_udp_checksum(packet):
        packet[UDP].chksum = 0
        return UDP(packet[UDP]).chksum

    def send_packet(self):
        try:
            self._send_timestamp = datetime.now()
            if self._packet.haslayer(UDP):
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

        if not self._response_packet.haslayer(TCP) \
                and not self._response_packet.haslayer(ICMP) \
                and not self._response_packet.haslayer(UDP):
            raise "Response is not a TCP, UDP or ICMP packet"

        if self._response_packet.haslayer(TCP):
            if TCPFlags.SYN | TCPFlags.ACK == self._response_packet[TCP].flags:
                self.logger.info(f"Port {self._target_port} is open")
            elif TCPFlags.RST | TCPFlags.ACK == self._response_packet[TCP].flags:
                self.logger.info(f"Port {self._target_port} is closed")
            else:
                raise "Unexpected response to TCP packet"



