from abc import abstractmethod
from scapy.all import *
from TcpFlags import TCPFlags
from scapy.layers.inet import IP, TCP, ICMP, UDP, RandNum, in4_chksum
from datetime import datetime


class Check:
    """
        Abstract base class representing the interface for a check in NMAP OS-detection.

        Inheriting classes are expected to implement the 'prepare_packet', 'send_packet',
        and 'analyze_response' methods.

        Attributes:
        - target_ip (str): The target IP address to perform OS-detection on.
        - target_port (int): The target port to perform OS-detection on.
        - packet (scapy.Packet): The packet used for the check.
        - response_packet (scapy.Packet): The response packet received after sending the check.
        - packet_seq_number (scapy.RandNum): Randomized sequence number for the packet.
        - send_timestamp (datetime): Timestamp when the packet was sent.
        - packet_ack_number (scapy.RandNum): Randomized acknowledgment number for the packet.
    """

    def __init__(self, target_ip, target_port):
        """
        Initialize a Check instance.

            Parameters:
            - target_ip (str): The target IP address to perform OS-detection on.
            - target_port (int): The target port to perform OS-detection on.
        """
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        self._packet = None
        self._response_packet = None
        self._target_ip = target_ip
        self._target_port = target_port
        self._packet_seq_number = RandNum(0, 5000)
        self._send_timestamp = None
        self._packet_ack_number = RandNum(0, 5000)

    def get_sent_packet(self):
        """
        Get the sent packet.

        Returns:
        The sent packet.
        """
        return self._packet

    def get_response_packet(self):
        """
        Get the response packet received after sending the check.

        Returns:
        The response packet.
        """
        return self._response_packet

    def get_response_checksum(self) -> int:
        """
        Get the checksum value of the IP layer in the response packet.

        Returns:
        int: The checksum value of the response.
        """
        return self.get_ip_checksum(self._response_packet)

    def get_request_checksum(self) -> int:
        """
        Get the checksum value of the IP layer in the request packet.

        Returns:
        int: The checksum value of the request.
        """
        return self.get_ip_checksum(self._packet)

    def get_ip_checksum(self, packet_to_calc) -> int:
        """
        Calculate and retrieve the checksum value of the IP layer in the given packet.

        Parameters:
        - packet_to_calc: The packet for which the IP checksum needs to be calculated.

        Returns:
        int: The calculated checksum value, or 0 if packet is invalid.
        """
        if not packet_to_calc:
            self.logger.error("This function was incorrectly called on an empty packet")
            return 0
        if not packet_to_calc.haslayer(IP):
            self.logger.error("This function was incorrectly called on a non IP packet")
            return 0

        return in4_chksum(socket.IPPROTO_IP, packet_to_calc[IP], bytes(packet_to_calc[IP]))

    def is_icmp_response_code_zero(self) -> bool:
        """
        Check if the ICMP response code in the response packet is zero.

        Returns:
        bool: True if the ICMP response code is zero, False otherwise or if packet is invalid.
        """
        if not self._response_packet:
            self.logger.error("This function was incorrectly called on an empty packet")
            return False

        if not self._response_packet.haslayer(ICMP):
            self.logger.error("This function was incorrectly called on a non ICMP packet")
            return False

        return self._response_packet[ICMP].type == 0

    """
        Get the TCP flags present in the response packet.

        Returns:
        str: The TCP flags as a string. Empty string if packet is invalid.
    """
    def get_tcp_flags(self)-> str:
        if not self._response_packet or not self._response_packet.haslayer(TCP):
            self.logger.error("This function was incorrectly called on an invalid TCP packet")
            return ""

        return self._response_packet[TCP].flags

    def is_response_urgent_bit_set(self) -> bool:
        """
        Check if the urgent bit is set in the TCP flags of the response packet.

        Returns:
        bool: True if the urgent bit is set, False otherwise or if packet is invalid.
        """
        if not self._response_packet or not self._response_packet.haslayer(TCP):
            self.logger.error("This function was incorrectly called on an invalid TCP packet")
            return False

        # Read the urgent field from the TCP packet
        return bool(self._response_packet[TCP].urgptr)

    def is_response_reserved_bit_set(self) -> bool:
        """
        Check if the reserved bit is set in the TCP flags of the response packet.

        Returns:
        bool: True if the reserved bit is set, False otherwise or if packet is invalid.
        """
        if not self._response_packet or not self._response_packet.haslayer(TCP):
            self.logger.error("This function was incorrectly called on an invalid TCP packet")
            return False

        # Read the reserved field from the TCP packet
        return bool(self._response_packet[TCP].flags & 0x70)

    def is_response_ece_set(self) -> bool:
        """
        Check if the Explicit Congestion Notification Echo (ECE) flag is set in the TCP flags of the response packet.

        Returns:
        bool: True if the ECE flag is set, False otherwise or if packet is invalid.
        """
        if not self._response_packet or not self._response_packet.haslayer(TCP):
            self.logger.error("This function was incorrectly called on an invalid TCP packet")
            return False

        return bool(self._response_packet[TCP].flags & 0x40) # 0x40 is the ECE flag

    def is_response_cwr_set(self) -> bool:
        """
        Check if the Congestion Window Reduced (CWR) flag is set in the TCP flags of the response packet.

        Returns:
        bool: True if the CWR flag is set, False otherwise or if packet is invalid.
        """
        if not self._response_packet or not self._response_packet.haslayer(TCP):
            self.logger.error("This function was incorrectly called on an invalid TCP packet")
            return False

        return bool(self._response_packet[TCP].flags & 0x80) # 0x80 is the CWR flag

    def is_response_packet_empty(self) -> bool:
        """
        Check if the response packet is empty.

        Returns:
            bool: True if the response packet is empty, False otherwise.
        """
        return not self._response_packet

    def get_dont_fragment_bit_value(self) -> str:
        """
        Get the value of the Don't Fragment (DF) bit in the IP header or ICMP type for the response packet.

        Returns:
            str: 'Y' if the DF bit is set or the ICMP type indicates fragmentation is needed,
            'N' otherwise or if function was called on invalid packet.
        """
        if not self._response_packet:
            self.logger.error("This function was incorrectly called on an empty packet")
            return 'N'

        # If this is an ICMP packet, check if DF bit is set by verifying the type is FRAGMENTATION_NEEDED
        if self._response_packet.haslayer(ICMP):
            FRAGMENTATION_NEEDED = 3
            return 'Y' if self._response_packet[ICMP].type == FRAGMENTATION_NEEDED else 'N'

        # If this is an IP packet, check if DF bit is set by reading the bit value
        if self._response_packet.haslayer(IP):
            return 'Y' if self._response_packet[IP].flags.DF else 'N'

        self.logger.error("This function was incorrectly called on a non-IP, non-ICMP packet")
        return 'N'

    def get_probe_ack_number(self) -> int:
        """
        Get the Acknowledgment (ACK) number from the probe packet.

        Returns:
            int: The Acknowledgment (ACK) number from the probe packet.
        """
        return self._packet_ack_number

    def get_probe_sequence_number(self) -> int:
        """
        Get the Sequence Number from the probe packet.

        Returns:
            int: The Sequence Number from the probe packet.
        """
        return self._packet_seq_number

    def get_response_sequence_number(self)-> int:
        """
        Get the Sequence Number from the TCP header of the response packet.

        Returns:
            int: The Sequence Number from the TCP header. Returns 0 if the packet is empty or not a TCP packet.
        """
        if not self._response_packet or not self._response_packet.haslayer(TCP):
            self.logger.info("This function was incorrectly called on a non TCP packet")
            return 0

        if (TCPFlags.SYN | TCPFlags.ACK) != self._response_packet[TCP].flags:
            self.logger.debug("This function was incorrectly called on a TCP packet returned to a non-open port")
            # Continue with the function

        return self._response_packet[TCP].seq  # ISN - Initial sequence number

    def get_received_window_size(self) -> int:
        """
        Get the advertised window size from the TCP header of the response packet.

        Returns:
            int: The advertised window size from the TCP header. Returns 0 if packet is invalid.
        """
        if not self._response_packet or not self._response_packet.haslayer(TCP):
            self.logger.debug("This function was incorrectly called on a non-TCP packet")
            return 0

        return self._response_packet[TCP].window

    def get_received_tcp_options(self):
        """
        Get the TCP options from the TCP header of the response packet.

        Returns:
            list: A list of tuples representing the TCP options. Returns an empty list if the packet is empty or not a TCP packet.
        """
        if not self._response_packet or not self._response_packet.haslayer(TCP):
            self.logger.debug("This function was incorrectly called on a non TCP packet")
            return []

        return self._response_packet[TCP].options

    def get_response_ttl(self) -> int:
        """
        Get the Time-to-Live (TTL) value from the IP header of the response packet.

        Returns:
            int: The Time-to-Live (TTL) value from the IP header. Returns 0 if the packet is invalid.
        """
        if not self._response_packet or not self._response_packet.haslayer('IP'):
            self.logger.debug("This function was incorrectly called on a non IP packet")
            return 0
        return self._response_packet[IP].ttl

    def get_send_time(self) -> datetime:
        """
        Get the timestamp representing the send time of the network packet.

        Returns:
            datetime: The timestamp indicating the time when the packet was sent.
        """
        return self._send_timestamp

    def send_packet(self):
        """
        Send the prepared network packet and record the send timestamp.

        Returns:
            None

        Raises:
            Exception: If an error occurs while sending the packet,
            an exception is raised with a corresponding error message.
        """
        try:
            self._send_timestamp = datetime.now()
            self._response_packet = sr1(self._packet, verbose=0, timeout=10)
            self.logger.info("sent a packet")
        except Exception as e:
            self.logger.error(f"Error sending request: {e}")
            raise

    def parse_response_packet(self):
        """
        Parse the response packet to determine the status of the target port.

        This method checks for the type of response packet (TCP, UDP, or ICMP) and analyzes the corresponding flags
        to infer the status of the target port. It logs the results as open, closed, or an unexpected response.

        Returns:
            None

        Raises:
            Exception: If the response packet is not a TCP, UDP, or ICMP packet,
            or if an unexpected response is encountered.
        """
        if not self._response_packet:
            # This is not an error, according to documentation it's expected to sometimes happen and should
            # be treated downstream
            self.logger.debug(f"Response packet is empty for port {self._target_port}")
            return

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

    @abstractmethod
    def prepare_packet(self):
        """
        Abstract method to be implemented by subclasses for preparing a network packet.

        This method should define the necessary steps to construct and format a network packet.

        Raises:
            NotImplementedError: If the method is not implemented in the subclass.
        """
        pass

