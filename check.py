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

    def is_response_packet_empty(self) -> bool:
        """
        Check if the response packet is empty.

        Returns:
            bool: True if the response packet is empty, False otherwise.
        """
        return not self._response_packet

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

    @abstractmethod
    def prepare_packet(self):
        """
        Abstract method to be implemented by subclasses for preparing a network packet.

        This method should define the necessary steps to construct and format a network packet.

        Raises:
            NotImplementedError: If the method is not implemented in the subclass.
        """
        pass

