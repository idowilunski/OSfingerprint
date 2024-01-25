from abc import abstractmethod
from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP, UDP, RandNum, in4_chksum
from datetime import datetime


class Check:
    """
        Base class representing the API for a check in NMAP OS-detection.

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
        self._sent_packet = None
        self._response_packet = None
        self._target_ip = target_ip
        self._target_port = target_port
        self._send_timestamp = None

    def get_sent_packet(self):
        """
        Get the sent packet.

        Returns:
        The sent packet.
        """
        return self._sent_packet

    def get_response_packet(self):
        """
        Get the response packet received after sending the check.

        Returns:
        The response packet.
        """
        return self._response_packet

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
            self._response_packet = sr1(self._sent_packet, verbose=0, timeout=10)
            self.logger.info("sent a packet")
        except Exception as e:
            self.logger.error(f"Error sending request: {e}")
            raise

