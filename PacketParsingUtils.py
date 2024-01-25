from scapy.layers.inet import IP, TCP, ICMP, UDP, RandNum, in4_chksum
import logging

logger = logging.getLogger(__name__)


def get_packet_ip_len(packet) -> int:
    """
    Get the length of the IP layer in the input packet

    Parameters:
    - packet (IPPacket): packet to parse IP length from

    Returns:
    int: The length of the IP layer, or 0 if packet is invalid.
    """
    if not packet:
        logger.debug("This function was called on an empty packet")
        return 0

    if not packet.haslayer(IP):
        logger.debug("This function was called on a non IP packet")
        return 0

    return packet[IP].len


def get_packet_ip_id(packet) -> int:
    """
    Get the identification field value of the IP layer in the input packet.

    Parameters:
    - packet (IPPacket): packet to parse IP length from

    Returns:
    int: The identification field value, or 0 if packet is invalid.
    """
    if not packet:
        logger.error("This function was incorrectly called on an empty packet")
        return 0

    if not packet.haslayer(IP):
        logger.error("This function was incorrectly called on a non IP packet")
        return 0

    return packet[IP].id


def get_packet_tsval(packet) -> int:
    """
    Get the Timestamp Value (TSval) from the TCP options in the input packet.

    Parameters:
    - packet (IPPacket): packet to parse TSval from

    Returns:
    int: The TSval if present in the TCP options, 0 otherwise or if packet is invalid.
    """
    if not packet or not packet.haslayer(TCP):
        logger.error("This function was incorrectly called on an invalid TCP packet")
        return 0

    # Iterate over all options in the response packet, find "Timestamp" option if exists and return it
    timestamp_option = next(
            (option[1][0] for option in packet[TCP].options if option[0] == "Timestamp"), None)
    return timestamp_option if timestamp_option is not None else 0


def get_packet_ack_number(packet) -> int:
    """
    Get the Acknowledgment (ACK) number from the TCP header of the packet.

    Parameters:
    - packet (IPPacket): packet to parse ACK number from

    Returns:
        int: The Acknowledgment (ACK) number from the TCP header.
        Returns 0 if the packet is empty or packet is invalid.
    """
    if not packet:
        logger.error("This function was incorrectly called on an empty packet")
        return 0

    if not packet.haslayer(TCP):
        logger.error("This function was incorrectly called on a non-TCP packet")
        return 0

    return packet[TCP].ack