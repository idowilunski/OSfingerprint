from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP, in4_chksum
import logging
from TcpFlags import TCPFlags

logger = logging.getLogger(__name__)


def verify_packet_valid(packet, should_verify_ip=False, should_verify_tcp=False, should_verify_icmp=False):
    if not packet:
        logger.error("This function was incorrectly called on an empty packet")
        return False

    if should_verify_ip and not packet.haslayer(IP):
        logger.error("This function was incorrectly called on a non IP packet")
        return False

    if should_verify_icmp and not packet.haslayer(ICMP):
        logger.error("This function was incorrectly called on a non ICMP packet")
        return False

    if should_verify_tcp and not packet.haslayer(TCP):
        logger.error("This function was incorrectly called on an invalid TCP packet")
        return False

    return True


def get_packet_ip_len(packet) -> int:
    """
    Get the length of the IP layer in the input packet

    Parameters:
    - packet (IPPacket): packet to parse IP length from

    Returns:
    int: The length of the IP layer, or 0 if packet is invalid.
    """
    if not verify_packet_valid(packet, should_verify_ip=True):
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
    if not verify_packet_valid(packet, should_verify_ip=True):
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

    if not verify_packet_valid(packet, should_verify_tcp=True):
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
    if not verify_packet_valid(packet, should_verify_tcp=True):
        return 0

    return packet[TCP].ack


def get_packet_sequence_number(packet)-> int:
    """
    Get the Sequence Number from the TCP header of the packet.

    Parameters:
    - packet (IPPacket): packet to parse sequence number from

    Returns:
        int: The Sequence Number from the TCP header. Returns 0 if the packet is empty or not a TCP packet.
    """
    if not verify_packet_valid(packet, should_verify_tcp=True):
        return 0

    if (TCPFlags.SYN | TCPFlags.ACK) != packet[TCP].flags:
        logger.debug("This function was incorrectly called on a TCP packet returned to a non-open port")
        # Continue with the function

    return packet[TCP].seq  # ISN - Initial sequence number


def get_received_window_size(packet) -> int:
    """
    Get the advertised window size from the TCP header of the packet.

    Parameters:
    - packet (IPPacket): packet to parse window size number from

    Returns:
        int: The advertised window size from the TCP header. Returns 0 if packet is invalid.
    """
    if not verify_packet_valid(packet, should_verify_tcp=True):
        return 0

    return packet[TCP].window


def get_packet_tcp_options(packet):
    """
    Get the TCP options from the TCP header of the response packet.

    Parameters:
    - packet (IPPacket): packet to parse TCP options from

    Returns:
        list: A list of tuples representing the TCP options.
        Returns an empty list if the packet is empty or not a TCP packet.
    """
    if not verify_packet_valid(packet, should_verify_tcp=True):
        return []

    return packet[TCP].options


def get_packet_ttl(packet) -> int:
    """
    Get the Time-to-Live (TTL) value from the IP header of the input packet.

    Parameters:
    - packet (IPPacket): packet to parse TTL from

    Returns:
        int: The Time-to-Live (TTL) value from the IP header. Returns 0 if the packet is invalid.
    """
    if not verify_packet_valid(packet, should_verify_ip=True):
        return 0

    return packet[IP].ttl


def get_dont_fragment_bit_value(packet) -> str:
    """
    Get the value of the Don't Fragment (DF) bit in the IP header or ICMP type for the packet.

    Parameters:
    - packet (IPPacket): packet to parse Don't Fragment bit from

    Returns:
        str: 'Y' if the DF bit is set or the ICMP type indicates fragmentation is needed,
        'N' otherwise or if function was called on invalid packet.
    """
    if not packet:
        logger.error("This function was incorrectly called on an empty packet")
        return 'N'

    # If this is an ICMP packet, check if DF bit is set by verifying the type is FRAGMENTATION_NEEDED
    if packet.haslayer(ICMP):
        FRAGMENTATION_NEEDED = 3
        return 'Y' if packet[ICMP].type == FRAGMENTATION_NEEDED else 'N'

    # If this is an IP packet, check if DF bit is set by reading the bit value
    if packet.haslayer(IP):
        return 'Y' if packet[IP].flags.DF else 'N'

    logger.error("This function was incorrectly called on a non-IP, non-ICMP packet")
    return 'N'


def is_cwr_set(packet) -> bool:
    """
    Check if the Congestion Window Reduced (CWR) flag is set in the TCP flags of the input packet.

    Parameters:
    - packet (IPPacket): packet to parse CWR bit from

    Returns:
    bool: True if the CWR flag is set, False otherwise or if packet is invalid.
    """
    if not verify_packet_valid(packet, should_verify_tcp=True):
        return False

    return bool(packet[TCP].flags & 0x80) # 0x80 is the CWR flag


def is_ece_set(packet) -> bool:
    """
    Check if the Explicit Congestion Notification Echo (ECE) flag is set in the TCP flags of the input packet.

    Parameters:
    - packet (IPPacket): packet to parse ECE bit from

    Returns:
    bool: True if the ECE flag is set, False otherwise or if packet is invalid.
    """
    if not verify_packet_valid(packet, should_verify_tcp=True):
        return False

    return bool(packet[TCP].flags & 0x40) # 0x40 is the ECE flag


def is_reserved_bit_set(packet) -> bool:
    """
    Check if the reserved bit is set in the TCP flags of the input packet.

    Parameters:
    - packet (IPPacket): packet to parse reserved bit from

    Returns:
    bool: True if the reserved bit is set, False otherwise or if packet is invalid.
    """
    if not verify_packet_valid(packet, should_verify_tcp=True):
        return False

    # Read the reserved field from the TCP packet
    return bool(packet[TCP].flags & 0x70)


def is_urgent_bit_set(packet) -> bool:
    """
    Check if the urgent bit is set in the TCP flags of the input packet.

    Parameters:
    - packet (IPPacket): packet to parse urgent bit from

    Returns:
    bool: True if the urgent bit is set, False otherwise or if packet is invalid.
    """
    if not verify_packet_valid(packet, should_verify_tcp=True):
        return False

    # Read the urgent field from the TCP packet
    return bool(packet[TCP].urgptr)


def get_tcp_flags(packet) -> str:
    """
    Get the TCP flags present in the input packet.

    Parameters:
    - packet (IPPacket): packet to parse TCP flags from

    Returns:
    str: The TCP flags as a string. Empty string if packet is invalid.
    """
    if not verify_packet_valid(packet, should_verify_tcp=True):
        return ""

    return packet[TCP].flags


def get_packet_type(packet) -> int:
    """
    Check if the packet type in the packet is zero.

    Parameters:
    - packet (IPPacket): packet to parse type from

    Returns:
    int: ICMP type, 0 if packet is invalid.
    """
    if not verify_packet_valid(packet, should_verify_icmp=True):
        return 0

    return packet[ICMP].type


def get_ip_checksum(packet) -> int:
    """
    Calculate and retrieve the checksum value of the IP layer in the given packet.

    Parameters:
    - packet: The packet for which the IP checksum needs to be calculated.

    Returns:
    int: The calculated checksum value, or 0 if packet is invalid.
    """
    if not verify_packet_valid(packet, should_verify_ip=True):
        return 0

    return in4_chksum(socket.IPPROTO_IP, packet[IP], bytes(packet[IP]))
