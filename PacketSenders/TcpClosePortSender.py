import logging
from Packets.TcpClosePortPackets import *
from PacketSenders.PacketSender import *


class TcpClosePortSender(PacketSender):
    """
    Represents a TCP packet sender for conducting TCP probe tests on a closed port.

    Attributes:
        _checks_list (list): A list containing TCP probe objects for conducting tests.

    Methods:
        send_packets(): Sends TCP packets to the target for conducting TCP probe tests.

    Note:
        This class inherits from PacketSender, which provides common functionalities for packet sending.
    """
    def __init__(self, target_ip, target_close_port):
        super().__init__()
        self._checks_list = [TcpPacket5(target_ip, target_close_port),
                             TcpPacket6(target_ip, target_close_port),
                             TcpPacket7(target_ip, target_close_port)]
