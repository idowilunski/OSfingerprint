from Packets.TcpOpenPortPackets import *
from PacketSenders.PacketSender import *


class TcpOpenPortSender(PacketSender):
    """
    Represents a TCP packet sender for conducting TCP probe tests on an open port.

    Attributes:
        _checks_list (list): A list containing TCP probe objects for conducting tests.

    Note:
        This class inherits from PacketSender, which provides common functionalities for packet sending.
    """
    def __init__(self, target_ip, target_open_port):
        super().__init__()
        self._checks_list = [TcpPacket2(target_ip, target_open_port),
                             TcpPacket3(target_ip, target_open_port),
                             TcpPacket4(target_ip, target_open_port)]
