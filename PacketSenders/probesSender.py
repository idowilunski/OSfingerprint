from Packets.probePackets import *
from PacketSenders.PacketSender import *


class ProbesSender(PacketSender):
    """
    Represents a packet sender for conducting a sequence of probe tests on a target.

    Attributes:
        _checks_list (list): A list containing probe packet objects for conducting tests.

    Note:
        This class inherits from PacketSender, which provides common functionalities for packet sending.
    """
    def __init__(self, target_ip, target_open_port):
        super().__init__()
        self._checks_list = [ProbePacket1(target_ip, target_open_port),
                             ProbePacket2(target_ip, target_open_port),
                             ProbePacket3(target_ip, target_open_port),
                             ProbePacket4(target_ip, target_open_port),
                             ProbePacket5(target_ip, target_open_port),
                             ProbePacket6(target_ip, target_open_port)]
