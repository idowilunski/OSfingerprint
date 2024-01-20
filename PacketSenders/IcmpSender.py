import logging
from Packets.icmpPackets import *
from PacketSenders.PacketSender import *


class IcmpSender(PacketSender):
    """
    Represents a sender for ICMP Echo packets used for testing.

    Attributes:
        _checks_list (list): A list containing ICMP Echo packet objects for conducting tests.
    """
    def __init__(self, target_ip, target_open_port):
        super().__init__()
        self._checks_list = [IcmpPacket1(target_ip, target_open_port),
                             IcmpPacket2(target_ip, target_open_port)]

