import logging
from  Packets.icmpPackets import *
from PacketSender import *


class EchoSender(PacketSender):
    def __init__(self, target_ip, target_open_port):
        super().__init__(target_ip, target_open_port)
        self._checks_list = [IcmpPacket1(target_ip, target_open_port),
                             IcmpPacket2(target_ip, target_open_port)]

