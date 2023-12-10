from EcnPackets import *
from PacketSender import *


class EcnSender(PacketSender):
    def __init__(self, target_ip, target_open_port):
        super().__init__(target_ip, target_open_port)
        self._checks_list = [EcnPacket(target_ip, target_open_port)]
