import logging
from UdpProbes import *
from PacketSender import *


class UdpSender(PacketSender):
    def __init__(self, target_ip, target_close_port, target_open_port):
        super().__init__(target_ip, target_open_port)
        self._checks_list = [UdpProbe(target_ip, target_close_port)]
