import logging
from TcpClosePortPackets import *
from PacketSender import *


class TcpClosePortSender(PacketSender):
    def __init__(self, target_ip, target_close_port):
        super().__init__(target_ip, target_close_port)
        self._checks_list = [TcpPacket5(target_ip, target_close_port),
                             TcpPacket6(target_ip, target_close_port),
                             TcpPacket7(target_ip, target_close_port)]
