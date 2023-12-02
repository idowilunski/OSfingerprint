import logging
from TcpPackets import *
from PacketSender import *


class TcpSender(PacketSender):
    def __init__(self, target_ip, target_open_port, target_close_port):
        super().__init__(target_ip, target_open_port)
        self._checks_list = [TcpPacket2(target_ip, target_open_port),
                             TcpPacket3(target_ip, target_open_port),
                             TcpPacket4(target_ip, target_open_port),
                             TcpPacket5(target_ip, target_close_port),
                             TcpPacket6(target_ip, target_close_port),
                             TcpPacket7(target_ip, target_close_port)]
