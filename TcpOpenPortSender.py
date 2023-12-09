from TcpOpenPortPackets import *
from PacketSender import *


class TcpOpenPortSender(PacketSender):
    def __init__(self, target_ip, target_open_port):
        super().__init__(target_ip, target_open_port)
        self._checks_list = [TcpPacket2(target_ip, target_open_port),
                             TcpPacket3(target_ip, target_open_port),
                             TcpPacket4(target_ip, target_open_port)]
