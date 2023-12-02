import logging
from TcpPackets import *


# TODO - make it inherit code from "PacketSender" that defines all those functions
#  and the CTOR here will only change the checks list?
class TcpSender:
    def __init__(self, target_ip, target_open_port, target_close_port):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        self._checks_list = [TcpPacket2(target_ip, target_open_port),
                             TcpPacket3(target_ip, target_open_port),
                             TcpPacket4(target_ip, target_open_port),
                             TcpPacket5(target_ip, target_close_port),
                             TcpPacket6(target_ip, target_close_port),
                             TcpPacket7(target_ip, target_close_port)]

    def parse_response_packets(self):
        _ = [check.parse_response_packet() for check in self._checks_list]

    def prepares_packets(self):
        _ = [check.prepare_packet() for check in self._checks_list]

    def send_packets(self):
        _ = [check.send_packet() for check in self._checks_list]

    def get_checks_list(self):
        return self._checks_list
