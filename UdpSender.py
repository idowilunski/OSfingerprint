import logging
from UdpProbes import *


# TODO - make it inherit code from "PacketSender" that defines all those functions
#  and the CTOR here will only change the checks list?
class TcpSender:
    def __init__(self, target_ip, target_close_port):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        self._checks_list = [UdpProbe(target_ip, target_close_port)]

    def parse_response_packets(self):
        _ = [check.parse_response_packet() for check in self._checks_list]

    def prepares_packets(self):
        _ = [check.prepare_packet() for check in self._checks_list]

    def send_packets(self):
        _ = [check.send_packet() for check in self._checks_list]

    def get_checks_list(self):
        return self._checks_list
