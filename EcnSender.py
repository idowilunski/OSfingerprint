import logging
from EcnPackets import *


class EcnSender:
    def __init__(self, target_ip, target_open_port):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        self._target_ip = target_ip
        self._target_open_port = target_open_port

        self._checks_list = [EcnPacket(target_ip, target_open_port)]

    def parse_response_packets(self):
        _ = [check.parse_response_packet() for check in self._checks_list]

    def prepares_packets(self):
        _ = [check.prepare_packet() for check in self._checks_list]

    def send_packets(self):
        _ = [check.send_packet() for check in self._checks_list]

    def get_checks_list(self):
        return self._checks_list
