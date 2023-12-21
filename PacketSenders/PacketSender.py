import logging


class PacketSender:
    def __init__(self, target_ip, target_open_port):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        self._checks_list = None

    def parse_response_packets(self):
        try:
            _ = [check.parse_response_packet() for check in self._checks_list]
        except:
            pass

    def prepare_packets(self):
        _ = [check.prepare_packet() for check in self._checks_list]

    def send_packets(self):
        _ = [check.send_packet() for check in self._checks_list]

    def get_checks_list(self):
        return self._checks_list
