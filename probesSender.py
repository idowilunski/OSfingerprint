import logging
from seqProbes import *


# Generates 6 TCP probes, sends them and parses the response
class ProbesSender:
    def __init__(self, target_ip, target_open_port):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        self._target_ip = target_ip
        self._target_open_port = target_open_port

        self._checks_list = [ProbePacket1(target_ip, target_open_port),
                             ProbePacket2(target_ip, target_open_port),
                             ProbePacket3(target_ip, target_open_port),
                             ProbePacket4(target_ip, target_open_port),
                             ProbePacket5(target_ip, target_open_port),
                             ProbePacket6(target_ip, target_open_port)]

    # TODO make it one liners
    def parse_response_packets(self):
        for check in self._checks_list:
            check.parse_response_packet()

    def prepare_probes(self):
        for check in self._checks_list:
            check.prepare_probe_packet()

    def send_probes(self):
        start_time = time.time()

        for check in self._checks_list:
            check.send_packet()

        end_time = time.time()
        total_time_taken = (end_time - start_time) * 1000  # Convert to milliseconds

        # TODO: how do we assert this?
        # assert total_time_taken == 500, f"Total time taken: {total_time_taken} ms, expected 500 ms"

    def get_checks_list(self):
        return self._checks_list
