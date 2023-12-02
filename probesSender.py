import logging
from probePackets import *

# TODO - remove code duplication between probes sender and echo sender
# Generates 6 TCP probes, sends them and parses the response
class ProbesSender:
    def __init__(self, target_ip, target_open_port):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        self._checks_list = [ProbePacket1(target_ip, target_open_port),
                             ProbePacket2(target_ip, target_open_port),
                             ProbePacket3(target_ip, target_open_port),
                             ProbePacket4(target_ip, target_open_port),
                             ProbePacket5(target_ip, target_open_port),
                             ProbePacket6(target_ip, target_open_port)]

    def parse_response_packets(self):
            _ = [check.parse_response_packet() for check in self._checks_list]

    def prepare_packets(self):
            _ = [check.prepare_packet() for check in self._checks_list]

    def send_packets(self):
        start_time = time.time()

        _ = [check.send_packet() for check in self._checks_list]

        end_time = time.time()
        total_time_taken = (end_time - start_time) * 1000  # Convert to milliseconds

        # TODO: how do we assert this?
        # assert total_time_taken == 500, f"Total time taken: {total_time_taken} ms, expected 500 ms"

    def get_checks_list(self):
        return self._checks_list
