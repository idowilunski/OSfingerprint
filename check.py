from abc import ABC, abstractmethod
import logging


# Check is an abstract base class representing the interface for a "check" in OS-detection
# Usage of inheriting class is expected to be: prepare_packet, send_packet, and analyze_response.
class Check:
    def __init__(self, target_ip, target_port):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        self._packet = None
        self._response_packet = None
        self._target_ip = target_ip
        self._target_port = target_port

    @abstractmethod
    def prepare_packet(self):
        pass

    @abstractmethod
    def send_packet(self):
        pass

    @abstractmethod
    def analyze_response_packet(self):
        pass
