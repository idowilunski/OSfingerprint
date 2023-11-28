import requests
import logging
from scapy.all import *

# TODO add inheritence from virtual parent and override prepare and analyze
from scapy.layers.inet import IP, TCP


class SeqCheck:
    def __init__(self, target_ip, target_port):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        self._request = None
        self._response = None
        self._target_ip = target_ip
        self._target_port = target_port

    def prepare_request(self):
        # Construct a SYN packet, TCP request for target IP and port
        self._request = IP(dst=self._target_ip) / TCP(dport=self._target_port, flags="S")

    def send_request(self):
        try:
            self._response = sr1(self._request, timeout=1, verbose=0)
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error sending request: {e}")
            raise

    def analyze_response(self):
        if self._response:
            if self._response.haslayer(TCP):
                # TODO - make it into an enum?
                if self._response[TCP].flags == 0x12:  # SYN-ACK
                    seq_number = self._response[TCP].seq
                    self.logger.info(f"Port {self._target_port} is open")
                elif self._response[TCP].flags == 0x14:  # RST-ACK
                    self.logger.info(f"Port {self._target_port} is closed")
                    # TODO - isn't this an error? or is it ok for nmap detection ?
            else:
                self.logger.error("Unexpected response")
                # TODO - what exception to raise?
                raise
        else:
            self.logger.error("Response is empty")
            # TODO - what exception to raise?
            raise