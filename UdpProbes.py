import logging
from check import Check
from scapy.layers.inet import IP, UDP


# Prepares U1 packet according to the following documentation, under "UDP (U1)":
# https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
class UdpProbe(Check):
    def __init__(self, target_ip, target_close_port):
        super().__init__(target_ip, target_close_port)

    def prepare_packet(self):
        # The character ‘C’ (0x43) is repeated 300 times for the data field.
        # The IP ID value is set to 0x1042 for operating systems which allow us to set this.
        # If the port is truly closed and there is no firewall in place,
        # Nmap expects to receive an ICMP port unreachable message in return.
        data_field = b'\x43' * 300
        self._packet = IP(dst=self._target_ip) / UDP(dport=self._target_port) / data_field
