import logging

from Packets.EcnChecks import EcnPacket
from Packets.TcpClosePortChecks import *
from Packets.TcpOpenPortChecks import *
from Packets.UdpChecks import UdpProbe
from Packets.icmpChecks import *
from Packets.probeChecks import *


class CheckManager:
    """
    Represents a base class for sending and handling responses for various packet checks.

    Attributes:
        _ecn_checks_list (list): A list containing ECN packet check objects.
        _icmp_checks_list (list): A list containing ICMP packet check objects.
        _probe_checks_list (list): A list containing probe packet check objects.
        _tcp_close_port_checks_list (list): A list containing TCP close port packet check objects.
        _tcp_open_port_checks_list (list): A list containing TCP open port packet check objects.
        _udp_checks_list (list): A list containing UDP packet check objects.

    Methods:
        send_packets(): Sends packets to the target for conducting all the NMAP checks.
    """
    def __init__(self, target_ip, target_open_port, target_close_port):
        """
        Initializes a CheckManager object
        """
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        self._ecn_checks_list = [EcnPacket(target_ip, target_open_port)]
        self._icmp_checks_list = [IcmpPacket1(target_ip, target_open_port),
                             IcmpPacket2(target_ip, target_open_port)]
        self._probe_checks_list = [ProbePacket1(target_ip, target_open_port),
                             ProbePacket2(target_ip, target_open_port),
                             ProbePacket3(target_ip, target_open_port),
                             ProbePacket4(target_ip, target_open_port),
                             ProbePacket5(target_ip, target_open_port),
                             ProbePacket6(target_ip, target_open_port)]
        self._tcp_close_port_checks_list = [TcpPacket5(target_ip, target_close_port),
                             TcpPacket6(target_ip, target_close_port),
                             TcpPacket7(target_ip, target_close_port)]
        self._tcp_open_port_checks_list = [TcpPacket2(target_ip, target_open_port),
                             TcpPacket3(target_ip, target_open_port),
                             TcpPacket4(target_ip, target_open_port)]
        self._udp_checks_list = [UdpProbe(target_ip, target_close_port)]

    def get_udp_checks_list(self):
        return self._udp_checks_list

    def get_open_port_checks_list(self):
        return self._tcp_open_port_checks_list

    def get_ecn_checks_list(self):
        return self._ecn_checks_list

    def get_icmp_checks_list(self):
        return self._icmp_checks_list

    def get_close_port_checks_list(self):
        return self._tcp_close_port_checks_list

    def get_probe_checks_list(self):
        return self._probe_checks_list

    def send_packets(self):
        """
        Sends packets to the target for conducting checks.
        """
        _ = [check.send_packet() for check in self._ecn_checks_list]
        _ = [check.send_packet() for check in self._icmp_checks_list]
        _ = [check.send_packet() for check in self._probe_checks_list]
        _ = [check.send_packet() for check in self._tcp_close_port_checks_list]
        _ = [check.send_packet() for check in self._tcp_open_port_checks_list]
        _ = [check.send_packet() for check in self._udp_checks_list]
