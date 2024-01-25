import logging

from Packets.EcnChecks import EcnCheck1
from Packets.TcpClosePortChecks import *
from Packets.TcpOpenPortChecks import *
from Packets.UdpChecks import *
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
        self._ecn_checks_list = [EcnCheck1(target_ip, target_open_port)]
        self._icmp_checks_list = [IcmpCheck1(target_ip, target_open_port),
                             IcmpCheck2(target_ip, target_open_port)]
        self._probe_checks_list = [ProbeCheck1(target_ip, target_open_port),
                             ProbeCheck2(target_ip, target_open_port),
                             ProbeCheck3(target_ip, target_open_port),
                             ProbeCheck4(target_ip, target_open_port),
                             ProbeCheck5(target_ip, target_open_port),
                             ProbeCheck6(target_ip, target_open_port)]
        self._tcp_close_port_checks_list = [TcpCheck5(target_ip, target_close_port),
                             TcpCheck6(target_ip, target_close_port),
                             TcpCheck7(target_ip, target_close_port)]
        self._tcp_open_port_checks_list = [TcpCheck2(target_ip, target_open_port),
                             TcpCheck3(target_ip, target_open_port),
                             TcpCheck4(target_ip, target_open_port)]
        self._udp_checks_list = [UdpCheck1(target_ip, target_close_port)]

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
