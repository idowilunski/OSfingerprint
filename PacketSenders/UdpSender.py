from Packets.UdpProbes import *
from PacketSenders.PacketSender import *


class UdpSender(PacketSender):
    """
    Represents a UDP packet sender for conducting UDP probe NMAP tests for OS-detection.

    Attributes:
        _checks_list (list): A list containing UDP probe objects for conducting tests.

    Note:
        This class inherits from PacketSender, which provides common functionalities for packet sending.
    """
    def __init__(self, target_ip, target_close_port):
        """
        Initializes a UdpSender object with the specified target IP and close port.

        Parameters:
            target_ip (str): The IP address of the target.
            target_close_port (int): The close port on the target for sending the UDP probe.
        """
        super().__init__()
        self._checks_list = [UdpProbe(target_ip, target_close_port)]
