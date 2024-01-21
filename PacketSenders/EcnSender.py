from Packets import EcnPackets
from Packets.EcnPackets import *
from PacketSenders.PacketSender import *


class EcnSender(PacketSender):
    """
    Represents a sender for ECN (Explicit Congestion Notification) packets used for testing.

    Attributes:
        _checks_list (list): A list containing ECN packet objects for conducting tests.
    """
    def __init__(self, target_ip, target_open_port):
        """
        Initializes an EcnSender object with the specified target IP and open port.

        Parameters:
            target_ip (str): The IP address of the target.
            target_open_port (int): The open port on the target for sending ECN packets.
        """
        super().__init__()
        self._checks_list = [EcnPacket(target_ip, target_open_port)]
