import logging


class PacketSender:
    """
    Represents a base class for sending and handling responses for various packet checks.

    Attributes:
        _checks_list (list): A list containing packet check objects.

    Methods:
        parse_response_packets(): Parses the response packets received from the target.
        prepare_packets(): Prepares the packet checks before sending.
        send_packets(): Sends packets to the target for conducting checks.
        get_checks_list(): Returns the list of packet check objects.
    """
    def __init__(self):
        """
        Initializes a PacketSender object
        """
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        self._checks_list = None

    def parse_response_packets(self):
        """
        Parses the response packets received from the target.
        """
        try:
            _ = [check.parse_response_packet() for check in self._checks_list]
        except:
            pass

    def prepare_packets(self):
        """
         Prepares the packet checks before sending.
         """
        _ = [check.prepare_packet() for check in self._checks_list]

    def send_packets(self):
        """
        Sends packets to the target for conducting checks.
        """
        _ = [check.send_packet() for check in self._checks_list]

    def get_checks_list(self):
        """
        Returns the list of packet check objects.
        """
        return self._checks_list
