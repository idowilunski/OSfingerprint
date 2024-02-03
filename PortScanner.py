import socket
import threading


class PortScanner:
    """
    A class for performing threaded port scanning on a specified IP address.

    Attributes:
        open_ports (list): A list containing open ports discovered during the scan.
        closed_ports (list): A list containing closed ports discovered during the scan.

    Methods:
        scan_ports_range(ip_addr, start_port, end_port): Scan a range of ports on the given IP address.
        perform_port_scan(ip_addr): Perform a threaded port scan on a specified IP address.
    """

    def __init__(self):
        """
        Initializes a PortScanner object.
        """
        self.open_ports = []
        self.closed_ports = []

    def scan_ports_range(self, ip_addr, start_port, end_port):
        """
        Scan a range of ports on the given IP address.

        Parameters:
        - ip_addr (str): The target IP address to scan.
        - start_port (int): The starting port of the range.
        - end_port (int): The ending port of the range.

        Description:
        The function goes over each port in the specified range and tries to connect to it.
        If the connection is successful (open port), it is appended to the open_ports list.
        If the connection fails (closed port), it is appended to the closed_ports list.
        The function exits once it finds at least one open port and one closed port.

        Return value:
        The function does not return a value but sets two attributes: open_ports and closed_ports.
        """
        for port in range(start_port, end_port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            try:
                sock.connect((ip_addr, port))
                self.open_ports.append(port)
            except (socket.timeout, socket.error):
                self.closed_ports.append(port)
            finally:
                sock.close()

                if len(self.open_ports) > 0 and len(self.closed_ports) > 0:
                    break

    def perform_port_scan(self, ip_addr):
        """
        Perform a threaded port scan on a specified IP address.

        Parameters:
        - ip_addr (str): The target IP address to scan.

        Description:
        The function initiates a threaded port scan on the specified IP address using the scan_ports_range method.
        It divides the port range (from 1 to 1000) into threads, each responsible for scanning a segment of ports.
        The open_ports and closed_ports attributes are initialized to empty lists to store the results.
        Multiple threads are created to concurrently scan different port ranges.
        Once all threads complete, the function waits for their completion using the join method.
        The result of the scan is returned as a tuple containing the first open port and the first closed port found.

        Return value:
        A tuple containing the first open port and the first closed port found during the port scan.
        """
        self.open_ports, self.closed_ports = [], []

        start_port = 1
        end_port = 65535
        port_step = 100

        threads = []

        for port in range(start_port, end_port + 1, port_step):
            thread = threading.Thread(target=self.scan_ports_range, args=(ip_addr, port, port + port_step - 1))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        return self.open_ports[0], self.closed_ports[0]

