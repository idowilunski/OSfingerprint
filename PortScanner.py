import socket
import threading

open_ports = []
closed_ports = []


def scan_ports_range(ip_addr, start_port, end_port):
    """
    Scan a range of ports on the given IP address.

    Parameters:
    - ip_address (str): The target IP address to scan.
    - start_port (int): The starting port of the range.
    - end_port (int): The ending port of the range.

    Description:
    The function goes over each port in the specified range and tries to connect to it.
    If the connection is successful (open port), it is appended to the global variable `open_ports`.
    If the connection fails (closed port), it is appended to the global variable `close_ports`.
    The function exits once it finds at least one open port and one closed port.

    Return value:
    The function does not return a value but sets two global variables: `open_ports` and `close_ports`.
    """
    global open_ports, closed_ports

    # Iterate over the port range and try to connect to it, append result to relevant global variable
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        try:
            sock.connect((ip_addr, port))
            open_ports.append(port)
        except (socket.timeout, socket.error):
            closed_ports.append(port)
        finally:
            sock.close()
            # If we know of at least one open port and one close port, exit the function
            if len(open_ports) > 0 and len(closed_ports) > 0:
                break


def perform_port_scan(ip_addr):
    """
    Perform a threaded port scan on a specified IP address.

    Parameters:
    - ip_addr (str): The target IP address to scan.

    Description:
    The function initiates a threaded port scan on the specified IP address using the `scan_ports_range` function.
    It divides the port range (from 1 to 1000) into threads, each responsible for scanning a segment of ports.
    The global variables `open_ports` and `closed_ports` are initialized to empty lists to store the results.
    Multiple threads are created to concurrently scan different port ranges.
    Once all threads complete, the function waits for their completion using the `join` method.
    The result of the scan is returned as a tuple containing the first open port and the first closed port found.

    Return value:
    A tuple containing the first open port and the first closed port found during the port scan.
    """
    global open_ports, closed_ports

    open_ports, closed_ports = [], []

    # Initialize scanning parameters
    start_port = 1
    end_port = 1000
    port_step = 50

    threads = []

    # Create a thread per 50 ports to scan, each thread will receive the ip address we're scanning and a range of ports
    # to scan, will go over them and append the open/close ports results to the global variables, accordingly
    for port in range(start_port, end_port + 1, port_step):
        thread = threading.Thread(target=scan_ports_range, args=(ip_addr, port, port + port_step - 1))
        threads.append(thread)
        thread.start()

    # Wait for all thread to finish before determining the results
    for thread in threads:
        thread.join()

    return open_ports[0], closed_ports[0]
