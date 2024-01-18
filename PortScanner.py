import socket
import threading

open_ports = []
closed_ports = []


def scan_ports_range(host, start_port, end_port):
    global open_ports, closed_ports

    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        try:
            sock.connect((host, port))
            open_ports.append(port)
        except (socket.timeout, socket.error):
            closed_ports.append(port)
        finally:
            sock.close()
            if len(open_ports) > 0 and len(closed_ports) > 0:
                break


def perform_port_scan(ip_addr):
    global open_ports, closed_ports

    open_ports, closed_ports = [], []

    start_port = 1
    end_port = 1000
    port_step = 50

    threads = []
    for port in range(start_port, end_port + 1, port_step):
        thread = threading.Thread(target=scan_ports_range, args=(ip_addr, port, port + port_step - 1))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    return open_ports[0], closed_ports[0]
