import threading
import socket

open_port = None
closed_port = None
scan_complete = threading.Event()

def scan_ports_range(host, start_port, end_port):
    global open_port, closed_port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)

    try:
        for port in range(start_port, end_port + 1):
            sock.connect((host, port))
            open_port = port
    except (socket.timeout, socket.error):
        closed_port = port
    finally:
        sock.close()

    scan_complete.set()

def perform_port_scan():
    global open_port, closed_port, scan_complete
    open_port, closed_port = None, None
    scan_complete.clear()

    target_host = "localhost"  # Replace with your target host
    start_port = 1
    end_port = 1000
    port_step = 50

    threads = []
    for port in range(start_port, end_port + 1, port_step):
        thread = threading.Thread(target=scan_ports_range, args=(target_host, port, port + port_step - 1))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    scan_complete.wait()

    return open_port, closed_port
