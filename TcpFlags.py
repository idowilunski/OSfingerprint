# TCP flags, as documented in https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq
# Under : "TCP flags (F)"
class TCPFlags:
    FIN = 0x01  # Final
    SYN = 0x02  # Synchronize
    RST = 0x04  # Reset
    PSH = 0x08  # Push
    ACK = 0x10  # Acknowledgment
    URG = 0x20  # Urgent
    ECE = 0x40  # Explicit Congestion Notification Echo
    CWR = 0x80  # Congestion Window Reduced
