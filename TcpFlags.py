class TCPFlags:
    """
    Class representing TCP flags as defined in the TCP protocol.

    The class provides constants for commonly used TCP flags, each represented by a hexadecimal value.
    as documented in https://nmap.org/book/osdetect-methods.html#osdetect-probes-seq under : "TCP flags (F)"
    """
    FIN = 0x01  # Final
    SYN = 0x02  # Synchronize
    RST = 0x04  # Reset
    PSH = 0x08  # Push
    ACK = 0x10  # Acknowledgment
    URG = 0x20  # Urgent
    ECE = 0x40  # Explicit Congestion Notification Echo
    CWR = 0x80  # Congestion Window Reduced
