from check import Check


class DummyCheck(Check):
    def __init__(self):
        pass

    def get_received_window_size(self):
        return 1234