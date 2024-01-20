from PacketSenders.probesSender import ProbesSender
from DummyProbePacket import DummyProbePacket


class DummyProbeSender(ProbesSender):
    def __init__(self):
        self._checks_list = [DummyProbePacket(), DummyProbePacket(), DummyProbePacket(),
                             DummyProbePacket(), DummyProbePacket(), DummyProbePacket()]
