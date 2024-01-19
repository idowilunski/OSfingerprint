# test Fingeprint class
import pytest
from Fingerprint import Fingerprint
from Result.TCheck import TCheck
from Result.Sequence import Sequence
from Result.Options import Options
from Result.WindowSize import WindowSize
from Result.Ecn import Ecn
from Result.U1 import U1
from Result.IE import IE

#@pytest.fixture
#def setup_data():
#    data = {'key': 'value'}
#    return data


def test_fingerprint_ctor():
    fp = Fingerprint()
    assert isinstance(fp.SEQ, Sequence)
    assert isinstance(fp.OPS, Options)
    assert isinstance(fp.WIN, WindowSize)
    assert isinstance(fp.ECN, Ecn)
    assert fp.name == "N/A"
    assert fp.CPE == "N/A"
    assert isinstance(fp.T1, TCheck)
    assert isinstance(fp.T2, TCheck)
    assert isinstance(fp.T3, TCheck)
    assert isinstance(fp.T4, TCheck)
    assert isinstance(fp.T5, TCheck)
    assert isinstance(fp.T6, TCheck)
    assert isinstance(fp.T7, TCheck)
    assert isinstance(fp.U1, U1)
    assert isinstance(fp.IE, IE)

#def test_init_from_response():
#    fp = Fingerprint()
#    ecn_sender = EcnSender()
#    open_ports_sender = OpenPortsSender()
#    udp_sender =
#    fp.init_from_response(ecn_sender, open_ports_sender, udp_sender, icmp_sender, probe_sender,
#                           close_ports_sender)

#TODO create comparison functions for testing of seq, IE, etc... can use the comparison funcs of score similarilty and verify it's max score.
