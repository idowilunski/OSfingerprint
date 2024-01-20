# test WindowSize.py
import pytest
from Result.U1 import U1
#import DummyProbeSender


def test_init_initializes_all_members():
    u1 = U1()
    assert u1.r is None
    assert u1.df is None
    assert u1.t is None
    assert u1.tg is None
    assert u1.ipl is None
    assert u1.un is None
    assert u1.ripl is None
    assert u1.rid is None
    assert u1.ripck is None
    assert u1.ruck is None
    assert u1.rud is None












def test_init_from_db_with_missing_keys_doesnt_raise_exception():
    w_size = WindowSize()

    dict_missing_w1= {"W2": "abc", "W3": "dce", "W4": "fgh", "W5": "ijk", "W6": "lmn"}
    w_size.init_from_db(dict_missing_w1)

    dict_missing_w2= {"W1": "abc", "W3": "dce", "W4": "fgh", "W5": "ijk", "W6": "lmn"}
    w_size.init_from_db(dict_missing_w2)

    dict_missing_w3= {"W1": "abc", "W2": "dce", "W4": "fgh", "W5": "ijk", "W6": "lmn"}
    w_size.init_from_db(dict_missing_w3)

    dict_missing_w4= {"W1": "abc", "W2": "dce", "W3": "fgh", "W5": "ijk", "W6": "lmn"}
    w_size.init_from_db(dict_missing_w4)

    dict_missing_w5= {"W1": "abc", "W2": "dce", "W3": "fgh", "W4": "ijk", "W6": "lmn"}
    w_size.init_from_db(dict_missing_w5)

    dict_missing_w6= {"W1": "abc", "W2": "dce", "W3": "fgh", "W4": "ijk", "W5": "lmn"}
    w_size.init_from_db(dict_missing_w6)

    empty_dict = {}
    w_size.init_from_db(empty_dict)


def test_init_from_db_with_invalid_dict_raises_exception():
    w_size = WindowSize()

    with pytest.raises(Exception, match="Init from DB called with a non dictionary object!"):
        w_size.init_from_db(list())


def test_init_from_db_happy_flow():
    w = WindowSize()
    dict_to_init_from = {"W1": "abc", "W2": "dce", "W3": "fgh", "W4": "ijk", "W5": "lmn", "W6": "opq"}
    w.init_from_db(dict_to_init_from)
    assert w.w1 == "abc"
    assert w.w2 == "dce"
    assert w.w3 == "fgh"
    assert w.w4 == "ijk"
    assert w.w5 == "lmn"
    assert w.w6 == "opq"


def test_calculate_similarity_score():
    w1 = WindowSize()
    w1.w1 = "a"
    w1.w2 = "b"
    w1.w3 = "c"
    w1.w4 = "d"
    w1.w5 = "e"
    w1.w6 = "f"
    empty_w = WindowSize()

    w3 = WindowSize()
    w3.w1 = "a"
    assert w1.calculate_similarity_score(empty_w) == 0
    assert w1.calculate_similarity_score(w3) == 15

    w3.w2 = "b"
    assert w1.calculate_similarity_score(w3) == 30

    w3.w3 = "c"
    assert w1.calculate_similarity_score(w3) == 45

    w3.w4 = "d"
    assert w1.calculate_similarity_score(w3) == 60

    w3.w5 = "e"
    assert w1.calculate_similarity_score(w3) == 75

    w3.w6 = "f"
    assert w1.calculate_similarity_score(w3) == 90


def test_init_from_response_happy_flow():
    dummy_probe_sender = DummyProbeSender.DummyProbeSender()
    w = WindowSize()
    w.init_from_response(dummy_probe_sender)
    assert w.w1 == 1234
    assert w.w2 == 1234
    assert w.w3 == 1234
    assert w.w4 == 1234
    assert w.w5 == 1234
    assert w.w6 == 1234
