# test_your_module.py
import pytest
from Result.WindowSize import WindowSize


def test_init_initializes_all_members():
    w_size = WindowSize()
    assert w_size.w1 is None
    assert w_size.w2 is None
    assert w_size.w3 is None
    assert w_size.w4 is None
    assert w_size.w5 is None
    assert w_size.w6 is None


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

# TODO need to verify init from DB that's ok, and init from response that's ok or with bugs
