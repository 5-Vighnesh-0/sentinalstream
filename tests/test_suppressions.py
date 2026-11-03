import pytest

from backend.api.suppressions import suppressed_by, validate

ALERT = {"src_ip": "127.0.0.1", "dst_ip": "127.0.0.1", "dst_port": 42361, "attack_type": "anomaly"}


def rule(id, **fields):
    return {"id": id, **{f: None for f in ("src_ip", "dst_ip", "dst_port", "attack_type")}, **fields}


def test_an_exact_rule_matches_only_its_pattern():
    exact = rule(1, **ALERT)
    assert suppressed_by([exact], ALERT) == 1
    assert suppressed_by([exact], {**ALERT, "dst_port": 80}) is None


def test_a_null_field_means_any():
    assert suppressed_by([rule(1, attack_type="anomaly", src_ip="127.0.0.1")], {**ALERT, "dst_port": 9}) == 1


def test_the_lowest_id_wins():
    assert suppressed_by([rule(2, attack_type="anomaly"), rule(5, **ALERT)], ALERT) == 2


def test_validation_refuses_an_all_any_rule_and_bad_values():
    with pytest.raises(ValueError):
        validate({})
    for bad in ({"src_ip": "not-an-ip"}, {"dst_port": 70000}, {"attack_type": "x" * 65}):
        with pytest.raises(ValueError):
            validate(bad)


def test_validation_keeps_only_known_fields_and_normalises_ips():
    assert validate({"dst_ip": "::0001", "attack_type": "anomaly", "extra": 1}) == {
        "src_ip": None, "dst_ip": "::1", "dst_port": None, "attack_type": "anomaly"}
