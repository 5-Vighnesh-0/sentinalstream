import pandas as pd

from backend.ml import cicids


def raw(rows):
    """rows: (duration_us, fwd, bwd, label)"""
    return pd.DataFrame({
        " Flow Duration": [r[0] for r in rows],
        " Total Fwd Packets": [r[1] for r in rows],
        " Total Backward Packets": [r[2] for r in rows],
        "Total Length of Fwd Packets": [10] * len(rows),
        " Total Length of Bwd Packets": [20] * len(rows),
        " Label": [r[3] for r in rows],
    })


def test_clean_groups_dedups_and_drops_rare(monkeypatch):
    monkeypatch.setattr(cicids, "MIN_CLASS_ROWS", 2)
    monday = raw([(1, 1, 1, "BENIGN"), (2, 1, 1, "BENIGN"), (2, 1, 1, "BENIGN"), (-1, 1, 1, "BENIGN")])
    thursday = raw([(3, 2, 0, "Web Attack � Brute Force"), (4, 2, 0, "Web Attack � XSS"),
                    (5, 9, 0, "Heartbleed"), (6, 3, 0, "FTP-Patator"), (7, 3, 0, "SSH-Patator")])
    df, report = cicids.clean([("Monday.csv", monday), ("Thursday.csv", thursday)])

    assert report["rows_read"] == 9
    assert report["rows_dropped_invalid"] == 1  # negative duration
    assert report["duplicates_removed"] == 1
    assert report["dropped_rare_classes"] == {"Heartbleed": 1}
    assert report["class_rows"] == {"BENIGN": 2, "WebAttack": 2, "BruteForce": 2}
    assert set(df["day"]) == {"Monday.csv", "Thursday.csv"}


def test_split_is_stratified_and_deterministic():
    df = pd.DataFrame({"x": range(100), "label": ["BENIGN"] * 80 + ["DoS"] * 20})
    _, test_a = cicids.split(df)
    _, test_b = cicids.split(df)
    assert test_a.index.equals(test_b.index)
    assert (len(test_a), (test_a["label"] == "DoS").sum()) == (20, 4)
