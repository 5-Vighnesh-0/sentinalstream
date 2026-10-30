import numpy as np
import pytest

from backend.evaluation.benchmark import binary_metrics, recall_at_fpr


def test_recall_at_fpr_uses_the_benign_score_quantile():
    attack = np.array([False] * 100 + [True] * 4)
    scores = np.concatenate([np.arange(100), [50, 98.5, 99.5, 200]])  # benign p99 = 98.01
    assert recall_at_fpr(attack, scores, 0.01) == 0.75


def test_binary_metrics():
    attack = np.array([True, True, True, False, False, False, False, False])
    flagged = np.array([True, True, False, True, False, False, False, False])
    scores = np.array([0.9, 0.8, 0.2, 0.7, 0.1, 0.1, 0.1, 0.1])
    m = binary_metrics(attack, flagged, scores)
    assert (m["precision"], m["recall"], m["fpr_benign"]) == (pytest.approx(2 / 3), pytest.approx(2 / 3), 0.2)
    assert m["f1"] == pytest.approx(2 / 3)
    assert 0 < m["pr_auc"] <= 1
