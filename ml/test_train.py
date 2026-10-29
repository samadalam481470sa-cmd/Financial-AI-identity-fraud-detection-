from pathlib import Path
from train import FEATURE_NAMES, synthetic_dataset, train

def test_deterministic_synthetic_data():
    x, y = synthetic_dataset(800)
    a, b = synthetic_dataset(800)
    assert x.shape == (800, len(FEATURE_NAMES))
    assert (x == a).all()
    assert (y == b).all()

def test_train_and_metrics(tmp_path):
    out = train(tmp_path, 800)
    assert (tmp_path / "synthetic_fraud_model.joblib").exists()
    assert (tmp_path / "metrics.json").exists()
    assert out["dataset"] == "synthetic_labels_only"
    assert 0 <= out["average_precision"] <= 1
    assert 0 <= out["brier_score"] <= 1
    assert out["split"]["test"] == 160
