# Fraud machine learning research track

This directory contains a **reproducible trainable ML experiment** for an illustrative synthetic fraud dataset. It uses gradient-boosted trees with an independent calibration partition and a held-out test partition. No real user or financial records are used.

```bash
pip install -r ml/requirements.txt
python ml/train.py --output ml/artifacts --rows 6000
PYTHONPATH=ml python -m pytest ml/test_train.py -q
```

The output includes `synthetic_fraud_model.joblib` and `metrics.json`. Artifacts are ignored by Git and must not be loaded from untrusted sources (joblib loads arbitrary Python pickle content).

**Do not claim that the scores are real-world fraud prediction accuracy.** Labels are created by a programmed synthetic process and any high performance may simply reflect learning that process. The model is NOT connected to authorization endpoints and is NEVER permitted to bypass the signed-action policy.

To progress to real supervised models: establish authorized, privacy reviewed fraud outcomes; leakage-safe time-grouped splits; authenticated feature provenance; drift/fairness analyses; calibration and rejection option; operational safeguards and offline/shadow validation with human review.
