import numpy as np
import joblib
import os
import warnings
warnings.filterwarnings('ignore')
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import LabelEncoder

MODEL_DIR = 'models'

def train_models(X, y):
    os.makedirs(MODEL_DIR, exist_ok=True)

    le    = LabelEncoder()
    y_enc = le.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_enc, test_size=0.2, random_state=42
    )

    # Random Forest
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X_train, y_train)
    rf_preds = rf.predict(X_test)
    rf_acc   = accuracy_score(y_test, rf_preds)
    present  = np.unique(y_test)
    print(f'\n[RF] Accuracy: {rf_acc:.2%}')
    print(classification_report(
        y_test, rf_preds,
        labels=present,
        target_names=le.inverse_transform(present),
        zero_division=0
    ))

    # Logistic Regression
    lr = LogisticRegression(max_iter=2000, random_state=42)
    lr.fit(X_train, y_train)
    lr_preds = lr.predict(X_test)
    lr_acc   = accuracy_score(y_test, lr_preds)
    print(f'[LR] Accuracy: {lr_acc:.2%}')
    print(classification_report(
        y_test, lr_preds,
        labels=present,
        target_names=le.inverse_transform(present),
        zero_division=0
    ))

    # Isolation Forest
    iso = IsolationForest(contamination=0.1, random_state=42)
    iso.fit(X_train)

    joblib.dump(rf,  f'{MODEL_DIR}/rf_model.pkl')
    joblib.dump(lr,  f'{MODEL_DIR}/lr_model.pkl')
    joblib.dump(iso, f'{MODEL_DIR}/iso_model.pkl')
    joblib.dump(le,  f'{MODEL_DIR}/label_encoder.pkl')
    print('\n[Models] Saved to models/')

    return rf, lr, iso, le


def compute_context_score(rf, le, feature_vector, multiplier):
    """Context-aware risk score (0-10) — ML output × context multiplier."""
    fv      = feature_vector.reshape(1, -1)
    proba   = rf.predict_proba(fv)[0]
    weights = {'Critical': 1.0, 'High': 0.75, 'Medium': 0.5, 'Low': 0.25}
    base    = 0.0
    for i, encoded in enumerate(rf.classes_):
        label  = le.inverse_transform([encoded])[0]
        base  += proba[i] * weights.get(label, 0.0)
    score = min(10.0, round(base * 10 * multiplier, 2))
    return score


def compute_cvss_score(cvss_raw):
    """Plain CVSS-based risk score (0-10) — no context, no ML."""
    return round(min(float(cvss_raw), 10.0), 2)


def score_records(enriched_records):
    from features import build_feature_vector

    rf  = joblib.load(f'{MODEL_DIR}/rf_model.pkl')
    iso = joblib.load(f'{MODEL_DIR}/iso_model.pkl')
    le  = joblib.load(f'{MODEL_DIR}/label_encoder.pkl')

    scored = []
    for rec in enriched_records:
        fv            = build_feature_vector(rec)
        context_score = compute_context_score(rf, le, fv, rec.get('multiplier', 1.0))
        cvss_score    = compute_cvss_score(rec.get('cvss_score', 0.0))
        anomaly_flag  = iso.predict(fv.reshape(1, -1))[0] == -1
        label         = le.inverse_transform(rf.predict(fv.reshape(1, -1)))[0]

        scored.append({
            **rec,
            'cvss_risk_score':    cvss_score,
            'risk_score':         context_score,
            'rf_label':           label,
            'anomaly_flag':       bool(anomaly_flag),
        })

    scored.sort(key=lambda x: x['risk_score'], reverse=True)
    print(f'[Scorer] {len(scored)} records scored.')
    return scored


if __name__ == '__main__':
    from parser import parse_openvas_report
    from enrichment import enrich
    from features import build_dataset

    records  = parse_openvas_report('data/openvas_report.xml')
    enriched = enrich(records)
    X, y, _  = build_dataset(enriched)
    train_models(X, y)
    scored = score_records(enriched)
    for r in scored[:3]:
        print(f"{r['cve_id']} | CVSS Score: {r['cvss_risk_score']} | Context Score: {r['risk_score']} | {r['rf_label']}")
