import numpy as np

CRITICALITY_MAP = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
SEGMENT_MAP     = {'Internal': 2, 'Data': 3, 'Management': 3, 'DMZ': 4}

def build_feature_vector(record):
    """
    Builds an 8-element feature vector from an enriched record.
    Returns (vector, label_dict)
    """
    fv = [
        float(record.get('cvss_score', 0.0)),
        float(record.get('epss_score', 0.0)),
        CRITICALITY_MAP.get(record.get('asset_criticality', 'low'), 1),
        SEGMENT_MAP.get(record.get('segment', 'Internal'), 2),
        int(record.get('exposure_flag', 0)),
        int(record.get('vuln_age', 0)),
        int(record.get('public_exploit', 0)),
        int(record.get('hist_exploit', 0)),
    ]
    return np.array(fv, dtype=float)


def assign_label(cvss_score, multiplier):
    """
    Assigns a risk label based on adjusted score.
    Used for training data generation.
    """
    adjusted = cvss_score * multiplier
    if adjusted >= 9.0:
        return 'Critical'
    elif adjusted >= 7.0:
        return 'High'
    elif adjusted >= 4.0:
        return 'Medium'
    else:
        return 'Low'


def build_dataset(enriched_records):
    X, y, meta = [], [], []
    for rec in enriched_records:
        fv    = build_feature_vector(rec)
        label = assign_label(rec.get('cvss_score', 0), rec.get('multiplier', 1.0))
        X.append(fv)
        y.append(label)
        meta.append({
            'cve_id':   rec['cve_id'],
            'host_ip':  rec['host_ip'],
            'label':    label,
        })
    return np.array(X), y, meta


if __name__ == '__main__':
    from parser import parse_openvas_report
    from enrichment import enrich
    records  = parse_openvas_report('data/openvas_report.xml')
    enriched = enrich(records)
    X, y, meta = build_dataset(enriched)
    print(f'[Features] Dataset shape: {X.shape}')
    print(f'[Features] Labels: {set(y)}')
    print(f'[Features] Sample: {X[0]} → {y[0]}')