import os
from parser import parse_openvas_report, parse_zap_report
from enrichment import enrich
from features import build_dataset
from ml_scorer import train_models, score_records
from db import store_records


def run_pipeline():

    print('\n=== PHASE 3: Parsing ===')
    records = parse_openvas_report('data/openvas_report.xml')

    if os.path.exists('data/zap_report.xml'):
        zap_records = parse_zap_report('data/zap_report.xml')
        records    += zap_records
        print(f'[Parser] Combined total: {len(records)} records')
    else:
        print('[Parser] No ZAP report found — using OpenVAS only.')

    if not records:
        print('[Pipeline] No records to process. Exiting.')
        return

    print('\n=== PHASE 4: Enrichment ===')
    enriched = enrich(records)

    print('\n=== PHASE 5: Feature Vectors ===')
    X, y, _ = build_dataset(enriched)

    print('\n=== PHASE 6: ML Training & Scoring ===')
    train_models(X, y)
    scored = score_records(enriched)

    print('\n=== PHASE 7: Storing in MongoDB ===')
    store_records(scored)

    print('\n=== PIPELINE COMPLETE ===')
    print('Top 5 vulnerabilities by risk score:')
    for r in scored[:5]:
        print(f"  {r['cve_id']} | {r['host_ip']} | Score: {r['risk_score']} | {r['rf_label']} | Source: {r.get('source','?')}")


if __name__ == '__main__':
    run_pipeline()
