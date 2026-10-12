import requests
import json
import time

# ── load asset register ───────────────────────────────────────────────────────
def load_assets(path='data/assets.json'):
    with open(path) as f:
        return json.load(f)

# ── NVD API ───────────────────────────────────────────────────────────────────
def query_nvd(cve_id):
    url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}'
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get('vulnerabilities', [])
            if vulns:
                cve   = vulns[0].get('cve', {})
                metrics = cve.get('metrics', {})
                # try CVSSv3 first, then CVSSv2
                if 'cvssMetricV31' in metrics:
                    score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                elif 'cvssMetricV30' in metrics:
                    score = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
                elif 'cvssMetricV2' in metrics:
                    score = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
                else:
                    score = 0.0

                published = cve.get('published', '')
                refs      = cve.get('references', [])
                pub_exploit = any(
                    'exploit' in r.get('url', '').lower()
                    for r in refs
                )
                return {
                    'nvd_cvss':      score,
                    'published':     published,
                    'public_exploit': int(pub_exploit),
                }
    except Exception as e:
        print(f'[NVD] Error for {cve_id}: {e}')
    return {'nvd_cvss': 0.0, 'published': '', 'public_exploit': 0}

# ── EPSS API ──────────────────────────────────────────────────────────────────
def query_epss(cve_id):
    url = f'https://api.first.org/data/v1/epss?cve={cve_id}'
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if data.get('data'):
                return float(data['data'][0].get('epss', 0.0))
    except Exception as e:
        print(f'[EPSS] Error for {cve_id}: {e}')
    return 0.0

# ── risk multipliers ──────────────────────────────────────────────────────────
SEGMENT_MULTIPLIER = {
    'DMZ':        1.4,
    'Management': 1.3,
    'Data':       1.3,
    'Internal':   1.0,
}

CRITICALITY_MULTIPLIER = {
    'critical': 1.4,
    'high':     1.3,
    'medium':   1.1,
    'low':      1.0,
}

def get_multiplier(asset):
    seg  = SEGMENT_MULTIPLIER.get(asset.get('segment', 'Internal'), 1.0)
    crit = CRITICALITY_MULTIPLIER.get(asset.get('criticality', 'low'), 1.0)
    exp  = 1.2 if asset.get('exposure_flag', 0) == 1 else 1.0
    return round(seg * crit * exp, 3)

# ── vulnerability age ─────────────────────────────────────────────────────────
def vuln_age_days(published_str):
    from datetime import datetime
    if not published_str:
        return 0
    try:
        pub = datetime.fromisoformat(published_str.replace('Z', '+00:00'))
        return (datetime.now(pub.tzinfo) - pub).days
    except:
        return 0

# ── main enrichment pipeline ──────────────────────────────────────────────────
def enrich(records, assets_path='data/assets.json'):
    assets  = load_assets(assets_path)
    enriched = []

    for i, rec in enumerate(records):
        print(f'[Enrichment] Processing {i+1}/{len(records)}: {rec["cve_id"]}')

        # get asset context
        asset = assets.get(rec['host_ip'], {
            'criticality': 'low',
            'segment': 'Internal',
            'exposure_flag': 0
        })

        # query APIs
        nvd_data   = query_nvd(rec['cve_id'])
        epss_score = query_epss(rec['cve_id'])
        time.sleep(1)  # respect rate limits

        multiplier = get_multiplier(asset)
        age        = vuln_age_days(nvd_data['published'])

        enriched.append({
            **rec,
            'epss_score':        epss_score,
            'nvd_cvss':          nvd_data['nvd_cvss'],
            'public_exploit':    nvd_data['public_exploit'],
            'hist_exploit':      0,  # updated in Phase 6
            'vuln_age':          age,
            'asset_criticality': asset.get('criticality', 'low'),
            'segment':           asset.get('segment', 'Internal'),
            'exposure_flag':     asset.get('exposure_flag', 0),
            'multiplier':        multiplier,
        })

    print(f'[Enrichment] Done. {len(enriched)} records enriched.')
    return enriched


if __name__ == '__main__':
    from parser import parse_openvas_report
    records  = parse_openvas_report('data/openvas_report.xml')
    enriched = enrich(records)
    for r in enriched[:2]:
        print(r)