import xml.etree.ElementTree as ET
from datetime import datetime


def parse_openvas_report(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    records = []
    seen    = set()

    for result in root.iter('result'):
        cve_id = None
        nvt    = result.find('nvt')
        if nvt is not None:
            refs = nvt.find('refs')
            if refs is not None:
                for ref in refs.findall('ref'):
                    if ref.get('type') == 'cve':
                        cve_id = ref.get('id')
                        break

        host_elem     = result.find('host')
        host_ip       = host_elem.text.strip() if host_elem is not None and host_elem.text else 'unknown'
        port_elem     = result.find('port')
        port_raw      = port_elem.text.strip() if port_elem is not None and port_elem.text else 'general/tcp'
        port_num, protocol = (port_raw.split('/') + ['tcp'])[:2] if '/' in port_raw else (port_raw, 'tcp')
        severity_elem = result.find('severity')
        cvss_score    = float(severity_elem.text.strip()) if severity_elem is not None and severity_elem.text else 0.0
        name_elem     = result.find('name')
        vuln_name     = name_elem.text.strip() if name_elem is not None and name_elem.text else 'Unknown'
        desc_elem     = result.find('description')
        description   = desc_elem.text.strip() if desc_elem is not None and desc_elem.text else ''

        if not cve_id or cvss_score == 0.0:
            continue
        key = (cve_id, host_ip)
        if key in seen:
            continue
        seen.add(key)

        records.append({
            'cve_id':      cve_id,
            'host_ip':     host_ip,
            'port':        port_num,
            'protocol':    protocol,
            'vuln_name':   vuln_name,
            'cvss_score':  cvss_score,
            'description': description[:500],
            'scan_date':   datetime.utcnow().isoformat(),
            'source':      'OpenVAS',
        })

    print(f'[OpenVAS Parser] {len(records)} unique records extracted.')
    return records


def parse_zap_report(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    records = []
    seen    = set()

    sites = root.findall('site')
    if not sites:
        sites = root.findall('.//site')

    print(f'[ZAP Parser] Found {len(sites)} site(s) in report.')

    for site in sites:
        host_ip = site.get('host', 'unknown')
        port    = site.get('port', '80')

        alertitems = site.findall('.//alertitem')
        print(f'[ZAP Parser] {len(alertitems)} alert items found for {host_ip}')

        for alertitem in alertitems:
            risk_code  = int(alertitem.findtext('riskcode', '0'))
            if risk_code == 0:
                continue

            cvss_map   = {3: 8.0, 2: 5.0, 1: 2.0}
            cvss_score = cvss_map.get(risk_code, 0.0)
            vuln_name  = alertitem.findtext('alert', 'Unknown')
            description= alertitem.findtext('desc', '')[:500]
            solution   = alertitem.findtext('solution', '')

            cve_id = None
            refs   = alertitem.findtext('reference', '')
            for line in refs.split('\n'):
                line = line.strip()
                if line.startswith('CVE-'):
                    cve_id = line
                    break

            if not cve_id:
                plugin_id = alertitem.findtext('pluginid', '0')
                cve_id    = f'ZAP-{plugin_id}-{vuln_name[:15].strip().replace(" ", "-")}'

            key = (cve_id, host_ip)
            if key in seen:
                continue
            seen.add(key)

            records.append({
                'cve_id':      cve_id,
                'host_ip':     host_ip,
                'port':        port,
                'protocol':    'tcp',
                'vuln_name':   vuln_name,
                'cvss_score':  cvss_score,
                'description': description,
                'solution':    solution,
                'scan_date':   datetime.utcnow().isoformat(),
                'source':      'OWASP-ZAP',
            })

    print(f'[ZAP Parser] {len(records)} unique records extracted.')
    return records


if __name__ == '__main__':
    import os
    records = parse_openvas_report('data/openvas_report.xml')
    if os.path.exists('data/zap_report.xml'):
        zap     = parse_zap_report('data/zap_report.xml')
        records += zap
    print(f'[Parser] Combined total: {len(records)} records')
    for r in records[:3]:
        print(r)
