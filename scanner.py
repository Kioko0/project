import subprocess
import threading
import os
import time
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform
import xml.etree.ElementTree as ET

scan_state = {
    'running':          False,
    'openvas_status':   'idle',
    'zap_status':       'idle',
    'openvas_progress': 0,
    'zap_progress':     0,
    'pipeline_status':  'idle',
    'message':          'Ready. Enter a target IP to begin.',
    'error':            None,
    'target_ip':        '',
}

OPENVAS_HOST = 'openvas'
OPENVAS_PORT = 9390
OPENVAS_USER = 'admin'
OPENVAS_PASS = 'admin123'
NETWORK      = 'vulnerability-lab_pentest-lab'


def run_openvas_scan(target_ip):
    global scan_state
    try:
        scan_state['openvas_status']   = 'running'
        scan_state['openvas_progress'] = 0
        scan_state['message']          = f'OpenVAS: Connecting to scanner...'

        connection = TLSConnection(hostname=OPENVAS_HOST, port=OPENVAS_PORT)
        transform  = EtreeCheckCommandTransform()

        with Gmp(connection=connection, transform=transform) as gmp:
            gmp.authenticate(OPENVAS_USER, OPENVAS_PASS)
            scan_state['message'] = 'OpenVAS: Authenticated. Setting up scan...'

            # get Full and Fast config
            configs   = gmp.get_scan_configs()
            config_id = None
            for c in configs.findall('config'):
                if 'Full and fast' in (c.findtext('name') or ''):
                    config_id = c.get('id')
                    break

            # get OpenVAS Default scanner
            scanners   = gmp.get_scanners()
            scanner_id = None
            for s in scanners.findall('scanner'):
                if 'OpenVAS' in (s.findtext('name') or ''):
                    scanner_id = s.get('id')
                    break

            if not config_id or not scanner_id:
                raise Exception('Scan config or scanner not found in OpenVAS.')

            # create target
            port_list_id = '33d0cd82-57c6-11e1-8ed1-406186ea4fc5'
            target    = gmp.create_target(
                name=f'Scan-{target_ip}-{int(time.time())}',
                hosts=[target_ip],
                port_list_id=port_list_id,
            )
            target_id = target.get('id')

            # create and start task
            task = gmp.create_task(
                name=f'Task-{target_ip}-{int(time.time())}',
                config_id=config_id,
                target_id=target_id,
                scanner_id=scanner_id,
            )
            task_id = task.get('id')
            gmp.start_task(task_id)
            scan_state['message'] = f'OpenVAS: Scanning {target_ip}...'

            # poll progress
            while True:
                time.sleep(20)
                task_resp = gmp.get_task(task_id=task_id)
                task_el   = task_resp.find('task')
                status    = task_el.findtext('status') or ''
                progress  = int(task_el.findtext('progress') or 0)
                scan_state['openvas_progress'] = max(progress, 0)
                scan_state['message'] = f'OpenVAS: {status} ({progress}%)'

                if status == 'Done':
                    break
                if status in ('Stopped', 'Failed'):
                    raise Exception(f'OpenVAS scan {status}')

            # export XML report
            reports   = gmp.get_reports(
                filter_string=f'task_id={task_id} rows=-1'
            )
            report_id = reports.find('.//report').get('id')
            report    = gmp.get_report(
                report_id=report_id,
                report_format_id='a994b278-1f62-11e1-96ac-406186ea4fc5',
                ignore_pagination=True,
                details=True,
            )
            with open('data/openvas_report.xml', 'w') as f:
                f.write(ET.tostring(report, encoding='unicode'))

            scan_state['openvas_status']   = 'done'
            scan_state['openvas_progress'] = 100
            scan_state['message']          = 'OpenVAS: Scan complete.'

    except Exception as e:
        scan_state['openvas_status'] = 'error'
        scan_state['error']          = str(e)
        scan_state['message']        = f'OpenVAS error: {str(e)}'


def run_zap_scan(target_ip):
    global scan_state
    try:
        scan_state['zap_status']    = 'running'
        scan_state['zap_progress']  = 10
        scan_state['message']       = f'ZAP: Scanning {target_ip}...'

        result = subprocess.run([
            'docker', 'run', '--rm',
            '--network', NETWORK,
            '-v', f'{os.path.abspath("data")}:/zap/wrk/:rw',
            'ghcr.io/zaproxy/zaproxy:stable',
            'zap-baseline.py',
            '-t', f'http://{target_ip}',
            '-x', 'zap_report.xml',
        ], capture_output=True, text=True, timeout=600)

        # return code 2 = warnings found (normal for ZAP)
        if result.returncode in (0, 2):
            scan_state['zap_status']   = 'done'
            scan_state['zap_progress'] = 100
            scan_state['message']      = 'ZAP: Scan complete.'
        else:
            raise Exception(result.stderr[-300:] or 'ZAP scan failed.')

    except Exception as e:
        scan_state['zap_status'] = 'error'
        scan_state['error']      = str(e)
        scan_state['message']    = f'ZAP error: {str(e)}'


def run_pipeline():
    global scan_state
    scan_state['pipeline_status'] = 'running'
    scan_state['message']         = 'Running ML pipeline...'

    try:
        result = subprocess.run(
            ['python3', 'main.py'],
            capture_output=True, text=True,
            cwd=os.path.abspath('.')
        )
        if result.returncode == 0:
            scan_state['pipeline_status'] = 'done'
            scan_state['message']         = 'Complete. Results are ready.'
        else:
            scan_state['pipeline_status'] = 'error'
            scan_state['message']         = f'Pipeline error: {result.stderr[-300:]}'
    except Exception as e:
        scan_state['pipeline_status'] = 'error'
        scan_state['message']         = str(e)


def run_full_scan(target_ip):
    global scan_state
    scan_state.update({
        'running':          True,
        'openvas_status':   'idle',
        'zap_status':       'idle',
        'pipeline_status':  'idle',
        'openvas_progress': 0,
        'zap_progress':     0,
        'error':            None,
        'target_ip':        target_ip,
        'message':          f'Starting scans against {target_ip}...',
    })

    # update assets.json with the target IP
    import json
    assets = {
        target_ip: {
            'hostname':       target_ip,
            'criticality':    'high',
            'segment':        'DMZ',
            'exposure_flag':  1,
        }
    }
    with open('data/assets.json', 'w') as f:
        json.dump(assets, f, indent=2)

    # run OpenVAS and ZAP in parallel
    t1 = threading.Thread(target=run_openvas_scan, args=(target_ip,))
    t2 = threading.Thread(target=run_zap_scan,     args=(target_ip,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # proceed with pipeline even if one scanner failed
    if scan_state['openvas_status'] == 'error' and scan_state['zap_status'] == 'error':
        scan_state['message'] = 'Both scans failed. Cannot run pipeline.'
        scan_state['running'] = False
        return

    run_pipeline()
    scan_state['running'] = False


def run_pipeline_only():
    global scan_state
    scan_state.update({
        'running':          True,
        'pipeline_status':  'idle',
        'error':            None,
        'message':          'Running pipeline on existing reports...',
    })
    openvas_ok = os.path.exists('data/openvas_report.xml')
    zap_ok     = os.path.exists('data/zap_report.xml')
    scan_state['openvas_status'] = 'done' if openvas_ok else 'error'
    scan_state['zap_status']     = 'done' if zap_ok     else 'error'
    run_pipeline()
    scan_state['running'] = False


def check_reports():
    openvas = os.path.exists('data/openvas_report.xml')
    zap     = os.path.exists('data/zap_report.xml')
    return openvas, zap
