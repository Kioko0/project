import os
import threading
import smtplib
from flask import Flask, render_template, request, redirect, url_for, jsonify
from db import get_all_scored, get_by_segment
from dotenv import load_dotenv
from scanner import scan_state, run_full_scan, run_pipeline_only, check_reports

load_dotenv()

app       = Flask(__name__)
THRESHOLD = float(os.getenv('ALERT_THRESHOLD', 8.0))


def send_alert(record):
    try:
        smtp_host = os.getenv('SMTP_HOST', '')
        if not smtp_host:
            print(f'[Alert] Would alert: {record["cve_id"]} score={record["risk_score"]}')
            return
        smtp_user = os.getenv('SMTP_USER', '')
        smtp_pass = os.getenv('SMTP_PASS', '')
        msg = (f'Subject: CRITICAL VULNERABILITY ALERT\n\n'
               f'CVE: {record["cve_id"]}\nHost: {record["host_ip"]}\n'
               f'Risk Score: {record["risk_score"]}\nLabel: {record["rf_label"]}')
        with smtplib.SMTP(smtp_host, 587) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, smtp_user, msg)
    except Exception as e:
        print(f'[Alert] Failed: {e}')


@app.route('/')
def index():
    segment = request.args.get('segment', '')
    show    = request.args.get('show', 'false')
    records = []

    if show == 'true':
        records = get_by_segment(segment) if segment else get_all_scored()
        for r in records:
            if r.get('risk_score', 0) >= THRESHOLD:
                send_alert(r)

    openvas_exists, zap_exists = check_reports()

    return render_template('index.html',
                           records=records,
                           segment=segment,
                           scan=scan_state,
                           show=show,
                           openvas_exists=openvas_exists,
                           zap_exists=zap_exists)


@app.route('/start-scan', methods=['POST'])
def start_scan():
    if scan_state['running']:
        return jsonify({'status': 'already running'})
    target_ip = request.form.get('target_ip', '').strip()
    if not target_ip:
        return redirect(url_for('index'))
    thread = threading.Thread(target=run_full_scan, args=(target_ip,))
    thread.daemon = True
    thread.start()
    return redirect(url_for('index', show='false'))


@app.route('/run-pipeline', methods=['POST'])
def run_pipeline():
    if scan_state['running']:
        return jsonify({'status': 'already running'})
    thread = threading.Thread(target=run_pipeline_only)
    thread.daemon = True
    thread.start()
    return redirect(url_for('index', show='false'))


@app.route('/scan-status')
def get_scan_status():
    return jsonify(scan_state)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
