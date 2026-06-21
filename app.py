"""
IDOR Hunter Pro — Flask Application
Weeks 1+2+3: Manual URL + Report Generator + Proxy Mode
"""

import json
import uuid
import threading
import queue
import os
from datetime import datetime
from dataclasses import asdict
from flask import (Flask, render_template, request, jsonify,
                   Response, stream_with_context, send_file)

from core.engine import IDORScanner, ScanSession, detect_id_params
from core.report_generator import generate_html_report, generate_pdf_report
from core.proxy_session import ProxySession

app = Flask(__name__)
app.secret_key = 'idor-hunter-pro-2024'

# ── In-memory stores ──────────────────────────────────────────────────────────
scan_sessions: dict = {}
scan_threads:  dict = {}
event_queues:  dict = {}
proxy_sessions: dict = {}
proxy_event_queues: dict = {}


# ── Helpers ───────────────────────────────────────────────────────────────────

def parse_cookies(raw: str) -> dict:
    cookies = {}
    if not raw:
        return cookies
    for part in raw.split(';'):
        part = part.strip()
        if '=' in part:
            k, v = part.split('=', 1)
            cookies[k.strip()] = v.strip()
    return cookies


def parse_headers(raw: str) -> dict:
    headers = {}
    if not raw:
        return headers
    for line in raw.strip().split('\n'):
        line = line.strip()
        if ':' in line:
            k, v = line.split(':', 1)
            headers[k.strip()] = v.strip()
    return headers


def parse_endpoints(raw: str) -> list:
    endpoints = []
    for line in raw.strip().split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(' ', 2)
        if len(parts) == 1:
            endpoints.append({'method': 'GET', 'url': parts[0], 'body': None})
        elif len(parts) == 2:
            endpoints.append({'method': parts[0].upper(), 'url': parts[1], 'body': None})
        elif len(parts) == 3:
            try:
                body = json.loads(parts[2])
            except Exception:
                body = None
            endpoints.append({'method': parts[0].upper(), 'url': parts[1], 'body': body})
    return endpoints


# ── Page Routes ───────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan/new')
def new_scan():
    return render_template('new_scan.html')


@app.route('/scan/<scan_id>')
def scan_monitor(scan_id):
    sess = scan_sessions.get(scan_id)
    if not sess:
        return render_template('404.html'), 404
    return render_template('monitor.html', scan_id=scan_id, session=sess)


@app.route('/findings')
def findings_board():
    all_findings = []
    for sess in scan_sessions.values():
        for f in (sess.findings or []):
            all_findings.append({**asdict(f), 'scan_id': sess.id, 'target': sess.target})
    return render_template('findings.html', findings=all_findings)


@app.route('/findings/<finding_id>')
def finding_detail(finding_id):
    for sess in scan_sessions.values():
        for f in (sess.findings or []):
            if f.id == finding_id:
                return render_template('finding_detail.html',
                                       finding=asdict(f), session=sess)
    return render_template('404.html'), 404


@app.route('/report/<finding_id>')
def report_builder(finding_id):
    for sess in scan_sessions.values():
        for f in (sess.findings or []):
            if f.id == finding_id:
                return render_template('report_builder.html',
                                       finding=asdict(f), session=sess)
    return render_template('404.html'), 404


# ── Scan API ──────────────────────────────────────────────────────────────────

@app.route('/api/scan/start', methods=['POST'])
def api_start_scan():
    data = request.json
    scan_id = str(uuid.uuid4())[:8]

    cookies   = parse_cookies(data.get('cookies', ''))
    headers   = parse_headers(data.get('headers', ''))
    endpoints = parse_endpoints(data.get('endpoints', ''))
    target_domains = [d.strip() for d in data.get('target_domains', '').split(',') if d.strip()]

    if not endpoints:
        return jsonify({'error': 'No valid endpoints provided'}), 400

    sess = ScanSession(
        id=scan_id,
        target=data.get('target', 'Unknown'),
        base_user_id=data.get('user_id', '1'),
        session_cookies=cookies,
        session_headers=headers,
        endpoints=endpoints,
        findings=[],
        status='idle',
        progress={},
        started_at=None,
        completed_at=None,
        stats={},
        target_domains=target_domains
    )
    scan_sessions[scan_id] = sess

    q = queue.Queue()
    event_queues[scan_id] = q

    def progress_callback(event, edata):
        q.put({'event': event, 'data': edata})

    def run_scan():
        scanner = IDORScanner(sess, progress_callback)
        scanner.run()
        q.put({'event': 'done', 'data': {}})

    t = threading.Thread(target=run_scan, daemon=True)
    scan_threads[scan_id] = t
    t.start()

    return jsonify({'scan_id': scan_id, 'status': 'started'})


@app.route('/api/scan/<scan_id>/events')
def api_scan_events(scan_id):
    q = event_queues.get(scan_id)
    if not q:
        return jsonify({'error': 'Scan not found'}), 404

    def generate():
        while True:
            try:
                item = q.get(timeout=30)
                yield f"event: {item['event']}\ndata: {json.dumps(item['data'])}\n\n"
                if item['event'] == 'done':
                    break
            except queue.Empty:
                yield "event: heartbeat\ndata: {}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
    )


@app.route('/api/scan/<scan_id>/status')
def api_scan_status(scan_id):
    sess = scan_sessions.get(scan_id)
    if not sess:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({
        'id': sess.id, 'status': sess.status,
        'stats': sess.stats, 'findings_count': len(sess.findings or []),
        'target': sess.target
    })


@app.route('/api/scan/<scan_id>/findings')
def api_scan_findings(scan_id):
    sess = scan_sessions.get(scan_id)
    if not sess:
        return jsonify({'error': 'Not found'}), 404
    return jsonify([asdict(f) for f in (sess.findings or [])])


@app.route('/api/findings')
def api_all_findings():
    all_findings = []
    for sess in scan_sessions.values():
        for f in (sess.findings or []):
            all_findings.append({**asdict(f), 'scan_id': sess.id, 'target': sess.target})
    return jsonify(all_findings)


@app.route('/api/sessions')
def api_sessions():
    return jsonify([{
        'id': s.id, 'target': s.target, 'status': s.status,
        'findings': len(s.findings or []),
        'started_at': s.started_at, 'stats': s.stats
    } for s in scan_sessions.values()])


@app.route('/api/scan/preview', methods=['POST'])
def api_preview_endpoints():
    data = request.json
    endpoints = parse_endpoints(data.get('endpoints', ''))
    result = []
    for ep in endpoints:
        params = detect_id_params(ep['url'], ep.get('body'))
        result.append({
            'url': ep['url'], 'method': ep['method'],
            'params_found': len(params),
            'params': [{'key': p.key, 'value': p.original_value,
                        'type': p.param_type, 'location': p.location}
                       for p in params],
            'testable': len(params) > 0
        })
    return jsonify(result)


# ── Report API ────────────────────────────────────────────────────────────────

@app.route('/api/report/<finding_id>/html')
def api_report_html(finding_id):
    for sess in scan_sessions.values():
        for f in (sess.findings or []):
            if f.id == finding_id:
                html = generate_html_report(asdict(f), asdict(sess))
                return Response(html, mimetype='text/html',
                    headers={'Content-Disposition':
                             f'attachment; filename="idor_report_{finding_id}.html"'})
    return jsonify({'error': 'Not found'}), 404


@app.route('/api/report/<finding_id>/pdf')
def api_report_pdf(finding_id):
    for sess in scan_sessions.values():
        for f in (sess.findings or []):
            if f.id == finding_id:
                os.makedirs('reports', exist_ok=True)
                path = f'reports/idor_report_{finding_id}.pdf'
                generate_pdf_report(asdict(f), path)
                return send_file(path, mimetype='application/pdf',
                    as_attachment=True,
                    download_name=f'idor_report_{finding_id}.pdf')
    return jsonify({'error': 'Not found'}), 404


@app.route('/api/report/<finding_id>/preview')
def api_report_preview(finding_id):
    for sess in scan_sessions.values():
        for f in (sess.findings or []):
            if f.id == finding_id:
                html = generate_html_report(asdict(f), asdict(sess))
                return Response(html, mimetype='text/html')
    return jsonify({'error': 'Not found'}), 404


from core.crawl_session import CrawlSession
crawl_sessions: dict = {}
crawl_event_queues: dict = {}


# ── Crawl API ─────────────────────────────────────────────────────────────────

@app.route('/api/crawl/start', methods=['POST'])
def api_crawl_start():
    data = request.json
    crawl_id = str(uuid.uuid4())[:8]
    q = queue.Queue()
    crawl_event_queues[crawl_id] = q

    target_domains = [d.strip() for d in data.get('target_domains', '').split(',') if d.strip()]
    cookies = parse_cookies(data.get('cookies', ''))

    def on_event(event, edata):
        q.put({'event': event, 'data': edata})

    def on_finding(finding):
        if crawl_id not in scan_sessions:
            sess = ScanSession(
                id=crawl_id,
                target=data.get('target', 'Crawl Session'),
                base_user_id=data.get('user_id', '1'),
                session_cookies={}, session_headers={},
                endpoints=[], findings=[], status='running',
                progress={},
                started_at=datetime.utcnow().isoformat(),
                completed_at=None, stats={},
                target_domains=target_domains
            )
            scan_sessions[crawl_id] = sess
        scan_sessions[crawl_id].findings.append(finding)

    sess = CrawlSession(
        session_id=crawl_id,
        base_url=data.get('base_url', ''),
        base_user_id=data.get('user_id', '1'),
        auth_mode=data.get('auth_mode', 'cookies'),
        cookies=cookies,
        username=data.get('username'),
        password=data.get('password'),
        login_url=data.get('login_url'),
        max_depth=int(data.get('max_depth', 4)),
        max_pages=int(data.get('max_pages', 60)),
        target_domains=target_domains,
        event_callback=on_event,
        finding_callback=on_finding
    )
    crawl_sessions[crawl_id] = sess
    sess.start()
    return jsonify({'crawl_id': crawl_id, 'status': 'started'})


@app.route('/api/crawl/stop/<crawl_id>', methods=['POST'])
def api_crawl_stop(crawl_id):
    sess = crawl_sessions.get(crawl_id)
    if not sess:
        return jsonify({'error': 'Not found'}), 404
    sess.stop()
    return jsonify({'status': 'stopped', 'stats': sess.get_stats()})


@app.route('/api/crawl/<crawl_id>/events')
def api_crawl_events(crawl_id):
    q = crawl_event_queues.get(crawl_id)
    if not q:
        return jsonify({'error': 'Not found'}), 404

    def generate():
        while True:
            try:
                item = q.get(timeout=30)
                yield f"event: {item['event']}\ndata: {json.dumps(item['data'])}\n\n"
                if item['event'] == 'complete':
                    break
            except queue.Empty:
                yield "event: heartbeat\ndata: {}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
    )


@app.route('/api/crawl/<crawl_id>/status')
def api_crawl_status(crawl_id):
    sess = crawl_sessions.get(crawl_id)
    if not sess:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(sess.get_stats())


# ── Proxy API ─────────────────────────────────────────────────────────────────

@app.route('/api/proxy/start', methods=['POST'])
def api_proxy_start():
    data = request.json
    proxy_id = str(uuid.uuid4())[:8]
    q = queue.Queue()
    proxy_event_queues[proxy_id] = q
    target_domains = [d.strip() for d in data.get('target_domains', '').split(',') if d.strip()]

    def on_event(event, edata):
        q.put({'event': event, 'data': edata})

    def on_finding(finding):
        if proxy_id not in scan_sessions:
            sess = ScanSession(
                id=proxy_id,
                target=data.get('target', 'Proxy Session'),
                base_user_id=data.get('user_id', '1'),
                session_cookies={}, session_headers={},
                endpoints=[], findings=[], status='running',
                progress={},
                started_at=datetime.utcnow().isoformat(),
                completed_at=None, stats={},
                target_domains=target_domains
            )
            scan_sessions[proxy_id] = sess
        scan_sessions[proxy_id].findings.append(finding)

    sess = ProxySession(
        session_id=proxy_id,
        base_user_id=data.get('user_id', '1'),
        event_callback=on_event,
        finding_callback=on_finding,
        target_domains=target_domains
    )
    proxy_sessions[proxy_id] = sess
    sess.start()
    return jsonify({'proxy_id': proxy_id, 'status': 'started'})


@app.route('/api/proxy/stop/<proxy_id>', methods=['POST'])
def api_proxy_stop(proxy_id):
    sess = proxy_sessions.get(proxy_id)
    if not sess:
        return jsonify({'error': 'Not found'}), 404
    sess.stop()
    return jsonify({'status': 'stopped', 'stats': sess.get_stats()})


@app.route('/api/proxy/event', methods=['POST'])
def api_proxy_event():
    data = request.json
    event = data.get('event')
    edata = data.get('data', {})
    if proxy_sessions:
        sess = list(proxy_sessions.values())[-1]
        if event == 'endpoint_captured':
            sess.ingest(edata.get('endpoint', {}))
    return jsonify({'status': 'ok'})


@app.route('/api/proxy/<proxy_id>/events')
def api_proxy_events(proxy_id):
    q = proxy_event_queues.get(proxy_id)
    if not q:
        return jsonify({'error': 'Not found'}), 404

    def generate():
        while True:
            try:
                item = q.get(timeout=30)
                yield f"event: {item['event']}\ndata: {json.dumps(item['data'])}\n\n"
            except queue.Empty:
                yield "event: heartbeat\ndata: {}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
    )


@app.route('/api/proxy/<proxy_id>/status')
def api_proxy_status(proxy_id):
    sess = proxy_sessions.get(proxy_id)
    if not sess:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(sess.get_stats())


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import urllib3
    urllib3.disable_warnings()
    print("\n  IDOR Hunter Pro\n  http://127.0.0.1:5000\n")
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
