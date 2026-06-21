"""
IDOR Hunter Pro — Week 3
Proxy Session Manager
Receives captured endpoints from mitmproxy addon → auto-scans → flags findings live
"""

import threading
import queue
import time
import hashlib
from datetime import datetime
from dataclasses import asdict

from core.engine import (
    IDORScanner, ScanSession, detect_id_params,
    make_request, generate_test_ids, inject_id,
    compute_diff_score, find_sensitive_fields,
    classify_finding, calculate_cvss,
    Finding, EndpointParam, Evidence,
    matches_target_domain, is_noise_domain
)


class ProxySession:
    """
    Manages a live proxy scanning session.
    Endpoints arrive from mitmproxy → get queued → auto-scanned → findings emitted.
    """

    def __init__(self, session_id: str, base_user_id: str,
                 event_callback=None, finding_callback=None,
                 target_domains: list = None):
        self.session_id = session_id
        self.base_user_id = base_user_id
        self.event_callback = event_callback      # SSE emitter
        self.finding_callback = finding_callback  # Finding storage
        self.target_domains = target_domains or []

        self.endpoint_queue = queue.Queue()
        self.captured = []
        self.findings = []
        self.stats = {
            'captured': 0,
            'scanned': 0,
            'noise_filtered': 0,
            'probes_sent': 0,
            'confirmed': 0,
            'suspected': 0,
        }
        self._running = False
        self._worker_thread = None

    def start(self):
        self._running = True
        self._worker_thread = threading.Thread(
            target=self._scan_worker, daemon=True)
        self._worker_thread.start()
        self._emit('proxy_started', {
            'session_id': self.session_id,
            'message': 'Proxy mode active — browse your target'
        })

    def stop(self):
        self._running = False
        self._emit('proxy_stopped', {
            'session_id': self.session_id,
            'stats': self.stats
        })

    def ingest(self, endpoint: dict):
        """Called when mitmproxy captures a new endpoint."""
        if not matches_target_domain(endpoint['url'], self.target_domains):
            self.stats['noise_filtered'] = self.stats.get('noise_filtered', 0) + 1
            return

        self.captured.append(endpoint)
        self.stats['captured'] += 1
        self.endpoint_queue.put(endpoint)
        self._emit('endpoint_captured', {
            'url': endpoint['url'],
            'method': endpoint['method'],
            'total_captured': self.stats['captured']
        })

    def _emit(self, event: str, data: dict):
        if self.event_callback:
            self.event_callback(event, data)

    def _scan_worker(self):
        """Background worker — pulls endpoints from queue and scans them."""
        while self._running:
            try:
                endpoint = self.endpoint_queue.get(timeout=2)
            except queue.Empty:
                continue

            self._scan_endpoint(endpoint)
            self.stats['scanned'] += 1
            self.endpoint_queue.task_done()

    def _scan_endpoint(self, endpoint: dict):
        url = endpoint['url']
        method = endpoint.get('method', 'GET')
        body = endpoint.get('body')
        cookies = self._parse_cookies(endpoint.get('cookies', ''))
        headers = {k: v for k, v in endpoint.get('headers', {}).items()
                   if k.lower() not in ('host', 'content-length')}

        params = detect_id_params(url, body)
        if not params:
            return

        self._emit('scanning', {
            'url': url,
            'method': method,
            'params': len(params)
        })

        # Baseline request
        baseline = make_request(url, method, headers, cookies, body)

        for param in params:
            test_ids = generate_test_ids(
                param.original_value, self.base_user_id, param.param_type)

            hit_count = 0
            best_score = 0.0
            best_evidence = None

            for test_id in test_ids:
                if not self._running:
                    return

                probe_url, probe_body = inject_id(url, param, test_id, body)
                probe_resp = make_request(
                    probe_url, method, headers, cookies, probe_body)

                self.stats['probes_sent'] += 1
                diff = compute_diff_score(baseline, probe_resp)

                self._emit('probe', {
                    'url': url,
                    'param': param.key,
                    'test_id': test_id,
                    'status_code': probe_resp.get('status_code'),
                    'diff_score': diff,
                    'probes_sent': self.stats['probes_sent']
                })

                if diff >= 0.4:
                    hit_count += 1
                    if diff > best_score:
                        best_score = diff
                        sensitive = find_sensitive_fields(probe_resp.get('body'))
                        best_evidence = Evidence(
                            original_request={
                                'url': url, 'method': method,
                                'headers': headers, 'body': body
                            },
                            exploit_request={
                                'url': probe_url, 'method': method,
                                'headers': headers, 'body': probe_body
                            },
                            original_response=baseline,
                            exploit_response=probe_resp,
                            injected_id=test_id,
                            fields_exposed=sensitive,
                            diff_score=diff
                        )

                time.sleep(0.15)

            if best_evidence and best_score >= 0.4:
                status = classify_finding(best_score, hit_count)
                cvss_score, cvss_vector = calculate_cvss(
                    best_evidence.fields_exposed, method)

                finding = Finding(
                    id=hashlib.md5(
                        f"{url}{param.key}{best_evidence.injected_id}".encode()
                    ).hexdigest()[:12],
                    endpoint=url,
                    method=method,
                    param=param,
                    status=status,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    evidence=best_evidence,
                    timestamp=datetime.utcnow().isoformat(),
                    hit_count=hit_count
                )

                self.findings.append(finding)
                if status == 'confirmed':
                    self.stats['confirmed'] += 1
                else:
                    self.stats['suspected'] += 1

                self._emit('finding', {'finding': asdict(finding)})

                if self.finding_callback:
                    self.finding_callback(finding)

    def _parse_cookies(self, raw: str) -> dict:
        cookies = {}
        if not raw:
            return cookies
        for part in raw.split(';'):
            part = part.strip()
            if '=' in part:
                k, v = part.split('=', 1)
                cookies[k.strip()] = v.strip()
        return cookies

    def get_stats(self) -> dict:
        return {**self.stats, 'findings': len(self.findings)}
