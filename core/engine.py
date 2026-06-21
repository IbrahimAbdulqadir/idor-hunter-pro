"""
IDOR Hunter Pro — Core Enumeration Engine
Phase 1 (Week 1): Manual URL mode with full diff analysis
"""

import requests
import uuid
import re
import json
import time
import hashlib
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime


# ─── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class EndpointParam:
    location: str          # 'path', 'query', 'body'
    key: str
    original_value: str
    param_type: str        # 'numeric', 'uuid', 'unknown'

@dataclass
class Evidence:
    original_request: dict
    exploit_request: dict
    original_response: dict
    exploit_response: dict
    injected_id: str
    fields_exposed: list[str]
    diff_score: float

@dataclass
class Finding:
    id: str
    endpoint: str
    method: str
    param: EndpointParam
    status: str            # 'confirmed', 'suspected', 'false_positive'
    cvss_score: float
    cvss_vector: str
    evidence: Evidence
    timestamp: str
    hit_count: int = 0     # confirmed needs 3 independent hits

@dataclass
class ScanSession:
    id: str
    target: str
    base_user_id: str
    session_cookies: dict
    session_headers: dict
    endpoints: list[dict]
    findings: list[Finding]
    status: str            # 'idle', 'running', 'paused', 'complete'
    progress: dict
    started_at: Optional[str]
    completed_at: Optional[str]
    stats: dict = field(default_factory=dict)
    target_domains: list = field(default_factory=list)  # allowlist; empty = block known noise only


# ─── ID Pattern Detection ─────────────────────────────────────────────────────

NUMERIC_PATTERNS = [
    r'/(\d{1,10})(?:/|$|\?)',          # /123/ or /123
    r'[?&](?:id|user_id|uid|account_id|profile_id|order_id|doc_id|file_id|item_id|record_id)=(\d+)',
]

UUID_PATTERNS = [
    r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$|\?)',
    r'[?&](?:id|uuid|guid|token)=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
]

SENSITIVE_FIELDS = [
    'email', 'phone', 'address', 'ssn', 'password', 'token', 'secret',
    'credit_card', 'card_number', 'cvv', 'bank_account', 'dob', 'birth',
    'salary', 'income', 'name', 'username', 'first_name', 'last_name',
    'zip', 'postal', 'social_security', 'passport', 'license', 'ip_address',
    'payment', 'billing', 'shipping', 'balance', 'account_number'
]


# ─── Known Tracker / Third-Party Noise Domains ───────────────────────────────
# These domains commonly load on every page and produce false-positive
# "ID-like" parameters (analytics IDs, pixel tracking, session beacons)
# that have nothing to do with the target's actual API surface.

KNOWN_NOISE_DOMAINS = {
    'google-analytics.com', 'www.google-analytics.com',
    'analytics.google.com', 'googletagmanager.com',
    'doubleclick.net', 'googlesyndication.com',
    'facebook.com', 'connect.facebook.net',
    'fullstory.com', 'rs.fullstory.com',
    'hotjar.com', 'mixpanel.com', 'segment.io', 'segment.com',
    'intercom.io', 'intercomcdn.com',
    'amplitude.com', 'heap.io', 'heapanalytics.com',
    'cloudflareinsights.com', 'cdn.cookielaw.org',
    'browser-intake-datadoghq.com', 'datadoghq-browser-agent.com',
    'sentry.io', 'bugsnag.com',
    'criteo.com', 'taboola.com', 'outbrain.com',
    'pendo.io', 'fullstory.com', 'clarity.ms',
    'newrelic.com', 'nr-data.net',
    'optimizely.com', 'cdn.optimizely.com',
    'rum.browser-intake-datadoghq.com',
}


def is_noise_domain(url: str) -> bool:
    """Check if a URL belongs to a known third-party tracker/analytics domain."""
    try:
        hostname = urlparse(url).hostname or ''
        hostname = hostname.lower()
        for noise in KNOWN_NOISE_DOMAINS:
            if hostname == noise or hostname.endswith('.' + noise):
                return True
    except Exception:
        pass
    return False


def matches_target_domain(url: str, target_domains: list[str]) -> bool:
    """
    If target_domains is provided (non-empty), only allow URLs whose
    hostname matches one of them (exact or subdomain match).
    If target_domains is empty, allow everything except known noise domains.
    """
    if not target_domains:
        return not is_noise_domain(url)

    try:
        hostname = (urlparse(url).hostname or '').lower()
    except Exception:
        return False

    for domain in target_domains:
        domain = domain.lower().strip()
        if not domain:
            continue
        if hostname == domain or hostname.endswith('.' + domain):
            return True
    return False


def detect_id_params(url: str, body: dict = None) -> list[EndpointParam]:
    """Extract all ID-like parameters from URL path, query string, and body."""
    params = []

    # Path-based numeric IDs
    for pattern in NUMERIC_PATTERNS:
        for match in re.finditer(pattern, url, re.IGNORECASE):
            params.append(EndpointParam(
                location='path' if '/' in pattern else 'query',
                key='id',
                original_value=match.group(1),
                param_type='numeric'
            ))

    # Path-based UUIDs
    for pattern in UUID_PATTERNS:
        for match in re.finditer(pattern, url, re.IGNORECASE):
            params.append(EndpointParam(
                location='path' if '/' in pattern else 'query',
                key='uuid',
                original_value=match.group(1),
                param_type='uuid'
            ))

    # Query string params
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    for key, values in qs.items():
        val = values[0]
        if re.match(r'^\d+$', val):
            params.append(EndpointParam(location='query', key=key, original_value=val, param_type='numeric'))
        elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', val, re.I):
            params.append(EndpointParam(location='query', key=key, original_value=val, param_type='uuid'))

    # Body params
    if body:
        for key, val in body.items():
            val_str = str(val)
            if re.match(r'^\d+$', val_str):
                params.append(EndpointParam(location='body', key=key, original_value=val_str, param_type='numeric'))
            elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', val_str, re.I):
                params.append(EndpointParam(location='body', key=key, original_value=val_str, param_type='uuid'))

    # Deduplicate by value
    seen = set()
    unique = []
    for p in params:
        if p.original_value not in seen:
            seen.add(p.original_value)
            unique.append(p)
    return unique


def generate_test_ids(original_id: str, base_user_id: str, param_type: str) -> list[str]:
    """Generate the full set of probe IDs for a given parameter."""
    test_ids = []

    if param_type == 'numeric':
        orig = int(original_id) if original_id.isdigit() else 1
        base = int(base_user_id) if base_user_id.isdigit() else 1

        # Adjacent to your own ID
        for delta in [-3, -2, -1, 1, 2, 3]:
            candidate = base + delta
            if candidate > 0:
                test_ids.append(str(candidate))

        # Classic enumeration 1–20 (fast for Week 1)
        for i in range(1, 21):
            if str(i) not in test_ids and str(i) != original_id:
                test_ids.append(str(i))

        # High-value IDs
        for special in ['100', '1000', '9999', '0']:
            if special not in test_ids:
                test_ids.append(special)

    elif param_type == 'uuid':
        # Random UUIDs
        for _ in range(10):
            test_ids.append(str(uuid.uuid4()))
        # Nil UUID edge case
        test_ids.append('00000000-0000-0000-0000-000000000000')

    return test_ids


# ─── Request Builder ──────────────────────────────────────────────────────────

def inject_id(url: str, param: EndpointParam, new_id: str, body: dict = None):
    """Replace the target ID in URL path, query, or body."""
    new_url = url
    new_body = body.copy() if body else {}
    original = param.original_value

    if param.location in ('path', 'query'):
        new_url = url.replace(original, new_id, 1)

    if param.location == 'body' and body:
        new_body[param.key] = new_id

    return new_url, new_body


def make_request(url: str, method: str, headers: dict, cookies: dict, body: dict = None, timeout: int = 10):
    """Execute a single HTTP request and return a normalized response dict."""
    try:
        resp = requests.request(
            method=method.upper(),
            url=url,
            headers=headers,
            cookies=cookies,
            json=body if body else None,
            timeout=timeout,
            allow_redirects=True,
            verify=False  # Bug bounty targets often have custom certs
        )
        try:
            resp_body = resp.json()
        except Exception:
            resp_body = resp.text

        return {
            'status_code': resp.status_code,
            'headers': dict(resp.headers),
            'body': resp_body,
            'body_size': len(resp.content),
            'content_type': resp.headers.get('Content-Type', ''),
            'elapsed_ms': int(resp.elapsed.total_seconds() * 1000),
            'url': url,
            'error': None
        }
    except requests.exceptions.Timeout:
        return {'status_code': 0, 'body': None, 'body_size': 0, 'error': 'timeout', 'url': url}
    except Exception as e:
        return {'status_code': 0, 'body': None, 'body_size': 0, 'error': str(e), 'url': url}


# ─── Diff Engine ──────────────────────────────────────────────────────────────

def extract_fields(body) -> set[str]:
    """Recursively extract all keys from a JSON response body."""
    fields = set()
    if isinstance(body, dict):
        for k, v in body.items():
            fields.add(k.lower())
            fields |= extract_fields(v)
    elif isinstance(body, list):
        for item in body:
            fields |= extract_fields(item)
    return fields


def find_sensitive_fields(body) -> list[str]:
    """Find which sensitive field names appear in a response body."""
    all_fields = extract_fields(body)
    return [f for f in SENSITIVE_FIELDS if f in all_fields]


def body_fingerprint(body) -> str:
    """Create a structural fingerprint of a response (keys, not values)."""
    if isinstance(body, dict):
        return hashlib.md5(json.dumps(sorted(body.keys())).encode()).hexdigest()
    elif isinstance(body, str):
        return hashlib.md5(body[:500].encode()).hexdigest()
    return 'empty'


def compute_diff_score(baseline: dict, probe: dict) -> float:
    """
    Score 0.0–1.0 measuring how different two responses are.
    High score = likely IDOR. Considers status, size, structure, sensitive fields.
    """
    score = 0.0

    # Same error/blocked → not IDOR
    if probe.get('error') or probe.get('status_code') in (401, 403, 404, 429):
        return 0.0

    # Status code changed in a meaningful way
    b_status = baseline.get('status_code', 0)
    p_status = probe.get('status_code', 0)
    if p_status == 200 and b_status == 200:
        score += 0.2
    elif p_status == 200 and b_status != 200:
        score += 0.4

    # Body size difference (different user = different data volume)
    b_size = baseline.get('body_size', 0)
    p_size = probe.get('body_size', 0)
    if b_size > 0 and p_size > 0:
        size_ratio = abs(b_size - p_size) / max(b_size, p_size)
        if 0.05 < size_ratio < 0.95:   # Some difference but not empty
            score += size_ratio * 0.2

    # Structural fingerprint match (same schema = real data, not error page)
    b_fp = body_fingerprint(baseline.get('body'))
    p_fp = body_fingerprint(probe.get('body'))
    if b_fp == p_fp and b_fp != 'empty':
        score += 0.3

    # Sensitive fields present in probe response
    sensitive = find_sensitive_fields(probe.get('body'))
    if sensitive:
        score += min(len(sensitive) * 0.05, 0.3)

    return min(round(score, 3), 1.0)


def classify_finding(diff_score: float, hit_count: int) -> str:
    """Determine finding status based on diff score and confirmation count."""
    if diff_score >= 0.6 and hit_count >= 3:
        return 'confirmed'
    elif diff_score >= 0.4:
        return 'suspected'
    else:
        return 'false_positive'


# ─── CVSS Auto-Scorer ─────────────────────────────────────────────────────────

def calculate_cvss(sensitive_fields: list[str], method: str) -> tuple[float, str]:
    """
    Estimate CVSS 3.1 base score based on what was exposed.
    Returns (score, vector_string).
    """
    # Determine impact based on exposed data
    high_impact_fields = {'password', 'ssn', 'credit_card', 'social_security', 'bank_account', 'cvv', 'token', 'secret'}
    med_impact_fields = {'email', 'phone', 'address', 'salary', 'income', 'dob', 'passport'}

    exposed = set(sensitive_fields)
    if exposed & high_impact_fields:
        confidentiality = 'H'
        integrity = 'H' if method in ('POST', 'PUT', 'PATCH', 'DELETE') else 'N'
    elif exposed & med_impact_fields:
        confidentiality = 'H'
        integrity = 'L' if method in ('POST', 'PUT', 'PATCH', 'DELETE') else 'N'
    else:
        confidentiality = 'L'
        integrity = 'N'

    # IDOR is always: Network, Low complexity, No privileges, No user interaction
    vector = f"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:{confidentiality}/I:{integrity}/A:N"

    # Simplified scoring
    score_map = {
        ('H', 'H'): 9.1,
        ('H', 'L'): 8.1,
        ('H', 'N'): 6.5,
        ('L', 'N'): 4.3,
    }
    score = score_map.get((confidentiality, integrity), 5.0)

    return score, vector


# ─── Main Scanner ─────────────────────────────────────────────────────────────

class IDORScanner:
    def __init__(self, session: ScanSession, progress_callback=None):
        self.session = session
        self.progress_callback = progress_callback
        self._stop = False

    def stop(self):
        self._stop = True

    def _emit(self, event: str, data: dict):
        if self.progress_callback:
            self.progress_callback(event, data)

    def run(self):
        self.session.status = 'running'
        self.session.started_at = datetime.utcnow().isoformat()
        findings = []
        total_endpoints = len(self.session.endpoints)

        self._emit('phase', {'phase': 1, 'label': 'Discovery', 'message': f'Analyzing {total_endpoints} endpoints...'})

        # Phase 1: Filter noise domains, then detect ID params per endpoint
        target_domains = getattr(self.session, 'target_domains', []) or []
        noise_filtered = 0
        testable = []
        for ep in self.session.endpoints:
            if not matches_target_domain(ep['url'], target_domains):
                noise_filtered += 1
                continue
            params = detect_id_params(ep['url'], ep.get('body'))
            if params:
                testable.append({**ep, 'params': params})

        self._emit('discovery_complete', {
            'total': total_endpoints,
            'testable': len(testable),
            'skipped': total_endpoints - len(testable) - noise_filtered,
            'noise_filtered': noise_filtered
        })

        # Phase 2 & 3: Enumerate + Diff + Confirm
        self._emit('phase', {'phase': 2, 'label': 'Enumeration', 'message': f'Testing {len(testable)} endpoints...'})

        for ep_idx, ep in enumerate(testable):
            if self._stop:
                break

            method = ep.get('method', 'GET').upper()
            headers = {**self.session.session_headers}
            cookies = self.session.session_cookies
            body = ep.get('body')

            # Baseline — your own request
            baseline_resp = make_request(ep['url'], method, headers, cookies, body)

            for param in ep['params']:
                if self._stop:
                    break

                test_ids = generate_test_ids(
                    param.original_value,
                    self.session.base_user_id,
                    param.param_type
                )

                hit_count = 0
                best_evidence = None
                best_score = 0.0

                for test_id in test_ids:
                    if self._stop:
                        break

                    probe_url, probe_body = inject_id(ep['url'], param, test_id, body)
                    probe_resp = make_request(probe_url, method, headers, cookies, probe_body)

                    diff = compute_diff_score(baseline_resp, probe_resp)

                    self._emit('probe', {
                        'endpoint': ep['url'],
                        'param': param.key,
                        'test_id': test_id,
                        'status_code': probe_resp.get('status_code'),
                        'diff_score': diff,
                        'ep_index': ep_idx,
                        'ep_total': len(testable)
                    })

                    if diff >= 0.4:
                        hit_count += 1
                        if diff > best_score:
                            best_score = diff
                            sensitive = find_sensitive_fields(probe_resp.get('body'))
                            best_evidence = Evidence(
                                original_request={'url': ep['url'], 'method': method, 'headers': headers, 'body': body},
                                exploit_request={'url': probe_url, 'method': method, 'headers': headers, 'body': probe_body},
                                original_response=baseline_resp,
                                exploit_response=probe_resp,
                                injected_id=test_id,
                                fields_exposed=sensitive,
                                diff_score=diff
                            )

                    # Rate limit courtesy
                    time.sleep(0.15)

                if best_evidence and best_score >= 0.4:
                    status = classify_finding(best_score, hit_count)
                    cvss_score, cvss_vector = calculate_cvss(best_evidence.fields_exposed, method)

                    finding = Finding(
                        id=hashlib.md5(f"{ep['url']}{param.key}{best_evidence.injected_id}".encode()).hexdigest()[:12],
                        endpoint=ep['url'],
                        method=method,
                        param=param,
                        status=status,
                        cvss_score=cvss_score,
                        cvss_vector=cvss_vector,
                        evidence=best_evidence,
                        timestamp=datetime.utcnow().isoformat(),
                        hit_count=hit_count
                    )
                    findings.append(finding)
                    self._emit('finding', {'finding': asdict(finding)})

        self.session.findings = findings
        self.session.status = 'complete'
        self.session.completed_at = datetime.utcnow().isoformat()
        self.session.stats = {
            'total_endpoints': total_endpoints,
            'testable_endpoints': len(testable),
            'total_findings': len(findings),
            'confirmed': len([f for f in findings if f.status == 'confirmed']),
            'suspected': len([f for f in findings if f.status == 'suspected']),
            'false_positives': len([f for f in findings if f.status == 'false_positive']),
        }

        self._emit('complete', {'stats': self.session.stats})
        return findings
