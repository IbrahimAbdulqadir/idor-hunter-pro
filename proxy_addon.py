"""
IDOR Hunter Pro — Week 3
Proxy Mode: mitmproxy addon
Intercepts browser traffic → detects IDs → fires probes → reports findings live

Run with:
    mitmdump -s proxy_addon.py --listen-port 8080 --ssl-insecure
"""

import json
import re
import time
import threading
import requests as req_lib
from datetime import datetime
from urllib.parse import urlparse, parse_qs

# ── Config ────────────────────────────────────────────────────────────────────
FLASK_URL       = "http://127.0.0.1:5000"
PROXY_SCAN_ID   = None   # Set when proxy session starts via Flask
SKIP_EXTENSIONS = {'.js', '.css', '.png', '.jpg', '.ico', '.svg',
                   '.woff', '.woff2', '.ttf', '.gif', '.mp4', '.webp'}
SKIP_HOSTS      = {'127.0.0.1', 'localhost', '10.0.2.15'}
NUMERIC_PATTERN = re.compile(r'(?<![a-zA-Z])(\d{1,10})(?![a-zA-Z])')
UUID_PATTERN    = re.compile(
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)

# ── State ─────────────────────────────────────────────────────────────────────
captured_endpoints = []
seen_urls = set()
lock = threading.Lock()


def should_skip(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.hostname in SKIP_HOSTS:
        return True
    path = parsed.path.lower()
    if any(path.endswith(ext) for ext in SKIP_EXTENSIONS):
        return True
    if 'logout' in path or 'static' in path:
        return True
    return False


def has_id_params(url: str, body: dict = None) -> bool:
    parsed = urlparse(url)
    # Check path
    if NUMERIC_PATTERN.search(parsed.path) or UUID_PATTERN.search(parsed.path):
        return True
    # Check query
    qs = parse_qs(parsed.query)
    for val_list in qs.values():
        for val in val_list:
            if re.match(r'^\d+$', val) or UUID_PATTERN.match(val):
                return True
    # Check body
    if body:
        for val in body.values():
            val_str = str(val)
            if re.match(r'^\d+$', val_str) or UUID_PATTERN.match(val_str):
                return True
    return False


def notify_flask(event: str, data: dict):
    """Send captured endpoint or finding to Flask via internal API."""
    try:
        req_lib.post(
            f"{FLASK_URL}/api/proxy/event",
            json={'event': event, 'data': data},
            timeout=3
        )
    except Exception:
        pass


def parse_body(flow) -> dict:
    """Try to parse request body as JSON."""
    try:
        if flow.request.content:
            return json.loads(flow.request.content.decode('utf-8', errors='ignore'))
    except Exception:
        pass
    return {}


# ── mitmproxy Addon ───────────────────────────────────────────────────────────

class IDORHunterAddon:

    def __init__(self):
        print("\n  [IDOR Hunter Pro] Proxy Mode Active")
        print(f"  Listening on port 8080")
        print(f"  Reporting to Flask: {FLASK_URL}")
        print(f"  Configure your browser proxy: 127.0.0.1:8080\n")

    def request(self, flow):
        """Called for every request passing through the proxy."""
        url = flow.request.pretty_url

        if should_skip(url):
            return

        # Deduplicate by URL+method
        sig = f"{flow.request.method}:{url}"
        with lock:
            if sig in seen_urls:
                return
            seen_urls.add(sig)

        body = parse_body(flow)

        if not has_id_params(url, body):
            return

        # Capture cookies + headers from the live request
        cookies_str = flow.request.headers.get('cookie', '')
        headers = dict(flow.request.headers)

        endpoint = {
            'url': url,
            'method': flow.request.method.upper(),
            'body': body if body else None,
            'cookies': cookies_str,
            'headers': headers,
            'captured_at': datetime.utcnow().isoformat()
        }

        with lock:
            captured_endpoints.append(endpoint)

        print(f"  [CAPTURE] {flow.request.method} {url}")

        # Notify Flask — triggers auto-scan
        notify_flask('endpoint_captured', {
            'endpoint': endpoint,
            'total_captured': len(captured_endpoints)
        })

    def response(self, flow):
        """Called after response received — log status for context."""
        url = flow.request.pretty_url
        if should_skip(url):
            return
        status = flow.response.status_code
        if status in (401, 403, 404):
            return
        # Only log successful responses with ID params
        if has_id_params(url):
            print(f"  [RESPONSE] {status} {flow.request.method} {url}")


addons = [IDORHunterAddon()]
