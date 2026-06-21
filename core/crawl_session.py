"""
IDOR Hunter Pro — Week 4
Crawl Mode: Playwright headless browser discovers endpoints automatically
No proxy, no certificates, no third-party noise — direct browser automation.
"""

import threading
import queue
import time
import hashlib
from datetime import datetime
from dataclasses import asdict
from urllib.parse import urljoin, urlparse

from core.engine import (
    detect_id_params, make_request, generate_test_ids, inject_id,
    compute_diff_score, find_sensitive_fields, classify_finding,
    calculate_cvss, matches_target_domain, is_noise_domain,
    Finding, EndpointParam, Evidence
)


class CrawlSession:
    """
    Manages a Playwright-driven crawl session.
    Logs in (credentials or cookies) -> crawls pages up to max_depth ->
    captures every XHR/fetch with ID params -> auto-scans -> emits findings live.
    """

    def __init__(self, session_id: str, base_url: str, base_user_id: str,
                 auth_mode: str = 'cookies',           # 'cookies' or 'credentials'
                 cookies: dict = None,
                 username: str = None, password: str = None,
                 login_url: str = None,
                 username_selector: str = None,
                 password_selector: str = None,
                 submit_selector: str = None,
                 max_depth: int = 4,
                 max_pages: int = 60,
                 target_domains: list = None,
                 event_callback=None,
                 finding_callback=None):

        self.session_id = session_id
        self.base_url = base_url
        self.base_user_id = base_user_id

        self.auth_mode = auth_mode
        self.cookies = cookies or {}
        self.username = username
        self.password = password
        self.login_url = login_url or base_url
        self.username_selector = username_selector or 'input[type="email"], input[name="username"], input[name="email"]'
        self.password_selector = password_selector or 'input[type="password"]'
        self.submit_selector = submit_selector or 'button[type="submit"], input[type="submit"]'

        self.max_depth = max_depth
        self.max_pages = max_pages
        self.target_domains = target_domains or [urlparse(base_url).hostname]

        self.event_callback = event_callback
        self.finding_callback = finding_callback

        self.visited_pages = set()
        self.captured_endpoints = []
        self.findings = []
        self.stats = {
            'pages_crawled': 0,
            'endpoints_captured': 0,
            'noise_filtered': 0,
            'probes_sent': 0,
            'confirmed': 0,
            'suspected': 0,
        }
        self._running = False
        self._thread = None

    def _emit(self, event: str, data: dict):
        if self.event_callback:
            self.event_callback(event, data)

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def get_stats(self) -> dict:
        return {**self.stats, 'findings': len(self.findings)}

    # ── Main crawl + scan pipeline ────────────────────────────────────────────

    def _run(self):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self._emit('error', {
                'message': 'Playwright not installed. Run: pip install playwright && playwright install chromium'
            })
            self._running = False
            return

        self._emit('phase', {'phase': 1, 'label': 'Login', 'message': 'Authenticating...'})

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)

            # Apply cookie auth if provided
            if self.auth_mode == 'cookies' and self.cookies:
                domain = urlparse(self.base_url).hostname
                cookie_list = [
                    {'name': k, 'value': v, 'domain': domain, 'path': '/'}
                    for k, v in self.cookies.items()
                ]
                context.add_cookies(cookie_list)
                self._emit('login_complete', {'method': 'cookies'})

            page = context.new_page()

            # Track every network request matching our criteria
            def on_request(request):
                self._on_network_request(request)

            page.on('request', on_request)

            # Credential-based login flow
            if self.auth_mode == 'credentials' and self.username and self.password:
                try:
                    page.goto(self.login_url, timeout=15000)
                    page.fill(self.username_selector, self.username)
                    page.fill(self.password_selector, self.password)
                    page.click(self.submit_selector)
                    page.wait_for_load_state('networkidle', timeout=10000)
                    self._emit('login_complete', {'method': 'credentials'})
                except Exception as e:
                    self._emit('error', {'message': f'Login failed: {str(e)}'})

            self._emit('phase', {'phase': 2, 'label': 'Crawling', 'message': f'Mapping site up to depth {self.max_depth}...'})

            # BFS crawl
            self._crawl_bfs(page, self.base_url)

            browser.close()

        self._emit('phase', {'phase': 3, 'label': 'Scanning', 'message': f'Scanning {len(self.captured_endpoints)} captured endpoints...'})
        self._scan_captured()

        self._emit('complete', {'stats': self.get_stats()})
        self._running = False

    def _on_network_request(self, request):
        """Called for every network request the page makes."""
        try:
            url = request.url
            method = request.method

            if not matches_target_domain(url, self.target_domains):
                self.stats['noise_filtered'] += 1
                return

            # Skip static assets
            if any(url.lower().endswith(ext) for ext in
                   ['.js', '.css', '.png', '.jpg', '.svg', '.woff', '.woff2', '.ico', '.gif']):
                return

            body = None
            if method in ('POST', 'PUT', 'PATCH'):
                try:
                    post_data = request.post_data
                    if post_data:
                        import json as json_lib
                        body = json_lib.loads(post_data)
                except Exception:
                    pass

            # Only capture if it has detectable ID params
            params = detect_id_params(url, body)
            if not params:
                return

            sig = f"{method}:{url}"
            if any(e['url'] == url and e['method'] == method for e in self.captured_endpoints):
                return

            headers = {}
            try:
                headers = dict(request.headers)
            except Exception:
                pass

            endpoint = {
                'url': url, 'method': method, 'body': body,
                'headers': headers, 'captured_at': datetime.utcnow().isoformat()
            }
            self.captured_endpoints.append(endpoint)
            self.stats['endpoints_captured'] += 1

            self._emit('endpoint_captured', {
                'url': url, 'method': method,
                'total_captured': self.stats['endpoints_captured']
            })
        except Exception:
            pass

    def _crawl_bfs(self, page, start_url: str):
        """Breadth-first crawl up to max_depth, clicking nav links and buttons."""
        queue_list = [(start_url, 0)]
        visited = set()

        while queue_list and self._running:
            if len(visited) >= self.max_pages:
                break

            url, depth = queue_list.pop(0)
            if url in visited or depth > self.max_depth:
                continue
            visited.add(url)

            try:
                page.goto(url, timeout=15000, wait_until='domcontentloaded')
                page.wait_for_timeout(800)  # let XHR settle

                self.stats['pages_crawled'] += 1
                self._emit('page_crawled', {
                    'url': url, 'depth': depth,
                    'pages_crawled': self.stats['pages_crawled']
                })

                # Click likely nav elements to trigger more XHR (menus, tabs)
                self._click_interactive_elements(page)

                if depth < self.max_depth:
                    links = self._extract_links(page, start_url)
                    for link in links:
                        if link not in visited:
                            queue_list.append((link, depth + 1))

            except Exception as e:
                self._emit('page_error', {'url': url, 'error': str(e)})
                continue

    def _click_interactive_elements(self, page):
        """Click nav tabs/menu items that often load data via XHR without navigation."""
        selectors = [
            'nav a', '[role="tab"]', '[role="menuitem"]',
            'button[aria-haspopup]', '.sidebar a', '.menu a'
        ]
        for sel in selectors:
            try:
                elements = page.query_selector_all(sel)
                for el in elements[:5]:  # limit to avoid runaway clicking
                    try:
                        el.click(timeout=1000)
                        page.wait_for_timeout(400)
                    except Exception:
                        continue
            except Exception:
                continue

    def _extract_links(self, page, base_url: str) -> list:
        """Extract same-domain links from the current page."""
        links = []
        try:
            hrefs = page.eval_on_selector_all('a[href]', 'els => els.map(e => e.href)')
            base_domain = urlparse(base_url).hostname
            for href in hrefs:
                try:
                    if urlparse(href).hostname == base_domain:
                        if href not in links:
                            links.append(href)
                except Exception:
                    continue
        except Exception:
            pass
        return links[:20]  # cap branching factor per page

    # ── Scanning captured endpoints ───────────────────────────────────────────

    def _scan_captured(self):
        for endpoint in self.captured_endpoints:
            if not self._running:
                break
            self._scan_endpoint(endpoint)

    def _scan_endpoint(self, endpoint: dict):
        url = endpoint['url']
        method = endpoint.get('method', 'GET')
        body = endpoint.get('body')
        headers = {k: v for k, v in endpoint.get('headers', {}).items()
                   if k.lower() not in ('host', 'content-length')}
        cookies = self.cookies

        params = detect_id_params(url, body)
        if not params:
            return

        self._emit('scanning', {'url': url, 'method': method, 'params': len(params)})

        baseline = make_request(url, method, headers, cookies, body)

        for param in params:
            test_ids = generate_test_ids(param.original_value, self.base_user_id, param.param_type)
            hit_count = 0
            best_score = 0.0
            best_evidence = None

            for test_id in test_ids:
                if not self._running:
                    return

                probe_url, probe_body = inject_id(url, param, test_id, body)
                probe_resp = make_request(probe_url, method, headers, cookies, probe_body)

                self.stats['probes_sent'] += 1
                diff = compute_diff_score(baseline, probe_resp)

                self._emit('probe', {
                    'url': url, 'param': param.key, 'test_id': test_id,
                    'status_code': probe_resp.get('status_code'),
                    'diff_score': diff, 'probes_sent': self.stats['probes_sent']
                })

                if diff >= 0.4:
                    hit_count += 1
                    if diff > best_score:
                        best_score = diff
                        sensitive = find_sensitive_fields(probe_resp.get('body'))
                        best_evidence = Evidence(
                            original_request={'url': url, 'method': method, 'headers': headers, 'body': body},
                            exploit_request={'url': probe_url, 'method': method, 'headers': headers, 'body': probe_body},
                            original_response=baseline,
                            exploit_response=probe_resp,
                            injected_id=test_id,
                            fields_exposed=sensitive,
                            diff_score=diff
                        )
                time.sleep(0.15)

            if best_evidence and best_score >= 0.4:
                status = classify_finding(best_score, hit_count)
                cvss_score, cvss_vector = calculate_cvss(best_evidence.fields_exposed, method)

                finding = Finding(
                    id=hashlib.md5(f"{url}{param.key}{best_evidence.injected_id}".encode()).hexdigest()[:12],
                    endpoint=url, method=method, param=param, status=status,
                    cvss_score=cvss_score, cvss_vector=cvss_vector,
                    evidence=best_evidence, timestamp=datetime.utcnow().isoformat(),
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
