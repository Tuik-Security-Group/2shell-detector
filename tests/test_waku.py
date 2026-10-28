# SPDX-License-Identifier: LGPL-3.0-only
# Copyright (c) 2026 Tuik Security Group
"""Synthetic wire-level safeguards for the opt-in component-only probe."""
import contextlib
import io
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import unittest

import twoshell


LANDING = '<meta name="generator" content="Waku"><script>globalThis.__WAKU_HYDRATE__=true;globalThis.__WAKU_PREFETCHED__={};</script>'


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def handle_request(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        self.server.calls.append((self.command, self.path, body, dict(self.headers)))
        mode = self.server.mode
        status, output, mime, headers = 200, LANDING, 'text/html', {}
        if self.path.startswith('/RSC/R/'):
            status, output, mime = 404, '404 Not Found', 'text/plain'
            if self.command == 'GET' and mode == 'preflight-redirect':
                status, headers = 302, {'Location': '/elsewhere'}
            if self.command == 'POST':
                self.server.posts += 1
                candidate = b'["$1:a:a"]' in body and b'{"a":{}}' not in body
                if candidate and mode not in ('fixed', 'fixed-fingerprint'):
                    status, output = 500, 'Internal Server Error'
                if mode == 'body-filter' and b'["$1:a:a"]' in body:
                    status, output = 500, 'Internal Server Error'
                if mode == 'generic-error':
                    status, output = 500, 'Internal Server Error'
                if mode == 'wrong-mime' and candidate:
                    mime = 'text/html'
                if mode == 'block' and self.server.posts == 2:
                    status, output = 403, 'blocked'
                if mode == 'challenge' and self.server.posts == 2:
                    headers['cf-mitigated'] = 'challenge'
                if mode == 'truncate' and self.server.posts == 2:
                    output = 'x' * (twoshell.BODY_LIMIT + 1)
                if mode == 'late-mismatch' and self.server.posts == 4:
                    status, output = 404, '404 Not Found'
        elif mode == 'health-failure' and self.server.posts:
            status, output = 503, 'unavailable'
        elif mode == 'no-fingerprint':
            output = 'Ordinary site'
        data = output.encode()
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(data)))
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    do_GET = handle_request
    do_POST = handle_request


@contextlib.contextmanager
def fixture(mode='affected'):
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.mode, server.calls, server.posts = mode, [], 0
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, 'http://127.0.0.1:%d/' % server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


def scan(url, *args):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = twoshell.main([url, '--react-probe', '--waku-probe', '--json',
                              '--request-interval', '0', *args])
    return code, json.loads(out.getvalue())


class WakuTests(unittest.TestCase):
    def test_repeated_difference_and_controls_only_mark_react_cve(self):
        with fixture() as (server, url):
            code, report = scan(url, '--samples', '3')
            self.assertEqual(code, 1)
            cves = {row['cve']: row for row in report['results']}
            self.assertEqual(cves['CVE-2025-55182']['status'], 'vulnerable')
            self.assertEqual(cves['CVE-2025-66478']['status'], 'unknown')
            self.assertEqual(cves['CVE-2025-66478']['coverage']['state'], 'not_enabled')
            posts = [x for x in server.calls if x[0] == 'POST']
            self.assertEqual(len(posts), 5)
            self.assertEqual(len({x[1] for x in posts}), 1)
            self.assertEqual(report['request_count'], 12)
            self.assertEqual(len(report['health_checks']), 5)
            for _, path, body, headers in posts:
                self.assertRegex(path, r'^/RSC/R/twoshell-missing-[0-9a-f]{32}\.txt$')
                self.assertLess(len(body), 512)
                self.assertNotIn(b'$ACTION', body)
                self.assertNotIn(b'constructor', body)
                self.assertTrue(all('action' not in h.lower() for h in headers))
            self.assertIn(b'{"a":{}}', posts[2][2])

    def test_fixed_and_body_filter_do_not_become_findings(self):
        for mode, expected_posts in [('fixed', 2), ('body-filter', 3), ('generic-error', 1), ('late-mismatch', 4), ('wrong-mime', 2)]:
            with self.subTest(mode=mode), fixture(mode) as (server, url):
                code, report = scan(url)
                self.assertEqual(code, 3)
                self.assertFalse(report['react_probe']['positive'])
                self.assertEqual(server.posts, expected_posts)

    def test_block_challenge_and_truncation_stop_sequence(self):
        for mode in ['block', 'challenge', 'truncate']:
            with self.subTest(mode=mode), fixture(mode) as (server, url):
                _, report = scan(url, '--samples', '3')
                self.assertFalse(report['react_probe']['positive'])
                self.assertEqual(server.posts, 2)
                self.assertIsNotNone(report['active_stop_reason'])
                self.assertEqual(len(report['health_checks']), 2)

    def test_health_failure_stops_after_first_post(self):
        with fixture('health-failure') as (server, url):
            code, report = scan(url)
            self.assertEqual(code, 4)
            self.assertEqual(server.posts, 1)
            self.assertTrue(report['possible_service_impact'])

    def test_preflight_redirect_is_never_followed(self):
        with fixture('preflight-redirect') as (server, url):
            _, report = scan(url)
            self.assertEqual(server.posts, 0)
            self.assertEqual(len(server.calls), 2)
            self.assertEqual(report['results'][2]['coverage']['state'], 'blocked')

    def test_budget_root_and_opt_in_boundaries(self):
        for args, suffix, expected_posts in [(('--max-requests', '11'), '', 0), ((), 'nested', 0)]:
            with self.subTest(args=args, suffix=suffix), fixture() as (server, url):
                _, report = scan(url + suffix, *args)
                self.assertEqual(server.posts, expected_posts)
                self.assertEqual(len(server.calls), 1)
        with fixture() as (server, url):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                twoshell.main([url, '--react-probe', '--json', '--request-interval', '0'])
            self.assertFalse(any('/RSC/' in row[1] for row in server.calls))

    def test_fingerprint_requires_metadata_hydration_and_html(self):
        response = {'reachable': True, 'headers': {'content-type': 'text/html'}, 'body': LANDING}
        self.assertTrue(twoshell.waku_indicator(response))
        for body in ['Waku', LANDING.replace('__WAKU_HYDRATE__', 'ordinary'), LANDING.replace('content="Waku"', 'content="other"')]:
            self.assertFalse(twoshell.waku_indicator(dict(response, body=body)))
        self.assertFalse(twoshell.waku_indicator(dict(response, headers={'content-type': 'text/plain'})))

    def test_waku_flag_requires_active_opt_in_before_network(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            twoshell.main(['https://unused.invalid/', '--waku-probe'])
