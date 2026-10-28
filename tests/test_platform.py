# SPDX-License-Identifier: LGPL-3.0-only
# Copyright (c) 2026 Tuik Security Group
"""Regression coverage for ambiguous error pages and explicit challenge responses."""
import contextlib
import io
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

import twoshell


class PlatformHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def handle_request(self):
        server = self.server
        size = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(size)
        server.calls.append((self.command, self.path))
        candidate = b'["$1:a:a"]' in body
        php = self.command == 'POST' and not self.headers.get('Next-Action')
        control = self.command == 'POST' and not candidate and not php
        if self.command == 'GET':
            status, content_type = 200, 'text/html'
            response = b'<html><script>self.__next_f=[]</script><a href="/next">next</a></html>'
        elif php:
            status, content_type = 200, 'text/plain'
            response = b'Session ID is too long or contains illegal characters; Failed to read session data; Failed to write session data (files)'
        elif candidate:
            status, content_type = 500, server.candidate_type
            response = (b'1:E{"digest":"fixture"}' if server.strict else b'<html>Error: digest unavailable</html>')
        else:
            status, content_type, response = 404, 'text/plain', b'Action not found'
        challenged = (server.challenge == 'baseline' or
                      (server.challenge == 'candidate' and candidate) or
                      (server.challenge == 'control' and control) or
                      (server.challenge == 'php' and php) or
                      (server.challenge == 'health' and self.command == 'GET' and len(server.calls) > 1))
        self.send_response(status)
        if content_type:
            self.send_header('Content-Type', content_type)
        if challenged:
            self.send_header('CF-Mitigated', ' Challenge ')
        for key, value in server.extra_headers.items():
            self.send_header(key, value)
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    do_GET = handle_request
    do_POST = handle_request


@contextlib.contextmanager
def fixture(candidate_type='text/x-component', strict=True, challenge=None, headers=None):
    server = ThreadingHTTPServer(('127.0.0.1', 0), PlatformHandler)
    server.calls, server.candidate_type, server.strict = [], candidate_type, strict
    server.challenge, server.extra_headers = challenge, headers or {}
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, 'http://127.0.0.1:%d/' % server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def scan(url, *args):
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        code = twoshell.main([url, '--json', '--request-interval', '0', *args])
    return code, json.loads(stdout.getvalue())


def react_results(report):
    return [x for x in report['results'] if x['family'] == 'React2Shell']


class PlatformTests(unittest.TestCase):
    def test_challenged_redirect_is_not_followed(self):
        response = dict(reachable=True, http_status=302, body='', headers={
            'cf-mitigated': 'challenge', 'location': '/next'})
        with mock.patch.object(twoshell, 'fetch', return_value=response) as fetch:
            url, result = twoshell.fetch_with_redirects('http://127.0.0.1:12345/', 5)
        self.assertEqual(url, 'http://127.0.0.1:12345/')
        self.assertIs(result, response)
        fetch.assert_called_once()

    def test_non_flight_errors_are_inconclusive(self):
        for content_type in ('text/html', 'application/json', ''):
            for strict in (True, False):
                with self.subTest(content_type=content_type, strict=strict), fixture(content_type, strict) as (server, url):
                    code, report = scan(url, '--react-probe')
                    self.assertEqual(code, 3)
                    self.assertTrue(all(x['status'] == 'unknown' and x['coverage']['state'] == 'inconclusive'
                                        for x in react_results(report)))
                    self.assertEqual(report['active_request_count'], 1)
                    self.assertEqual(report['request_count'], 3)

    def test_hosting_headers_do_not_suppress_positive_behavior(self):
        for headers in ({'Server': 'Vercel'}, {'Server': 'Netlify'}, {'Netlify-Vary': 'query'}, {'Server': 'cloudflare'}):
            with self.subTest(headers=headers), fixture(headers=headers) as (server, url):
                code, report = scan(url, '--react-probe')
                self.assertEqual(code, 1)
                self.assertTrue(all(x['status'] == 'vulnerable' for x in react_results(report)))
                self.assertEqual(report['active_request_count'], 2)

    def test_broad_flight_error_still_requires_and_passes_control(self):
        with fixture(strict=False) as (server, url):
            code, report = scan(url, '--react-probe')
            self.assertEqual(code, 1)
            self.assertEqual(report['react_probe']['control_variant'], 'missing_action_404')

    def test_challenged_baseline_skips_discovery_imports_and_posts(self):
        with fixture(challenge='baseline') as (server, url), tempfile.TemporaryDirectory() as tmp:
            routes = Path(tmp) / 'routes.txt'
            routes.write_text('/imported\n')
            code, report = scan(url, '--active', '--discover', '--routes-file', str(routes))
            self.assertEqual(code, 3)
            self.assertEqual(server.calls, [('GET', '/')])
            self.assertEqual(report['active_request_count'], 0)
            self.assertTrue(report['active_stop_reason'])
            self.assertTrue(all(x['coverage']['state'] == 'blocked' for x in react_results(report)))
            self.assertEqual(report['request_evidence'][0]['response_mitigation'], 'cloudflare_challenge')

    def test_challenge_on_candidate_or_control_never_confirms(self):
        for phase, posts in [('candidate', 1), ('control', 2)]:
            with self.subTest(phase=phase), fixture(challenge=phase) as (server, url):
                code, report = scan(url, '--react-probe', '--samples', '3')
                self.assertEqual(code, 3)
                self.assertEqual(report['active_request_count'], posts)
                self.assertTrue(all(x['status'] == 'unknown' and x['coverage']['state'] == 'blocked'
                                    for x in react_results(report)))

    def test_challenged_health_is_not_healthy_even_with_200(self):
        with fixture(challenge='health') as (server, url):
            code, report = scan(url, '--react-probe')
            self.assertEqual(code, 4)
            self.assertTrue(report['possible_service_impact'])
            self.assertEqual(report['active_request_count'], 1)
            self.assertFalse(report['health_checks'][0]['healthy'])

    def test_php_warning_on_challenge_is_not_a_finding(self):
        with fixture(challenge='php') as (server, url):
            code, report = scan(url, '--active', '--samples', '3')
            self.assertEqual(code, 3)
            self.assertEqual(report['active_request_count'], 1)
            self.assertFalse(any(x['status'] == 'vulnerable' for x in report['results']))
            self.assertEqual(report['results'][0]['coverage']['state'], 'blocked')

    def test_batch_skips_later_paths_after_200_challenge(self):
        with fixture(challenge='baseline') as (server, url), tempfile.TemporaryDirectory() as tmp:
            targets, output = Path(tmp) / 'urls.txt', Path(tmp) / 'reports'
            targets.write_text(url + '\n' + url + 'next\n')
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = twoshell.main(['--urls-file', str(targets), '--active', '--discover',
                                       '--output-dir', str(output), '--request-interval', '0', '--site-interval', '0'])
            summary = json.loads((output / 'summary.json').read_text())
            self.assertEqual(code, 3)
            self.assertEqual(server.calls, [('GET', '/')])
            self.assertEqual(summary['targets'][1]['state'], 'skipped_origin')


if __name__ == '__main__':
    unittest.main()
