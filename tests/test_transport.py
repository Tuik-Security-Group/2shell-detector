# SPDX-License-Identifier: LGPL-3.0-only
# Copyright (c) 2026 Tuik Security Group
"""Verify direct-only transport through the real request subprocess."""
import contextlib
import errno
import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
import socket
import ssl
import threading
import time
import unittest
from unittest import mock
import urllib.request

import twoshell
from fixture_server import FixtureHandler


class RecordingFixture(FixtureHandler):
    def do_GET(self):
        self.server.received.append(('GET', self.path))
        super().do_GET()

    def do_POST(self):
        self.server.received.append(('POST', self.path))
        super().do_POST()

    def log_message(self, *args):
        pass


class ProxyTrap(BaseHTTPRequestHandler):
    def reject(self):
        self.server.received.append((self.command, self.path))
        self.send_response(502)
        self.send_header('Content-Length', '0')
        self.end_headers()

    do_GET = reject
    do_POST = reject
    do_CONNECT = reject

    def log_message(self, *args):
        pass


class SizedFixture(RecordingFixture):
    def do_GET(self):
        self.server.received.append(('GET', self.path))
        body = b'<html>response simulator only</html>' + b' ' * self.server.body_size
        if self.server.compressed:
            body = gzip.compress(body)
        self.send_response(self.server.status)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Content-Type', 'text/html')
        if self.server.compressed:
            self.send_header('Content-Encoding', 'gzip')
        if self.server.challenge:
            self.send_header('cf-mitigated', 'challenge')
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        if not self.server.large_post and not self.server.block_post:
            return super().do_POST()
        self.server.received.append(('POST', self.path))
        self.rfile.read(int(self.headers.get('Content-Length', 0)))
        body = (b'Session ID is too long or contains illegal characters; '
                b'Failed to read session data; Failed to write session data (files)' + b' ' * 131072)
        self.send_response(403 if self.server.block_post else 200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


class PostLimitFixture(FixtureHandler):
    """Large synthetic responses; all received requests remain small."""
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.server.received.append(('GET', self.path))
        if self.server.mode == 'health_failure' and self.server.bodies:
            self.send_error(503, 'Synthetic health failure')
            return
        super().do_GET()

    def do_POST(self):
        self.server.received.append(('POST', self.path))
        body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        self.server.bodies.append(body)
        mode, size = self.server.mode, self.server.size
        prefix = b' ' * size
        status, mime, headers = 200, 'text/plain', {}
        response = prefix + b'No supported signature in this synthetic response.'
        if mode == 'positive':
            if self.headers.get('Next-Action'):
                if b'["$1:a:a"]' in body:
                    status, mime, response = 500, 'text/x-component', prefix + b'1:E{"digest":"fixture"}\n'
                else:
                    status, response = 404, prefix + b'Missing action'
            else:
                response = prefix + (b'Session ID is too long or contains illegal characters; '
                                     b'Failed to read session data; Failed to write session data (files)')
        elif mode == 'generic_error' and self.headers.get('Next-Action'):
            status, mime, response = 500, 'text/x-component', prefix + b'1:E{"digest":"generic"}\n'
        elif mode in ('blocked', 'rate_limited'):
            status = 403 if mode == 'blocked' else 429
        elif mode == 'challenge':
            headers['cf-mitigated'] = 'challenge'
        elif mode == 'redirect':
            status, headers['Location'] = 302, '/never-follow'
        if self.server.compressed:
            response = gzip.compress(response)
            headers['Content-Encoding'] = 'gzip'
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(response)))
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        try:
            if mode == 'slow':
                for chunk in (response[n:n + 1024] for n in range(0, len(response), 1024)):
                    self.wfile.write(chunk)
                    self.wfile.flush()
                    time.sleep(0.1)
            else:
                self.wfile.write(response)
        except (BrokenPipeError, ConnectionResetError):
            pass


@contextlib.contextmanager
def local_server(handler):
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    server.received = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, 'http://127.0.0.1:%d' % server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


def proxy_environment(proxy, uppercase=False):
    env = {key: value for key, value in os.environ.items()
           if not key.lower().endswith('_proxy') and key != 'REQUEST_METHOD'}
    for key in ('http_proxy', 'https_proxy', 'all_proxy'):
        env[key.upper() if uppercase else key] = proxy
    env['no_proxy'] = env['NO_PROXY'] = ''
    return env


class TransportTests(unittest.TestCase):
    def post_limit_scan(self, mode='negative', size=96000, compressed=False, cap=1048576, timeout=3):
        with local_server(PostLimitFixture) as (server, base):
            server.mode, server.size, server.compressed, server.bodies = mode, size, compressed, []
            output = io.StringIO()
            with contextlib.redirect_stdout(output), mock.patch.object(twoshell.secrets, 'token_hex', return_value='a' * 32):
                code = twoshell.main([base + '/patched', '--active', '--json', '--request-interval', '0',
                                      '--max-requests', '7', '--max-post-bytes', str(cap), '--timeout', str(timeout)])
            report = json.loads(output.getvalue())
            self.assertLessEqual(report['request_count'], 7)
            self.assertEqual(report['active_request_count'], len(report['health_checks']))
            self.assertTrue(all(len(body) < 4096 for body in server.bodies))
            for row in report['request_evidence']:
                if row['response_body_limit']:
                    self.assertLessEqual(row['response_bytes_captured'], row['response_body_limit'])
                if row['method'] == 'POST' and not row['error']:
                    self.assertEqual(row['response_body_limit'], cap)
            self.assertEqual(report['limits']['max_post_response_bytes'], cap)
            return code, report, server.received, server.bodies

    def test_post_limit_only_changes_reads_not_probe_payloads(self):
        _, old, _, old_bodies = self.post_limit_scan(cap=65536)
        _, larger, _, larger_bodies = self.post_limit_scan()
        self.assertEqual(old_bodies, larger_bodies)
        self.assertEqual(old['active_request_count'], larger['active_request_count'])
        self.assertTrue(all(r['outcome'] == 'inconclusive' for r in old['results'][:4]))
        self.assertTrue(all(r['outcome'] == 'no vulnerability detected' for r in larger['results'][:4]))

    def test_large_post_signatures_and_controls_are_fully_examined(self):
        for compressed in (False, True):
            with self.subTest(compressed=compressed):
                code, report, _, _ = self.post_limit_scan(mode='positive', size=512000, compressed=compressed)
                self.assertEqual(code, 1)
                self.assertEqual(report['active_request_count'], 3)
                self.assertTrue(all(r['status'] == 'vulnerable' for r in report['results'][:4]))
                self.assertTrue(all(h['healthy'] for h in report['health_checks']))

    def test_large_compressed_negative_post_response(self):
        _, report, _, _ = self.post_limit_scan(size=512000, compressed=True)
        self.assertTrue(all(r['outcome'] == 'no vulnerability detected' for r in report['results'][:4]))

    def test_post_wire_and_decompression_caps_still_fail_closed(self):
        for compressed in (False, True):
            with self.subTest(compressed=compressed):
                _, report, _, _ = self.post_limit_scan(mode='positive', size=1048577, compressed=compressed)
                self.assertFalse(any(r['status'] == 'vulnerable' for r in report['results']))
                self.assertTrue(all(r['outcome'] != 'no vulnerability detected' for r in report['results'][:4]))
                self.assertTrue(any(r['body_truncated'] for r in report['request_evidence'] if r['method'] == 'POST'))

    def test_larger_post_cap_preserves_gate_redirect_and_health_stops(self):
        for mode in ('blocked', 'rate_limited', 'challenge', 'redirect', 'health_failure'):
            with self.subTest(mode=mode):
                code, report, calls, _ = self.post_limit_scan(mode=mode)
                self.assertEqual(report['active_request_count'], 1)
                self.assertFalse(any(r['status'] == 'vulnerable' for r in report['results']))
                self.assertNotIn(('GET', '/never-follow'), calls)
                if mode == 'health_failure':
                    self.assertEqual(code, 4)
                    self.assertTrue(report['possible_service_impact'])
                else:
                    self.assertTrue(report['active_stop_reason'])

    def test_generic_large_react_errors_do_not_become_positive(self):
        _, report, _, _ = self.post_limit_scan(mode='generic_error')
        self.assertFalse(any(r['status'] == 'vulnerable' for r in report['results']))
        self.assertFalse(report['react_probe']['positive'])
        self.assertEqual(report['react_probe']['control']['http_status'], 500)

    def test_raised_post_cap_retains_total_request_deadline(self):
        _, report, _, _ = self.post_limit_scan(mode='slow', timeout=0.5)
        self.assertEqual(report['active_request_count'], 1)
        self.assertEqual(report['request_evidence'][1]['error'], 'request_deadline_exceeded')
        self.assertTrue(report['health_checks'][0]['healthy'])

    def test_post_limit_rejects_invalid_configuration_before_requests(self):
        for value in ('0', '65535', '1048577', '2.5'):
            with self.subTest(value=value), mock.patch.object(twoshell, 'send_request') as send, \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                twoshell.main(['https://example.invalid/', '--max-post-bytes', value])
            send.assert_not_called()
        for value in (True, 65535, 1048577):
            with self.subTest(worker_limit=value), mock.patch.object(urllib.request.OpenerDirector, 'open') as opened:
                with self.assertRaises(ValueError):
                    twoshell.perform_request(urllib.request.Request('https://example.invalid/'), 1, post_body_limit=value)
                opened.assert_not_called()

    def sized_scan(self, size=96000, compressed=False, status=200, challenge=False,
                   large_post=False, block_post=False, path='/patched', flags=()):
        with local_server(SizedFixture) as (server, base):
            server.body_size, server.compressed, server.status = size, compressed, status
            server.challenge, server.large_post, server.block_post = challenge, large_post, block_post
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = twoshell.main([base + path, '--active', '--json', '--request-interval', '0',
                                      '--max-requests', '7', *flags])
            report = json.loads(output.getvalue())
            self.assertEqual(report['active_request_count'], len(report['health_checks']))
            self.assertTrue(all(h['healthy'] for h in report['health_checks']))
            self.assertLessEqual(report['request_count'], 7)
            for evidence in report['request_evidence']:
                self.assertLessEqual(evidence['response_bytes_captured'], evidence['response_body_limit'])
                if evidence['method'] == 'POST':
                    self.assertEqual(evidence['response_body_limit'], 65536)
            return code, report, server.received

    def test_larger_baselines_allow_existing_positive_checks_and_health_pairs(self):
        for size in (96000, 512000):
            with self.subTest(size=size):
                code, report, _ = self.sized_scan(size=size, path='/vulnerable')
                self.assertEqual(code, 1)
                self.assertEqual(report['active_request_count'], 3)
                self.assertTrue(all(r['status'] == 'vulnerable' for r in report['results'][:4]))

    def test_large_negative_and_compressed_baselines_are_readable(self):
        for compressed in (False, True):
            with self.subTest(compressed=compressed):
                _, report, _ = self.sized_scan(size=512000, compressed=compressed)
                self.assertEqual(report['active_request_count'], 2)
                self.assertTrue(all(r['outcome'] == 'no vulnerability detected' for r in report['results'][:4]))

    def test_wire_and_decoded_get_bounds_and_lower_cli_limit(self):
        for compressed, flags in ((False, ()), (True, ()), (False, ('--max-get-bytes', '65536'))):
            with self.subTest(compressed=compressed, flags=flags):
                _, report, calls = self.sized_scan(size=twoshell.GET_BODY_LIMIT + 1, compressed=compressed, flags=flags)
                self.assertEqual(report['active_request_count'], 0)
                self.assertEqual(len(calls), 1)
                self.assertTrue(report['request_evidence'][0]['body_truncated'])
                self.assertEqual(report['limits']['max_get_response_bytes'], 65536 if flags else 1048576)
        _, report, _ = self.sized_scan(size=96000, flags=('--max-get-bytes', '65536'))
        self.assertEqual(report['active_request_count'], 0)

    def test_large_post_signature_is_still_inconclusive(self):
        _, report, _ = self.sized_scan(large_post=True)
        self.assertFalse(any(r['status'] == 'vulnerable' for r in report['results']))
        self.assertTrue(all(r['outcome'] != 'no vulnerability detected' for r in report['results'][:4]))

    def test_large_get_does_not_remove_gating_or_error_stops(self):
        for status, challenge in ((403, False), (429, False), (500, False), (200, True)):
            with self.subTest(status=status, challenge=challenge):
                _, report, calls = self.sized_scan(status=status, challenge=challenge)
                self.assertEqual(report['active_request_count'], 0)
                self.assertTrue(all(method == 'GET' for method, _ in calls))
        _, report, _ = self.sized_scan(block_post=True)
        self.assertEqual(report['active_request_count'], 1)
        self.assertTrue(report['active_stop_reason'])

    def test_get_limit_validation_happens_before_requests(self):
        for value in ('0', '65535', '1048577', '2.5'):
            with self.subTest(value=value), mock.patch.object(twoshell, 'send_request') as send, \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                twoshell.main(['https://example.invalid/', '--max-get-bytes', value])
            send.assert_not_called()

    def test_error_categories_do_not_copy_exception_details(self):
        cases = [(socket.gaierror(-2, 'secret'), 'dns'),
                 (ssl.SSLCertVerificationError('secret'), 'tls_certificate'),
                 (ssl.SSLError('secret'), 'tls_handshake'), (TimeoutError('secret'), 'timeout'),
                 (ConnectionRefusedError('secret'), 'connection_refused'),
                 (ConnectionResetError('secret'), 'connection_closed'),
                 (OSError(errno.ENETUNREACH, 'secret'), 'network_unreachable'),
                 (urllib.error.URLError('https://user:secret@example.invalid/?token=secret'), 'connection_error')]
        for error, category in cases:
            with self.subTest(category=category), mock.patch.object(
                    urllib.request.OpenerDirector, 'open', side_effect=urllib.error.URLError(error)):
                response = twoshell.perform_request(urllib.request.Request('https://example.invalid/'), 1)
                self.assertEqual(response['network_error_kind'], category)
                self.assertNotIn('secret', json.dumps(response))

    def test_redirect_diagnostics_are_sanitized_and_do_not_expand_scope(self):
        from test_discovery import fixture, page
        cases = [('/?token=secret', 'discovery_scope'),
                 ('https://outside.invalid/a?token=secret', 'cross_origin'),
                 ('https://user:secret@outside.invalid/', 'invalid_location'),
                 ('/', 'redirect_loop'), (None, 'missing_location')]
        for target, reason in cases:
            with self.subTest(reason=reason), fixture({'/': page('', status=302,
                    **({'Location': target} if target else {}))}) as (server, url):
                log = twoshell.RequestLog(10, 0)
                _, response = twoshell.fetch_with_redirects(url, 3, log, discovery=True)
                self.assertEqual(response['redirect_stop_reason'], reason)
                self.assertEqual(log[0]['redirect_stop_reason'], reason)
                self.assertEqual(server.calls, [('GET', '/')])
                self.assertNotIn('secret', json.dumps(log))

    def test_followed_chain_hop_and_budget_reasons_are_saved(self):
        from test_discovery import fixture, page
        pages = {'/': page('', status=302, Location='/one'),
                 '/one': page('', status=302, Location='/two'),
                 '/two': page('', status=302, Location='/three')}
        with fixture(pages) as (_, url):
            log = twoshell.RequestLog(10, 0)
            _, response = twoshell.fetch_with_redirects(url, 3, log)
            self.assertEqual([r['redirect_stop_reason'] for r in log], ['followed', 'followed', 'hop_limit'])
            self.assertEqual(response['redirect_target'], url + 'three')
            log = twoshell.RequestLog(1, 0)
            _, response = twoshell.fetch_with_redirects(url, 3, log)
            self.assertEqual(response['redirect_stop_reason'], 'request_budget')
            self.assertEqual(len(log), 1)

    def test_active_checks_ignore_proxy_environment_in_child(self):
        with local_server(RecordingFixture) as (direct, base), local_server(ProxyTrap) as (proxy, proxy_url):
            for uppercase in (False, True):
                with self.subTest(uppercase=uppercase), mock.patch.dict(
                        os.environ, proxy_environment(proxy_url, uppercase), clear=True):
                    direct.received.clear()
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        code = twoshell.main([base + '/vulnerable', '--active', '--json',
                                              '--request-interval', '0', '--max-requests', '7'])
                    report = json.loads(output.getvalue())
                    self.assertEqual(code, 1)
                    self.assertEqual(proxy.received, [])
                    self.assertEqual(report['request_count'], 7)
                    self.assertEqual(report['active_request_count'], 3)
                    self.assertEqual([method for method, _ in direct.received],
                                     ['GET', 'POST', 'GET', 'POST', 'GET', 'POST', 'GET'])
                    self.assertTrue(all(row['healthy'] for row in report['health_checks']))
                    self.assertTrue(all(row['status'] == 'vulnerable' for row in report['results']
                                        if row['family'] in {'PHP2Shell', 'React2Shell'}))

    def test_https_ignores_proxy_and_does_not_downgrade_tls(self):
        # The target intentionally speaks HTTP; an HTTPS request must fail
        # directly instead of tunneling through the proxy or weakening TLS.
        with local_server(RecordingFixture) as (_, base), local_server(ProxyTrap) as (proxy, proxy_url):
            with mock.patch.dict(os.environ, proxy_environment(proxy_url), clear=True):
                response = twoshell.fetch(base.replace('http:', 'https:', 1) + '/vulnerable', 3)
            self.assertFalse(response['reachable'])
            self.assertEqual(proxy.received, [])

    def test_environment_and_platform_proxy_discovery_are_never_called(self):
        # getproxies also discovers platform settings when no env override exists.
        for scheme in ('http', 'https'):
            with self.subTest(scheme=scheme), mock.patch.object(
                    urllib.request, 'getproxies', side_effect=AssertionError('implicit proxy discovery')), \
                    mock.patch.object(urllib.request.OpenerDirector, 'open', side_effect=OSError):
                response = twoshell.perform_request(
                    urllib.request.Request(scheme + '://transport.example.invalid/'), 1)
                self.assertFalse(response['reachable'])


if __name__ == '__main__':
    unittest.main()
