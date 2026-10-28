# SPDX-License-Identifier: LGPL-3.0-only
# Copyright (c) 2026 Tuik Security Group
"""Discovery boundary and end-to-end regression tests; synthetic loopback only."""
import contextlib
import io
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import unittest

import twoshell


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def handle_request(self):
        self.server.calls.append((self.command, self.path))
        self.rfile.read(int(self.headers.get('Content-Length', 0)))
        status, mime, body, headers = self.server.pages.get(self.path, (404, 'text/plain', 'missing', {}))
        if self.command == 'POST':
            if self.path.endswith('.php'):
                body = 'Session ID is too long or contains illegal characters; Failed to read session data; Failed to write session data (files)'
            else:
                status, body = 405, 'No actions on static page'
        body = body.encode()
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(body)))
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    do_GET = handle_request
    do_POST = handle_request


def page(body, mime='text/html', status=200, **headers):
    return status, mime, body, headers


@contextlib.contextmanager
def fixture(pages):
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.calls, server.pages = [], pages
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, 'http://127.0.0.1:%d/' % server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


def scan(url, *flags):
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        code = twoshell.main([url, '--json', '--request-interval', '0', *flags])
    return code, json.loads(stdout.getvalue())


class DiscoveryTests(unittest.TestCase):
    def test_static_discovered_page_separates_detection_from_coverage(self):
        pages = {'/': page('<meta name="generator" content="Astro"><a href="/privacy/">Privacy</a>'),
                 '/privacy/': page('Static privacy page')}
        with fixture(pages) as (server, url):
            code, report = scan(url, '--active', '--discover')
            self.assertEqual(code, 3)
            self.assertEqual(server.calls, [('GET', '/'), ('GET', '/privacy/'),
                ('POST', '/'), ('GET', '/'), ('POST', '/'), ('GET', '/')])
            for item in report['results'][:4]:
                self.assertEqual(item['outcome'], 'no vulnerability detected')
                self.assertEqual(item['detection']['result'], 'no vulnerability detected')
                self.assertFalse(item['detection']['signature_detected'])
                self.assertEqual(item['coverage']['state'], 'partial')
                self.assertTrue(item['coverage']['limited'])
                self.assertIn('HTTP 405', item['coverage']['summary'])
                self.assertIn('not actively tested', item['coverage']['summary'])
                self.assertEqual(item['coverage']['routes'][1]['reason'], 'no_technology_indicator')
                self.assertEqual(item['applicability']['state'], 'unknown')
                self.assertEqual(item['applicability']['basis'], 'unverified')
                self.assertEqual(item['status'], 'unknown')
            self.assertEqual(report['results'][-1]['detection']['result'], 'not assessed')

    def test_discovery_without_active_checks_does_not_claim_no_detection(self):
        with fixture({'/': page('<a href="/privacy/">Privacy</a>'), '/privacy/': page('Static')}) as (server, url):
            code, report = scan(url, '--discover')
            self.assertEqual(code, 3)
            self.assertTrue(all(method == 'GET' for method, path in server.calls))
            for item in report['results']:
                self.assertEqual(item['detection']['result'], 'not assessed')
                self.assertEqual(item['applicability']['state'], 'unknown')

    def test_expanded_profile_finds_hidden_route_and_honors_explicit_caps(self):
        pages = {'/': page('<script src="/app.js"></script>'),
                 '/app.js': page('fetch("/account.php");', 'application/javascript'),
                 '/account.php': page('Local application')}
        with fixture(pages) as (server, url):
            code, report = scan(url, '--profile', 'expanded')
            self.assertEqual(code, 1)
            self.assertEqual(report['profile'], 'expanded')
            self.assertEqual(report['limits']['max_requests'], 60)
            self.assertEqual(report['limits']['max_samples_per_check_per_route'], 2)
            self.assertEqual(report['limits']['request_interval_seconds'], 0)
            self.assertTrue(report['waku_probe_enabled'])
            self.assertTrue(report['react_error_triage_enabled'])
            self.assertLessEqual(report['request_count'], 60)
            server.calls.clear()
            _, limited = scan(url, '--profile', 'expanded', '--samples', '1', '--max-requests', '7', '--max-active-routes', '1')
            self.assertLessEqual(limited['request_count'], 7)
            self.assertEqual(limited['limits']['max_samples_per_check_per_route'], 1)
            self.assertEqual(len(limited['health_checks']), limited['active_request_count'])

    def test_js_route_found_only_when_opted_in(self):
        pages = {'/': page('<script src="/assets/app.js"></script>'),
                 '/assets/app.js': page('fetch("/account.php");', 'application/javascript'),
                 '/account.php': page('Local application')}
        with fixture(pages) as (server, url):
            _, old = scan(url, '--discover', '--php-probe')
            self.assertNotIn(('GET', '/assets/app.js'), server.calls)
            server.calls.clear()
            code, report = scan(url, '--discover', '--discover-js', '--php-probe')
            self.assertEqual(code, 1)
            self.assertEqual(report['discovered_routes'][0]['discovered_via'], 'javascript')
            self.assertTrue(all(x['status'] == 'unknown' for x in old['results']))
            self.assertNotIn(('POST', '/assets/app.js'), server.calls)
            self.assertEqual(len(report['health_checks']), report['active_request_count'])

    def test_sitemap_index_finds_route_and_excludes_outside_origin(self):
        pages = {'/': page('Static landing'),
                 '/sitemap.xml': page('<sitemapindex><sitemap><loc>/pages.xml</loc></sitemap><sitemap><loc>https://outside.invalid/a.xml</loc></sitemap></sitemapindex>', 'application/xml'),
                 '/pages.xml': page('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>/account.php</loc></url></urlset>', 'text/xml'),
                 '/account.php': page('Local application')}
        with fixture(pages) as (server, url):
            code, report = scan(url, '--discover', '--discover-sitemaps', '--php-probe')
            self.assertEqual(code, 1)
            self.assertEqual(report['discovered_routes'][0]['discovered_via'], 'sitemap')
            self.assertEqual([x['state'] for x in report['discovery_resources']], ['read', 'read'])

    def test_literal_filter_does_not_follow_post_dynamic_or_action_paths(self):
        body = '''fetch('/read.php'); fetch('/write.php', {method:'POST'});
        fetch('/dynamic.php' + id); fetch('/query.php?a=1'); fetch('//outside.invalid/read.php');
        fetch('/%2564elete.php'); fetch('/save.php'); fetch('/read.php');
        ({href:'/nested', to:'/portal'}); fetch('/read%3fsecret.php');'''
        self.assertEqual(twoshell.javascript_links('https://example.test/', body),
                         ['https://example.test/read.php', 'https://example.test/nested', 'https://example.test/portal'])

    def test_xml_declarations_and_invalid_xml_rejected(self):
        for body in ['<!DOCTYPE a [<!ENTITY a "x">]><urlset/>', '<broken>', '<html/>']:
            with self.subTest(body=body), self.assertRaises(ValueError):
                twoshell.sitemap_links('https://example.test/', body)

    def test_resources_obey_caps_and_do_not_become_assessed_routes(self):
        pages = {'/': page(''.join('<script src="/s%d.js"></script>' % i for i in range(4)))}
        pages.update({'/s%d.js' % i: page('fetch("/p%d.php")' % i, 'text/javascript') for i in range(4)})
        with fixture(pages) as (server, url):
            _, report = scan(url, '--discover', '--discover-js')
            self.assertEqual(sum(path.endswith('.js') for method, path in server.calls), 2)
            self.assertEqual([x['reason'] for x in report['discovery_resources'][-2:]], ['resource_limit'] * 2)
            self.assertFalse(any(x.endswith('.js') for x in report['assessed_urls']))

    def test_shared_budget_preserves_health_pairs(self):
        pages = {'/': page('<script src="/s.js"></script>'),
                 '/s.js': page('fetch("/hidden.php")', 'text/javascript'), '/hidden.php': page('PHP route')}
        with fixture(pages) as (server, url):
            _, report = scan(url, '--discover', '--discover-js', '--discover-sitemaps', '--php-probe',
                             '--max-requests', '5', '--max-active-routes', '1')
            self.assertLessEqual(report['request_count'], 5)
            self.assertEqual(len(report['health_checks']), report['active_request_count'])
            self.assertTrue(any(x['reason'] == 'request_budget' for x in report['skipped_discovery']))

    def test_resource_challenge_stops_active_and_remaining_discovery(self):
        pages = {'/': page('<script src="/s.js"></script><a href="/hidden.php">App</a>'),
                 '/s.js': page('challenge', 'text/html', **{'cf-mitigated': 'challenge'})}
        with fixture(pages) as (server, url):
            _, report = scan(url, '--discover', '--discover-js', '--discover-sitemaps', '--active')
            self.assertEqual(server.calls, [('GET', '/'), ('GET', '/s.js')])
            self.assertEqual(report['active_stop_reason'], 'discovery_resource_blocked')
            self.assertEqual(report['active_request_count'], 0)

    def test_sitemap_not_requested_after_failed_or_blocked_baseline(self):
        for status in [403, 429, 500]:
            with self.subTest(status=status), fixture({'/': page('Unavailable', status=status)}) as (server, url):
                _, report = scan(url, '--discover', '--discover-sitemaps', '--active')
                self.assertEqual(server.calls, [('GET', '/')])
                self.assertEqual(report['active_request_count'], 0)
        response = dict(reachable=False, http_status=None, headers={}, body='')
        self.assertEqual(twoshell.discover_routes('https://unused.invalid/', response, 1,
                                                   discover_sitemaps=True), [])

    def test_resource_redirect_query_and_action_not_requested(self):
        for redirect in ['/logout.js', '/s.js?token=secret', 'http://outside.invalid/s.js', '/%2564elete.js']:
            with self.subTest(redirect=redirect), fixture({
                    '/': page('<script src="/s.js"></script>'),
                    '/s.js': page('', 'text/plain', 302, Location=redirect)}) as (server, url):
                _, report = scan(url, '--discover', '--discover-js')
                self.assertEqual(server.calls, [('GET', '/'), ('GET', '/s.js')])
                self.assertEqual(report['discovery_resources'][0]['state'], 'unreadable')

    def test_external_base_and_wrong_mime_cannot_invent_routes(self):
        response = dict(reachable=True, http_status=200, headers={'content-type': 'text/html'},
                        body='<base href="https://outside.invalid/"><script src="https://example.test/app.js"></script>')
        self.assertEqual(twoshell.html_links('https://example.test/', response, scripts=True),
                         ['https://example.test/app.js'])
        self.assertIsNone(twoshell.discovery_url('https://example.test/', '/path%00.php'))
        with fixture({'/': page('<base href="https://outside.invalid/"><script src="app.js"></script>')}) as (server, url):
            scan(url, '--discover', '--discover-js')
            self.assertEqual(server.calls, [('GET', '/')])
        with fixture({'/': page('<script src="/app.js"></script>'),
                      '/app.js': page('fetch("/hidden.php")')}) as (server, url):
            _, report = scan(url, '--discover', '--discover-js')
            self.assertEqual(report['discovered_routes'], [])
            self.assertEqual(report['discovery_resources'][0]['reason'], 'unexpected_content_type')

    def test_new_flags_require_discovery_before_network(self):
        with fixture({'/': page('')}) as (server, url):
            for flag in ['--discover-js', '--discover-sitemaps']:
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    scan(url, flag)
            self.assertEqual(server.calls, [])

    def test_large_javascript_uses_bounded_prefix_and_reports_partial(self):
        with fixture({'/': page('<script src="/app.js"></script>'),
                      '/app.js': page('fetch("/visible.php");' + ' ' * 70000 + 'fetch("/late.php");', 'text/javascript'),
                      '/visible.php': page('Local PHP')}) as (server, url):
            code, report = scan(url, '--discover', '--discover-js', '--php-probe')
            self.assertEqual(code, 1)
            self.assertNotIn(('GET', '/late.php'), server.calls)
            self.assertEqual(report['discovery_resources'][0]['reason'], 'javascript_prefix_only')
            self.assertTrue(report['discovery_summary']['partial'])
            self.assertTrue(all(x['response_bytes_captured'] <= x['response_body_limit'] for x in report['request_evidence']))

    def test_large_html_prefix_is_reported_as_partial_discovery(self):
        with fixture({'/': page(' ' * 70000 + '<a href="/late.php">late</a>')}) as (server, url):
            _, report = scan(url, '--active', '--discover')
            self.assertNotIn(('GET', '/late.php'), server.calls)
            self.assertEqual(report['active_request_count'], 2)
            self.assertTrue(report['discovery_summary']['partial'])
            self.assertEqual(report['discovery_summary']['prefix_only_pages'], [url])

    def test_separate_php_cve_explicitly_unassessed(self):
        with fixture({'/': page('')}) as (server, url):
            _, report = scan(url)
            self.assertEqual(report['cves_not_assessed'][0]['cve'], 'CVE-2026-115560')
            self.assertTrue(all(x['status'] == 'unknown' for x in report['results']))


if __name__ == '__main__':
    unittest.main()
