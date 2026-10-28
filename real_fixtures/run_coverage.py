#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
# Copyright (c) 2026 Tuik Security Group
"""Loopback-only framework and endpoint-discovery acceptance tests.

Requires prepare_coverage.py and cached PHP Apache images. The experimental
framework requests reuse only the tiny property-reference/control bodies;
they never load a real server action or include executable code.
"""
import argparse
import contextlib
from datetime import datetime, timezone
import hashlib
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import urllib.request
import uuid

from run_matrix import MatrixRun, Gateway, next_server, command, ready, HERE, OUT
sys.path.insert(0, str(OUT))
import twoshell


class DiscoveryGateway(Gateway):
    def handle_request(self):
        if self.command == 'GET' and self.path in {'/', '/app.js', '/sitemap.xml'}:
            self.server.requests.append((self.command, self.path))
            body, mime = {
                '/': (b'<html>Local landing<script src="/app.js"></script></html>', 'text/html'),
                '/app.js': (b'fetch("/portal/account");', 'text/javascript'),
                '/sitemap.xml': (b'<urlset><url><loc>/portal/account</loc></url></urlset>', 'application/xml'),
            }[self.path]
            self.reply(200, body, mime)
            return
        super().handle_request()

    do_GET = handle_request
    do_POST = handle_request


@contextlib.contextmanager
def discovery_gateway(backend):
    server = ThreadingHTTPServer(('127.0.0.1', 0), DiscoveryGateway)
    server.backend, server.alternate, server.mode = backend, None, 'opaque'
    server.requests, server.candidates = [], 0
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, 'http://127.0.0.1:%d' % server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


@contextlib.contextmanager
def framework_server(work, framework, react):
    folder = work / (framework + '-' + react)
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    args = ([str(folder / 'node_modules/.bin/waku'), 'start', '--host', '127.0.0.1', '--port', str(port)]
            if framework == 'waku' else
            [str(folder / 'node_modules/.bin/react-router-serve'), 'build/server/index.js'])
    with (folder / 'runtime.log').open('w') as log:
        process = subprocess.Popen(args, cwd=folder, env=dict(os.environ, NODE_ENV='production',
                                   HOST='127.0.0.1', PORT=str(port)), stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            base = 'http://127.0.0.1:%d' % port
            ready(base + '/')
            identity = {name: json.loads((folder / 'node_modules' / name / 'package.json').read_text())['version']
                        for name in [framework, 'react', 'react-dom', 'react-server-dom-webpack', '@vitejs/plugin-rsc']}
            assert all(identity[name] == react for name in ['react', 'react-dom', 'react-server-dom-webpack'])
            identity['lockfile_sha256'] = hashlib.sha256((folder / 'package-lock.json').read_bytes()).hexdigest()
            yield base, identity
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)


def experimental_pair(base, framework):
    assert base.startswith('http://127.0.0.1:')
    path = '/RSC/F/twoshell-missing/action.txt' if framework == 'waku' else '/'
    evidence = twoshell.RequestLog(8, 0.2)
    responses = []
    action_id = 'twoshell-missing-' + uuid.uuid4().hex
    for reference in ['["$1:a:a"]', '["$1:a"]']:
        boundary = '----LocalFixture' + uuid.uuid4().hex
        body = ('--' + boundary + '\r\nContent-Disposition: form-data; name="1"\r\n\r\n{}\r\n' +
                '--' + boundary + '\r\nContent-Disposition: form-data; name="0"\r\n\r\n' + reference +
                '\r\n--' + boundary + '--\r\n').encode()
        headers = {'Content-Type': 'multipart/form-data; boundary=' + boundary, 'Accept-Encoding': 'identity'}
        if framework == 'react-router':
            headers['rsc-action-id'] = action_id
        response = twoshell.send_request(urllib.request.Request(base + path, data=body, headers=headers), 5, evidence)
        health = twoshell.fetch(base + '/', 5, evidence)
        responses.append({'reference': reference, 'status': response.get('http_status'),
                          'content_type': response.get('headers', {}).get('content-type'),
                          'body': response.get('body', '')[:2048], 'error': response.get('error'),
                          'health_ok': health['reachable'] and health.get('http_status') == 200})
        if not responses[-1]['health_ok']:
            raise RuntimeError('Framework fixture health failed; stop experimental requests')
    return {'path': path, 'responses': responses, 'request_evidence': evidence,
            'production_detector_added': False, 'payload_executes_code': False}


class CoverageRun(MatrixRun):
    def __init__(self, work):
        super().__init__(work)
        self.framework_experiments = []
        self.ports = []

    def run_next_discovery(self):
        for version in ['15.5.6', '15.5.7']:
            affected = version == '15.5.6'
            with next_server(self.work, version) as port, discovery_gateway(port) as (gateway, base):
                self.ports.extend([port, gateway.server_port])
                folder = self.work / ('next-' + version)
                identity = {'next': version, 'mode': 'production-webpack',
                            'lockfile_sha256': hashlib.sha256((folder / 'package-lock.json').read_bytes()).hexdigest(),
                            'gateway': 'simulated static landing with JS/sitemap-only application URL'}
                self.check('Next ' + version + ' direct', 'http://127.0.0.1:%d/portal/account' % port,
                           ['--react-probe'], 'React2Shell', affected, 'vulnerable' if affected else 'unknown', identity)
                for method, flags in [('html', []), ('javascript', ['--discover-js']),
                                      ('sitemap', ['--discover-sitemaps']), ('expanded', ['--profile', 'expanded'])]:
                    self.check('Next ' + version + ' via ' + method, base + '/',
                               ['--react-probe', '--discover'] + flags, 'React2Shell', affected,
                               'vulnerable' if affected and flags else 'unknown', identity)

    def run_frameworks(self):
        for framework in ['waku', 'react-router']:
            for react in ['19.2.0', '19.2.1']:
                with framework_server(self.work, framework, react) as (base, identity):
                    self.ports.append(int(base.rsplit(':', 1)[1]))
                    self.check(framework + ' React ' + react + ' existing detector', base + '/',
                               ['--react-probe', '--discover', '--discover-js'], 'React2Shell',
                               react == '19.2.0', 'unknown', identity)
                    if framework == 'waku':
                        report = self.check('Waku component parser React ' + react, base + '/',
                                   ['--react-probe', '--waku-probe'], 'React2Shell', react == '19.2.0',
                                   'vulnerable' if react == '19.2.0' else 'unknown', identity,
                                   cve='CVE-2025-55182')
                        assert next(x for x in report['results'] if x['cve'] == 'CVE-2025-66478')['status'] == 'unknown'
                        report = self.check('Waku expanded profile React ' + react, base + '/',
                                   ['--profile', 'expanded'], 'React2Shell', react == '19.2.0',
                                   'vulnerable' if react == '19.2.0' else 'unknown', identity,
                                   cve='CVE-2025-55182')
                        assert next(x for x in report['results'] if x['cve'] == 'CVE-2025-66478')['status'] == 'unknown'
                    self.framework_experiments.append({'framework': framework, 'react': react, 'identity': identity,
                                                       'pair': experimental_pair(base, framework)})

    def run_discovery_php(self):
        site = self.work / 'php-discovery'
        (site / 'app').mkdir(parents=True, exist_ok=True)
        # Real PHP handler, no signature emulation; separate static entry pages
        # model a marketing frontend that only reveals the app in JS/sitemap.
        (site / 'index.html').write_text('<html>Static landing<script src="/assets.js"></script></html>')
        (site / 'assets.js').write_text('fetch("/app/status.php");\n')
        (site / 'sitemap.xml').write_text('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>/app/status.php</loc></url></urlset>')
        (site / 'app/status.php').write_text("<?php header('Content-Type: text/html'); echo '<main>Local PHP application</main>';\n")
        for version in ['8.5.11', '8.5.12']:
            for visible in [True, False]:
                ini = self.work / ('php-' + version + '-' + str(visible) + '.ini')
                ini.write_text('display_errors=' + ('On' if visible else 'Off') +
                               '\nlog_errors=Off\nexpose_php=Off\nsession.upload_progress.enabled=1\n')
                name = 'twoshell-coverage-' + uuid.uuid4().hex[:12]
                try:
                    command('docker', 'run', '--rm', '-d', '--pull=never', '--name', name,
                            '-p', '127.0.0.1::80', '-v', str(site) + ':/var/www/html:ro',
                            '-v', str(ini) + ':/usr/local/etc/php/conf.d/coverage.ini:ro', 'php:' + version + '-apache')
                    address = command('docker', 'port', name, '80/tcp')
                    assert address.startswith('127.0.0.1:') and '\n' not in address
                    self.ports.append(int(address.rsplit(':', 1)[1]))
                    base = 'http://' + address
                    ready(base + '/')
                    identity = {'php': command('docker', 'exec', name, 'php', '-r', 'echo PHP_VERSION;'),
                                'display_errors': visible, 'expose_php': False,
                                'image_id': command('docker', 'inspect', '--format', '{{.Image}}', name),
                                'application': 'minimal PHP route behind static landing; not a CMS'}
                    assert identity['php'] == version
                    for method, flags in [('html', []), ('javascript', ['--discover-js']),
                                          ('sitemap', ['--discover-sitemaps']),
                                          ('both', ['--discover-js', '--discover-sitemaps']),
                                          ('expanded', ['--profile', 'expanded'])]:
                        expected = 'vulnerable' if version == '8.5.11' and visible and flags else 'unknown'
                        self.check('PHP ' + version + ' errors ' + str(visible) + ' via ' + method,
                                   base + '/', ['--php-probe', '--discover'] + flags, 'PHP2Shell',
                                   version == '8.5.11', expected, identity)
                finally:
                    removed = subprocess.run(['docker', 'rm', '-f', name], text=True, capture_output=True, timeout=30)
                    if removed.returncode and 'No such container' not in removed.stderr:
                        raise RuntimeError('Container cleanup failed: ' + name)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run = CoverageRun(args.work_dir.resolve())
    try:
        run.run_frameworks()
        run.run_next_discovery()
        run.run_discovery_php()
    finally:
        listeners = []
        for port in run.ports:
            with socket.socket() as s:
                s.settimeout(0.2)
                if s.connect_ex(('127.0.0.1', port)) == 0:
                    listeners.append(port)
        result = {'created_at': datetime.now(timezone.utc).isoformat(),
                  'checker_sha256': hashlib.sha256((OUT / 'twoshell.py').read_bytes()).hexdigest(),
                  'records': run.records, 'framework_experiments': run.framework_experiments,
                  'cleanup': {'ports_checked': run.ports, 'remaining_listeners': listeners},
                  'summary': {'cases': len(run.records),
                              'expectations_passed': sum(x['assertions_passed'] for x in run.records),
                              'affected_detected': sum(x['known_affected_release_present'] and x['detected'] for x in run.records),
                              'affected_unknown': sum(x['known_affected_release_present'] and not x['detected'] for x in run.records),
                              'unaffected_false_positives': sum(not x['known_affected_release_present'] and x['detected'] for x in run.records)}}
        args.output.write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result['summary']), flush=True)
    if listeners or not all(x['assertions_passed'] for x in run.records):
        sys.exit(1)
