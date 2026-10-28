#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
# Copyright (c) 2026 Tuik Security Group
"""Run the detection-only integration matrix on loopback and clean up fixtures.

Build Next.js fixtures first with prepare_matrix.py. Requires cached official
php:8.5.11-apache and php:8.5.12-apache images for PHP cases.
"""
import argparse
import contextlib
from datetime import datetime, timezone
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import uuid

from prepare_matrix import MATRIX, OLDER

HERE = Path(__file__).resolve().parent
OUT = HERE.parent
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=30).stdout.strip()


def ready(url, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with OPENER.open(url, timeout=0.5) as response:
                if response.status == 200:
                    return response.read(65536)
        except OSError:
            time.sleep(0.1)
    raise RuntimeError('Fixture not ready: ' + url)


@contextlib.contextmanager
def next_server(work, version):
    folder = work / ('next-' + version)
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    with (folder / 'runtime.log').open('w') as log:
        process = subprocess.Popen([str(folder / 'node_modules/.bin/next'), 'start',
                                    '--hostname', '127.0.0.1', '-p', str(port)], cwd=folder,
                                   env=dict(os.environ, NEXT_TELEMETRY_DISABLED='1'),
                                   stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            ready('http://127.0.0.1:%d/portal/account' % port)
            actual = json.loads((folder / 'node_modules/next/package.json').read_text())['version']
            if actual != version:
                raise RuntimeError('Unexpected Next.js runtime: ' + actual)
            yield port
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)


class Gateway(BaseHTTPRequestHandler):
    """Controlled local reverse proxy; WAF/error modes are simulations."""
    def log_message(self, *args):
        pass

    def reply(self, status, body, content_type='text/html', headers=()):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        for name, value in headers:
            if name.lower() not in ('content-length', 'content-type', 'transfer-encoding', 'connection', 'server', 'date'):
                self.send_header(name, value)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass  # A bounded scanner may close after its response-size limit.

    def handle_request(self):
        self.server.requests.append((self.command, self.path))
        size = int(self.headers.get('Content-Length', '0'))
        if not 0 <= size <= 4096:
            self.reply(400, b'Lab request limit')
            return
        body = self.rfile.read(size) if size else None
        if self.path == '/' and self.command == 'GET':
            self.reply(200, b'<a href="/section">Applications</a>' if self.server.mode != 'opaque' else b'Landing page')
            return
        if self.path == '/section' and self.command == 'GET':
            self.reply(200, b'<a href="/portal/account">Application</a>')
            return
        if not self.path.startswith('/portal'):
            self.reply(405, b'No action here')
            return
        if self.command == 'POST' and self.server.mode == 'blocked':
            self.reply(403, b'Local simulated WAF block')
            return
        if self.command == 'POST' and self.server.mode == 'generic-digest':
            self.reply(500, b'Error: {"digest":"gateway-generic-error"}', 'text/x-component')
            return
        port = self.server.backend
        if self.command == 'POST' and self.server.mode in ('mixed-visible', 'mixed-sticky'):
            # Route by candidate/control pair. The first pair reaches fixed,
            # later pairs reach affected in mixed-visible. Sticky stays fixed.
            if b'["$1:a:a"]' in (body or b''):
                self.server.candidates += 1
            if self.server.mode == 'mixed-visible' and self.server.candidates >= 2:
                port = self.server.alternate
        if self.server.mode == 'mixed-hidden' and self.server.alternate:
            # Deterministic load-balancer case: scanner POSTs reach the fixed
            # replica; GETs alternate between the fixed and affected replicas.
            if self.command == 'GET' and len(self.server.requests) % 2:
                port = self.server.alternate
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        headers = {name: value for name, value in self.headers.items()
                   if name.lower() not in ('host', 'connection', 'content-length')}
        try:
            connection.request(self.command, self.path, body=body, headers=headers)
            response = connection.getresponse()
            # Relay one byte beyond the scanner cap. Large static JS responses
            # then exercise bounded-prefix discovery instead of crashing the
            # lab proxy and simulating a transport failure.
            data = response.read(65537)
            if self.server.mode == 'custom-error' and response.status >= 500:
                self.reply(response.status, b'An application error occurred.')
            else:
                self.reply(response.status, data, response.getheader('Content-Type', 'text/plain'), response.getheaders())
        finally:
            connection.close()

    do_GET = handle_request
    do_POST = handle_request


@contextlib.contextmanager
def gateway(backend, alternate=None):
    server = ThreadingHTTPServer(('127.0.0.1', 0), Gateway)
    server.backend = backend
    server.alternate = alternate
    server.mode = 'transparent'
    server.requests = []
    server.candidates = 0
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, 'http://127.0.0.1:%d' % server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class MatrixRun:
    def __init__(self, work):
        self.work = work
        self.records = []

    def check(self, label, url, args, family, affected, expected, identity, expected_coverage=None,
              expected_review=None, expected_posts=None, cve=None):
        run = subprocess.run([sys.executable, str(OUT / 'twoshell.py'), url, '--json',
                              '--request-interval', '0'] + args,
                             capture_output=True, text=True, timeout=90)
        report = json.loads(run.stdout)
        items = [item for item in report['results'] if item['family'] == family and (cve is None or item['cve'] == cve)]
        actual = {item['status'] for item in items}
        success = (actual == {expected} and not report['possible_service_impact'] and
                   run.returncode == (1 if expected == 'vulnerable' else 3) and
                   report['request_count'] <= report['limits']['max_requests'] and
                   len(report['health_checks']) == report['active_request_count'] and
                   all(item['healthy'] for item in report['health_checks']))
        if expected_coverage:
            success = success and all(item['coverage']['state'] == expected_coverage for item in items)
        if expected_review is not None:
            signal = (report.get('react_probe') or {}).get('review_signal', {})
            success = success and (signal.get('repeatable', False) == expected_review)
        if expected_posts is not None:
            success = success and report['active_request_count'] == expected_posts
        self.records.append({'case': label, 'known_affected_release_present': affected,
                             'expected_status': expected, 'assertions_passed': success,
                             'detected': actual == {'vulnerable'},
                             'identity': identity, 'exit_code': run.returncode, 'report': report})
        print(label + ': ' + '/'.join(sorted(actual)) + (' [expected]' if success else ' [FAILED]'), flush=True)
        return report

    def run_next(self):
        for version, react, affected in MATRIX:
            folder = self.work / ('next-' + version)
            identity = {'next': version, 'react': react, 'mode': 'production-webpack', 'base_path': '/portal',
                        'lockfile_sha256': hashlib.sha256((folder / 'package-lock.json').read_bytes()).hexdigest()}
            expected = 'vulnerable' if affected else 'unknown'
            with next_server(self.work, version) as port, gateway(port) as (proxy, base):
                self.check(version + ' direct nested route', 'http://127.0.0.1:%d/portal/account' % port,
                           ['--react-probe'], 'React2Shell', affected, expected, identity)
                self.check(version + ' proxy two-level discovery', base + '/',
                           ['--react-probe', '--discover'], 'React2Shell', affected, expected, identity)
                proxy.mode = 'opaque'
                routes = self.work / 'approved-routes.txt'
                routes.write_text('/portal/account\n')
                self.check(version + ' imported unlinked route', base + '/',
                           ['--react-probe', '--routes-file', str(routes)], 'React2Shell', affected, expected, identity)
                proxy.mode = 'blocked'
                self.check(version + ' simulated WAF block', base + '/portal/account',
                           ['--react-probe'], 'React2Shell', affected, 'unknown', identity, 'blocked')
                proxy.mode = 'custom-error'
                self.check(version + ' proxy custom error', base + '/portal/account',
                           ['--react-probe'], 'React2Shell', affected, 'unknown', identity, 'completed_no_signature')
                self.check(version + ' repeated custom-error triage', base + '/portal/account',
                           ['--react-probe', '--samples', '2', '--react-error-triage'],
                           'React2Shell', affected, 'unknown', identity,
                           'inconclusive' if affected else 'completed_no_signature', affected,
                           4 if affected else 2)
                proxy.mode = 'blocked'
                self.check(version + ' repeated WAF stop', base + '/portal/account',
                           ['--react-probe', '--samples', '3', '--react-error-triage'],
                           'React2Shell', affected, 'unknown', identity, 'blocked', False, 1)
                self.check(version + ' expanded profile honors WAF', base + '/portal/account',
                           ['--profile', 'expanded'], 'React2Shell', affected, 'unknown', identity)
                proxy.mode = 'custom-error'
                self.check(version + ' expanded profile masked error', base + '/portal/account',
                           ['--profile', 'expanded'], 'React2Shell', affected, 'unknown', identity,
                           expected_review=affected)
                if not affected:
                    proxy.mode = 'generic-digest'
                    self.check(version + ' generic digest false-positive control', base + '/portal/account',
                               ['--react-probe'], 'React2Shell', False, 'unknown', identity, 'inconclusive')
        with next_server(self.work, '16.0.6') as affected_port, next_server(self.work, '16.0.7') as fixed_port:
            with gateway(fixed_port, affected_port) as (proxy, base):
                proxy.mode = 'mixed-hidden'
                self.check('Mixed replicas with probes reaching fixed instance', base + '/portal/account',
                           ['--react-probe'], 'React2Shell', True, 'unknown',
                           {'next_replicas': ['16.0.6', '16.0.7'], 'routing': 'controlled simulation'},
                           'completed_no_signature')
                self.check('Mixed hidden replicas remain unknown with repeats', base + '/portal/account',
                           ['--react-probe', '--samples', '3'], 'React2Shell', True, 'unknown',
                           {'next_replicas': ['16.0.6', '16.0.7'], 'routing': 'all POSTs fixed'},
                           'completed_no_signature', False, 3)
                self.check('Expanded profile cannot reach hidden affected replica', base + '/portal/account',
                           ['--profile', 'expanded'], 'React2Shell', True, 'unknown',
                           {'next_replicas': ['16.0.6', '16.0.7'], 'routing': 'all POSTs fixed'})
                proxy.mode = 'mixed-visible'
                proxy.candidates = 0
                self.check('Mixed replicas second sample reaches affected instance', base + '/portal/account',
                           ['--react-probe', '--samples', '3'], 'React2Shell', True, 'vulnerable',
                           {'next_replicas': ['16.0.6', '16.0.7'], 'routing': 'first candidate fixed, later candidate/control affected'},
                           'detected', False, 3)
                proxy.candidates = 0
                self.check('Expanded profile sees second affected sample', base + '/portal/account',
                           ['--profile', 'expanded'], 'React2Shell', True, 'vulnerable',
                           {'next_replicas': ['16.0.6', '16.0.7'], 'routing': 'first candidate fixed, later candidate/control affected'})
                proxy.mode = 'mixed-sticky'
                proxy.candidates = 0
                self.check('Sticky routing keeps all samples on fixed replica', base + '/portal/account',
                           ['--react-probe', '--samples', '3'], 'React2Shell', True, 'unknown',
                           {'next_replicas': ['16.0.6', '16.0.7'], 'routing': 'sticky simulation to fixed'},
                           'completed_no_signature', False, 3)
                self.check('Expanded profile respects sticky routing limit', base + '/portal/account',
                           ['--profile', 'expanded'], 'React2Shell', True, 'unknown',
                           {'next_replicas': ['16.0.6', '16.0.7'], 'routing': 'sticky simulation to fixed'})

    def run_older(self):
        for version, react, _ in OLDER:
            folder = self.work / ('next-' + version)
            identity = {'next': version, 'react': react, 'mode': 'production-webpack',
                        'lockfile_sha256': hashlib.sha256((folder / 'package-lock.json').read_bytes()).hexdigest()}
            with next_server(self.work, version) as port:
                self.check(version + ' older Next.js control',
                           'http://127.0.0.1:%d/portal/account' % port,
                           ['--react-probe'], 'React2Shell', False, 'unknown', identity)

    def run_php(self):
        site = self.work / 'php-site'
        site.mkdir(exist_ok=True)
        (site / 'index.php').write_bytes((HERE / 'php/index.php').read_bytes())
        (site / 'state.php').write_text("<?php header('Content-Type: application/json'); echo json_encode(["
                                      "'version'=>PHP_VERSION,'sapi'=>PHP_SAPI,'display_errors'=>ini_get('display_errors'),"
                                      "'upload_progress'=>ini_get('session.upload_progress.enabled'),'expose_php'=>ini_get('expose_php')]);")
        for version in ('8.5.11', '8.5.12'):
            for visible in (True, False):
                ini = self.work / 'matrix-php.ini'
                ini.write_text('display_errors=' + ('On' if visible else 'Off') +
                               '\nlog_errors=Off\nexpose_php=Off\nsession.upload_progress.enabled=1\n')
                name = 'twoshell-matrix-' + uuid.uuid4().hex[:12]
                try:
                    command('docker', 'run', '--rm', '-d', '--pull=never', '--name', name,
                            '-p', '127.0.0.1::80', '-v', str(site) + ':/var/www/html:ro',
                            '-v', str(ini) + ':/usr/local/etc/php/conf.d/twoshell.ini:ro', 'php:' + version + '-apache')
                    address = command('docker', 'port', name, '80/tcp')
                    if not address.startswith('127.0.0.1:') or '\n' in address:
                        raise RuntimeError('Unexpected container port mapping')
                    state = json.loads(ready('http://' + address + '/state.php'))
                    assert state == {'version': version, 'sapi': 'apache2handler', 'display_errors': '1' if visible else '',
                                     'upload_progress': '1', 'expose_php': ''}, state
                    identity = {'lab_only_runtime_state': state,
                                'image_id': command('docker', 'inspect', '--format', '{{.Image}}', name)}
                    self.check('PHP ' + version + ', errors ' + ('visible' if visible else 'hidden'),
                               'http://' + address + '/index.php', ['--php-probe'], 'PHP2Shell', version == '8.5.11',
                               'vulnerable' if version == '8.5.11' and visible else 'unknown', identity)
                    self.check('PHP ' + version + ', repeated, errors ' + ('visible' if visible else 'hidden'),
                               'http://' + address + '/index.php', ['--php-probe', '--samples', '3'],
                               'PHP2Shell', version == '8.5.11',
                               'vulnerable' if version == '8.5.11' and visible else 'unknown', identity,
                               expected_posts=1 if version == '8.5.11' and visible else 3)
                finally:
                    removed = subprocess.run(['docker', 'rm', '-f', name], text=True, capture_output=True, timeout=30)
                    if removed.returncode and 'No such container' not in removed.stderr:
                        raise RuntimeError('Container cleanup failed: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', type=Path, required=True)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument('--skip-php', action='store_true')
    selection.add_argument('--only-php', action='store_true')
    selection.add_argument('--only-older', action='store_true')
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    args.work_dir.mkdir(parents=True, exist_ok=True)
    run = MatrixRun(args.work_dir.resolve())
    completed = False
    try:
        if args.only_older:
            run.run_older()
        elif not args.only_php:
            run.run_next()
        if not args.skip_php and not args.only_older:
            run.run_php()
        completed = True
    finally:
        records = run.records
        summary = {'cases': len(records), 'expectations_passed': sum(row['assertions_passed'] for row in records),
                   'affected_cases_detected': sum(row['known_affected_release_present'] and row['detected'] for row in records),
                   'affected_cases_missed': sum(row['known_affected_release_present'] and not row['detected'] for row in records),
                   'fixed_cases_false_positive': sum(not row['known_affected_release_present'] and row['detected'] for row in records)}
        result = {'checked_at': datetime.now(timezone.utc).isoformat(),
                  'checker_sha256': hashlib.sha256((OUT / 'twoshell.py').read_bytes()).hexdigest(),
                  'completed': completed, 'php_skipped': args.skip_php or args.only_older,
                  'selection': 'older' if args.only_older else 'php' if args.only_php else 'matrix',
                  'scope': 'Loopback only. Real PHP/Next.js releases; proxy policies and mixed-instance routing are controlled simulations.',
                  'interpretation': 'Expected unknown results on affected releases count as detection misses. This matrix is not a representative sensitivity estimate.',
                  'summary': summary, 'records': records}
        args.report.write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(summary), flush=True)
    return 0 if completed and all(row['assertions_passed'] for row in run.records) else 1


if __name__ == '__main__':
    sys.exit(main())
