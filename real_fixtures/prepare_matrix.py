#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
# Copyright (c) 2026 Tuik Security Group
"""Prepare pinned local Next.js production fixtures; requires Node 22/24 and npm."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

MATRIX = [
    ('15.1.8', '19.0.0', True), ('15.1.9', '19.0.1', False),
    ('15.5.6', '19.1.0', True), ('15.5.7', '19.1.2', False),
    ('16.0.6', '19.2.0', True), ('16.0.7', '19.2.1', False),
]
OLDER = [('13.5.11', '18.2.0', False), ('14.2.33', '18.3.1', False),
         ('14.2.35', '18.3.1', False)]
HERE = Path(__file__).resolve().parent


def prepare(work, matrix=MATRIX):
    env = dict(os.environ, NEXT_TELEMETRY_DISABLED='1')
    for version, react, affected in matrix:
        name = 'next-' + version
        source = HERE / 'matrix' / name
        source.mkdir(parents=True, exist_ok=True)
        (source / 'app/account').mkdir(parents=True, exist_ok=True)
        package = {'name': 'twoshell-lab-' + version.replace('.', '-'), 'private': True,
                   'dependencies': {'next': version, 'react': react, 'react-dom': react}}
        (source / 'package.json').write_text(json.dumps(package, indent=2) + '\n')
        experimental = "cpus:1,serverActions:true" if version.startswith('13.') else "cpus:1"
        (source / 'next.config.js').write_text(
            "module.exports = {basePath:'/portal', experimental:{" + experimental + "}};\n")
        (source / 'app/layout.js').write_text(
            "export default function Layout({children}) { return <html><body>{children}</body></html>; }\n")
        (source / 'app/page.js').write_text(
            "export default function Page() { return <main>Local fixture <a href='/portal/account'>Account</a></main>; }\n")
        (source / 'app/account/page.js').write_text(
            "export default function Page() { return <main>Nested local fixture</main>; }\n")
        target = work / name
        if (target / 'node_modules').exists() or (target / '.next').exists():
            raise RuntimeError('Use a fresh work directory: ' + str(target))
        shutil.copytree(source, target, dirs_exist_ok=True)
        log = target / 'prepare.log'
        with log.open('w') as output:
            install = ['npm', 'ci' if (source / 'package-lock.json').exists() else 'install',
                       '--ignore-scripts', '--no-audit', '--no-fund']
            print('Installing ' + name, flush=True)
            subprocess.run(install, cwd=target, env=env, stdout=output, stderr=subprocess.STDOUT,
                           check=True, timeout=240)
            shutil.copyfile(target / 'package-lock.json', source / 'package-lock.json')
            print('Building ' + name, flush=True)
            build = [str(target / 'node_modules/.bin/next'), 'build']
            if version.startswith('16.'):
                build.append('--webpack')
            subprocess.run(build, cwd=target, env=env, stdout=output, stderr=subprocess.STDOUT,
                           check=True, timeout=240)
        print('Ready ' + name, flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--only-older', action='store_true', help='Build the three older Next.js controls only')
    args = parser.parse_args()
    prepare(args.work_dir.resolve(), OLDER if args.only_older else MATRIX)
