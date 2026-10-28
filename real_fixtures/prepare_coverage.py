#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
# Copyright (c) 2026 Tuik Security Group
"""Build minimal pinned production RSC fixtures, without upstream exploit code."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
PAIRS = [('waku', '0.27.1'), ('react-router', '7.9.6')]


def prepare(work, only=None):
    for framework, version in PAIRS:
        for react in ('19.2.0', '19.2.1'):
            name = framework + '-' + react
            if only and name != only:
                continue
            source = HERE / 'coverage' / name
            source.mkdir(parents=True, exist_ok=True)
            dependencies = {'react': react, 'react-dom': react, 'react-server-dom-webpack': react}
            if framework == 'waku':
                dependencies['waku'] = version if react == '19.2.0' else '0.27.3'
                files = {
                    'src/pages/_layout.tsx': "export default function Layout({children}) { return <html><body>{children}</body></html>; }\nexport const getConfig = () => ({render:'dynamic'});\n",
                    'src/pages/index.tsx': "import { Form } from '../components/form';\nasync function echo() { 'use server'; return 'local fixture'; }\nexport default function Home() { return <main>Local Waku fixture<Form action={echo}/></main>; }\nexport const getConfig = () => ({render:'dynamic'});\n",
                    'src/components/form.tsx': "'use client';\nexport function Form({action}) { return <form action={action}><button>Local fixture</button></form>; }\n",
                }
                build = ['node_modules/.bin/waku', 'build']
            else:
                dependencies.update({'react-router': version, '@react-router/dev': version,
                                     '@react-router/serve': version, '@vitejs/plugin-rsc': '0.5.6',
                                     'vite': '7.2.2', 'typescript': '5.9.2'})
                files = {
                    'vite.config.ts': "import {unstable_reactRouterRSC} from '@react-router/dev/vite';\nimport rsc from '@vitejs/plugin-rsc';\nimport {defineConfig} from 'vite';\nexport default defineConfig({plugins:[unstable_reactRouterRSC(),rsc()]});\n",
                    'react-router.config.ts': "export default {};\n",
                    'app/root.tsx': "import {Outlet,Links,Meta,ScrollRestoration} from 'react-router';\nexport function Layout({children}) { return <html><head><Meta/><Links/></head><body>{children}<ScrollRestoration/></body></html>; }\nexport default function Root() { return <Outlet/>; }\n",
                    'app/routes.ts': "import {index} from '@react-router/dev/routes';\nexport default [index('routes/home.tsx')];\n",
                    'app/routes/home.tsx': "async function echo() { 'use server'; return 'local fixture'; }\nexport function ServerComponent() { return <main>Local React Router RSC fixture<form action={echo}><button>Local fixture</button></form></main>; }\n",
                }
                build = ['node_modules/.bin/react-router', 'build']
            package = {'name': 'twoshell-local-' + name, 'private': True, 'type': 'module',
                       'dependencies': dependencies,
                       'overrides': {'react': react, 'react-dom': react, 'react-server-dom-webpack': react}}
            if framework == 'waku' and react == '19.2.1':
                package['overrides']['@vitejs/plugin-rsc'] = '0.5.6'
            files['package.json'] = json.dumps(package, indent=2) + '\n'
            for path, content in files.items():
                dest = source / path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(content)
            target = work / name
            if (target / 'node_modules').exists():
                raise RuntimeError('Use a fresh work directory: ' + str(target))
            shutil.copytree(source, target, dirs_exist_ok=True)
            env = dict(os.environ, NODE_ENV='production')
            with (target / 'prepare.log').open('w') as log:
                print('Installing ' + name, flush=True)
                lock = source / 'package-lock.json'
                matches = lock.exists() and json.loads(lock.read_text())['packages']['']['dependencies'] == dependencies
                subprocess.run(['npm', 'ci' if matches else 'install',
                                '--ignore-scripts', '--no-audit', '--no-fund'], cwd=target, env=env,
                               stdout=log, stderr=subprocess.STDOUT, check=True, timeout=240)
                shutil.copyfile(target / 'package-lock.json', source / 'package-lock.json')
                print('Building ' + name, flush=True)
                subprocess.run(build, cwd=target, env=env, stdout=log, stderr=subprocess.STDOUT,
                               check=True, timeout=240)
            print('Ready ' + name, flush=True)
    if not only:
        from prepare_matrix import prepare as prepare_next
        prepare_next(work, [('15.5.6', '19.1.0', True), ('15.5.7', '19.1.2', False)])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--only', help='Build just one fixture, e.g. waku-19.2.1')
    args = parser.parse_args()
    prepare(args.work_dir.resolve(), args.only)
