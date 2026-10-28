#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
# Copyright (c) 2026 Tuik Security Group
"""Verify or export only the explicitly reviewed source-release allowlist."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = 'RELEASE_FILES.json'
REQUIRED = {'twoshell.py', 'LICENSE', 'COPYING', 'NOTICE', 'README.md',
            'tools/build_source_zip.py'}


def checked_path(root, name):
    if not isinstance(name, str) or not name or '\\' in name or ':' in name:
        raise ValueError('Invalid release path')
    parts = name.split('/')
    if (PurePosixPath(name).is_absolute() or any(part in {'', '.', '..'} for part in parts)
            or any(part.lower() in {'.git', '.hg', '.svn', '__pycache__', 'node_modules'} for part in parts)):
        raise ValueError('Unsafe release path: ' + name)
    path = root
    for part in parts:
        path = path / part
        if path.is_symlink():
            raise ValueError('Symlink is not release source: ' + name)
    if not path.is_file():
        raise ValueError('Missing release file: ' + name)
    return path


def read_manifest(root):
    path = checked_path(root, MANIFEST)
    raw = path.read_bytes()
    manifest = json.loads(raw)
    if manifest.get('format') != 1 or not isinstance(manifest.get('files'), list):
        raise ValueError('Unsupported release manifest')
    names = set()
    for entry in manifest['files']:
        name = entry['path']
        checked_path(root, name)
        if name == MANIFEST or name in names:
            raise ValueError('Duplicate/self-referential manifest path: ' + name)
        if not isinstance(entry.get('sha256'), str) or not re.fullmatch('[0-9a-f]{64}', entry['sha256']):
            raise ValueError('Invalid source digest: ' + name)
        names.add(name)
    if not REQUIRED <= names:
        raise ValueError('Required source/license files missing from manifest')
    return manifest, raw


def verified_files(root):
    manifest, raw = read_manifest(root)
    files = {}
    for entry in manifest['files']:
        content = checked_path(root, entry['path']).read_bytes()
        if hashlib.sha256(content).hexdigest() != entry['sha256']:
            raise ValueError('Source changed; review before refreshing: ' + entry['path'])
        files[entry['path']] = content
    files[MANIFEST] = raw
    return files


def verified_repository(root):
    """Check the Git index as well as source hashes; ignore untracked files."""
    files = verified_files(root)
    root = root.resolve()
    try:
        top = subprocess.check_output(['git', 'rev-parse', '--show-toplevel'],
                                      cwd=root, stderr=subprocess.PIPE, timeout=10)
        if Path(top.decode('utf-8').rstrip('\n')).resolve() != root:
            raise ValueError('Repository check must run at the release repository root')
        raw = subprocess.check_output(['git', 'ls-files', '--cached', '--full-name', '-z'],
                                      cwd=root, stderr=subprocess.PIPE, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError('Repository check requires an accessible Git checkout') from exc
    tracked = {name for name in raw.decode('utf-8').split('\0') if name}
    extra, missing = tracked - set(files), set(files) - tracked
    if extra or missing:
        # Do not print filenames that may themselves identify a private client.
        raise ValueError('Git index differs from the release manifest: %d unlisted, %d missing; '
                         'review git ls-files locally' % (len(extra), len(missing)))
    return files


def refresh(root):
    manifest, _ = read_manifest(root)
    for entry in manifest['files']:
        entry['sha256'] = hashlib.sha256(checked_path(root, entry['path']).read_bytes()).hexdigest()
    manifest['files'].sort(key=lambda entry: entry['path'])
    (root / MANIFEST).write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    print('Refreshed existing allowlist only; review the manifest diff before release.')


def build(root, destination):
    files = verified_files(root)
    destination = destination.absolute()
    try:
        destination.resolve().relative_to(root.resolve())
    except ValueError:
        pass
    else:
        raise ValueError('Write the archive outside the source tree')
    # Exclusive creation avoids overwriting an earlier reviewed artifact.
    with destination.open('xb') as output:
        with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content in sorted(files.items()):
                info = zipfile.ZipInfo('2shell-detector/' + name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                archive.writestr(info, content)
    return len(files)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check', action='store_true')
    mode.add_argument('--check-repo', action='store_true',
                      help='Also require tracked Git paths to match the source allowlist')
    mode.add_argument('--refresh', action='store_true')
    mode.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        if args.refresh:
            refresh(ROOT)
        elif args.check_repo:
            print('Verified %d release files and the tracked Git file list.' % len(verified_repository(ROOT)))
        elif args.check:
            print('Verified %d release files.' % len(verified_files(ROOT)))
        else:
            print('Wrote %d source files to %s' % (build(ROOT, args.output), args.output))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print('Release check failed: ' + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
