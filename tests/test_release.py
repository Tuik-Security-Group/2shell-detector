# SPDX-License-Identifier: LGPL-3.0-only
# Copyright (c) 2026 Tuik Security Group
"""Ensure source archives cannot accidentally scoop up local/client files."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile

from tools import build_source_zip as release


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name)
        self.root = self.parent / 'source'
        self.root.mkdir()
        self.entries = []
        for name in sorted(release.REQUIRED):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'reviewed source\n')
            self.entries.append({'path': name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
        self.save()

    def save(self):
        (self.root / release.MANIFEST).write_text(json.dumps({'format': 1, 'files': self.entries}))

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args], stderr=subprocess.PIPE)

    def track_release(self):
        self.git('-c', 'init.templateDir=', 'init', '--quiet')
        self.git('add', '--', *[entry['path'] for entry in self.entries], release.MANIFEST)

    def test_repository_check_accepts_private_untracked_files(self):
        self.track_release()
        (self.root / 'clients.txt').write_text('synthetic private fixture')
        self.assertEqual(set(release.verified_repository(self.root)),
                         release.REQUIRED | {release.MANIFEST})
        archive = self.parent / 'source.zip'
        release.build(self.root, archive)
        with zipfile.ZipFile(archive) as zipped:
            self.assertNotIn('2shell-detector/clients.txt', zipped.namelist())

    def test_repository_check_rejects_extra_tracked_files(self):
        self.track_release()
        for name in ('private-client.txt', 'private client.txt', 'private\nclient.txt'):
            with self.subTest(name=name):
                (self.root / name).write_text('synthetic private fixture')
                self.git('add', '--', name)
                with self.assertRaises(ValueError) as raised:
                    release.verified_repository(self.root)
                self.assertNotIn(name, str(raised.exception))
                self.git('rm', '--cached', '--', name)

    def test_repository_check_rejects_force_added_ignored_report(self):
        (self.root / '.gitignore').write_text('twoshell-reports-*/\n')
        self.entries.append({'path': '.gitignore', 'sha256':
                             hashlib.sha256((self.root / '.gitignore').read_bytes()).hexdigest()})
        self.save()
        self.track_release()
        report = self.root / 'twoshell-reports-fixture/summary.json'
        report.parent.mkdir()
        report.write_text('{"target":"https://client.example.invalid/"}')
        self.git('add', '--force', '--', str(report))
        with self.assertRaises(ValueError):
            release.verified_repository(self.root)

    def test_repository_check_rejects_missing_tracked_source(self):
        self.track_release()
        self.git('rm', '--cached', '--', 'README.md')
        with self.assertRaises(ValueError):
            release.verified_repository(self.root)

    def test_repository_check_rejects_enclosing_repository(self):
        subprocess.run(['git', '-C', str(self.parent), '-c', 'init.templateDir=', 'init', '--quiet'],
                       check=True, capture_output=True)
        with self.assertRaises(ValueError):
            release.verified_repository(self.root)

    def test_repository_check_requires_git_checkout(self):
        with self.assertRaises(ValueError):
            release.verified_repository(self.root)
        self.assertEqual(set(release.verified_files(self.root)), release.REQUIRED | {release.MANIFEST})

    def test_default_report_directories_are_ignored(self):
        self.track_release()
        (self.root / '.gitignore').write_bytes((release.ROOT / '.gitignore').read_bytes())
        for path in ('twoshell-reports-20261028T000000Z-example/summary.json',
                     'nested/twoshell-reports-20261028T000000Z-example/summary.json'):
            with self.subTest(path=path):
                self.assertEqual(self.git('check-ignore', '--', path).decode().strip(), path)

    def test_unlisted_private_files_and_git_history_are_excluded(self):
        (self.root / 'clients.txt').write_text('private fixture')
        (self.root / '.git').mkdir()
        (self.root / '.git/config').write_text('private remote fixture')
        archive = self.parent / 'source.zip'
        release.build(self.root, archive)
        with zipfile.ZipFile(archive) as zipped:
            self.assertEqual(set(zipped.namelist()),
                             {'2shell-detector/' + name for name in release.REQUIRED | {release.MANIFEST}})

    def test_modified_source_rejected_before_output(self):
        (self.root / 'twoshell.py').write_text('modified source')
        archive = self.parent / 'source.zip'
        with self.assertRaises(ValueError):
            release.build(self.root, archive)
        self.assertFalse(archive.exists())

    def test_unsafe_paths_rejected(self):
        for name in ('../private', '/tmp/private', 'a/../../private', '.git/config',
                     'a/.git/config', 'a//b', './a', 'a\\b', 'C:/private'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                release.checked_path(self.root, name)

    def test_symlink_file_and_directory_rejected(self):
        (self.parent / 'private').write_text('private fixture')
        (self.root / 'link').symlink_to(self.parent / 'private')
        (self.root / 'dirlink').symlink_to(self.parent, target_is_directory=True)
        for name in ('link', 'dirlink/private'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                release.checked_path(self.root, name)

    def test_existing_archive_not_overwritten(self):
        archive = self.parent / 'source.zip'
        archive.write_bytes(b'previous artifact')
        with self.assertRaises(FileExistsError):
            release.build(self.root, archive)
        self.assertEqual(archive.read_bytes(), b'previous artifact')

    def test_refresh_does_not_add_unlisted_files(self):
        (self.root / 'twoshell.py').write_text('reviewed edit')
        (self.root / 'clients.txt').write_text('private fixture')
        release.refresh(self.root)
        self.assertEqual(set(release.verified_files(self.root)), release.REQUIRED | {release.MANIFEST})

    def test_duplicate_or_missing_required_file_rejected(self):
        original = list(self.entries)
        for entries in (original + original[:1], original[1:]):
            self.entries = entries
            self.save()
            with self.assertRaises(ValueError):
                release.verified_files(self.root)

    def test_archive_is_reproducible(self):
        first, second = self.parent / 'first.zip', self.parent / 'second.zip'
        release.build(self.root, first)
        release.build(self.root, second)
        self.assertEqual(first.read_bytes(), second.read_bytes())


if __name__ == '__main__':
    unittest.main()
