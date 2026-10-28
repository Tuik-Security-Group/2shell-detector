# SPDX-License-Identifier: LGPL-3.0-only
# Copyright (c) 2026 Tuik Security Group
"""Batch regressions use only loopback fixtures and temporary report folders."""
import contextlib
import csv
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock
from http.server import ThreadingHTTPServer

import twoshell
from fixture_server import FixtureHandler


class BatchHandler(FixtureHandler):
    def do_GET(self):
        self.server.events.append((self.server.server_port, "GET", self.path))
        if self.server.fail_health and self.server.posted:
            self.send_error(503)
            return
        super().do_GET()

    def do_POST(self):
        self.server.events.append((self.server.server_port, "POST", self.path))
        self.server.posted = True
        super().do_POST()

    def log_message(self, *args):
        pass


class BatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers, cls.threads = [], []
        cls.events = []
        for _ in range(2):
            server = ThreadingHTTPServer(("127.0.0.1", 0), BatchHandler)
            server.events = cls.events
            server.fail_health = server.posted = False
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            cls.servers.append(server)
            cls.threads.append(thread)
        cls.one, cls.two = ["http://127.0.0.1:%d" % s.server_port for s in cls.servers]

    @classmethod
    def tearDownClass(cls):
        for server, thread in zip(cls.servers, cls.threads):
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def setUp(self):
        self.events.clear()
        for server in self.servers:
            server.posted = server.fail_health = False
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.urls = self.root / "clients.txt"
        self.out = self.root / "reports"

    def run_batch(self, urls=None, flags=()):
        self.urls.write_text(urls or self.one + "/patched\n", encoding="utf-8")
        args = ["--urls-file", str(self.urls), "--output-dir", str(self.out),
                "--site-interval", "0", "--request-interval", "0", "--json"] + list(flags)
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = twoshell.main(args)
        self.stderr = stderr.getvalue()
        return code, json.loads(stdout.getvalue()) if stdout.getvalue() else None

    def load_site(self, row):
        return json.loads((self.out / row["report_file"]).read_text())

    def test_two_origins_sequential_reports_and_finding_summary(self):
        code, summary = self.run_batch(self.one + "/vulnerable\n" + self.two + "/patched\n",
                                       ["--active", "--max-requests", "7"])
        self.assertEqual(code, 1)
        self.assertTrue(summary["all_targets_scanned"])
        self.assertEqual(summary["counts"]["targets_with_findings"], 1)
        self.assertEqual(summary["limits"]["request_upper_bound"], 14)
        for row in summary["targets"]:
            report = self.load_site(row)
            self.assertLessEqual(report["request_count"], 7)
            self.assertEqual(len(report["health_checks"]), report["active_request_count"])
            self.assertTrue(all(h["healthy"] for h in report["health_checks"]))
            self.assertEqual(report["results"][-1]["status"], "unknown")
        ports = [event[0] for event in self.events]
        self.assertEqual(ports, sorted(ports, key=lambda port: port != self.servers[0].server_port))
        with (self.out / "summary.csv").open() as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["CVE-2025-55182"], "vulnerable")
        self.assertEqual(rows[1]["CVE-2025-55182"], "no vulnerability detected")
        self.assertEqual(rows[1]["CVE-2025-55182 status"], "unknown")
        self.assertEqual(rows[1]["CVE-2026-111497"], "not assessed")
        self.assertEqual(rows[1]["CVE-2026-111497 status"], "unknown")
        self.assertEqual(rows[0]["CVE-2025-55182 detection"], "vulnerability detected")
        self.assertEqual(rows[1]["CVE-2025-55182 detection"], "no vulnerability detected")
        self.assertEqual(rows[1]["CVE-2025-55182 applicability"], "unknown")
        self.assertEqual(rows[1]["CVE-2025-55182 applicability basis"], "unverified")
        item = summary["targets"][1]["results"][2]
        self.assertEqual(item["detection"]["result"], rows[1]["CVE-2025-55182 detection"])
        self.assertEqual(item["coverage_summary"], rows[1]["CVE-2025-55182 coverage summary"])
        self.assertEqual(json.loads((self.out / "summary.json").read_text()), summary)
        self.assertEqual((self.out / "remaining.txt").read_text(), "")

    def test_one_hundred_urls_end_to_end(self):
        targets = [self.one + "/client-%03d" % index for index in range(100)]
        code, summary = self.run_batch("\n".join(targets))
        self.assertEqual(code, 3)
        self.assertEqual(summary["counts"]["targets_completed"], 100)
        self.assertEqual(summary["counts"]["request_count"], 100)
        self.assertEqual(summary["counts"]["active_request_count"], 0)
        self.assertEqual(len(self.events), 100)
        self.assertEqual([row["url"] for row in summary["targets"]], targets)
        self.assertEqual(len({row["report_file"] for row in summary["targets"]}), 100)
        for row in summary["targets"]:
            self.assertEqual(self.load_site(row)["url"], row["url"])

    def test_bom_comments_blanks_and_duplicates(self):
        code, summary = self.run_batch("\ufeff# Client websites\n\n" + self.one + "/patched\n" +
                                       self.one + "/patched\n  " + self.two + "/patched  \n")
        self.assertEqual(code, 3)
        self.assertEqual(summary["duplicate_entries_skipped"], 1)
        self.assertEqual(len(self.events), 2)

    def test_canonical_equivalent_urls_are_deduplicated(self):
        self.urls.write_text("https://EXAMPLE.invalid:443\nhttps://example.invalid/\n")
        urls, count = twoshell.load_urls(self.urls)
        self.assertEqual(urls, ["https://example.invalid/"])
        self.assertEqual(count, 1)

    def test_bad_later_line_rejects_entire_list_before_network(self):
        for bad in ("client.example", "ftp://example.invalid/", "https://user:secret@example.invalid/",
                    "https://example.invalid/?token=secret", "https://example.invalid/#fragment",
                    "https://example.invalid/\\x", "https://[", "https://example.invalid:0/"):
            with self.subTest(bad=bad), self.assertRaises(SystemExit):
                self.run_batch(self.one + "/patched\n" + bad)
        self.assertEqual(self.events, [])
        self.assertFalse(self.out.exists())

    def test_empty_oversized_and_too_many_entries(self):
        for data in (b"# empty\n", b"#" * (twoshell.URLS_FILE_LIMIT + 1), b"\xff",
                     (self.one + "/patched\n").encode() * 1001):
            self.urls.write_bytes(data)
            with self.assertRaises((ValueError, UnicodeError)):
                twoshell.load_urls(self.urls)
        self.assertEqual(self.events, [])

    def test_incompatible_options_fail_before_requests(self):
        for flags in (["--inventory", "not-read.json"], ["--routes-file", "not-read.txt"],
                      ["--probe-path", "/app"], [self.one], ["--site-interval", "nan"],
                      ["--site-interval", "61"], ["--max-requests", "0"]):
            with self.subTest(flags=flags), self.assertRaises(SystemExit):
                self.run_batch(flags=flags)
        self.assertEqual(self.events, [])

    def test_existing_output_directory_is_not_overwritten(self):
        self.out.mkdir()
        marker = self.out / "summary.json"
        marker.write_text("keep this report")
        code, _ = self.run_batch()
        self.assertEqual(code, 2)
        self.assertEqual(marker.read_text(), "keep this report")
        self.assertEqual(self.events, [])

    def test_health_alert_halts_entire_batch_and_preserves_pending(self):
        self.servers[0].fail_health = True
        code, summary = self.run_batch(self.one + "/vulnerable\n" + self.two + "/patched\n", ["--active"])
        self.assertEqual(code, 4)
        self.assertEqual(summary["state"], "stopped_health")
        self.assertEqual(summary["counts"]["targets_pending"], 1)
        self.assertEqual({event[0] for event in self.events}, {self.servers[0].server_port})
        self.assertEqual((self.out / "remaining.txt").read_text(), self.two + "/patched\n")
        self.assertTrue(self.load_site(summary["targets"][0])["possible_service_impact"])

    def test_block_quarantines_origin_but_continues_other_clients(self):
        code, summary = self.run_batch(self.one + "/waf\n" + self.one + "/vulnerable\n" +
                                       self.two + "/patched\n", ["--active"])
        self.assertEqual(code, 3)
        self.assertEqual(summary["targets"][1]["state"], "skipped_origin")
        self.assertEqual(summary["targets"][2]["state"], "completed")
        self.assertFalse(any(event[2] == "/vulnerable" for event in self.events))
        self.assertEqual((self.out / "remaining.txt").read_text(), "")
        self.assertFalse(summary["all_targets_scanned"])

    def test_unreachable_target_does_not_prevent_next_site(self):
        with socket.socket() as closed:
            closed.bind(("127.0.0.1", 0))
            port = closed.getsockname()[1]
        code, summary = self.run_batch("http://127.0.0.1:%d/\n%s/patched\n" % (port, self.two))
        self.assertEqual(code, 2)
        self.assertEqual(summary["counts"]["targets_completed"], 2)
        self.assertEqual(summary["counts"]["targets_with_network_errors"], 1)
        self.assertFalse(self.load_site(summary["targets"][0])["reachable"])
        self.assertEqual(summary["targets"][0]["results"][0]["outcome"], "not assessed")

    def test_batch_discovery_retains_exact_origin_scope(self):
        code, summary = self.run_batch(self.one + "/external-redirect\n" + self.two + "/entry\n",
                                       ["--discover", "--react-probe"])
        self.assertEqual(code, 1)
        self.assertEqual(self.load_site(summary["targets"][0])["active_request_count"], 0)
        self.assertEqual(self.load_site(summary["targets"][1])["results"][2]["status"], "vulnerable")

    def test_interrupt_saves_completed_work_and_marks_current_uncertain(self):
        scan = twoshell.scan_target
        calls = []
        def interrupt_second(*args, **kwargs):
            calls.append(args[1])
            if len(calls) == 2:
                raise KeyboardInterrupt()
            return scan(*args, **kwargs)
        with mock.patch.object(twoshell, "scan_target", side_effect=interrupt_second):
            code, summary = self.run_batch(self.one + "/patched\n" + self.two + "/patched\n" + self.two + "/rsc\n")
        self.assertEqual(code, 130)
        self.assertEqual([r["state"] for r in summary["targets"]], ["completed", "interrupted", "pending"])
        self.assertFalse(summary["counts"]["request_counts_complete"])
        self.assertTrue((self.out / summary["targets"][0]["report_file"]).is_file())
        self.assertEqual((self.out / "remaining.txt").read_text(), self.two + "/rsc\n")

    def test_storage_failure_before_scan_sends_no_requests(self):
        with mock.patch.object(twoshell, "write_json_report", side_effect=OSError("disk full")):
            code, _ = self.run_batch()
        self.assertEqual(code, 2)
        self.assertEqual(self.events, [])

    def test_storage_failure_after_first_scan_stops_next_site(self):
        write = twoshell.write_json_report
        def fail_site(path, value):
            if path.name != "summary.json":
                raise OSError("disk full")
            return write(path, value)
        with mock.patch.object(twoshell, "write_json_report", side_effect=fail_site):
            code, _ = self.run_batch(self.one + "/patched\n" + self.two + "/patched\n")
        self.assertEqual(code, 2)
        self.assertEqual(len(self.events), 1)

    def test_atomic_failure_preserves_previous_checkpoint(self):
        path = self.root / "checkpoint.json"
        path.write_text("previous")
        def fail(stream):
            stream.write("incomplete")
            raise OSError("disk full")
        with self.assertRaises(OSError):
            twoshell.atomic_report(path, fail)
        self.assertEqual(path.read_text(), "previous")
        self.assertEqual(list(self.root.glob(".writing-*")), [])

    def test_site_interval_applies_between_completed_targets(self):
        with mock.patch.object(twoshell.time, "sleep") as sleep:
            self.run_batch(self.one + "/patched\n" + self.two + "/patched\n", ["--site-interval", "0.5"])
        sleep.assert_called_once_with(0.5)

    def test_cli_json_is_parseable_and_progress_goes_to_stderr(self):
        self.urls.write_text(self.one + "/patched\n" + self.two + "/patched\n")
        process = subprocess.run([sys.executable, str(Path(twoshell.__file__)),
            "--urls-file", str(self.urls), "--output-dir", str(self.out), "--json",
            "--site-interval", "0", "--request-interval", "0"],
            capture_output=True, text=True, timeout=15)
        self.assertEqual(process.returncode, 3)
        summary = json.loads(process.stdout)
        self.assertEqual(summary["counts"]["targets_completed"], 2)
        self.assertIn("[1/2]", process.stderr)
        self.assertIn("[2/2]", process.stderr)
        self.assertEqual(json.loads((self.out / "summary.json").read_text()), summary)


if __name__ == "__main__":
    unittest.main()
