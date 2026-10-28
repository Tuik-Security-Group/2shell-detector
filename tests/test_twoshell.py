#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
# Copyright (c) 2026 Tuik Security Group
"""Local fixture and version-rule checks; no code or crash payloads are generated."""

import contextlib
from datetime import datetime, timezone
import io
import gzip
import json
import shutil
import tempfile
import threading
import time
import unittest
from unittest import mock
from http.server import ThreadingHTTPServer
from pathlib import Path

import twoshell
from fixture_server import FixtureHandler


HERE = Path(__file__).resolve().parent
FIXTURE_EVIDENCE = {"source": "local_file", "source_ref": "fixture_evidence.json",
                    "artifact_digest": "sha256:7439bb85057cd5efe2da188ab23f9a271fd24bdad5257c9f6d46bdd3fc2a406d",
                    "observed_at": datetime.now(timezone.utc).isoformat()}


def fresh_inventory(name):
    data = json.loads((HERE / name).read_text())
    def refresh(item):
        if isinstance(item, dict):
            if item.get("source") == "local_file":
                item["observed_at"] = FIXTURE_EVIDENCE["observed_at"]
            for value in item.values():
                refresh(value)
        elif isinstance(item, list):
            for value in item:
                refresh(value)
    refresh(data)
    return data


class RecordedHandler(FixtureHandler):
    methods = []
    paths = []
    fail_health = False
    posted = False
    health_status = 503
    action_ids = []
    sample_candidates = 0
    sample_posts = 0

    def reply_sample(self, status, body, content_type="text/plain", encoding=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if encoding:
            self.send_header("Content-Encoding", encoding)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.methods.append("GET")
        self.paths.append(("GET", self.path))
        if self.path.startswith("/sampling-"):
            if self.path == "/sampling-health-later" and self.sample_posts >= 3:
                self.reply_sample(503, b"Unavailable")
            else:
                self.reply_sample(200, b"opaque" if self.path == "/sampling-opaque" else
                                  b"<html><script>self.__next_f=[]</script></html>", "text/html")
            return
        if self.fail_health and self.posted:
            self.send_error(self.health_status, "Simulated service health change")
            return
        if self.path == "/limited":
            self.send_error(429, "Simulated rate limit")
            return
        pages = {
            "/crawl": '<base href="/folder/"><a href="step#section">next</a><a href="/logout">logout</a><a href="/x?token=secret">query</a><a href="https://example.invalid/out">external</a><form action="/submit"></form>',
            "/folder/step": '<a href="/rsc">application</a><a href="/crawl">cycle</a>',
            "/crawl-php": '<a href="/vulnerable">PHP app</a>',
            "/many": ''.join('<a href="/fan/%d">app</a>' % i for i in range(12)),
            "/post-redirect": '<html>healthy</html>',
        }
        if self.path.startswith("/fan/"):
            pages[self.path] = '<script>self.__next_f=[]</script>'
        if self.path in pages:
            body = pages[self.path].encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/broken-chunks":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self.wfile.write(b"invalid-chunk-size\r\n")
            self.close_connection = True
            return
        if self.path == "/short-body":
            self.send_response(200)
            self.send_header("Content-Length", "100")
            self.end_headers()
            self.wfile.write(b"short")
            self.close_connection = True
            return
        if self.path == "/slow-body":
            self.send_response(200)
            self.send_header("Content-Length", "100")
            self.end_headers()
            try:
                for _ in range(100):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.05)
            except OSError:
                pass
            return
        return super().do_GET()

    def do_POST(self):
        self.methods.append("POST")
        self.paths.append(("POST", self.path))
        if self.path.startswith("/sampling-"):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            cls = type(self)
            cls.sample_posts += 1
            candidate = b'["$1:a:a"]' in body
            if candidate:
                cls.sample_candidates += 1
            if self.path == "/sampling-php":
                self.reply_sample(200, b"no warnings" if self.sample_posts == 1 else
                                  b"Session ID is too long or contains illegal characters\nFailed to read session data\nFailed to write session data (files)")
            elif self.path == "/sampling-block-later" and self.sample_candidates >= 2:
                self.reply_sample(403, b"Blocked")
            elif self.path == "/sampling-unreadable":
                self.reply_sample(500, b"unreadable", encoding="unsupported")
            elif self.path == "/sampling-mixed" and candidate and self.sample_candidates >= 2:
                self.reply_sample(500, b'1:E{"digest":"fixture"}\n', "text/x-component")
            elif self.path == "/sampling-generic" or (candidate and self.path in
                    ("/sampling-masked", "/sampling-masked-200", "/sampling-opaque", "/sampling-block-later", "/sampling-health-later")):
                self.reply_sample(500, b"Application error")
            elif self.path == "/sampling-masked-200" and not candidate:
                self.reply_sample(200, b"<html>__next_f</html>", "text/html")
            else:
                self.reply_sample(404, b"No such action")
            return
        if self.path == "/post-redirect":
            self.send_response(302)
            self.send_header("Location", "/rsc")
            self.end_headers()
            return
        if self.path.startswith("/fan/"):
            self.path = "/rsc"
        if self.headers.get("Next-Action"):
            self.action_ids.append(self.headers["Next-Action"])
        try:
            return super().do_POST()
        finally:
            type(self).posted = True

    def log_message(self, fmt, *args):
        pass


class TwoShellTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), RecordedHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        RecordedHandler.methods.clear()
        RecordedHandler.paths.clear()
        RecordedHandler.fail_health = False
        RecordedHandler.posted = False
        RecordedHandler.health_status = 503
        RecordedHandler.action_ids.clear()
        RecordedHandler.sample_candidates = 0
        RecordedHandler.sample_posts = 0

    def run_report(self, path, inventory_name=None, php_probe=False,
                   react_probe=False, active=False, discover=False, probe_paths=(), inventory_updates=None,
                   extra_args=(), routes_text=None):
        args = [self.base + path, "--json", "--request-interval", "0"] + list(extra_args)
        if php_probe:
            args.append("--php-probe")
        if react_probe:
            args.append("--react-probe")
        if active:
            args.append("--active")
        if discover:
            args.append("--discover")
        for probe_path in probe_paths:
            args.extend(["--probe-path", probe_path])
        with tempfile.TemporaryDirectory() as directory:
            if routes_text is not None:
                routes_path = Path(directory) / "routes.txt"
                routes_path.write_text(routes_text)
                args.extend(["--routes-file", str(routes_path)])
            if inventory_name:
                inventory = fresh_inventory(inventory_name)
                inventory["target_url"] = self.base + path
                inventory.update(inventory_updates or {})
                filename = Path(directory) / "inventory.json"
                filename.write_text(json.dumps(inventory))
                shutil.copyfile(HERE / "fixture_evidence.json", Path(directory) / "fixture_evidence.json")
                args.extend(["--inventory", str(filename)])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = twoshell.main(args)
            return code, json.loads(output.getvalue())

    def test_vulnerable_inventory(self):
        code, report = self.run_report("/vulnerable", "fixture_vulnerable.json")
        self.assertEqual(code, 1)
        self.assertEqual(len(report["results"]), 5)
        self.assertEqual({r["status"] for r in report["results"]}, {"vulnerable"})
        self.assertTrue(report["inventory_evidence"]["provenance_valid"])
        self.assertEqual(report["inventory_evidence"]["local_files_verified"], 1)
        self.assertEqual(RecordedHandler.methods, ["GET"])
        self.assertEqual({r["detection"]["result"] for r in report["results"]}, {"not assessed"})
        self.assertEqual({r["applicability"]["state"] for r in report["results"]}, {"applicable"})

    def test_patched_inventory(self):
        code, report = self.run_report("/patched", "fixture_patched.json")
        self.assertEqual(code, 0)
        self.assertEqual({r["status"] for r in report["results"]}, {"not vulnerable"})
        self.assertEqual({r["outcome"] for r in report["results"]}, {"not vulnerable"})
        self.assertEqual(RecordedHandler.methods, ["GET"])
        self.assertEqual({r["detection"]["result"] for r in report["results"]}, {"not assessed"})
        self.assertEqual({r["applicability"]["state"] for r in report["results"]}, {"applicable"})

    def test_absence_inventory_records_not_applicable_with_evidence(self):
        absent = {"php": {"present": False, "evidence": FIXTURE_EVIDENCE},
                  "react": {"present": False, "evidence": FIXTURE_EVIDENCE},
                  "brotli": {"present": False, "all_decoders_audited": True, "evidence": FIXTURE_EVIDENCE}}
        code, report = self.run_report("/patched", "fixture_patched.json", inventory_updates=absent)
        self.assertEqual(code, 0)
        for item in report["results"]:
            self.assertEqual(item["applicability"]["state"], "not_applicable")
            self.assertEqual(item["applicability"]["basis"], "deployment_inventory")
            self.assertEqual(item["detection"]["result"], "not assessed")
            self.assertEqual(item["status"], "not vulnerable")
        # A valid exclusion cannot silently spread to an additional URL.
        code, uncovered = self.run_report("/patched", "fixture_patched.json", inventory_updates=absent,
                                         probe_paths=("/unknown",))
        self.assertEqual(code, 3)
        self.assertEqual({r["applicability"]["state"] for r in uncovered["results"]}, {"unknown"})

    def test_incomplete_or_unverified_absence_does_not_exclude_technology(self):
        inventory = fresh_inventory("fixture_patched.json")
        inventory["php"] = {"present": False, "evidence": FIXTURE_EVIDENCE}
        inventory["deployment_evidence"]["all_instances_audited"] = False
        self.assertEqual(twoshell.assess(inventory)[0]["applicability"]["state"], "unknown")
        inventory["deployment_evidence"]["all_instances_audited"] = True
        inventory["php"].pop("evidence")
        self.assertEqual(twoshell.assess(inventory)[0]["applicability"]["state"], "unknown")

    def test_partial_failures_are_not_relabelled_as_negative_detections(self):
        completed = {"state": "completed_no_signature", "source": "landing", "http_status": 405}
        for state, reason, source in [("blocked", "baseline_http_403", "discovered"),
                                      ("error", "network_error", "discovered"),
                                      ("inconclusive", "unreadable_or_ambiguous_probe_response", "discovered"),
                                      ("skipped", "request_budget", "discovered"),
                                      ("skipped", "active_route_limit", "discovered"),
                                      ("skipped", "no_technology_indicator", "supplied")]:
            with self.subTest(state=state, reason=reason, source=source):
                item = twoshell.result("PHP2Shell", "CVE-2026-109618", "unknown", "No inventory")
                item["coverage"] = {"state": "partial", "routes": [completed, {"state": state, "reason": reason, "source": source}]}
                twoshell.attach_outcomes({"results": [item]})
                self.assertEqual(item["detection"]["result"], "inconclusive")
                self.assertEqual(item["outcome"], "inconclusive")
                self.assertEqual(item["applicability"]["state"], "unknown")

    def test_rejected_posts_display_no_detection_with_coverage_limit(self):
        code, report = self.run_report("/unknown", active=True)
        self.assertEqual(code, 3)
        self.assertEqual(RecordedHandler.methods, ["GET", "POST", "GET", "POST", "GET"])
        for item in report["results"][:4]:
            self.assertEqual(item["outcome"], "no vulnerability detected")
            self.assertEqual(item["status"], "unknown")
            self.assertIn("HTTP 405", item["outcome_reason"])
            self.assertIn("patch status unverified", item["outcome_reason"])
        self.assertEqual(report["results"][-1]["outcome"], "not assessed")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            twoshell.print_report(report, False)
        self.assertIn("NO VULNERABILITY DETECTED", out.getvalue())
        self.assertIn("Detection:", out.getvalue())
        self.assertIn("Coverage: LIMITED", out.getvalue())
        self.assertIn("Applicability: UNKNOWN", out.getvalue())
        self.assertNotIn("): UNKNOWN", out.getvalue())

    def test_negative_probe_with_health_failure_is_inconclusive(self):
        RecordedHandler.fail_health = True
        code, report = self.run_report("/patched", active=True)
        self.assertEqual(code, 4)
        self.assertEqual(report["results"][0]["outcome"], "inconclusive")
        self.assertTrue(all(item["outcome"] != "no vulnerability detected" for item in report["results"]))
        self.assertTrue(all(item["detection"]["result"] != "no vulnerability detected" for item in report["results"]))

    def test_partial_negative_and_blocked_coverage_is_inconclusive(self):
        code, report = self.run_report("/patched", active=True, probe_paths=("/waf",))
        self.assertEqual(code, 3)
        self.assertEqual(report["results"][0]["coverage"]["state"], "partial")
        self.assertEqual(report["results"][0]["outcome"], "inconclusive")

    def test_url_only_is_unknown_even_with_version_header(self):
        code, report = self.run_report("/vulnerable")
        self.assertEqual(code, 3)
        self.assertEqual({r["status"] for r in report["results"]}, {"unknown"})
        self.assertEqual(RecordedHandler.methods, ["GET"])

    def test_opt_in_php_probe_matches_only_unpatched_warning_sequence(self):
        code, report = self.run_report("/vulnerable", php_probe=True)
        self.assertEqual(code, 1)
        self.assertTrue(report["php_probe"]["positive"])
        self.assertEqual([r["status"] for r in report["results"][:2]],
                         ["vulnerable", "vulnerable"])
        self.assertEqual({r["status"] for r in report["results"][2:]}, {"unknown"})
        self.assertEqual(RecordedHandler.methods, ["GET", "POST", "GET"])

        RecordedHandler.methods.clear()
        code, report = self.run_report("/patched", php_probe=True)
        self.assertEqual(code, 3)
        self.assertFalse(report["php_probe"]["positive"])
        self.assertEqual({r["status"] for r in report["results"]}, {"unknown"})
        self.assertEqual(RecordedHandler.methods, ["GET", "POST", "GET"])

    def test_opt_in_react_probe_uses_digest_signature(self):
        code, report = self.run_report("/vulnerable", react_probe=True)
        self.assertEqual(code, 1)
        self.assertTrue(report["react_probe"]["positive"])
        self.assertEqual(report["react_probe"]["control"]["http_status"], 404)
        self.assertFalse(report["possible_service_impact"])
        self.assertEqual([r["status"] for r in report["results"][2:4]],
                         ["vulnerable", "vulnerable"])
        self.assertEqual(report["results"][2]["detection"]["result"], "vulnerability detected")
        self.assertEqual(report["results"][2]["applicability"]["basis"], "behavioral_signature")
        self.assertEqual(RecordedHandler.methods, ["GET", "POST", "GET", "POST", "GET"])

        RecordedHandler.methods.clear()
        code, report = self.run_report("/patched", react_probe=True)
        self.assertEqual(code, 3)
        self.assertFalse(report["react_probe"]["positive"])
        self.assertEqual({r["status"] for r in report["results"]}, {"unknown"})
        self.assertEqual(RecordedHandler.methods, ["GET", "POST", "GET"])

    def test_generic_digest_error_does_not_confirm_react(self):
        code, report = self.run_report("/generic-error", react_probe=True)
        self.assertEqual(code, 3)
        self.assertTrue(report["react_probe"]["candidate_signature"])
        self.assertFalse(report["react_probe"]["positive"])
        self.assertEqual(report["react_probe"]["control"]["http_status"], 500)
        self.assertEqual(RecordedHandler.methods, ["GET", "POST", "GET", "POST", "GET"])

    def test_native_broad_digest_pattern_requires_benign_control(self):
        code, report = self.run_report("/broad-error", react_probe=True)
        self.assertEqual(code, 1)
        self.assertTrue(report["react_probe"]["positive"])
        self.assertEqual(report["react_probe"]["signature"], "error_and_digest")
        self.assertEqual(report["react_probe"]["control"]["http_status"], 404)
        self.assertEqual(RecordedHandler.methods, ["GET", "POST", "GET", "POST", "GET"])

    def test_generic_broad_digest_error_does_not_confirm_react(self):
        code, report = self.run_report("/generic-broad-error", react_probe=True)
        self.assertEqual(code, 3)
        self.assertTrue(report["react_probe"]["candidate_signature"])
        self.assertFalse(report["react_probe"]["positive"])
        self.assertEqual(report["react_probe"]["signature"], "error_and_digest")
        self.assertEqual(report["react_probe"]["control"]["http_status"], 500)

    def test_active_runs_both_bounded_probes_and_health_checks(self):
        code, report = self.run_report("/vulnerable", active=True)
        self.assertEqual(code, 1)
        self.assertEqual(RecordedHandler.methods,
                         ["GET", "POST", "GET", "POST", "GET", "POST", "GET"])
        self.assertEqual(len(report["health_checks"]), 3)
        self.assertEqual(report["active_request_count"], 3)
        self.assertEqual([r["status"] for r in report["results"][:4]],
                         ["vulnerable"] * 4)
        self.assertEqual(report["results"][4]["status"], "unknown")

    def test_health_failure_stops_second_probe(self):
        RecordedHandler.fail_health = True
        code, report = self.run_report("/vulnerable", active=True)
        self.assertEqual(code, 4)
        self.assertTrue(report["possible_service_impact"])
        self.assertFalse(report["react_probe"]["attempted"])
        self.assertEqual(RecordedHandler.methods, ["GET", "POST", "GET"])

    def test_unhealthy_baseline_skips_active_probes(self):
        RecordedHandler.fail_health = True
        RecordedHandler.posted = True
        code, report = self.run_report("/vulnerable", active=True)
        self.assertEqual(code, 3)
        self.assertFalse(report["php_probe"]["attempted"])
        self.assertFalse(report["react_probe"]["attempted"])
        self.assertEqual(RecordedHandler.methods, ["GET"])

    def test_missing_backport_status_is_unknown(self):
        inventory = fresh_inventory("fixture_vulnerable.json")
        del inventory["php"]["vendor_patch"]
        self.assertEqual(twoshell.assess(inventory)[0]["status"], "unknown")

    def test_brotli_requires_complete_inventory_for_clean_result(self):
        brotli = {"evidence": FIXTURE_EVIDENCE, "decoders": [{"name": "edge", "implementation": "google-brotli-c",
                                "version": "1.2.1", "decodes_untrusted_data": True,
                                "evidence": FIXTURE_EVIDENCE}]}
        self.assertEqual(twoshell.assess_brotli(brotli)["status"], "unknown")
        brotli["all_decoders_audited"] = True
        self.assertEqual(twoshell.assess_brotli(brotli)["status"], "not vulnerable")
        self.assertEqual(twoshell.assess_brotli({"present": False, "evidence": FIXTURE_EVIDENCE})["status"], "unknown")
        self.assertEqual(twoshell.assess_brotli({"all_decoders_audited": True,
                                                  "decoders": [], "evidence": FIXTURE_EVIDENCE})["status"], "unknown")

    def test_brotli_detects_vulnerable_copy_among_multiple_decoders(self):
        brotli = {"all_decoders_audited": True, "evidence": FIXTURE_EVIDENCE, "decoders": [
            {"name": "patched edge", "implementation": "google-brotli-c",
             "version": "1.2.1", "decodes_untrusted_data": True, "evidence": FIXTURE_EVIDENCE},
            {"name": "app runtime", "implementation": "dotnet-brotli",
             "version": "10.0.13", "decodes_untrusted_data": True,
             "vendor_patch": False, "evidence": FIXTURE_EVIDENCE}]}
        finding = twoshell.assess_brotli(brotli)
        self.assertEqual(finding["status"], "vulnerable")
        self.assertIn("app runtime", finding["reason"])
        brotli["decoders"][1]["version"] = "10.0.14"
        self.assertEqual(twoshell.assess_brotli(brotli)["status"], "not vulnerable")

    def test_node_runtime_brotli_boundary(self):
        brotli = {"all_decoders_audited": True, "evidence": FIXTURE_EVIDENCE, "decoders": [
            {"name": "Node runtime", "implementation": "nodejs-brotli",
             "version": "22.23.3", "decodes_untrusted_data": True,
             "vendor_patch": False, "evidence": FIXTURE_EVIDENCE}]}
        self.assertEqual(twoshell.assess_brotli(brotli)["status"], "vulnerable")
        brotli["decoders"][0]["version"] = "22.23.4"
        self.assertEqual(twoshell.assess_brotli(brotli)["status"], "not vulnerable")

    def test_inventory_requires_deployment_and_component_provenance(self):
        inventory = fresh_inventory("fixture_patched.json")
        del inventory["deployment_evidence"]
        self.assertEqual({item["status"] for item in twoshell.assess(inventory)}, {"unknown"})
        inventory["deployment_evidence"] = {**FIXTURE_EVIDENCE, "all_instances_audited": True,
                                            "deployment_id": "synthetic-test",
                                            "running_artifact": FIXTURE_EVIDENCE["artifact_digest"]}
        del inventory["php"]["evidence"]
        self.assertEqual(twoshell.assess(inventory)[0]["status"], "unknown")
        stale = dict(FIXTURE_EVIDENCE, observed_at="2025-01-01T00:00:00Z")
        self.assertFalse(twoshell.evidence_valid(stale))

    def test_tampered_local_evidence_is_rejected_before_network_request(self):
        inventory = fresh_inventory("fixture_patched.json")
        inventory["target_url"] = self.base + "/patched"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inventory.json"
            path.write_text(json.dumps(inventory))
            (Path(directory) / "fixture_evidence.json").write_text("tampered")
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    twoshell.main([self.base + "/patched", "--inventory", str(path)])
        self.assertEqual(error.exception.code, 2)
        self.assertEqual(RecordedHandler.methods, [])

    def test_non_next_rsc_inventory_is_assessed_separately(self):
        inventory = fresh_inventory("fixture_vulnerable.json")
        inventory["react"].update({"framework": "waku", "next_app_router": False})
        self.assertEqual(twoshell.assess(inventory)[2]["status"], "vulnerable")
        self.assertEqual(twoshell.assess(inventory)[3]["status"], "not vulnerable")

    def test_multiple_rsc_copies_require_complete_audit(self):
        inventory = fresh_inventory("fixture_patched.json")
        inventory["react"].pop("rsc_package")
        inventory["react"]["rsc_components"] = [
            {"present": True, "rsc_package": "react-server-dom-webpack",
             "rsc_version": "19.2.1", "rsc_exposed": True, "evidence": FIXTURE_EVIDENCE},
            {"present": True, "rsc_package": "react-server-dom-parcel",
             "rsc_version": "19.2.0", "rsc_exposed": True,
             "rsc_vendor_patch": False, "evidence": FIXTURE_EVIDENCE}]
        self.assertEqual(twoshell.assess(inventory)[2]["status"], "vulnerable")
        inventory["react"]["rsc_components"][1]["rsc_version"] = "19.2.1"
        self.assertEqual(twoshell.assess(inventory)[2]["status"], "not vulnerable")
        inventory["react"]["all_rsc_packages_audited"] = False
        self.assertEqual(twoshell.assess(inventory)[2]["status"], "unknown")

    def test_same_origin_redirect_and_discovered_rsc_route(self):
        code, report = self.run_report("/redirect", react_probe=True, discover=True)
        self.assertEqual(code, 1)
        self.assertEqual(report["effective_url"], self.base + "/entry")
        self.assertEqual(len(report["discovered_routes"]), 1)
        self.assertEqual(report["discovered_routes"][0]["url"], self.base + "/rsc")
        self.assertEqual(report["active_request_count"], 3)
        self.assertEqual(report["results"][2]["confidence"], "behavioral_positive")
        self.assertEqual(RecordedHandler.methods.count("POST"), 3)

    def test_external_redirect_is_not_followed(self):
        code, report = self.run_report("/external-redirect", discover=True, react_probe=True)
        self.assertEqual(code, 3)
        self.assertEqual(report["active_request_count"], 0)
        self.assertEqual(RecordedHandler.methods, ["GET"])

    def test_redirect_hop_cap_never_posts_to_unfetched_destination(self):
        code, report = self.run_report("/chain-1", discover=True, react_probe=True)
        self.assertEqual(code, 3)
        self.assertEqual(report["active_request_count"], 0)
        self.assertEqual(RecordedHandler.methods, ["GET", "GET", "GET"])

    def test_synthetic_waf_block_leaves_negative_probe_unknown(self):
        code, report = self.run_report("/waf", active=True)
        self.assertEqual(code, 3)
        self.assertEqual({item["status"] for item in report["results"]}, {"unknown"})
        self.assertEqual(report["php_probe"]["http_status"], 403)
        self.assertEqual(report["results"][0]["outcome"], "blocked")
        self.assertFalse(report["react_probe"]["attempted"])
        self.assertIn("block", report["active_stop_reason"])
        self.assertEqual(RecordedHandler.methods, ["GET", "POST", "GET"])
        self.assertFalse(report["possible_service_impact"])

    def test_explicit_safe_path_is_probed_and_evidence_is_redacted(self):
        code, report = self.run_report("/entry", react_probe=True, probe_paths=("/rsc",))
        self.assertEqual(code, 1)
        self.assertEqual(report["route_probes"][1]["react_probe"]["positive"], True)
        self.assertTrue(all("PHPSESSID" not in json.dumps(item) for item in report["request_evidence"]))
        record = twoshell.evidence_record(
            type("Request", (), {"get_method": lambda self: "GET",
                                 "full_url": "https://example.test/path?secret=123"})(),
            {"http_status": 200, "body_sha256": "abc", "body_bytes_captured": 3})
        self.assertNotIn("secret=123", json.dumps(record))

    def test_query_string_is_redacted_and_never_posted(self):
        code, report = self.run_report("/vulnerable?token=private", active=True)
        self.assertEqual(code, 3)
        self.assertEqual(report["url"], self.base + "/vulnerable?[redacted]")
        self.assertEqual(report["active_request_count"], 0)
        self.assertNotIn("private", json.dumps(report))
        self.assertEqual(RecordedHandler.methods, ["GET"])

    def test_inventory_for_other_url_is_rejected_before_network_request(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                twoshell.main([self.base + "/patched", "--inventory",
                                 str(HERE / "fixture_vulnerable.json")])
        self.assertEqual(error.exception.code, 2)
        self.assertEqual(RecordedHandler.methods, [])

    def test_discovery_budget_counts_discarded_redirects(self):
        baseline = {"reachable": True, "http_status": 200, "headers": {},
                    "body": "".join(f'<a href="/route-{i}">link</a>' for i in range(20))}
        with mock.patch.object(twoshell, "fetch_with_redirects",
                side_effect=lambda url, *args, **kwargs: (url + "?login=1", baseline)) as fetcher:
            self.assertEqual(twoshell.discover_routes(self.base, baseline, 1, limit=3), [])
        self.assertEqual(fetcher.call_count, 3)

    def test_malformed_discovered_url_does_not_crash(self):
        baseline = {"reachable": True, "http_status": 200, "headers": {},
                    "body": '<a href="http://[invalid">broken</a>'}
        self.assertEqual(twoshell.discover_routes(self.base, baseline, 1), [])
        with mock.patch.object(twoshell, "fetch", return_value={
                **baseline, "http_status": 302, "headers": {"location": "http://[invalid"}}):
            url, response = twoshell.fetch_with_redirects(self.base, 1)
        self.assertEqual(url, self.base)
        self.assertEqual(response["http_status"], 302)

    def test_redirect_loop_keeps_response_associated_with_fetched_url(self):
        with mock.patch.object(twoshell, "fetch", side_effect=[
                {"reachable": True, "http_status": 302, "headers": {"location": "/b"}},
                {"reachable": True, "http_status": 302, "headers": {"location": "/a"}}]) as fetcher:
            url, _ = twoshell.fetch_with_redirects(self.base + "/a", 1)
        self.assertEqual(url, self.base + "/b")
        self.assertEqual(fetcher.call_count, 2)

    def test_broken_http_responses_return_network_error_without_traceback(self):
        for path in ("/broken-chunks", "/short-body"):
            with self.subTest(path=path):
                code, report = self.run_report(path, active=True)
                self.assertEqual(code, 2)
                self.assertFalse(report["reachable"])
                self.assertEqual(report["active_request_count"], 0)

    def test_slow_body_is_limited_by_total_request_deadline(self):
        started = time.monotonic()
        response = twoshell.fetch(self.base + "/slow-body", 0.5)
        self.assertLess(time.monotonic() - started, 2.5)
        self.assertFalse(response["reachable"])
        self.assertEqual(response["error"], "request_deadline_exceeded")

    def test_gzip_probe_responses_are_detected_and_decoding_is_bounded(self):
        code, report = self.run_report("/gzip-vulnerable", active=True)
        self.assertEqual(code, 1)
        self.assertEqual([item["status"] for item in report["results"][:4]], ["vulnerable"] * 4)
        decoded, truncated, error = twoshell.decode_response(gzip.compress(b"a" * 1_000_000), "gzip")
        self.assertEqual(len(decoded), twoshell.BODY_LIMIT)
        self.assertTrue(truncated)
        self.assertIsNone(error)
        self.assertEqual(twoshell.decode_response(b"invalid", "gzip")[2], "invalid_compressed_response")

    def test_rate_limited_baseline_never_gets_a_post(self):
        code, report = self.run_report("/limited", active=True)
        self.assertEqual(code, 3)
        self.assertEqual(report["active_request_count"], 0)
        self.assertEqual(RecordedHandler.methods, ["GET"])

    def test_changed_health_status_stops_remaining_routes(self):
        RecordedHandler.fail_health = True
        RecordedHandler.health_status = 429
        code, report = self.run_report("/vulnerable", active=True, probe_paths=("/patched",))
        self.assertEqual(code, 4)
        self.assertTrue(report["possible_service_impact"])
        self.assertEqual(RecordedHandler.methods.count("POST"), 1)

    def test_failed_probe_stops_next_check_even_if_health_get_succeeds(self):
        baseline = {"reachable": True, "http_status": 200, "body": "healthy"}
        with mock.patch.object(twoshell, "php_warning_probe", return_value={
                "attempted": True, "positive": False, "error": "request_deadline_exceeded"}), \
             mock.patch.object(twoshell, "health_after_probe", return_value={"healthy": True}), \
             mock.patch.object(twoshell, "react_digest_probe") as react:
            report = twoshell.run_active_route(self.base, baseline, 1, True, True, [])
        react.assert_not_called()
        self.assertIsNotNone(report["active_stop_reason"])
        self.assertFalse(report["possible_service_impact"])

    def test_positive_extra_route_takes_precedence_over_failed_landing_url(self):
        code, report = self.run_report("/short-body", php_probe=True, probe_paths=("/vulnerable",))
        self.assertEqual(code, 1)
        self.assertEqual(report["results"][0]["status"], "vulnerable")

    def test_preexisting_broad_digest_does_not_become_a_finding(self):
        code, report = self.run_report("/preexisting-broad", react_probe=True)
        self.assertEqual(code, 3)
        self.assertFalse(report["react_probe"]["positive"])
        self.assertEqual(report["active_request_count"], 1)

    def test_react_candidate_and_control_reuse_the_same_action_id(self):
        self.run_report("/vulnerable", react_probe=True)
        self.assertEqual(len(RecordedHandler.action_ids), 2)
        self.assertEqual(RecordedHandler.action_ids[0], RecordedHandler.action_ids[1])

    def test_invalid_inventory_types_and_conflicting_claims_cannot_pass(self):
        mutations = [
            lambda data: data["react"].update(rsc_package=[]),
            lambda data: data["react"].update(rsc_components=[]),
            lambda data: data["react"].update(present=False),
            lambda data: data["brotli"]["decoders"][0].update(implementation=[]),
            lambda data: data["php"].update(present=False),
            lambda data: data["php"].update(vendor_patch="false")]
        for change in mutations:
            data = fresh_inventory("fixture_patched.json")
            change(data)
            with self.assertRaises(ValueError):
                twoshell.validate_inventory_schema(data)
            self.assertEqual({item["status"] for item in twoshell.assess(data)}, {"unknown"})

    def test_incomplete_instance_audit_preserves_known_vulnerable_component(self):
        data = fresh_inventory("fixture_vulnerable.json")
        data["deployment_evidence"]["all_instances_audited"] = False
        self.assertEqual(twoshell.assess(data)[0]["status"], "vulnerable")
        data = fresh_inventory("fixture_patched.json")
        data["deployment_evidence"]["all_instances_audited"] = False
        self.assertEqual({item["status"] for item in twoshell.assess(data)}, {"unknown"})

    def test_extra_route_cannot_inherit_an_unrelated_clean_inventory(self):
        code, report = self.run_report("/patched", "fixture_patched.json", probe_paths=("/unknown",))
        self.assertEqual(code, 3)
        self.assertEqual(report["inventory_uncovered_urls"], [self.base + "/unknown"])
        code, report = self.run_report("/patched", "fixture_patched.json", probe_paths=("/unknown",),
                                      inventory_updates={"covered_urls": [self.base + "/unknown"]})
        self.assertEqual(code, 0)

    def test_positive_probe_exposes_conflicting_inventory(self):
        code, report = self.run_report("/vulnerable", "fixture_patched.json", active=True)
        self.assertEqual(code, 1)
        self.assertTrue(all(item["evidence_conflict"] for item in report["results"][:4]))

    def test_duplicate_json_fields_and_unsafe_urls_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"php":{"present":true,"present":false}}')
            with self.assertRaises(ValueError):
                twoshell.load_inventory(path)
        for url in ("http://example.test/\npath", "http://@example.test/", "http://example.test:0/",
                    "http://example.test/with space", "http://example.test/\\path", "http://example.test/é"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                twoshell.validate_url(url)
        self.assertEqual(twoshell.parse_version("9" * 5000 + ".1.0"), None)

    def test_two_level_discovery_honors_base_and_ignores_action_links(self):
        code, report = self.run_report("/crawl", react_probe=True, discover=True)
        self.assertEqual(code, 1)
        self.assertEqual({row["url"] for row in report["discovered_routes"]},
                         {self.base + "/folder/step", self.base + "/rsc"})
        self.assertEqual(report["discovered_routes"][-1]["depth"], 2)
        paths = [path for _, path in RecordedHandler.paths]
        self.assertNotIn("/logout", paths)
        self.assertNotIn("/submit", paths)
        self.assertNotIn("/x?token=secret", paths)
        self.assertNotIn("secret", json.dumps(report))

    def test_discovery_does_not_reinterpret_external_base_as_internal(self):
        response = {"reachable": True, "http_status": 200, "headers": {},
                    "body": '<base href="https://example.invalid/"><a href="app">app</a>'}
        self.assertEqual(twoshell.discovered_links(self.base, response), [])

    def test_discovered_php_route_gets_enabled_php_probe(self):
        code, report = self.run_report("/crawl-php", php_probe=True, discover=True)
        self.assertEqual(code, 1)
        self.assertEqual(report["results"][0]["coverage"]["state"], "detected")
        self.assertEqual(report["route_probes"][-1]["url"], self.base + "/vulnerable")

    def test_imported_unlinked_routes_are_deduplicated_and_probed(self):
        code, report = self.run_report("/unknown", react_probe=True,
                                      routes_text="# approved paths\n/rsc\n" + self.base + "/rsc\n")
        self.assertEqual(code, 1)
        self.assertEqual(report["assessed_urls"], [self.base + "/unknown", self.base + "/rsc"])
        self.assertEqual(report["results"][2]["coverage"]["routes"][-1]["source"], "supplied")

    def test_routes_file_rejects_invalid_scope_before_any_request(self):
        bad_files = ["/rsc\nhttps://other.invalid/app", "//other.invalid/app", "/app?token=secret",
                     "/app#fragment", "relative/path", "/ta\tb", "/" + "x" * 66000,
                     "\n".join("/app%d" % i for i in range(11))]
        for content in bad_files:
            with self.subTest(content=content[:40]), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    self.run_report("/unknown", react_probe=True, routes_text=content)
                self.assertEqual(error.exception.code, 2)
        self.assertEqual(RecordedHandler.methods, [])

    def test_supplied_route_precedes_discovery_and_cap_is_reported(self):
        code, report = self.run_report("/entry", react_probe=True, discover=True,
                                      routes_text="/patched", extra_args=["--max-active-routes", "2"])
        self.assertEqual(code, 3)
        self.assertNotIn(("POST", "/rsc"), RecordedHandler.paths)
        coverage = report["results"][2]["coverage"]
        self.assertEqual(coverage["state"], "partial")
        self.assertEqual(coverage["routes"][-1]["reason"], "active_route_limit")

    def test_discovery_page_cap_reports_unfetched_links(self):
        code, report = self.run_report("/many", discover=True,
                                      extra_args=["--max-discovery-pages", "2"])
        self.assertEqual(report["request_count"], 3)
        self.assertEqual(len(report["discovered_routes"]), 2)
        self.assertEqual(len(report["skipped_discovery"]), 10)
        self.assertTrue(all(row["reason"] == "discovery_page_limit" for row in report["skipped_discovery"]))

    def test_total_budget_does_not_start_partial_probe_sequences(self):
        for cap, posts in [(1, 0), (4, 0), (5, 2)]:
            with self.subTest(cap=cap):
                RecordedHandler.methods.clear()
                code, report = self.run_report("/vulnerable", react_probe=True,
                                              extra_args=["--max-requests", str(cap)])
                self.assertLessEqual(report["request_count"], cap)
                self.assertEqual(RecordedHandler.methods.count("POST"), posts)
                self.assertEqual(len(report["health_checks"]), posts)
                self.assertFalse(report["possible_service_impact"])
                if not posts:
                    self.assertEqual(report["results"][2]["coverage"]["routes"][0]["reason"], "request_budget")

    def test_discovery_budget_reserves_health_and_controls(self):
        code, report = self.run_report("/many", react_probe=True, discover=True,
                                      extra_args=["--max-requests", "10", "--max-active-routes", "1"])
        self.assertLessEqual(report["request_count"], 10)
        self.assertEqual(report["active_request_count"], 1)
        self.assertEqual(len(report["health_checks"]), 1)
        self.assertFalse(report["possible_service_impact"])
        self.assertTrue(any(row["reason"] == "request_budget" for row in report["skipped_discovery"]))

    def test_budget_includes_redirect_hops_and_imported_urls(self):
        code, report = self.run_report("/chain-1", discover=True, routes_text="/rsc\n/patched",
                                      extra_args=["--max-requests", "3"])
        self.assertEqual(report["request_count"], 3)
        self.assertEqual(RecordedHandler.methods, ["GET"] * 3)
        self.assertEqual(report["limits"]["requests_remaining"], 0)

    def test_coverage_distinguishes_disabled_unsupported_and_negative(self):
        _, report = self.run_report("/patched", php_probe=True)
        self.assertEqual(report["results"][0]["coverage"]["state"], "completed_no_signature")
        self.assertEqual(report["results"][2]["coverage"]["state"], "not_enabled")
        self.assertEqual(report["results"][4]["coverage"]["state"], "no_supported_remote_check")
        self.assertTrue(all(not item["coverage"]["negative_is_clearance"] for item in report["results"]))
        self.assertEqual({item["status"] for item in report["results"]}, {"unknown"})

    def test_coverage_distinguishes_block_and_skipped_other_family(self):
        _, report = self.run_report("/waf", active=True)
        self.assertEqual(report["results"][0]["coverage"]["state"], "blocked")
        self.assertEqual(report["results"][2]["coverage"]["state"], "skipped")
        _, report = self.run_report("/limited", active=True)
        self.assertEqual(report["results"][0]["coverage"]["state"], "blocked")

    def test_coverage_reports_ambiguous_controls_and_network_errors(self):
        _, report = self.run_report("/generic-error", react_probe=True)
        self.assertEqual(report["results"][2]["coverage"]["state"], "inconclusive")
        _, report = self.run_report("/short-body", react_probe=True)
        self.assertEqual(report["results"][2]["coverage"]["state"], "error")

    def test_health_stop_keeps_unprobed_imported_route_visible(self):
        RecordedHandler.fail_health = True
        _, report = self.run_report("/vulnerable", active=True, routes_text="/rsc")
        row = report["results"][2]["coverage"]["routes"][-1]
        self.assertEqual(row["state"], "skipped")
        self.assertEqual(row["reason"], "health_check_failed")

    def test_post_redirect_is_not_followed_and_stops_other_active_probe(self):
        _, report = self.run_report("/post-redirect", active=True)
        self.assertEqual(report["active_request_count"], 1)
        self.assertEqual(report["results"][0]["coverage"]["state"], "blocked")
        self.assertIn("redirected", report["active_stop_reason"])
        self.assertNotIn(("GET", "/rsc"), RecordedHandler.paths)

    def test_truncated_baseline_is_not_actively_probed(self):
        baseline = {"reachable": True, "http_status": 200, "body": "partial", "body_truncated": True}
        with mock.patch.object(twoshell, "php_warning_probe") as php:
            report = twoshell.run_active_route(self.base, baseline, 1, True, True, [])
        php.assert_not_called()
        self.assertEqual(report["active_request_count"], 0)

    def test_truncated_signature_is_inconclusive(self):
        response = {"reachable": True, "http_status": 500, "body": 'E{"digest":"x"}', "body_truncated": True}
        with mock.patch.object(twoshell, "send_request", return_value=response):
            probe = twoshell.react_digest_probe(self.base, 1)
        self.assertFalse(probe["positive"])
        self.assertTrue(probe["body_truncated"])

    def test_next_200_control_requires_strict_flight_and_next_html(self):
        baseline = {"reachable": True, "http_status": 200, "headers": {}, "body": '<script>self.__next_f=[]</script>'}
        candidate = {"attempted": True, "positive": True, "http_status": 500,
                     "signature": "flight_digest", "content_type": "text/x-component"}
        control = {"attempted": True, "positive": False, "http_status": 200,
                   "content_type": "text/html", "next_html_marker": True}
        cases = [(baseline, candidate, control, True),
                 (dict(baseline, body='opaque'), candidate, control, False),
                 (baseline, candidate, dict(control, next_html_marker=False), False),
                 (baseline, candidate, dict(control, content_type='text/plain'), False),
                 (baseline, dict(candidate, signature='error_and_digest'), control, False),
                 (baseline, dict(candidate, content_type='text/html'), control, False),
                 (baseline, candidate, dict(control, marker_present=True), False),
                 (baseline, candidate, dict(control, body_truncated=True), False)]
        for initial, probe, benign, expected in cases:
            with self.subTest(expected=expected, probe=probe, control=benign):
                with mock.patch.object(twoshell, 'react_digest_probe', side_effect=[dict(probe), dict(benign)]), \
                     mock.patch.object(twoshell, 'health_after_probe', return_value={'healthy': True}):
                    result = twoshell.run_active_route(self.base, initial, 1, False, True, [])
                self.assertEqual(result['react_probe']['positive'], expected)
                if expected:
                    self.assertEqual(result['react_probe']['control_variant'], 'next_html_200')

    def test_pacing_is_applied_between_requests(self):
        log = twoshell.RequestLog(3, 0.2)
        log.last_finished = 10.0
        response = json.dumps({"reachable": True, "http_status": 200})
        with mock.patch.object(twoshell.time, "monotonic", return_value=10.05), \
             mock.patch.object(twoshell.time, "sleep") as pause, \
             mock.patch.object(twoshell.subprocess, "run", return_value=type('Run', (), {'returncode': 0, 'stdout': response})()):
            twoshell.fetch(self.base, 1, log)
        self.assertAlmostEqual(pause.call_args.args[0], 0.15)
        self.assertEqual(len(log), 1)

    def test_invalid_limits_are_rejected_without_network(self):
        for option, value in [("--max-requests", "121"), ("--max-active-routes", "7"),
                              ("--max-discovery-pages", "21"), ("--request-interval", "nan")]:
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                self.run_report("/unknown", extra_args=[option, value])
        self.assertEqual(RecordedHandler.methods, [])

    def test_repeat_samples_catch_later_affected_replica_and_stop(self):
        code, report = self.run_report("/sampling-mixed", react_probe=True, extra_args=["--samples", "3"])
        self.assertEqual(code, 1)
        self.assertEqual(report["react_probe"]["samples_attempted"], 2)
        self.assertEqual(report["active_request_count"], 3)
        self.assertEqual(len(report["health_checks"]), 3)
        self.assertEqual(report["request_count"], 7)

    def test_repeat_samples_cannot_clear_sticky_patched_replica(self):
        code, report = self.run_report("/sampling-sticky", react_probe=True, extra_args=["--samples", "3"])
        self.assertEqual(code, 3)
        self.assertEqual(report["react_probe"]["samples_attempted"], 3)
        self.assertEqual(report["results"][2]["coverage"]["state"], "completed_no_signature")

    def test_repeat_php_stops_after_warning_finding(self):
        code, report = self.run_report("/sampling-php", php_probe=True, extra_args=["--samples", "3"])
        self.assertEqual(code, 1)
        self.assertEqual(report["php_probe"]["samples_attempted"], 2)
        self.assertEqual(report["active_request_count"], 2)

    def test_confirmed_families_are_not_repeated(self):
        code, report = self.run_report("/vulnerable", active=True, extra_args=["--samples", "3"])
        self.assertEqual(code, 1)
        self.assertEqual(report["active_request_count"], 3)
        self.assertEqual(len(report["route_probes"][0]["samples"]), 1)

    def test_masked_error_triage_is_opt_in(self):
        code, report = self.run_report("/sampling-masked", react_probe=True)
        self.assertEqual(code, 3)
        self.assertEqual(report["active_request_count"], 1)
        self.assertNotIn("review_signal", report["react_probe"])

    def test_repeatable_masked_errors_are_review_signals_never_findings(self):
        for path in ("/sampling-masked", "/sampling-masked-200"):
            with self.subTest(path=path):
                code, report = self.run_report(path, react_probe=True,
                    extra_args=["--samples", "2", "--react-error-triage"])
                self.assertEqual(code, 3)
                self.assertEqual({item["status"] for item in report["results"]}, {"unknown"})
                signal = report["react_probe"]["review_signal"]
                self.assertTrue(signal["repeatable"])
                self.assertFalse(signal["establishes_vulnerability"])
                self.assertEqual(signal["matching_samples"], 2)
                self.assertEqual(report["active_request_count"], 4)
                self.assertEqual(report["results"][2]["coverage"]["state"], "inconclusive")

    def test_single_difference_does_not_claim_repeatability(self):
        code, report = self.run_report("/sampling-masked", react_probe=True, extra_args=["--react-error-triage"])
        self.assertEqual(code, 3)
        self.assertFalse(report["react_probe"]["review_signal"]["repeatable"])

    def test_generic_errors_and_opaque_baselines_do_not_get_review_signals(self):
        for path in ("/sampling-generic", "/sampling-opaque"):
            with self.subTest(path=path):
                code, report = self.run_report(path, react_probe=True,
                    extra_args=["--samples", "2", "--react-error-triage"])
                self.assertEqual(code, 3)
                self.assertNotIn("review_signal", report["react_probe"])
                self.assertEqual(report["active_request_count"], 4 if path.endswith("generic") else 2)

    def test_repeat_budget_preserves_health_and_possible_controls(self):
        code, report = self.run_report("/sampling-masked", react_probe=True,
            extra_args=["--samples", "3", "--react-error-triage", "--max-requests", "8"])
        self.assertEqual(code, 3)
        self.assertEqual(report["request_count"], 5)
        self.assertEqual(report["react_probe"]["samples_attempted"], 1)
        self.assertEqual(len(report["health_checks"]), 2)
        self.assertEqual(report["route_probes"][0]["samples"][-1]["react_probe"]["skip_reason"], "request_budget")

    def test_later_block_stops_sampling_and_preserves_prior_review_signal(self):
        code, report = self.run_report("/sampling-block-later", react_probe=True,
            extra_args=["--samples", "3", "--react-error-triage"])
        self.assertEqual(code, 3)
        self.assertEqual(report["active_request_count"], 3)
        self.assertEqual(report["results"][2]["coverage"]["state"], "blocked")
        self.assertFalse(report["react_probe"]["review_signal"]["repeatable"])
        self.assertIn("allowlist", report["results"][2]["coverage"]["routes"][0]["next_step"])

    def test_health_change_on_repeat_stops_before_control(self):
        code, report = self.run_report("/sampling-health-later", react_probe=True,
            extra_args=["--samples", "3", "--react-error-triage"])
        self.assertEqual(code, 4)
        self.assertEqual(report["active_request_count"], 3)
        self.assertEqual(len(report["health_checks"]), 3)
        self.assertFalse(report["health_checks"][-1]["healthy"])

    def test_unreadable_probe_is_not_resampled(self):
        code, report = self.run_report("/sampling-unreadable", react_probe=True,
            extra_args=["--samples", "3", "--react-error-triage"])
        self.assertEqual(code, 3)
        self.assertEqual(report["active_request_count"], 1)
        self.assertEqual(report["results"][2]["coverage"]["state"], "inconclusive")

    def test_sampling_input_errors_are_rejected_before_network(self):
        for args in (["--samples", "0", "--active"], ["--samples", "4", "--active"],
                     ["--samples", "2"], ["--react-error-triage"],
                     ["--php-probe", "--react-error-triage"]):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                self.run_report("/patched", extra_args=args)
        self.assertEqual(RecordedHandler.methods, [])

    def test_version_boundaries(self):
        cases = [
            ("php", "8.4.26", "affected"), ("php", "8.4.27", "fixed"),
            ("php", "5.3.29", "unknown"),
            ("rsc", "19.2.0", "affected"), ("rsc", "19.2.1", "fixed"),
            ("next", "15.5.6", "affected"), ("next", "15.5.7", "fixed"),
            ("brotli", "1.0.9", "affected"), ("brotli", "1.0.10", "fixed"),
            ("brotli", "1.1.0", "affected"), ("brotli", "1.1.1", "fixed"),
            ("brotli", "1.2.0", "affected"), ("brotli", "1.2.1", "fixed"),
            ("dotnet-brotli", "8.0.32", "affected"),
            ("dotnet-brotli", "8.0.33", "fixed"),
            ("dotnet-brotli", "9.0.21", "affected"),
            ("dotnet-brotli", "9.0.22", "fixed"),
            ("dotnet-brotli", "10.0.13", "affected"),
            ("dotnet-brotli", "10.0.14", "fixed"),
            ("nodejs-brotli", "22.23.3", "affected"),
            ("nodejs-brotli", "22.23.4", "fixed"),
            ("nodejs-brotli", "24.22.0", "affected"),
            ("nodejs-brotli", "24.22.1", "fixed"),
            ("nodejs-brotli", "26.12.0", "affected"),
            ("nodejs-brotli", "26.12.1", "fixed"),
            ("next", "14.3.0-canary.77", "unknown"),
        ]
        for component, version, expected in cases:
            with self.subTest(component=component, version=version):
                self.assertEqual(twoshell.version_state(component, version), expected)


if __name__ == "__main__":
    unittest.main()
