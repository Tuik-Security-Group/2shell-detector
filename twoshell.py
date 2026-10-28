#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
# Copyright (c) 2026 Tuik Security Group
"""Detection-only triage for React2Shell, PHP2Shell and HTTP2Shell.

Default mode sends one GET. Opt-in PHP sends one small multipart POST; React
sends one and, after a candidate match, one benign control POST. Every POST is
followed by a health GET. No code payloads or malformed compressed streams
are sent.
An optional operator-supplied deployment inventory enables version verdicts.
"""

import argparse
import base64
import csv
import errno
from datetime import datetime, timedelta, timezone
import hashlib
from html.parser import HTMLParser
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
import xml.etree.ElementTree as ET
import zlib
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit


USER_AGENT = "2Shell-Detector/1.9.3"
URLS_FILE_LIMIT = 1024 * 1024
MAX_BATCH_URLS = 1000
ROUTES_FILE_LIMIT = 65536
MAX_IMPORTED_ROUTES = 10
BODY_LIMIT = 65536
GET_BODY_LIMIT = 1024 * 1024
MAX_POST_BODY_LIMIT = 1024 * 1024
INVENTORY_LIMIT = 1024 * 1024
EVIDENCE_LIMIT = 4 * 1024 * 1024
BLOCKED_STATUSES = {401, 403, 407, 429}
CVES = {
    "PHP2Shell": ("CVE-2026-109618", "CVE-2026-109619"),
    "React2Shell": ("CVE-2025-55182", "CVE-2025-66478"),
    "HTTP2Shell": ("CVE-2026-111497",),
}
CVES_NOT_ASSESSED = [{"cve": "CVE-2026-115560", "family": "PHP session upload progress",
                      "reason": "Separate serializer-switch configuration issue; existing PHP2Shell signatures and version ranges do not assess this CVE.",
                      "next_step": "Ask the client to review the PHP advisory and deployed session serializer configuration.",
                      "source": "https://www.php.net/archive/2026.php"}]
PHP_FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
DOTNET_BROTLI_FIXED = {(8, 0): 33, (9, 0): 22, (10, 0): 14}
NODE_BROTLI_FIXED = {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}
NEXT_FIXED = {(15, 0): 5, (15, 1): 9, (15, 2): 6, (15, 3): 6,
              (15, 4): 8, (15, 5): 7, (16, 0): 7}
RSC_PACKAGES = {"react-server-dom-webpack", "react-server-dom-parcel",
                "react-server-dom-turbopack"}


def parse_version(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}", value):
        return None
    return tuple(map(int, value.split(".")))


def version_state(component, value):
    """Return affected/fixed/unknown for upstream releases of this CVE only."""
    v = parse_version(value)
    if v is None:
        return "unknown"
    major, minor, patch = v
    if component == "php":
        if (major, minor) in PHP_FIXED:
            return "fixed" if patch >= PHP_FIXED[(major, minor)] else "affected"
        if major < 5 or (major == 5 and minor < 4):
            return "unknown"
        if major < 8 or (major == 8 and minor < 2):
            return "affected"  # Vendor backports must be checked separately.
        return "unknown"
    if component == "rsc":
        if major < 19:
            return "fixed"  # This React Server Components CVE starts at React 19.
        if major != 19:
            return "unknown"
        if minor == 0:
            return "fixed" if patch >= 1 else "affected"
        if minor == 1:
            return "fixed" if patch >= 2 else "affected"
        if minor == 2:
            return "fixed" if patch >= 1 else "affected"
        return "fixed"  # Later stable 19.x lines include the fix.
    if component == "next":
        if major == 13 or (major == 14):
            return "fixed"  # Stable 13/14 and Pages Router excluded by advisory.
        if (major, minor) in NEXT_FIXED:
            return "fixed" if patch >= NEXT_FIXED[(major, minor)] else "affected"
        if (major == 15 and minor >= 6) or (major == 16 and minor >= 1):
            return "fixed"
        return "unknown"
    if component == "brotli":
        if major != 1:
            return "unknown"
        if minor == 0:
            if patch < 3:
                return "unknown"
            return "fixed" if patch >= 10 else "affected"
        if minor == 1:
            return "fixed" if patch >= 1 else "affected"
        if minor == 2:
            return "fixed" if patch >= 1 else "affected"
        return "fixed"
    if component == "dotnet-brotli":
        if (major, minor) in DOTNET_BROTLI_FIXED:
            return "fixed" if patch >= DOTNET_BROTLI_FIXED[(major, minor)] else "affected"
        return "unknown"
    if component == "nodejs-brotli":
        if major in NODE_BROTLI_FIXED:
            return "fixed" if v >= NODE_BROTLI_FIXED[major] else "affected"
        return "unknown"
    raise ValueError("unknown component")


def result(family, cve, status, reason, confidence=None, applicability=None):
    behavioral = confidence == "behavioral_positive"
    return {"family": family, "cve": cve, "status": status, "reason": reason,
            "confidence": confidence or ("inventory_attested" if status != "unknown" else "inconclusive"),
            "applicability": {
                "state": "applicable" if behavioral else applicability or "unknown",
                "basis": "behavioral_signature" if behavioral else "deployment_inventory" if applicability else "unverified",
                "reason": ("A supported behavioral signature establishes a relevant input path on a tested route."
                           if behavioral else "Inventory confirms the technology and input path are present; vulnerability or patch status is reported separately."
                           if applicability == "applicable" else reason if applicability else
                           "Component presence or absence is not established. HTTP 405 and missing technology indicators do not establish non-applicability.")}}


def evidence_valid(evidence, *, patch=False):
    """Require a dated, immutable artifact reference for inventory assertions.

    This validates provenance fields, not the truth of the operator's claim.
    """
    if not isinstance(evidence, dict):
        return False
    if evidence.get("source") != "local_file":
        return False
    if not all(isinstance(evidence.get(key), str) and evidence[key].strip()
               for key in ("source", "source_ref", "artifact_digest", "observed_at")):
        return False
    if not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", evidence["artifact_digest"]):
        return False
    try:
        observed = datetime.fromisoformat(evidence["observed_at"].replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        if observed.tzinfo is None or observed > now or now - observed > timedelta(days=30):
            return False
    except ValueError:
        return False
    if patch and not (isinstance(evidence.get("patch_reference"), str)
                      and evidence["patch_reference"].strip()):
        return False
    return True


def deployment_evidence_valid(inventory):
    evidence = inventory.get("deployment_evidence") if isinstance(inventory, dict) else None
    return (evidence_valid(evidence) and
            isinstance(evidence.get("deployment_id"), str) and evidence["deployment_id"].strip() and
            isinstance(evidence.get("running_artifact"), str) and
            re.fullmatch(r"sha256:[0-9a-fA-F]{64}", evidence["running_artifact"]) is not None)


def validate_inventory_schema(inventory):
    """Reject mistyped or contradictory claims before they reach verdict logic."""
    if not isinstance(inventory, dict):
        raise ValueError("inventory must be an object")

    def fields(item, label, booleans=(), strings=(), check_evidence=True):
        if not isinstance(item, dict):
            raise ValueError(f"{label} must be an object")
        for key in booleans:
            if key in item and type(item[key]) is not bool:
                raise ValueError(f"{label}.{key} must be a boolean")
        for key in strings:
            if key in item and not isinstance(item[key], str):
                raise ValueError(f"{label}.{key} must be a string")
        if check_evidence and "evidence" in item:
            evidence(item["evidence"], label + ".evidence")

    def evidence(item, label):
        fields(item, label, ("all_instances_audited",),
               ("source", "source_ref", "artifact_digest", "observed_at",
                "patch_reference", "deployment_id", "running_artifact"), check_evidence=False)

    def components(item, key, label):
        value = item[key]
        if not isinstance(value, list) or len(value) > 256:
            raise ValueError(f"{label}.{key} must be a list of at most 256 components")
        if any(not isinstance(entry, dict) for entry in value):
            raise ValueError(f"{label}.{key} entries must be objects")
        return value

    fields(inventory, "inventory", strings=("target_url",))
    if "deployment_evidence" in inventory:
        evidence(inventory["deployment_evidence"], "deployment_evidence")
    if "covered_urls" in inventory:
        urls = inventory["covered_urls"]
        if not isinstance(urls, list) or len(urls) > 32 or any(not isinstance(url, str) for url in urls):
            raise ValueError("covered_urls must be a list of at most 32 URLs")
        target = validate_url(inventory.get("target_url", ""))
        if any(not same_origin(target, validate_url(url)) for url in urls):
            raise ValueError("covered_urls must have the target URL's origin")
    php = inventory.get("php")
    if php is not None:
        fields(php, "php", ("present", "web_exposed", "vendor_patch"), ("version",))
        if php.get("present") is False and php.get("web_exposed") is True:
            raise ValueError("PHP presence and exposure claims conflict")
    react = inventory.get("react")
    if react is not None:
        bools = ("present", "rsc_exposed", "next_app_router", "rsc_vendor_patch",
                 "next_vendor_patch", "all_rsc_packages_audited")
        fields(react, "react", bools, ("framework", "rsc_package", "rsc_version", "next_version"))
        if react.get("present") is False and (react.get("rsc_exposed") is True or
                react.get("next_app_router") is True or react.get("rsc_components")):
            raise ValueError("React absence conflicts with deployed RSC or Next.js claims")
        if react.get("framework") in {"react-router", "waku", "parcel-rsc", "vite-rsc", "rwsdk"} and react.get("next_app_router") is True:
            raise ValueError("Framework and Next.js App Router claims conflict")
        if "rsc_components" in react:
            entries = components(react, "rsc_components", "react")
            if not entries or "rsc_package" in react:
                raise ValueError("rsc_components must be nonempty and cannot accompany a legacy rsc_package")
            for index, entry in enumerate(entries):
                fields(entry, f"react.rsc_components[{index}]", bools, ("rsc_package", "rsc_version"))
                if entry.get("present") is False and entry.get("rsc_exposed") is True:
                    raise ValueError("RSC component presence and exposure claims conflict")
    brotli = inventory.get("brotli")
    if brotli is not None:
        fields(brotli, "brotli", ("present", "all_decoders_audited", "decodes_untrusted_data", "vendor_patch"),
               ("implementation", "version", "name"))
        entries = components(brotli, "decoders", "brotli") if "decoders" in brotli else [brotli]
        if brotli.get("present") is False and brotli.get("decoders"):
            raise ValueError("Brotli absence conflicts with listed decoder copies")
        for index, entry in enumerate(entries):
            fields(entry, f"brotli.decoders[{index}]", ("present", "decodes_untrusted_data", "vendor_patch"),
                   ("implementation", "version", "name"))
            if entry.get("present") is False and entry.get("decodes_untrusted_data") is True:
                raise ValueError("Decoder presence and exposure claims conflict")


def unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field in inventory")
        result[key] = value
    return result


def load_inventory(path):
    with open(path, "rb") as handle:
        raw = handle.read(INVENTORY_LIMIT + 1)
    if len(raw) > INVENTORY_LIMIT:
        raise ValueError("inventory exceeds the 1 MiB limit")
    inventory = json.loads(raw, object_pairs_hook=unique_json_object)
    validate_inventory_schema(inventory)
    return inventory


def verify_local_evidence(inventory, inventory_path):
    """Check hashes of referenced local evidence before making network requests."""
    evidence_items = [inventory.get("deployment_evidence")]
    for key in ("php", "react", "brotli"):
        item = inventory.get(key)
        if isinstance(item, dict):
            evidence_items.append(item.get("evidence"))
            if key == "react":
                for component in item.get("rsc_components", []) if isinstance(item.get("rsc_components"), list) else []:
                    if isinstance(component, dict):
                        evidence_items.append(component.get("evidence"))
            if key == "brotli":
                for decoder in item.get("decoders", []) if isinstance(item.get("decoders"), list) else []:
                    if isinstance(decoder, dict):
                        evidence_items.append(decoder.get("evidence"))
    base = Path(inventory_path).resolve().parent
    verified = set()
    for evidence in evidence_items:
        if not isinstance(evidence, dict) or evidence.get("source") != "local_file":
            continue
        ref = evidence.get("source_ref")
        if not isinstance(ref, str) or not ref or Path(ref).is_absolute() or ".." in Path(ref).parts:
            raise ValueError("local evidence source_ref must be a relative path inside the inventory directory")
        path = (base / ref).resolve()
        try:
            path.relative_to(base)
        except ValueError as exc:
            raise ValueError("local evidence file is outside the inventory directory") from exc
        if not path.is_file():
            raise ValueError("local evidence file is missing, outside the inventory directory, or larger than 4 MiB")
        with path.open("rb") as handle:
            raw = handle.read(EVIDENCE_LIMIT + 1)
        if len(raw) > EVIDENCE_LIMIT:
            raise ValueError("local evidence exceeds the 4 MiB limit")
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        expected = evidence.get("artifact_digest")
        if not isinstance(expected, str) or digest != expected.lower():
            raise ValueError(f"local evidence hash does not match: {ref}")
        verified.add(ref)
    return len(verified)


def assess_version(family, cve, item, component, exposed_key, version_key,
                   patch_key="vendor_patch"):
    if not isinstance(item, dict):
        return result(family, cve, "unknown", "No trusted deployment inventory for this component.")
    if not evidence_valid(item.get("evidence"), patch=item.get(patch_key) is True):
        return result(family, cve, "unknown", "Component evidence is missing, invalid, or lacks a vendor patch reference.")
    if item.get("present") is False or item.get(exposed_key) is False:
        return result(family, cve, "not vulnerable", "Inventory says the affected component or input path is absent at this URL.",
                      applicability="not_applicable")
    if item.get("present") is not True or item.get(exposed_key) is not True:
        return result(family, cve, "unknown", "Component presence or exposure is not confirmed in the inventory.")
    if item.get(patch_key) is True:
        return result(family, cve, "not vulnerable", "Inventory confirms a vendor fix is deployed.", applicability="applicable")
    state = version_state(component, item.get(version_key))
    version = item.get(version_key, "unspecified")
    if state == "fixed":
        return result(family, cve, "not vulnerable", f"Installed {component} {version} is at or beyond the upstream fix.", applicability="applicable")
    if state == "affected" and item.get(patch_key) is False:
        return result(family, cve, "vulnerable", f"Installed {component} {version} is affected and inventory confirms no vendor backport.", applicability="applicable")
    if state == "affected":
        return result(family, cve, "unknown", f"{component} {version} is in the affected upstream range; vendor backport status is unspecified.", applicability="applicable")
    return result(family, cve, "unknown", f"No reliable rule for {component} version {version}.", applicability="applicable")


def assess_brotli(inventory):
    """Assess every decoder copy; a clean result needs an explicitly complete list."""
    cve = CVES["HTTP2Shell"][0]
    if not isinstance(inventory, dict):
        return result("HTTP2Shell", cve, "unknown", "No trusted Brotli decoder inventory.")
    try:
        validate_inventory_schema({"brotli": inventory})
    except ValueError as exc:
        return result("HTTP2Shell", cve, "unknown", "Invalid decoder inventory: " + str(exc))
    if not evidence_valid(inventory.get("evidence")):
        return result("HTTP2Shell", cve, "unknown", "Brotli inventory lacks valid provenance evidence.")
    complete = inventory.get("all_decoders_audited") is True
    if "decoders" in inventory:
        decoders = inventory["decoders"]
        if not isinstance(decoders, list):
            return result("HTTP2Shell", cve, "unknown", "Brotli decoders must be a list.")
    elif inventory.get("present") is False:
        decoders = []
    else:
        decoders = [inventory]  # Legacy single-decoder inventory.
    if not decoders and inventory.get("present") is not False:
        return result("HTTP2Shell", cve, "unknown",
                      "Decoder list is empty without evidence that Brotli is absent.")
    findings = []
    for index, item in enumerate(decoders):
        if not isinstance(item, dict):
            findings.append(result("HTTP2Shell", cve, "unknown", "Decoder entry is invalid."))
            continue
        name = item.get("name") or f"decoder {index + 1}"
        if not evidence_valid(item.get("evidence"), patch=item.get("vendor_patch") is True):
            findings.append(result("HTTP2Shell", cve, "unknown", f"{name}: decoder evidence is missing or invalid."))
            continue
        component = {"google-brotli-c": "brotli", "dotnet-brotli": "dotnet-brotli",
                     "nodejs-brotli": "nodejs-brotli"}.get(
            item.get("implementation"))
        if item.get("decodes_untrusted_data") is False:
            finding = result("HTTP2Shell", cve, "not vulnerable",
                             "Inventory confirms this decoder cannot receive untrusted data at this URL.", applicability="not_applicable")
        elif component:
            candidate = dict(item)
            candidate.setdefault("present", True)
            finding = assess_version("HTTP2Shell", cve, candidate, component,
                                     "decodes_untrusted_data", "version")
        elif item.get("present") is not False and item.get("decodes_untrusted_data") is True \
                and item.get("vendor_patch") is True:
            finding = result("HTTP2Shell", cve, "not vulnerable",
                             "Inventory confirms a vendor fix for this decoder copy.", applicability="applicable")
        else:
            finding = result("HTTP2Shell", cve, "unknown",
                             "Decoder implementation, exposure, or patch status is not established.")
        finding["reason"] = f"{name}: {finding['reason']}"
        findings.append(finding)
    vulnerable = [item for item in findings if item["status"] == "vulnerable"]
    if vulnerable:
        return vulnerable[0]
    unknown = [item for item in findings if item["status"] == "unknown"]
    if unknown:
        return unknown[0]
    if not complete:
        return result("HTTP2Shell", cve, "unknown",
                      "Listed decoder copies appear unaffected, but the inventory does not confirm all copies were audited.")
    return result("HTTP2Shell", cve, "not vulnerable",
                  "Inventory confirms all Brotli decoder copies serving this URL were audited and are unaffected.",
                  applicability="not_applicable" if all(item["applicability"]["state"] == "not_applicable" for item in findings) else "applicable")


def assess(inventory):
    inventory = inventory or {}
    try:
        validate_inventory_schema(inventory)
    except ValueError as exc:
        return [result(family, cve, "unknown", "Invalid inventory: " + str(exc))
                for family, cves in CVES.items() for cve in cves]
    if not deployment_evidence_valid(inventory):
        return [result(family, cve, "unknown",
                       "Deployment evidence must identify a dated artifact and attest that all serving instances were audited.")
                for family, cves in CVES.items() for cve in cves]
    php = inventory.get("php")
    react = inventory.get("react")
    brotli = inventory.get("brotli")
    out = [assess_version("PHP2Shell", c, php, "php", "web_exposed", "version")
           for c in CVES["PHP2Shell"]]

    if isinstance(react, dict) and react.get("present") is False and evidence_valid(react.get("evidence")):
        out.extend(result("React2Shell", c, "not vulnerable", "Inventory confirms no React Server Components deployment.", applicability="not_applicable")
                   for c in CVES["React2Shell"])
    else:
        components = react.get("rsc_components") if isinstance(react, dict) else None
        if isinstance(components, list) and components:
            component_findings = []
            for component_item in components:
                if not isinstance(component_item, dict) or component_item.get("rsc_package") not in RSC_PACKAGES:
                    component_findings.append(result("React2Shell", CVES["React2Shell"][0], "unknown",
                                                      "An RSC component has no supported package name."))
                    continue
                finding = assess_version("React2Shell", CVES["React2Shell"][0], component_item,
                                         "rsc", "rsc_exposed", "rsc_version", "rsc_vendor_patch")
                finding["reason"] = component_item["rsc_package"] + ": " + finding["reason"]
                component_findings.append(finding)
            rsc = next((item for item in component_findings if item["status"] == "vulnerable"), None)
            if rsc is None:
                rsc = next((item for item in component_findings if item["status"] == "unknown"), None)
            if rsc is None and react.get("all_rsc_packages_audited") is True and evidence_valid(react.get("evidence")):
                rsc = result("React2Shell", CVES["React2Shell"][0], "not vulnerable",
                             "All inventoried RSC package copies and serving instances are attested unaffected.",
                             applicability="not_applicable" if all(item["applicability"]["state"] == "not_applicable" for item in component_findings) else "applicable")
            if rsc is None:
                rsc = result("React2Shell", CVES["React2Shell"][0], "unknown",
                             "RSC package list is incomplete or lacks evidence.")
        elif isinstance(react, dict) and react.get("rsc_package") not in RSC_PACKAGES:
            rsc = result("React2Shell", CVES["React2Shell"][0], "unknown",
                         "Inventory does not name a supported React Server DOM package.")
        else:
            rsc = assess_version("React2Shell", CVES["React2Shell"][0], react,
                                 "rsc", "rsc_exposed", "rsc_version", "rsc_vendor_patch")
            if rsc["status"] == "not vulnerable" and react.get("all_rsc_packages_audited") is not True:
                rsc = result("React2Shell", CVES["React2Shell"][0], "unknown",
                             "RSC package appears unaffected, but all copies were not attested audited.")
        out.append(rsc)
        non_next = isinstance(react, dict) and react.get("framework") in {
            "react-router", "waku", "parcel-rsc", "vite-rsc", "rwsdk"}
        if non_next and react.get("next_app_router") is True:
            next_result = result("React2Shell", CVES["React2Shell"][1], "unknown",
                                 "Framework and Next.js App Router claims conflict.")
        elif isinstance(react, dict) and evidence_valid(react.get("evidence")) and react.get("next_app_router") is False:
            next_result = result("React2Shell", CVES["React2Shell"][1], "not vulnerable",
                                 "Inventory confirms this URL does not use Next.js App Router.", applicability="not_applicable")
        else:
            next_result = assess_version("React2Shell", CVES["React2Shell"][1], react,
                                         "next", "next_app_router", "next_version", "next_vendor_patch")
        out.append(next_result)

    out.append(assess_brotli(brotli))
    if inventory["deployment_evidence"].get("all_instances_audited") is not True:
        out = [result(item["family"], item["cve"], "unknown",
                      "Listed component appears unaffected, but all serving instances were not audited.")
               if item["status"] == "not vulnerable" else item for item in out]
    return out


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs = []
        self.scripts = []
        self.base_href = None
        self.waku_generator = False

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if (tag == "meta" and attributes.get("name", "").lower() == "generator"
                and attributes.get("content", "").lower() == "waku"):
            self.waku_generator = True
        if tag == "script" and len(self.scripts) < 128:
            src = dict(attrs).get("src")
            if src:
                self.scripts.append(src)
        if tag == "base" and self.base_href is None:
            self.base_href = dict(attrs).get("href")
        if tag == "a" and len(self.hrefs) < 128:
            href = dict(attrs).get("href")
            if href:
                self.hrefs.append(href)


class RequestLog(list):
    """One sequential request budget, including redirects and health checks."""
    def __init__(self, limit=40, interval=0.2, get_body_limit=GET_BODY_LIMIT, post_body_limit=BODY_LIMIT):
        super().__init__()
        self.limit = limit
        self.interval = interval
        self.last_finished = None
        self.reserved = 0
        self.get_body_limit = get_body_limit
        self.post_body_limit = post_body_limit

    def available(self):
        return max(0, self.limit - len(self) - self.reserved)


def enough_requests(evidence_log, count):
    return not isinstance(evidence_log, RequestLog) or evidence_log.available() >= count


def canonical_url(url):
    parsed = urlsplit(validate_url(url))
    host = parsed.hostname.lower()
    if ":" in host:
        host = "[" + host + "]"
    port = parsed.port
    if port and port != (443 if parsed.scheme == "https" else 80):
        host += ":" + str(port)
    return urlunsplit((parsed.scheme, host, parsed.path or "/", parsed.query, ""))


def load_routes(path, base):
    """Validate the entire bounded list before sending any network request."""
    with Path(path).open("rb") as source:
        raw = source.read(ROUTES_FILE_LIMIT + 1)
    if len(raw) > ROUTES_FILE_LIMIT:
        raise ValueError("routes file exceeds 64 KiB")
    routes = []
    entries = 0
    for line_number, line in enumerate(raw.decode("utf-8-sig").splitlines(), 1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        entries += 1
        if entries > MAX_IMPORTED_ROUTES:
            raise ValueError("routes file allows at most ten entries")
        if value.startswith("//") or not (value.startswith("/") or value.startswith(("https://", "http://"))):
            raise ValueError("routes file line %d must be an absolute URL or /path" % line_number)
        if any(ord(char) <= 32 or ord(char) >= 127 for char in value) or "\\" in value:
            raise ValueError("routes file line %d has an invalid URL character" % line_number)
        candidate = canonical_url(urljoin(base, value))
        if not same_origin(base, candidate) or urlsplit(candidate).query:
            raise ValueError("routes file line %d must be same-origin with no query or fragment" % line_number)
        if candidate not in routes:
            routes.append(candidate)
    return routes


def load_urls(path):
    """Validate every batch entry before any request, deduplicating exact URLs."""
    with Path(path).open("rb") as source:
        raw = source.read(URLS_FILE_LIMIT + 1)
    if len(raw) > URLS_FILE_LIMIT:
        raise ValueError("URLs file exceeds 1 MiB")
    urls, seen, entries = [], set(), 0
    for number, line in enumerate(raw.decode("utf-8-sig").splitlines(), 1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        entries += 1
        if entries > MAX_BATCH_URLS:
            raise ValueError("URLs file allows at most 1000 entries")
        try:
            url = canonical_url(value)
            if urlsplit(url).query:
                raise ValueError("query strings are not allowed in batch targets")
        except ValueError as exc:
            # Do not echo input lines that may contain credentials or secrets.
            raise ValueError("URLs file line %d: %s" % (number, exc)) from exc
        if url not in seen:
            urls.append(url)
            seen.add(url)
    if not urls:
        raise ValueError("URLs file contains no targets")
    return urls, entries - len(urls)


def validate_url(url):
    if not isinstance(url, str) or not url or len(url) > 8192 or any(
            ord(char) <= 32 or ord(char) >= 127 for char in url) or "\\" in url:
        raise ValueError("URL must be ASCII with no spaces, control characters, or backslashes; encode international names and paths")
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or "@" in parsed.netloc or parsed.fragment:
        raise ValueError("URL must be http(s), contain a host, and have no credentials or fragment")
    try:
        if parsed.port == 0:
            raise ValueError("invalid URL port")
    except ValueError as exc:
        raise ValueError("invalid URL port") from exc
    return parsed.geturl()


def same_origin(base, candidate):
    left, right = urlsplit(base), urlsplit(candidate)
    return (left.scheme, left.hostname, left.port or (443 if left.scheme == "https" else 80)) == (
        right.scheme, right.hostname, right.port or (443 if right.scheme == "https" else 80))


def redacted_url(url):
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       "[redacted]" if parts.query else "", ""))


def evidence_record(request, response):
    """Retain bounded response proof without cookies, bodies, or URL queries."""
    return {"method": request.get_method(), "url": redacted_url(request.full_url),
            "http_status": response.get("http_status"),
            "error": response.get("error"),
            "network_error_kind": response.get("network_error_kind"),
            "redirect_target": response.get("redirect_target"),
            "redirect_stop_reason": response.get("redirect_stop_reason"),
            "response_sha256": response.get("body_sha256"),
            "response_bytes_captured": response.get("body_bytes_captured", 0),
            "body_truncated": response.get("body_truncated", False),
            "body_error": response.get("body_error"),
            "response_body_limit": response.get("body_limit"),
            "response_mitigation": response_mitigation(response),
            "elapsed_seconds": response.get("elapsed_seconds"),
            "content_type": (response.get("headers", {}).get("content-type") or "")[:120]}


def decode_response(raw, encoding, limit=BODY_LIMIT):
    """Bound decoded output as well as wire bytes, including gzip expansion."""
    if encoding in ("", "identity"):
        return raw[:limit].decode("utf-8", "replace"), len(raw) > limit, None
    if encoding not in ("gzip", "deflate"):
        return "", False, "unsupported_content_encoding"
    try:
        decoder = zlib.decompressobj(31 if encoding == "gzip" else zlib.MAX_WBITS)
        decoded = decoder.decompress(raw, limit + 1)
        truncated = len(decoded) > limit or bool(decoder.unconsumed_tail)
        if not truncated and (not decoder.eof or decoder.unused_data):
            return "", False, "invalid_compressed_response"
        return decoded[:limit].decode("utf-8", "replace"), truncated, None
    except zlib.error:
        return "", False, "invalid_compressed_response"


def network_error_kind(exc):
    """Categorize failures without retaining exception strings or secrets."""
    reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
    if isinstance(reason, socket.gaierror):
        return "dns"
    if isinstance(reason, ssl.SSLCertVerificationError):
        return "tls_certificate"
    if isinstance(reason, ssl.SSLError):
        return "tls_handshake"
    if isinstance(reason, TimeoutError):
        return "timeout"
    if isinstance(reason, ConnectionRefusedError):
        return "connection_refused"
    if isinstance(reason, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
        return "connection_closed"
    if isinstance(reason, OSError) and reason.errno in {errno.ENETUNREACH, errno.EHOSTUNREACH}:
        return "network_unreachable"
    if isinstance(reason, http.client.HTTPException):
        return "http_protocol"
    if isinstance(reason, ValueError):
        return "invalid_request"
    return "connection_error"


def redirect_destination(url, response):
    location = response.get("headers", {}).get("location")
    if not location:
        return None, "missing_location"
    try:
        return validate_url(urljoin(url, location)), None
    except ValueError:
        return None, "invalid_location"


def perform_request(request, timeout, get_body_limit=GET_BODY_LIMIT, post_body_limit=BODY_LIMIT):
    """Network operation executed in an isolated, deadline-limited child."""
    if type(get_body_limit) is not int or not BODY_LIMIT <= get_body_limit <= GET_BODY_LIMIT:
        raise ValueError("GET response limit must be between 65536 and 1048576 bytes")
    if type(post_body_limit) is not int or not BODY_LIMIT <= post_body_limit <= MAX_POST_BODY_LIMIT:
        raise ValueError("POST response limit must be between 65536 and 1048576 bytes")
    body_limit = get_body_limit if request.get_method() == "GET" else post_body_limit
    # Do not inherit environment or platform proxies for client assessments.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        try:
            response = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            raw = response.read(body_limit + 1)
            headers = {k.lower(): v for k, v in response.headers.items()}
            length = headers.get("content-length", "")
            if (length.isdigit() and len(length) < 12 and response.status not in (204, 304)
                    and len(raw) < min(int(length), body_limit + 1)):
                raise http.client.IncompleteRead(b"")
            body, decoded_truncated, body_error = decode_response(
                raw, headers.get("content-encoding", "").strip().lower(), body_limit)
            result = {"reachable": True, "http_status": response.status,
                    "headers": headers, "body": body, "body_error": body_error,
                    "body_truncated": len(raw) > body_limit or decoded_truncated,
                    "body_limit": body_limit,
                    "body_sha256": hashlib.sha256(raw[:body_limit]).hexdigest(),
                    "body_bytes_captured": min(len(raw), body_limit)}
            if 300 <= response.status < 400:
                target, failure = redirect_destination(request.full_url, result)
                result.update(redirect_target=redacted_url(target) if target else None,
                              redirect_stop_reason=failure or ("not_followed" if request.get_method() == "GET"
                                                               else "post_redirect_not_followed"))
    except (urllib.error.URLError, OSError, TimeoutError, http.client.HTTPException, ValueError) as exc:
        result = {"reachable": False, "error": type(exc).__name__, "network_error_kind": network_error_kind(exc)}
    return result


def http_worker():
    data = json.loads(sys.stdin.read(32768))
    request = urllib.request.Request(validate_url(data["url"]),
        data=base64.b64decode(data["data"]) if data["data"] is not None else None,
        headers=data["headers"], method=data["method"])
    print(json.dumps(perform_request(request, data["timeout"], data["get_body_limit"], data["post_body_limit"])))


def send_request(request, timeout, evidence_log=None):
    # A socket timeout alone is an inactivity timer: slow headers, slow body
    # bytes, or DNS can otherwise hold the whole scanner indefinitely. Killing
    # this single-request child closes its sockets and leaves no worker behind.
    if isinstance(evidence_log, RequestLog):
        if not enough_requests(evidence_log, 1):
            return {"reachable": False, "error": "request_budget_exhausted"}
        if evidence_log.last_finished is not None:
            time.sleep(max(0, evidence_log.interval - (time.monotonic() - evidence_log.last_finished)))
    payload = {"url": request.full_url, "method": request.get_method(),
               "headers": dict(request.header_items()), "timeout": timeout,
               "get_body_limit": getattr(evidence_log, "get_body_limit", GET_BODY_LIMIT),
               "post_body_limit": getattr(evidence_log, "post_body_limit", BODY_LIMIT),
               "data": base64.b64encode(request.data).decode("ascii") if request.data is not None else None}
    started = time.monotonic()
    try:
        child = subprocess.run([sys.executable, "-I", str(Path(__file__).resolve()), "--internal-http-worker"],
                               input=json.dumps(payload), text=True, capture_output=True,
                               timeout=timeout, check=False)
        response = json.loads(child.stdout) if child.returncode == 0 else None
        if not isinstance(response, dict) or not isinstance(response.get("reachable"), bool):
            response = {"reachable": False, "error": "http_worker_failed"}
    except subprocess.TimeoutExpired:
        response = {"reachable": False, "error": "request_deadline_exceeded", "network_error_kind": "request_deadline"}
    except (OSError, ValueError):
        response = {"reachable": False, "error": "http_worker_failed"}
    response["elapsed_seconds"] = round(time.monotonic() - started, 3)
    if evidence_log is not None:
        evidence_log.append(evidence_record(request, response))
    if isinstance(evidence_log, RequestLog):
        evidence_log.last_finished = time.monotonic()
    return response


def fetch(url, timeout, evidence_log=None):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                                   "Accept-Encoding": "identity"}, method="GET")
    return send_request(request, timeout, evidence_log)


def fetch_with_redirects(url, timeout, evidence_log=None, max_hops=2, discovery=False):
    """Follow only ordinary GET redirects within the exact origin."""
    seen = set()
    current = url
    for hop in range(max_hops + 1):
        if current in seen:
            break
        seen.add(current)
        evidence_index = len(evidence_log) if evidence_log is not None else None
        response = fetch(current, timeout, evidence_log)
        if not response["reachable"] or response_mitigation(response) or not 300 <= response["http_status"] < 400:
            return current, response
        candidate, reason = redirect_destination(current, response)
        if candidate:
            reason = ("cross_origin" if not same_origin(url, candidate) else
                      "discovery_scope" if discovery and not discovery_url(url, candidate, resource=True) else
                      "redirect_loop" if candidate in seen else "hop_limit" if hop == max_hops else
                      "request_budget" if not enough_requests(evidence_log, 1) else "followed")
        response.update(redirect_target=redacted_url(candidate) if candidate else None,
                        redirect_stop_reason=reason)
        if evidence_index is not None and len(evidence_log) > evidence_index:
            evidence_log[evidence_index].update(redirect_target=response["redirect_target"], redirect_stop_reason=reason)
        if reason != "followed":
            return current, response
        current = candidate
    return current, response


def discovery_url(base_url, reference, resource=False, resolution_base=None):
    """Never guess query values, cross origins, or follow obvious action paths."""
    if not reference or reference.startswith("#"):
        return None
    try:
        candidate = canonical_url(urljoin(resolution_base or base_url, reference.split("#", 1)[0]))
    except ValueError:
        return None
    parts = urlsplit(candidate)
    path = unquote(unquote(parts.path))
    if (not same_origin(base_url, candidate) or parts.query or
            any(c in path for c in "\\?#%") or any(ord(c) < 32 or ord(c) == 127 for c in path) or
            re.search(r"(?:^|[/_.-])(?:logout|signout|logoff|delete|remove|unsubscribe|"
                      r"reset|update|submit|save|purchase|checkout|confirm)(?:$|[/_.-])", path, re.I)):
        return None
    if not resource and re.search(r"\.(?:m?js|css|xml|json|map|png|jpe?g|gif|webp|svg|ico|pdf|zip|gz|woff2?|mp[34])$", path, re.I):
        return None
    return candidate


def html_links(base_url, response, scripts=False):
    if response_mitigation(response):
        return []
    if (not response["reachable"] or not 200 <= response["http_status"] < 300
            or response.get("body_error")):
        return []
    content_type = response.get("headers", {}).get("content-type", "").lower()
    if content_type and "html" not in content_type:
        return []
    parser = LinkParser()
    parser.feed(response.get("body", "")[:BODY_LIMIT])
    resolution_base = base_url
    if parser.base_href:
        try:
            resolution_base = canonical_url(urljoin(base_url, parser.base_href))
        except ValueError:
            pass
    links = []
    for href in parser.scripts if scripts else parser.hrefs:
        candidate = discovery_url(base_url, href, resource=scripts, resolution_base=resolution_base)
        if (candidate and same_origin(base_url, candidate) and candidate not in links and
                (not scripts or re.search(r"\.m?js$", urlsplit(candidate).path, re.I))):
            links.append(candidate)
    return links


def discovered_links(base_url, response):
    return html_links(base_url, response)


def javascript_links(base_url, body):
    """Conservative literal hints only; no JS execution, imports, or form actions.

    Only root-relative, one-argument fetch calls and href/to literals qualify.
    These are discovery hints, not proof of a route's safety or technology.
    """
    patterns = (r"\bfetch\s*\(\s*(['\"])(/[^'\"\\\s]{1,512})\1\s*\)",
                r"\b(?:href|to)\s*:\s*(['\"])(/[^'\"\\\s]{1,512})\1")
    links = []
    for pattern in patterns:
        for match in re.finditer(pattern, body[:BODY_LIMIT]):
            candidate = discovery_url(base_url, match.group(2))
            if candidate and candidate not in links:
                links.append(candidate)
            if len(links) >= 128:
                return links
    return links


def sitemap_links(base_url, body):
    # ElementTree does not fetch external entities; also reject all DTD/entity
    # declarations, including internal entity expansion, before parsing.
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)", body, re.I):
        raise ValueError("sitemap_declarations_rejected")
    try:
        root = ET.fromstring(body)
    except (ET.ParseError, ValueError):
        raise ValueError("invalid_sitemap_xml")
    kind = root.tag.rsplit("}", 1)[-1]
    if kind not in {"urlset", "sitemapindex"}:
        raise ValueError("unsupported_sitemap_root")
    links = []
    for entry in list(root)[:128]:
        expected = "url" if kind == "urlset" else "sitemap"
        if entry.tag.rsplit("}", 1)[-1] != expected:
            continue
        for loc in entry:
            if loc.tag.rsplit("}", 1)[-1] == "loc" and loc.text:
                candidate = discovery_url(base_url, loc.text.strip(), resource=kind == "sitemapindex")
                if candidate and candidate not in links:
                    links.append(candidate)
    return kind, links


def discover_routes(base_url, baseline, timeout, evidence_log=None, limit=8, seeds=(), details=None,
                    discover_js=False, discover_sitemaps=False, resources=None):
    """Two-level page discovery with optional two-script/two-sitemap GET caps."""
    routes = []
    resources = resources if resources is not None else []
    seen = {canonical_url(base_url)}
    seen.update(canonical_url(url) for url, _ in seeds)
    queue = []
    asset_seen, counts = set(), {"javascript": 0, "sitemap": 0}

    def read_resource(candidate, kind):
        if candidate in asset_seen:
            return None
        asset_seen.add(candidate)
        row = {"url": redacted_url(candidate), "kind": kind}
        resources.append(row)
        if counts[kind] >= 2 or not enough_requests(evidence_log, 1):
            row.update(state="skipped", reason="resource_limit" if counts[kind] >= 2 else "request_budget")
            return None
        counts[kind] += 1
        final_url, response = fetch_with_redirects(candidate, timeout, evidence_log, discovery=True)
        row.update(http_status=response.get("http_status"), final_url=redacted_url(final_url))
        if response_mitigation(response) or response.get("http_status") in BLOCKED_STATUSES:
            row.update(state="blocked", reason="discovery_resource_blocked", stop_active=True)
        elif (not response["reachable"] or response.get("body_error") or
                (response.get("body_truncated") and kind != "javascript") or
                not 200 <= response["http_status"] < 300):
            row.update(state="unreadable", reason="resource_unavailable_or_incomplete")
        else:
            mime = response.get("headers", {}).get("content-type", "").split(";", 1)[0].strip().lower()
            allowed = ({"text/javascript", "application/javascript", "application/x-javascript"}
                       if kind == "javascript" else {"application/xml", "text/xml"})
            if mime not in allowed:
                row.update(state="unreadable", reason="unexpected_content_type")
            else:
                row.update(state="read", reason="bounded_static_parse")
                if response.get("body_truncated") or len(response["body"]) > BODY_LIMIT:
                    row.update(state="partial", reason="javascript_prefix_only")
                return response["body"], row
        return None

    def add_page_links(seed_url, seed_response, depth):
        queue.extend((url, depth, "html") for url in discovered_links(seed_url, seed_response))
        if discover_js:
            for asset in html_links(seed_url, seed_response, scripts=True):
                if any(row.get("stop_active") for row in resources):
                    break
                read = read_resource(asset, "javascript")
                if read:
                    body, row = read
                    links = javascript_links(seed_url, body)
                    row["candidates"] = len(links)
                    queue.extend((url, depth, "javascript") for url in links)

    for seed_url, seed_response in [(base_url, baseline)] + list(seeds):
        add_page_links(seed_url, seed_response, 1)
    if (discover_sitemaps and baseline["reachable"] and 200 <= baseline["http_status"] < 300
            and not response_mitigation(baseline) and not baseline.get("body_error")):
        sitemap_queue = [(urljoin(base_url, "/sitemap.xml"), 0)]
        for sitemap, depth in sitemap_queue:
            if any(row.get("stop_active") for row in resources):
                break
            read = read_resource(sitemap, "sitemap")
            if not read:
                continue
            body, row = read
            try:
                kind, links = sitemap_links(sitemap, body)
            except ValueError as exc:
                row.update(state="unreadable", reason=str(exc))
                continue
            row["candidates"] = len(links)
            if kind == "urlset":
                queue.extend((url, 1, "sitemap") for url in links)
            elif depth == 0:
                sitemap_queue.extend((url, 1) for url in links)
            else:
                row.update(state="partial", reason="sitemap_index_depth_limit")
    attempted = 0
    for candidate, depth, via in queue:
        if candidate in seen:
            continue
        seen.add(candidate)
        stopped = any(row.get("stop_active") for row in resources)
        if stopped or attempted >= limit or not enough_requests(evidence_log, 1):
            if details is not None:
                details.append({"url": redacted_url(candidate), "source": "discovered", "depth": depth,
                                "reason": "discovery_resource_blocked" if stopped else
                                          "discovery_page_limit" if attempted >= limit else "request_budget"})
            continue
        attempted += 1
        final_url, response = fetch_with_redirects(candidate, timeout, evidence_log, discovery=True)
        if not same_origin(base_url, final_url) or urlsplit(final_url).query:
            if details is not None:
                details.append({"url": redacted_url(candidate), "source": "discovered", "depth": depth,
                                "reason": "redirected_to_query_or_outside_scope"})
            continue
        final_url = canonical_url(final_url)
        if final_url != candidate and final_url in seen:
            continue
        seen.add(final_url)
        notes = observations(response)
        routes.append({"url": final_url, "http_status": response.get("http_status"),
                       "reachable": response["reachable"], "depth": depth, "source": "discovered", "discovered_via": via,
                       "rsc_indicator": any("Next.js/RSC indicator" in note for note in notes),
                       "php_indicator": any("PHP" in note for note in notes) or urlsplit(final_url).path.lower().endswith(".php"),
                       "response": response})
        if depth < 2:
            add_page_links(final_url, response, depth + 1)
    return routes


def php_warning_probe(url, timeout, evidence_log=None):
    """One small, non-exploit PHP upload-progress probe. See NOTICE for provenance.

    An absent warning is inconclusive. This is opt-in because any POST may have
    application-side effects, even though the payload contains no code or OOM trigger.
    """
    boundary = "----TwoShell" + secrets.token_hex(12)
    field = secrets.token_hex(8)
    filename = secrets.token_hex(6) + ".txt"
    body = (f"--{boundary}\r\n"
            "Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n"
            f"{field}\r\n"
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"f\"; filename=\"{filename}\"\r\n"
            "Content-Type: text/plain\r\n\r\n"
            "1\r\n"
            f"--{boundary}--\r\n").encode("ascii")
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity",
                 "Cookie": "PHPSESSID=_",
                 "Content-Type": f"multipart/form-data; boundary={boundary}"})
    evidence_index = len(evidence_log) if evidence_log is not None else None
    response = send_request(request, timeout, evidence_log)
    if not response["reachable"]:
        return {"attempted": True, "positive": False, "error": response["error"],
                "request_evidence_index": evidence_index,
                "reason": "Probe request failed; no PHP verdict can be drawn."}
    markers = ("Session ID is too long or contains illegal characters",
               "Failed to read session data", "Failed to write session data (")
    positive = (not response_mitigation(response) and not response.get("body_error") and not response.get("body_truncated")
                and response["http_status"] not in BLOCKED_STATUSES
                and not 300 <= response["http_status"] < 400
                and all(marker in response["body"] for marker in markers))
    return {"attempted": True, "positive": positive,
            "response_mitigation": response_mitigation(response),
            "body_error": response.get("body_error"),
            "body_truncated": response.get("body_truncated", False),
            "request_evidence_index": evidence_index,
            "http_status": response["http_status"],
            "reason": ("Unpatched PHP session-write warning sequence observed."
                       if positive else "Warning sequence absent; this does not prove PHP is patched.")}


def react_signature(body):
    if 'E{"digest"' in body:
        return "flight_digest"
    if "digest" in body and "Error" in body:
        return "error_and_digest"
    return None


def waku_indicator(response):
    """Require both HTML metadata and hydration code; never a version verdict."""
    if not response.get("reachable"):
        return False
    if response.get("headers", {}).get("content-type", "").split(";", 1)[0].lower() != "text/html":
        return False
    body = response.get("body", "")[:BODY_LIMIT]
    parser = LinkParser()
    parser.feed(body)
    return parser.waku_generator and "__WAKU_HYDRATE__" in body and "__WAKU_PREFETCHED__" in body


def waku_component_probe(url, baseline, timeout, evidence_log):
    """Default-root Waku component decoder only: no action IDs or function route.

    Two candidates bracketed by three controls on a random missing component
    route distinguish the validated parser behavior. Every POST has a landing-page
    health GET. Any block, redirect, unreadable response or health failure stops
    the sequence. No retries, cookies, cache busters or alternative endpoints.
    """
    probe = {"attempted": False, "positive": False, "terminal": True,
             "protocol": "waku_component_parser", "responses": [],
             "coverage_state": "skipped", "skip_reason": "waku_default_root_only",
             "reason": "Waku check supports a fingerprinted root application with the default RSC base only."}
    route = {"react_probe": probe, "health_checks": [], "possible_service_impact": False,
             "active_stop_reason": None, "active_request_count": 0}
    if urlsplit(url).path not in ("", "/") or urlsplit(url).query or not waku_indicator(baseline):
        return route
    if not enough_requests(evidence_log, 11):
        probe.update(skip_reason="request_budget", reason="Waku check needs one preflight GET and five POST/health pairs.")
        return route
    endpoint = urljoin(url, "/RSC/R/twoshell-missing-" + secrets.token_hex(16) + ".txt")
    probe["probe_url"] = redacted_url(endpoint)

    def capture(response):
        status = response.get("http_status")
        compact = {key: response.get(key) for key in
                   ("http_status", "error", "body_error", "body_truncated")}
        compact.update(request_evidence_index=len(evidence_log) - 1,
                       response_mitigation=response_mitigation(response))
        if (response_mitigation(response) or status in BLOCKED_STATUSES
                or status is not None and 300 <= status < 400):
            probe.update(coverage_state="blocked", reason="Waku parser path was blocked or redirected.")
            route["active_stop_reason"] = "Waku preflight or probe blocked/redirected; further active requests stopped"
        elif not response.get("reachable"):
            probe.update(coverage_state="error", reason="Waku preflight or probe failed.")
            route["active_stop_reason"] = "Waku preflight or probe failed; further active requests stopped"
        elif response.get("body_error") or response.get("body_truncated"):
            probe.update(coverage_state="inconclusive", reason="Waku response was unreadable or truncated.")
            route["active_stop_reason"] = "Waku response incomplete; further active requests stopped"
        return compact

    def plain_response(response, status, text):
        mime = response.get("headers", {}).get("content-type", "").split(";", 1)[0].strip().lower()
        return response.get("http_status") == status and mime == "text/plain" and response.get("body", "").strip() == text

    preflight = fetch(endpoint, timeout, evidence_log)
    probe["preflight"] = capture(preflight)
    if route["active_stop_reason"]:
        return route
    if not plain_response(preflight, 404, "404 Not Found"):
        probe.update(reason="Random Waku component path did not return the validated missing-route response.",
                     skip_reason="waku_preflight_mismatch")
        return route
    for kind in ("control", "candidate", "present_property_control", "candidate", "control"):
        reference = '["$1:a"]' if kind == "control" else '["$1:a:a"]'
        value = '{"a":{}}' if kind == "present_property_control" else '{}'
        boundary = "----TwoShell" + secrets.token_hex(12)
        body = (f'--{boundary}\r\nContent-Disposition: form-data; name="1"\r\n\r\n{value}\r\n'
                f'--{boundary}\r\nContent-Disposition: form-data; name="0"\r\n\r\n{reference}\r\n'
                f'--{boundary}--\r\n').encode("ascii")
        response = send_request(urllib.request.Request(endpoint, data=body, method="POST",
            headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity",
                     "Content-Type": "multipart/form-data; boundary=" + boundary}), timeout, evidence_log)
        part = capture(response)
        part["kind"] = kind
        part["matches_missing_route"] = plain_response(response, 404, "404 Not Found")
        part["matches_parser_error"] = plain_response(response, 500, "Internal Server Error")
        probe["responses"].append(part)
        probe.update(attempted=True, http_status=response.get("http_status"),
                     request_evidence_index=part["request_evidence_index"])
        route["active_request_count"] += 1
        health = health_after_probe(url, timeout, evidence_log, baseline["http_status"])
        route["health_checks"].append(health)
        route["possible_service_impact"] = not health["healthy"]
        if route["active_stop_reason"] or not health["healthy"]:
            probe["coverage_state"] = "inconclusive" if not health["healthy"] else probe["coverage_state"]
            if not health["healthy"]:
                probe["reason"] = "Landing-page health changed after a Waku probe; assessment stopped."
            return route
        if kind != "candidate" and not part["matches_missing_route"]:
            probe.update(coverage_state="inconclusive", reason="Waku benign control did not match the missing-route response.")
            return route
        if kind == "candidate" and not part["matches_parser_error"]:
            prior_error = any(row["matches_parser_error"] for row in probe["responses"][:-1])
            probe.update(coverage_state="completed_no_signature" if part["matches_missing_route"] and not prior_error else "inconclusive",
                         reason="Waku parser difference absent or ambiguous; patch status remains unknown.")
            return route
    probe.update(positive=True, coverage_state="detected", signature="repeated_waku_component_difference",
                 reason="Fingerprinted Waku root: two parser errors and three missing-component controls, including a present-property control.")
    return route


def react_digest_probe(url, timeout, reference='["$1:a:a"]', evidence_log=None, action_id=None):
    """One bounded Next.js Server Action parser request. See NOTICE for provenance.

    The malformed property reference requests no function call or code execution.
    A request-level 500 is expected on a matching server. The benign reference
    is used as a control only after a candidate match.
    """
    boundary = "----TwoShell" + secrets.token_hex(12)
    body = (f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="1"\r\n\r\n'
            '{}\r\n'
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="0"\r\n\r\n'
            f'{reference}\r\n'
            f"--{boundary}--\r\n").encode("ascii")
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity",
                 "Content-Type": f"multipart/form-data; boundary={boundary}",
                 "Next-Action": action_id or secrets.token_hex(16),
                 "X-Nextjs-Request-Id": str(uuid.uuid4()),
                 "Next-Router-State-Tree": '[[["",{"children":["__PAGE__",{}]},null,null,true]]'})
    evidence_index = len(evidence_log) if evidence_log is not None else None
    response = send_request(request, timeout, evidence_log)
    if not response["reachable"]:
        return {"attempted": True, "positive": False, "error": response["error"],
                "request_evidence_index": evidence_index,
                "reason": "Probe request failed; no React verdict can be drawn."}
    body = response["body"]
    signature = react_signature(body)
    content_type = response.get("headers", {}).get("content-type", "").split(";", 1)[0].strip().lower()
    unexpected_type = response["http_status"] == 500 and signature is not None and content_type != "text/x-component"
    positive = (not response_mitigation(response) and content_type == "text/x-component"
                and not response.get("body_error") and not response.get("body_truncated")
                and response["http_status"] == 500 and signature is not None)
    return {"attempted": True, "positive": positive,
            "response_mitigation": response_mitigation(response),
            "ambiguous": unexpected_type,
            "body_error": response.get("body_error"),
            "marker_present": signature is not None,
            "content_type": content_type,
            "next_html_marker": "__next_f" in response.get("body", "")[:8000],
            "body_truncated": response.get("body_truncated", False),
            "request_evidence_index": evidence_index,
            "http_status": response["http_status"],
            "signature": signature if positive else None,
            "reason": ("500/digest appeared outside a Flight response; generic HTML/JSON errors are inconclusive."
                       if unexpected_type else "Next.js parser returned a candidate 500/digest pattern."
                       if positive else "500/digest patterns absent; this does not prove React is patched.")}


def health_after_probe(url, timeout, evidence_log=None, baseline_status=None):
    """A single ordinary GET to detect obvious service degradation before more probes."""
    evidence_index = len(evidence_log) if evidence_log is not None else None
    response = fetch(url, timeout, evidence_log)
    healthy = (response["reachable"] and usable_baseline_status(response["http_status"])
               and not response_mitigation(response)
               and not response.get("body_error") and not response.get("body_truncated")
               and (baseline_status is None or response["http_status"] == baseline_status))
    return {"reachable": response["reachable"],
            "request_evidence_index": evidence_index,
            "http_status": response.get("http_status"),
            "error": response.get("error"),
            "response_mitigation": response_mitigation(response),
            "healthy": healthy}


def response_mitigation(response):
    """An explicit challenge response is not application evidence. Hosting names
    alone do not establish that a request was blocked or that code is patched.
    https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/
    """
    value = response.get("headers", {}).get("cf-mitigated", "")
    return "cloudflare_challenge" if value.strip().lower() == "challenge" else None


def usable_baseline_status(status):
    return 200 <= status < 300 or status in (404, 405)


def observations(response):
    if not response["reachable"]:
        return []
    h = response.get("headers", {})
    body = response["body"][:8000].lower()
    notes = []
    match = re.search(r"\bphp/(\d+\.\d+\.\d+)",
                      h.get("x-powered-by", "") + " " + h.get("server", ""), re.I)
    if match:
        state = version_state("php", match.group(1))
        notes.append(f"PHP/{match.group(1)} advertised in a header ({state} upstream range); "
                     "headers can be stale or spoofed and vendor backports may apply.")
    elif "phpsessid" in h.get("set-cookie", "").lower():
        notes.append("PHPSESSID cookie seen; PHP patch level remains unknown.")
    if "__next_f" in body or "x-nextjs-cache" in h or "next.js" in h.get("x-powered-by", "").lower():
        notes.append("Next.js/RSC indicator seen; package and router versions remain unknown.")
    if h.get("content-encoding", "").lower() == "br":
        notes.append("Brotli response encoding seen; this says nothing about the server's decoder.")
    return notes


def run_active_route(url, baseline, timeout, want_php, want_react, evidence_log, error_triage=False, waku=False):
    """Probe one known route; stop this route immediately on health failure."""
    active_ready = (not urlsplit(url).query and baseline["reachable"] and not baseline.get("body_error")
                    and not response_mitigation(baseline)
                    and not baseline.get("body_truncated")
                    and usable_baseline_status(baseline["http_status"]))
    php_probe = None
    react_probe = None
    health_checks = []
    impact_alert = False
    stop_reason = "explicit challenge response on baseline" if response_mitigation(baseline) else None
    if want_php and active_ready and enough_requests(evidence_log, 2):
        php_probe = php_warning_probe(url, timeout, evidence_log)
        markers = ("Session ID is too long or contains illegal characters",
                   "Failed to read session data", "Failed to write session data (")
        if php_probe["positive"] and all(marker in baseline["body"] for marker in markers):
            php_probe["positive"] = False
            php_probe["ambiguous"] = True
            php_probe["reason"] = "Warning sequence was already present in GET response; probe evidence is ambiguous."
        health_checks.append(health_after_probe(url, timeout, evidence_log, baseline.get("http_status")))
        impact_alert = not health_checks[-1]["healthy"]
        if php_probe.get("response_mitigation"):
            stop_reason = "explicit challenge response after PHP probe"
        elif php_probe.get("http_status") in BLOCKED_STATUSES:
            stop_reason = "authentication, WAF block, or rate limit after PHP probe"
        elif 300 <= php_probe.get("http_status", 0) < 400:
            stop_reason = "PHP probe redirected; further active requests stopped"
        elif php_probe.get("error"):
            stop_reason = "PHP probe failed; further active requests stopped"
    elif want_php:
        php_probe = {"attempted": False, "positive": False,
                     "skip_reason": "request_budget" if active_ready else "baseline_not_usable",
                     "reason": "Baseline was unreachable, gated, redirected, errored, unreadable, or had a query string; PHP probe skipped."}
        if active_ready:
            php_probe["reason"] = "Request budget cannot fit PHP POST and its health GET."
    if want_react and active_ready and not impact_alert and not stop_reason and waku and waku_indicator(baseline):
        waku_route = waku_component_probe(url, baseline, timeout, evidence_log)
        waku_route.update(url=redacted_url(url), php_probe=php_probe)
        waku_route["health_checks"] = health_checks + waku_route["health_checks"]
        waku_route["active_request_count"] += int(bool(php_probe and php_probe["attempted"]))
        return waku_route
    if want_react and active_ready and not impact_alert and not stop_reason and enough_requests(evidence_log, 4):
        action_id = secrets.token_hex(16)
        react_probe = react_digest_probe(url, timeout, evidence_log=evidence_log, action_id=action_id)
        if react_probe["positive"] and react_signature(baseline["body"]):
            react_probe["positive"] = False
            react_probe["ambiguous"] = True
            react_probe["reason"] = "Digest signature was already in the GET response; probe evidence is ambiguous."
        react_probe["candidate_signature"] = react_probe["positive"]
        health_checks.append(health_after_probe(url, timeout, evidence_log, baseline.get("http_status")))
        impact_alert = not health_checks[-1]["healthy"]
        if react_probe.get("response_mitigation"):
            stop_reason = "explicit challenge response after React probe"
        elif react_probe.get("http_status") in BLOCKED_STATUSES:
            stop_reason = "authentication, WAF block, or rate limit after React probe"
        elif 300 <= react_probe.get("http_status", 0) < 400:
            stop_reason = "React probe redirected; further active requests stopped"
        elif react_probe.get("error"):
            stop_reason = "React probe failed; further active requests stopped"
        masked_candidate = (error_triage and not react_probe.get("response_mitigation") and react_probe.get("http_status") == 500
                            and not react_probe.get("marker_present")
                            and not react_probe.get("body_error") and not react_probe.get("body_truncated")
                            and not react_signature(baseline["body"])
                            and any("Next.js/RSC indicator" in note for note in observations(baseline)))
        if (react_probe["positive"] or masked_candidate) and not impact_alert and not stop_reason:
            control = react_digest_probe(url, timeout, '["$1:a"]', evidence_log, action_id=action_id)
            react_probe["control"] = control
            health_checks.append(health_after_probe(url, timeout, evidence_log, baseline.get("http_status")))
            impact_alert = not health_checks[-1]["healthy"]
            if control.get("response_mitigation"):
                stop_reason = "explicit challenge response after React control"
            elif control.get("http_status") in BLOCKED_STATUSES:
                stop_reason = "authentication, WAF block, or rate limit after React control"
            elif 300 <= control.get("http_status", 0) < 400:
                stop_reason = "React control redirected; further active requests stopped"
            elif control.get("error"):
                stop_reason = "React control failed; further active requests stopped"
            # Next 15.1.x renders a normal Next HTML page with 200 when the
            # benign reference resolves to no registered action. Do not accept
            # a generic 200: require Next indicators on baseline AND control,
            # HTML control content type, and a strict Flight candidate response.
            missing_action_404 = control.get("http_status") == 404
            next_html_200 = (control.get("http_status") == 200 and control.get("content_type") == "text/html"
                             and control.get("next_html_marker") and react_probe.get("signature") == "flight_digest"
                             and react_probe.get("content_type") == "text/x-component"
                             and any("Next.js/RSC indicator" in note for note in observations(baseline)))
            if (react_probe["positive"] and (missing_action_404 or next_html_200) and not control.get("body_error") and not control.get("body_truncated")
                    and not control.get("marker_present") and not impact_alert and not stop_reason):
                react_probe["control_variant"] = "missing_action_404" if missing_action_404 else "next_html_200"
                react_probe["reason"] = ("Malformed reference returned 500/digest ("
                                         + react_probe["signature"] + "); benign control matched "
                                         + react_probe["control_variant"] + ".")
            elif masked_candidate:
                masked_control = (missing_action_404 or (control.get("http_status") == 200
                                  and control.get("content_type") == "text/html" and control.get("next_html_marker")))
                if (masked_control and not control.get("body_error") and not control.get("body_truncated")
                        and not control.get("marker_present") and not impact_alert and not stop_reason):
                    react_probe["differential_signal"] = {
                        "kind": "masked_error_difference", "candidate_status": 500,
                        "control_status": control["http_status"]}
                    react_probe["reason"] = ("Candidate returned 500 without a digest and benign control differed; "
                                             "review signal only, not evidence of this CVE.")
                else:
                    react_probe["reason"] = "Error triage did not establish a usable candidate/control difference; patch status remains unknown."
            else:
                react_probe["positive"] = False
                react_probe["reason"] = ("Candidate signature observed, but benign control did not match a validated response "
                                         "or service health changed; React verdict is inconclusive.")
        elif react_probe["positive"]:
            react_probe["positive"] = False
            react_probe["reason"] = "Candidate signature observed, but the health GET failed before confirmation."
    elif want_react:
        react_probe = {"attempted": False, "positive": False,
                       "skip_reason": ("active_stopped" if impact_alert or stop_reason else
                                       "request_budget" if active_ready else "baseline_not_usable"),
                       "reason": ("Further probes stopped: " + stop_reason if stop_reason else
                                  "Service health check failed after PHP probe; React probe skipped."
                                  if impact_alert else
                                  "Baseline was unreachable, gated, redirected, errored, unreadable, or had a query string; React probe skipped.")}
        if active_ready and not impact_alert and not stop_reason:
            react_probe["reason"] = "Request budget cannot fit React candidate, possible control, and both health GETs."
    active_count = sum(bool(probe and probe["attempted"]) for probe in (php_probe, react_probe))
    active_count += int(bool(react_probe and react_probe.get("control", {}).get("attempted")))
    return {"url": redacted_url(url), "php_probe": php_probe, "react_probe": react_probe,
            "health_checks": health_checks, "possible_service_impact": impact_alert,
            "active_stop_reason": stop_reason,
            "active_request_count": active_count}


def run_sampled_route(url, baseline, timeout, want_php, want_react, evidence_log,
                      samples=1, error_triage=False, waku=False):
    """Bounded opt-in resampling, never a retry of a blocked/failed request.

    Samples are observations, not distinct replicas. Stop each family after a
    finding and all families on a health, transport, redirect, or gating stop.
    """
    rounds = []
    pending_php, pending_react = want_php, want_react
    stop = "sample_limit"
    for _ in range(samples):
        row = run_active_route(url, baseline, timeout, pending_php, pending_react,
                               evidence_log, error_triage, waku)
        rounds.append(row)
        if row["possible_service_impact"] or row["active_stop_reason"]:
            stop = "health_check_failed" if row["possible_service_impact"] else row["active_stop_reason"]
            break
        for key in ("php_probe", "react_probe"):
            probe = row[key]
            parts = ([probe] + ([probe["control"]] if probe.get("control") else [])) if probe else []
            done = (not probe or not probe.get("attempted") or probe.get("positive") or probe.get("terminal")
                    or any(part.get("body_error") or part.get("body_truncated") for part in parts))
            if key == "php_probe" and done:
                pending_php = False
            elif key == "react_probe" and done:
                pending_react = False
        if not (pending_php or pending_react):
            stop = "no_remaining_eligible_checks"
            break
    merged = {"url": redacted_url(url), "samples": rounds, "samples_requested": samples,
              "sampling_stop_reason": stop,
              "health_checks": [check for row in rounds for check in row["health_checks"]],
              "possible_service_impact": any(row["possible_service_impact"] for row in rounds),
              "active_stop_reason": rounds[-1]["active_stop_reason"],
              "active_request_count": sum(row["active_request_count"] for row in rounds)}
    for key in ("php_probe", "react_probe"):
        probes = [row[key] for row in rounds if row[key] is not None]
        attempted = [probe for probe in probes if probe.get("attempted")]
        selected = (next((probe for probe in probes if probe.get("positive")), None)
                    or next((probe for probe in probes if probe.get("differential_signal")), None)
                    or (attempted[-1] if attempted else probes[-1] if probes else None))
        merged[key] = dict(selected) if selected is not None else None
        if selected is not None:
            merged[key]["samples_attempted"] = len(attempted)
            merged[key]["sample_responses"] = attempted
            signals = [probe["differential_signal"] for probe in attempted if probe.get("differential_signal")]
            if signals and not merged[key].get("positive"):
                matching = sum(signal == signals[0] for signal in signals)
                merged[key]["review_signal"] = dict(signals[0], matching_samples=matching,
                    repeatable=matching >= 2, establishes_vulnerability=False,
                    limitation="Generic application errors and mixed replicas can produce this difference.")
    return merged


def route_coverage(entry, probe, enabled, route_stop=None):
    """Describe actual visibility without treating an absent signature as safety."""
    coverage = {"url": redacted_url(entry["url"]), "source": entry["source"]}
    baseline = entry["response"]
    state, reason = "skipped", entry.get("skip_reason", "no_technology_indicator")
    if not enabled:
        state, reason = "not_enabled", "active_probe_not_enabled"
    elif not baseline["reachable"]:
        state = "skipped" if baseline.get("error") == "request_budget_exhausted" else "error"
        reason = baseline.get("error", "network_error")
    elif baseline.get("http_status") in BLOCKED_STATUSES:
        state, reason = "blocked", "baseline_http_" + str(baseline["http_status"])
    elif probe and probe.get("attempted"):
        samples = probe.get("sample_responses", [probe])
        parts = [part for sample in samples for part in
                 ([sample] + ([sample["control"]] if sample.get("control") else []))]
        if probe.get("positive"):
            state, reason = "detected", "behavioral_signature"
        elif any(part.get("response_mitigation") for part in parts):
            state, reason = "blocked", "explicit_platform_challenge"
        elif any(part.get("http_status") in BLOCKED_STATUSES for part in parts):
            state, reason = "blocked", "authentication_waf_or_rate_limit"
        elif any(part.get("error") for part in parts):
            state, reason = "error", "probe_or_control_failed"
        elif any(300 <= part.get("http_status", 0) < 400 for part in parts):
            state, reason = "blocked", "post_redirect_not_followed"
        elif (any(part.get("body_error") or part.get("body_truncated") for part in parts)
              or any(sample.get("ambiguous") or sample.get("candidate_signature") for sample in samples)):
            state, reason = "inconclusive", "unreadable_or_ambiguous_probe_response"
        elif probe.get("review_signal"):
            state, reason = "inconclusive", "masked_error_difference_requires_review"
        else:
            state, reason = "completed_no_signature", "absence_of_signature_does_not_establish_patch_status"
        coverage["http_status"] = probe.get("http_status")
        coverage["request_evidence_index"] = probe.get("request_evidence_index")
        coverage["samples_attempted"] = probe.get("samples_attempted", 1)
        if probe.get("review_signal"):
            coverage["review_signal"] = probe["review_signal"]
    elif probe:
        reason = probe.get("skip_reason", "baseline_not_usable")
    elif route_stop:
        reason = route_stop
    if enabled and not (probe and probe.get("attempted")):
        if response_mitigation(baseline):
            state, reason = "blocked", "explicit_platform_challenge"
        elif baseline.get("body_error") or baseline.get("body_truncated"):
            state, reason = "inconclusive", "baseline_unreadable_or_truncated"
        elif urlsplit(entry["url"]).query:
            state, reason = "skipped", "query_string"
        elif 300 <= baseline.get("http_status", 0) < 400:
            state, reason = "blocked", "get_redirect_unresolved"
        elif baseline.get("http_status", 0) >= 500:
            state, reason = "skipped", "baseline_server_error"
    coverage.update(state=state, reason=reason)
    if probe and probe.get("protocol") == "waku_component_parser":
        state = probe["coverage_state"]
        coverage.update(state=state, reason=probe["reason"], remote_check="waku_component_parser",
                        probe_url=probe.get("probe_url"))
    if state == "blocked":
        coverage["next_step"] = ("Review authentication, redirects, and gateway policy with the client. "
                                 "For a confirmed WAF block, arrange a narrow scanner allowlist and rescan; "
                                 "honor rate limits. A block does not establish backend patch status.")
    elif state != "detected":
        coverage["next_step"] = (
            "Confirm the final application URL and supply known-safe application routes; review skipped routes and budgets. "
            "If this remains inconclusive, request deployed package/configuration evidence from the client. "
            "Do not treat an absent signature as clearance.")
    return coverage


def attach_coverage(checks, entries, routes, want_php, want_react, skipped_discovery, active_stop):
    route_map = {route["url"]: route for route in routes}
    for item in checks:
        family = item["family"]
        if family == "HTTP2Shell":
            item["coverage"] = {
                "state": "no_supported_remote_check", "remote_check": None, "routes": [],
                "negative_is_clearance": False,
                "next_step": "Ask the client for the Brotli decoder and hosting runtime versions; do not send malformed compressed data to production.",
                "limitations": ["No active Brotli decoder probe is implemented; HTTP response compression cannot establish decoder patch status."]}
            if item["status"] == "unknown":
                item["reason"] = "No supported remote Brotli decoder check; URL-only patch status remains unknown."
            continue
        php = family == "PHP2Shell"
        enabled, key = (want_php, "php_probe") if php else (want_react, "react_probe")
        per_route = []
        for entry in entries:
            route = route_map.get(redacted_url(entry["url"]), {})
            row = route_coverage(entry, route.get(key), enabled, active_stop)
            if (item["cve"] == "CVE-2025-66478" and row.get("remote_check") == "waku_component_parser"):
                row.update(state="not_enabled", reason="Waku evidence does not assess the Next.js-specific CVE.")
            per_route.append(row)
        for skipped in skipped_discovery:
            per_route.append({"url": skipped["url"], "source": skipped["source"],
                              "state": "skipped" if enabled else "not_enabled", "reason": skipped["reason"]})
        counts = {}
        for row in per_route:
            counts[row["state"]] = counts.get(row["state"], 0) + 1
        states = set(counts)
        state = ("detected" if "detected" in states else "not_enabled" if not enabled else
                 next(iter(states)) if len(states) == 1 else "partial")
        used_waku = any(row.get("remote_check") == "waku_component_parser" for row in per_route)
        item["coverage"] = {
            "state": state, "remote_check": "php_session_warnings" if php else
                "nextjs_and_waku_parser_differentials" if used_waku else "nextjs_parser_differential",
            "route_counts": counts, "routes": per_route, "negative_is_clearance": False,
            "limitations": (["Hidden PHP warnings can make affected and fixed builds indistinguishable."] if php else
                            ["Next.js and opt-in default-root Waku checks are supported; other RSC frameworks and custom Waku bases remain unassessed."])
                           + ["Only listed routes were considered; unauthenticated, bounded requests do not cover every route or serving replica.",
                              "Repeated samples do not establish distinct replicas; sticky routing can conceal an affected instance."]}
        if item["status"] == "unknown" and not item.get("evidence_conflict"):
            item["reason"] = "Remote coverage: " + state + "; patch status remains unknown. See per-route coverage and limitations."


def attach_outcomes(report):
    """Separate remote detection, coverage, and evidence-backed applicability.

    Retain legacy outcomes, deployment status and exit codes. A skipped discovery
    page without technology indicators is a coverage limit, not an ambiguous
    detection response. Blocks, failures and ambiguous responses remain distinct.
    """
    for item in report["results"]:
        coverage = item.get("coverage", {})
        state = coverage.get("state")
        routes = coverage.get("routes", [])
        completed = [row for row in routes if row["state"] == "completed_no_signature"]
        unselected = [row for row in routes if row["state"] == "skipped"
                      and row.get("source") == "discovered"
                      and row.get("reason") == "no_technology_indicator"]
        benign_partial = (state == "partial" and completed and unselected
                          and len(completed) + len(unselected) == len(routes)
                          and not report.get("active_stop_reason"))
        rejected = [row for row in routes if row.get("http_status") == 405]
        if state == "detected":
            outcome, explanation = "vulnerability detected", "A supported behavioral signature was observed; this is not an execution-based proof."
        elif state in ("not_enabled", "no_supported_remote_check", "skipped"):
            outcome = "not assessed"
            explanation = ("No supported remote check is available; patch status unverified."
                           if state == "no_supported_remote_check" else
                           "The active check was disabled or skipped; patch status unverified.")
        elif report.get("possible_service_impact"):
            outcome = "inconclusive"
            explanation = "A post-probe health check failed; review service health before retrying."
        elif state == "completed_no_signature" or benign_partial:
            outcome = "no vulnerability detected"
            explanation = ("Detection POSTs were rejected with HTTP 405 on one or more tested URLs. "
                           "Coverage limited; patch status unverified." if rejected else
                           "No vulnerability signature found on the tested routes; patch status unverified.")
            if unselected:
                explanation += " Additional discovered pages had no relevant technology indicators and were not actively tested."
        elif state == "blocked":
            outcome = "blocked"
            explanation = "Authentication, gateway policy, rate limiting, or a redirect prevented assessment."
        elif state == "error":
            outcome = "check failed"
            explanation = "A baseline, probe, or control request failed; patch status unverified."
        else:
            outcome = "inconclusive"
            explanation = "Coverage was partial or responses were ambiguous; review the per-route evidence."
        item["detection"] = {"result": outcome, "reason": explanation,
                             "signature_detected": state == "detected"}
        details = []
        if state == "no_supported_remote_check":
            details.append("No supported remote check is available.")
        elif state == "not_enabled":
            details.append("The remote check was not enabled.")
        else:
            details.append(f"{len(routes)} route(s) considered; {len(completed)} with completed no-signature responses.")
        if rejected:
            details.append(f"POST checks were not accepted (HTTP 405) on {len(rejected)} route(s).")
        if unselected:
            details.append(f"{len(unselected)} discovered page(s) had no relevant technology indicator and were not actively tested.")
        if any(row["state"] in {"blocked", "error", "inconclusive"} for row in routes):
            details.append("Some routes were blocked, failed, or returned ambiguous responses; review per-route evidence.")
        if any(row["state"] == "skipped" and row not in unselected for row in routes):
            details.append("Additional checks were skipped; review route reasons and request limits.")
        if report.get("discovery_summary", {}).get("partial") and state not in {"no_supported_remote_check", "not_enabled"}:
            details.append("Bounded discovery left some resources or routes unread.")
        if report.get("possible_service_impact") and state not in {"no_supported_remote_check", "not_enabled"}:
            details.append("A post-probe health check failed.")
        coverage["limited"] = bool(state not in {"detected", "completed_no_signature"} or rejected
                                   or any(row["state"] not in {"detected", "completed_no_signature"} for row in routes)
                                   or report.get("possible_service_impact")
                                   or report.get("discovery_summary", {}).get("partial"))
        coverage["summary"] = " ".join(details)
        item.setdefault("applicability", result(item["family"], item["cve"], item["status"], item["reason"],
                                               item.get("confidence"))["applicability"])
        if item["status"] in ("vulnerable", "not vulnerable"):
            outcome, explanation = item["status"], item["reason"]
        item.update(outcome=outcome, outcome_reason=explanation)


def atomic_report(path, writer):
    """Replace a completed file atomically; a failed write stops batch scanning."""
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="",
                                         dir=str(path.parent), prefix=".writing-", delete=False) as stream:
            temporary = Path(stream.name)
            writer(stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(str(temporary), str(path))
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def write_json_report(path, value):
    atomic_report(path, lambda stream: json.dump(value, stream, indent=2, ensure_ascii=True))


def save_batch_progress(folder, summary):
    rows = summary["targets"]
    completed = [row for row in rows if row["state"] == "completed"]
    summary["updated_at"] = datetime.now(timezone.utc).isoformat()
    summary["counts"] = {
        "targets_total": len(rows), "targets_completed": len(completed),
        "targets_pending": sum(row["state"] == "pending" for row in rows),
        "targets_skipped": sum(row["state"] == "skipped_origin" for row in rows),
        "targets_with_findings": sum(bool(row.get("positive_cves")) for row in completed),
        "targets_with_review_signals": sum(bool(row.get("review_signals")) for row in completed),
        "targets_with_network_errors": sum(row.get("exit_code") == 2 for row in completed),
        "request_count": sum(row.get("request_count", 0) for row in completed),
        "active_request_count": sum(row.get("active_request_count", 0) for row in completed),
        "request_counts_complete": not any(row["state"] in {"running", "interrupted", "error"} for row in rows)}
    summary["all_targets_scanned"] = len(completed) == len(rows)
    write_json_report(folder / "summary.json", summary)

    cves = [cve for values in CVES.values() for cve in values]
    def write_csv(stream):
        columns = ["url", "scan_state", "exit_code", "request_count", "active_request_count",
                   "positive_cves", "review_signals", "report_file", "reason",
                   "network_error_kind", "redirect_target", "redirect_stop_reason"]
        columns += [field for cve in cves for field in
                    (cve, cve + " coverage", cve + " status", cve + " outcome reason",
                     cve + " detection", cve + " detection reason", cve + " coverage summary",
                     cve + " applicability", cve + " applicability basis", cve + " applicability reason")]
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            values = {name: row.get(name, "") for name in columns[:12]}
            values["scan_state"] = row["state"]
            values["positive_cves"] = "; ".join(row.get("positive_cves", []))
            values["review_signals"] = "; ".join(row.get("review_signals", []))
            results = {item["cve"]: item for item in row.get("results", [])}
            for cve in cves:
                item = results.get(cve, {})
                values[cve] = item.get("outcome", "not assessed")
                values[cve + " coverage"] = item.get("coverage", "not_scanned")
                values[cve + " status"] = item.get("status", "not_scanned")
                values[cve + " outcome reason"] = item.get("outcome_reason", "No completed result is available.")
                values[cve + " detection"] = item.get("detection", {}).get("result", "not assessed")
                values[cve + " detection reason"] = item.get("detection", {}).get("reason", "No completed result is available.")
                values[cve + " coverage summary"] = item.get("coverage_summary", "No completed coverage is available.")
                for key in ("state", "basis", "reason"):
                    field = " applicability" + ("" if key == "state" else " " + key)
                    values[cve + field] = item.get("applicability", {}).get(key, "unknown")
            writer.writerow(values)
    atomic_report(folder / "summary.csv", write_csv)
    # Never automatically retry an interrupted, blocked, or health-alert target.
    atomic_report(folder / "remaining.txt", lambda stream: stream.write(
        "".join(row["url"] + "\n" for row in rows if row["state"] == "pending")))


def run_batch(args, targets, duplicates):
    name = args.output_dir or ("twoshell-reports-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-")
                               + secrets.token_hex(3))
    folder = Path(name).absolute()
    folder.mkdir(mode=0o700, parents=False, exist_ok=False)
    summary = {
        "checker_version": USER_AGENT, "mode": "sequential_url_batch", "output_dir": str(folder),
        "started_at": datetime.now(timezone.utc).isoformat(), "state": "in_progress", "exit_code": None,
        "duplicate_entries_skipped": duplicates, "negative_is_clearance": False,
        "cves_not_assessed": CVES_NOT_ASSESSED,
        "limits": {"max_requests_per_target": args.max_requests,
                   "max_get_response_bytes": args.max_get_bytes, "max_post_response_bytes": args.max_post_bytes,
                   "max_active_routes_per_target": args.max_active_routes,
                   "max_samples_per_check_per_route": args.samples,
                   "request_interval_seconds": args.request_interval,
                   "site_interval_seconds": max(args.site_interval, args.request_interval),
                   "request_upper_bound": args.max_requests * len(targets), "concurrency": 1},
        "options": {"php_probe": args.php_probe or args.active,
                    "react_probe": args.react_probe or args.active, "discover": args.discover,
                    "discover_js": args.discover_js, "discover_sitemaps": args.discover_sitemaps,
                    "react_error_triage": args.react_error_triage},
        "targets": [{"url": url, "state": "pending", "report_file": None} for url in targets]}
    stopped_origins = []
    save_batch_progress(folder, summary)  # Verify report storage before first network request.
    print("Batch reports: " + str(folder), file=sys.stderr, flush=True)
    current = None
    try:
        for index, row in enumerate(summary["targets"], 1):
            current = row
            if any(same_origin(row["url"], origin) for origin in stopped_origins):
                row.update(state="skipped_origin", reason="Earlier target on this origin was gated or stopped active checks; review before rescanning.")
                save_batch_progress(folder, summary)
                continue
            if any(item["state"] == "completed" for item in summary["targets"]):
                time.sleep(max(args.site_interval, args.request_interval))
            row["state"] = "running"
            save_batch_progress(folder, summary)
            print("[%d/%d] %s" % (index, len(targets), row["url"]), file=sys.stderr, flush=True)
            report, code = scan_target(args, row["url"])
            filename = "%04d-%s.json" % (index, hashlib.sha256(row["url"].encode("ascii")).hexdigest()[:12])
            write_json_report(folder / filename, report)
            row.update(state="completed", exit_code=code, report_file=filename,
                       network_error_kind=report["network_error_kind"],
                       redirect_target=report["redirect_target"], redirect_stop_reason=report["redirect_stop_reason"],
                       request_count=report["request_count"], active_request_count=report["active_request_count"],
                       possible_service_impact=report["possible_service_impact"],
                       positive_cves=[item["cve"] for item in report["results"] if item["status"] == "vulnerable"],
                       results=[{"family": item["family"], "cve": item["cve"], "status": item["status"],
                                 "confidence": item["confidence"], "coverage": item["coverage"]["state"],
                                 "outcome": item["outcome"], "outcome_reason": item["outcome_reason"],
                                 "detection": item["detection"], "coverage_summary": item["coverage"]["summary"],
                                 "coverage_limited": item["coverage"]["limited"], "applicability": item["applicability"]}
                                for item in report["results"]],
                       review_signals=sorted({probe["review_signal"]["kind"]
                           for route in report["route_probes"] for probe in [route.get("react_probe")]
                           if probe and probe.get("review_signal")}),
                       reason=report["active_stop_reason"] or report["error"] or "")
            if report["active_stop_reason"] or report["http_status"] in BLOCKED_STATUSES:
                stopped_origins.append(row["url"])
            if code == 4:
                summary.update(state="stopped_health", exit_code=4)
                save_batch_progress(folder, summary)
                break
            save_batch_progress(folder, summary)
        else:
            codes = {row.get("exit_code") for row in summary["targets"]}
            code = 1 if 1 in codes else 2 if 2 in codes else 3 if 3 in codes or None in codes else 0
            summary.update(state="completed", exit_code=code)
    except KeyboardInterrupt:
        if current is not None and current["state"] == "running":
            current.update(state="interrupted", reason="Scan interrupted; requests may have been sent. Review before retrying.")
        summary.update(state="interrupted", exit_code=130)
    except OSError:
        # Persistence errors fail closed. Existing completed files remain available.
        raise
    except Exception as exc:
        if current is not None and current["state"] == "running":
            current.update(state="error", reason="Internal scanner error: " + type(exc).__name__)
        summary.update(state="error", exit_code=2)
    save_batch_progress(folder, summary)
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        counts = summary["counts"]
        print("Batch %s: %d/%d targets scanned; %d with findings; %d with review signals." %
              (summary["state"], counts["targets_completed"], counts["targets_total"],
               counts["targets_with_findings"], counts["targets_with_review_signals"]))
        print("Reports and combined summaries: " + str(folder))
        print("No vulnerability detected is not a patch-status clearance; review coverage for incomplete or unassessed checks.")
    return summary["exit_code"]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", nargs="?", help="HTTP(S) URL to check (or use --urls-file)")
    parser.add_argument("--urls-file", metavar="FILE",
                        help="Batch: up to 1000 HTTP(S) URLs, one per line; blank lines and # comments allowed")
    parser.add_argument("--output-dir", metavar="DIR",
                        help="Batch: create a NEW directory for site reports and summary.json/summary.csv")
    parser.add_argument("--site-interval", type=float, default=1.0,
                        help="Batch: pause between target scans in seconds (default 1; maximum 60)")
    parser.add_argument("--inventory", help="Trusted JSON inventory of the deployed components (see README)")
    parser.add_argument("--php-probe", action="store_true",
                        help="Opt in to one small multipart POST that checks the PHP session-warning signature")
    parser.add_argument("--react-probe", action="store_true",
                        help="Opt in to a Next.js parser POST and a benign control after a candidate match")
    parser.add_argument("--active", action="store_true",
                        help="Run both bounded active probes, each followed by a health GET")
    parser.add_argument("--profile", choices=("standard", "expanded"), default="standard",
                        help="Expanded opts into active checks, bounded HTML/JS/sitemap discovery, Waku and error triage; 60 requests, 2 samples, 1-second spacing by default")
    parser.add_argument("--waku-probe", action="store_true",
                        help="With a React probe, use a component-only check on fingerprinted default-root Waku apps")
    parser.add_argument("--samples", type=int, default=None,
                        help="Maximum samples per enabled check per route (default 1; maximum 3); stop after a finding")
    parser.add_argument("--react-error-triage", action="store_true",
                        help="With a React probe, compare a benign control after a readable Next.js 500 without a digest; review only")
    parser.add_argument("--discover", action="store_true",
                        help="Follow same-origin GET redirects and discover HTML links to two levels")
    parser.add_argument("--discover-js", action="store_true",
                        help="With --discover, read at most two linked same-origin JS files for static URL hints")
    parser.add_argument("--discover-sitemaps", action="store_true",
                        help="With --discover, read at most two same-origin sitemap files, starting at /sitemap.xml")
    parser.add_argument("--routes-file", metavar="FILE",
                        help="Up to ten known-safe same-origin URLs or /paths, one per line; # comments allowed")
    parser.add_argument("--max-discovery-pages", type=int, default=8,
                        help="Maximum linked pages to fetch, excluding supplied URLs (default 8; maximum 20)")
    parser.add_argument("--max-active-routes", type=int, default=3,
                        help="Maximum routes receiving POSTs (default 3; maximum 6)")
    parser.add_argument("--max-requests", type=int, default=None,
                        help="Total request cap including redirects and health GETs (default 40; maximum 120)")
    parser.add_argument("--request-interval", type=float, default=None,
                        help="Minimum pause between sequential requests in seconds (default 0.2; maximum 5)")
    parser.add_argument("--probe-path", action="append", default=[], metavar="/PATH",
                        help="Additional known-safe same-origin route to probe (at most two; no query string)")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument("--timeout", type=float, default=5.0, help="Request timeout in seconds (default: 5)")
    parser.add_argument("--max-get-bytes", type=int, default=GET_BODY_LIMIT,
                        help="Maximum GET/health response bytes before and after decoding (65536–1048576; default 1048576)")
    parser.add_argument("--max-post-bytes", type=int, default=BODY_LIMIT,
                        help="Maximum POST response bytes before and after decoding (65536–1048576; default 65536); does not change request payloads")
    args = parser.parse_args(argv)
    expanded = args.profile == "expanded"
    if expanded:
        args.active = args.discover = args.discover_js = args.discover_sitemaps = True
        args.react_error_triage = args.waku_probe = True
    for name, value in {"samples": 2 if expanded else 1, "max_requests": 60 if expanded else 40,
                        "request_interval": 1.0 if expanded else 0.2}.items():
        if getattr(args, name) is None:
            setattr(args, name, value)
    try:
        if bool(args.url) == bool(args.urls_file):
            raise ValueError("provide exactly one URL or --urls-file")
        if args.urls_file and (args.inventory or args.routes_file or args.probe_path):
            raise ValueError("--inventory, --routes-file, and --probe-path are single-target options; list application URLs in --urls-file")
        if not args.urls_file and (args.output_dir or args.site_interval != 1.0):
            raise ValueError("--output-dir and --site-interval require --urls-file")
        if not 0 <= args.site_interval <= 60:
            raise ValueError("site-interval must be between 0 and 60 seconds")
        targets, duplicates = load_urls(args.urls_file) if args.urls_file else ([], 0)
        url = validate_url(targets[0] if targets else args.url)
        if not 0 < args.timeout <= 60:
            raise ValueError("timeout must be between 0 and 60 seconds")
        if not BODY_LIMIT <= args.max_get_bytes <= GET_BODY_LIMIT:
            raise ValueError("max-get-bytes must be between 65536 and 1048576")
        if not BODY_LIMIT <= args.max_post_bytes <= MAX_POST_BODY_LIMIT:
            raise ValueError("max-post-bytes must be between 65536 and 1048576")
        if not 1 <= args.max_discovery_pages <= 20:
            raise ValueError("max-discovery-pages must be between 1 and 20")
        if not 1 <= args.max_active_routes <= 6:
            raise ValueError("max-active-routes must be between 1 and 6")
        if not 1 <= args.max_requests <= 120:
            raise ValueError("max-requests must be between 1 and 120")
        if not 1 <= args.samples <= 3:
            raise ValueError("samples must be between 1 and 3")
        if args.react_error_triage and not (args.react_probe or args.active):
            raise ValueError("react-error-triage requires --react-probe or --active")
        if args.waku_probe and not (args.react_probe or args.active):
            raise ValueError("waku-probe requires --react-probe or --active")
        if (args.discover_js or args.discover_sitemaps) and not args.discover:
            raise ValueError("--discover-js and --discover-sitemaps require --discover")
        if args.samples != 1 and not (args.php_probe or args.react_probe or args.active):
            raise ValueError("samples requires an active probe")
        if not 0 <= args.request_interval <= 5:
            raise ValueError("request-interval must be between 0 and 5 seconds")
        if len(args.probe_path) > 2:
            raise ValueError("at most two --probe-path values are allowed")
        explicit_urls = []
        for path in args.probe_path:
            if not path.startswith("/") or path.startswith("//"):
                raise ValueError("--probe-path must start with one slash")
            if any(ord(char) <= 32 or ord(char) >= 127 for char in path) or "\\" in path:
                raise ValueError("--probe-path has an invalid URL character")
            candidate = validate_url(urljoin(url, path))
            if not same_origin(url, candidate) or urlsplit(candidate).query:
                raise ValueError("--probe-path must be same-origin and contain no query")
            if candidate not in explicit_urls and candidate != url:
                explicit_urls.append(candidate)
        if args.routes_file:
            for candidate in load_routes(args.routes_file, url):
                if canonical_url(candidate) not in {canonical_url(value) for value in [url] + explicit_urls}:
                    explicit_urls.append(candidate)
        inventory = None
        evidence_files_verified = 0
        if args.inventory:
            inventory = load_inventory(args.inventory)
            if not isinstance(inventory, dict) or inventory.get("target_url") != url:
                raise ValueError("inventory target_url must exactly match the URL being checked")
            evidence_files_verified = verify_local_evidence(inventory, args.inventory)
    except (ValueError, OSError, UnicodeError, RecursionError) as exc:
        parser.error(str(exc) if not isinstance(exc, RecursionError) else "inventory nesting is too deep")

    if args.urls_file:
        try:
            return run_batch(args, targets, duplicates)
        except OSError as exc:
            print("Batch report storage failed; no further scans started: " + str(exc), file=sys.stderr)
            return 2
    report, code = scan_target(args, url, explicit_urls, inventory, evidence_files_verified)
    print_report(report, args.json)
    return code


def scan_target(args, url, explicit_urls=(), inventory=None, evidence_files_verified=0):
    """Return one report and exit status without printing or persisting it."""
    evidence_log = RequestLog(args.max_requests, args.request_interval, args.max_get_bytes, args.max_post_bytes)
    effective_url, response = (fetch_with_redirects(url, args.timeout, evidence_log)
                               if args.discover else (url, fetch(url, args.timeout, evidence_log)))
    scannable = response["reachable"] and not response_mitigation(response) and not 300 <= response["http_status"] < 400
    checks = assess(inventory) if scannable else [
        result(family, cve, "unknown", "URL was unreachable, redirected, or challenged; deployment association cannot be checked.")
        for family, cves in CVES.items() for cve in cves]
    want_php = args.php_probe or args.active
    want_react = args.react_probe or args.active
    route_inputs = [{"url": effective_url, "response": response, "source": "landing",
                     "want_php": want_php, "want_react": want_react}]
    # Leave room for complete POST/health pairs and React candidate/control
    # sequences. Discovery may stop earlier; it must never starve health checks.
    evidence_log.reserved = min(evidence_log.available(),
                               args.max_active_routes * (2 * want_php + 4 * want_react)
                               + (7 if args.waku_probe and waku_indicator(response) else 0))
    for candidate in (() if response_mitigation(response) else explicit_urls):
        final_url, candidate_response = (fetch_with_redirects(candidate, args.timeout, evidence_log)
                                         if args.discover else (candidate, fetch(candidate, args.timeout, evidence_log)))
        if same_origin(url, final_url) and canonical_url(final_url) not in {canonical_url(entry["url"]) for entry in route_inputs}:
            route_inputs.append({"url": final_url, "response": candidate_response, "source": "supplied",
                                 "want_php": want_php, "want_react": want_react})
    skipped_discovery = []
    discovery_resources = []
    discovered = (discover_routes(effective_url, response, args.timeout, evidence_log,
                                  args.max_discovery_pages,
                                  seeds=[(entry["url"], entry["response"]) for entry in route_inputs[1:]],
                                  details=skipped_discovery, discover_js=args.discover_js,
                                  discover_sitemaps=args.discover_sitemaps,
                                  resources=discovery_resources) if args.discover else [])
    # Supplied routes precede discovered routes; pages with technology evidence
    # precede opaque pages. Every considered route still appears in coverage.
    for item in sorted(discovered, key=lambda item: not (item["rsc_indicator"] or item["php_indicator"])):
        route_inputs.append({"url": item["url"], "response": item["response"], "source": "discovered",
                             "want_php": want_php and item["php_indicator"],
                             "want_react": want_react and item["rsc_indicator"]})
    evidence_log.reserved = 0
    route_probes = []
    impact_alert = False
    active_stop_reason = "explicit challenge response on baseline" if response_mitigation(response) else None
    if any(row.get("stop_active") for row in discovery_resources):
        active_stop_reason = "discovery_resource_blocked"
    assessed_urls = list(dict.fromkeys(entry["url"] for entry in route_inputs))
    covered_urls = set((inventory or {}).get("covered_urls", []))
    if inventory:
        covered_urls.add(inventory["target_url"])
    coverage_urls = list(dict.fromkeys(assessed_urls + [item["url"] for item in skipped_discovery]))
    uncovered_urls = [route_url for route_url in coverage_urls if route_url not in covered_urls]
    if uncovered_urls:
        checks = [result(item["family"], item["cve"], "unknown",
                         "Inventory does not cover every assessed route; a negative probe cannot clear additional routes.")
                  if item["status"] == "not vulnerable" else item for item in checks]
    inventory_checks = {item["cve"]: dict(item) for item in checks}
    active_route_count = 0
    for entry in ([] if active_stop_reason else route_inputs):
        if not (want_php or want_react):
            break
        route_url, route_baseline = entry["url"], entry["response"]
        route_php, route_react = entry["want_php"], entry["want_react"]
        if not (route_php or route_react):
            continue
        if active_route_count >= args.max_active_routes:
            entry["skip_reason"] = "active_route_limit"
            continue
        route = run_sampled_route(route_url, route_baseline, args.timeout,
                                  route_php, route_react, evidence_log, args.samples, args.react_error_triage, args.waku_probe)
        route_probes.append(route)
        active_route_count += int(route["active_request_count"] > 0)
        impact_alert = route["possible_service_impact"]
        active_stop_reason = route["active_stop_reason"]
        if route["php_probe"] and route["php_probe"]["positive"]:
            checks = [result("PHP2Shell", item["cve"], "vulnerable",
                             "Non-exploit PHP warning sequence observed on " + redacted_url(route_url) + ".",
                             "behavioral_positive")
                      if item["family"] == "PHP2Shell" else item for item in checks]
        if route["react_probe"] and route["react_probe"]["positive"]:
            waku_finding = route["react_probe"].get("protocol") == "waku_component_parser"
            checks = [result("React2Shell", item["cve"], "vulnerable",
                             ("Repeated Waku component-parser difference observed on " + redacted_url(route_url) + ".")
                             if waku_finding else "Next.js 500/digest signature and validated benign control (" +
                             route["react_probe"]["control_variant"] + ") observed on " + redacted_url(route_url) + ".",
                             "behavioral_positive")
                      if item["family"] == "React2Shell" and (not waku_finding or item["cve"] == "CVE-2025-55182")
                      else item for item in checks]
        if impact_alert or active_stop_reason:
            break
    for item in checks:
        prior = inventory_checks[item["cve"]]
        if item["confidence"] == "behavioral_positive" and prior["status"] == "not vulnerable":
            item["evidence_conflict"] = True
            item["inventory_reason"] = prior["reason"]
    attach_coverage(checks, route_inputs, route_probes, want_php, want_react,
                    skipped_discovery, "health_check_failed" if impact_alert else active_stop_reason)
    first_route = route_probes[0] if route_probes else {}
    prefix_pages = [redacted_url(entry["url"]) for entry in route_inputs
                    if args.discover and len(entry["response"].get("body", "")) > BODY_LIMIT]
    php_probe = first_route.get("php_probe")
    react_probe = first_route.get("react_probe")
    health_checks = [check for route in route_probes for check in route["health_checks"]]
    active_request_count = sum(route["active_request_count"] for route in route_probes)
    deployment_evidence = inventory.get("deployment_evidence") if isinstance(inventory, dict) else None
    if not isinstance(deployment_evidence, dict):
        deployment_evidence = {}
    report = {"url": redacted_url(url),
              "profile": args.profile,
              "checked_at": datetime.now(timezone.utc).isoformat(),
              "checker_version": USER_AGENT,
              "reachable": response["reachable"],
              "http_status": response.get("http_status"),
              "error": response.get("error"),
              "network_error_kind": response.get("network_error_kind"),
              "redirect_target": response.get("redirect_target"),
              "redirect_stop_reason": response.get("redirect_stop_reason"),
              "effective_url": redacted_url(effective_url),
              "method": ("bounded GET route discovery; " if args.discover else "GET baseline; ") +
                        str(active_request_count) + " bounded POST(s), each followed by a health GET; no code payloads",
              "active_request_count": active_request_count,
              "request_count": len(evidence_log),
              "limits": {"max_requests": args.max_requests, "requests_remaining": evidence_log.available(),
                         "max_get_response_bytes": args.max_get_bytes, "max_post_response_bytes": args.max_post_bytes,
                         "request_interval_seconds": args.request_interval,
                         "max_discovery_pages": args.max_discovery_pages,
                         "max_active_routes": args.max_active_routes, "active_routes_used": active_route_count,
                         "max_samples_per_check_per_route": args.samples,
                         "max_javascript_files": 2 if args.discover_js else 0,
                         "max_sitemap_files": 2 if args.discover_sitemaps else 0,
                         "discovery_depth": 2, "redirect_hops": 2},
              "assessed_urls": [redacted_url(value) for value in assessed_urls],
              "inventory_uncovered_urls": [redacted_url(value) for value in uncovered_urls] if inventory else [],
              "inventory_used": bool(inventory),
              "inventory_evidence": ({"deployment_id": deployment_evidence.get("deployment_id"),
                                      "running_artifact": deployment_evidence.get("running_artifact"),
                                      "provenance_valid": deployment_evidence_valid(inventory),
                                      "local_files_verified": evidence_files_verified}
                                     if inventory else None),
              "php_probe": php_probe,
              "react_probe": react_probe, "health_checks": health_checks,
              "route_probes": route_probes,
              "discovered_routes": [{key: redacted_url(value) if key == "url" else value
                                      for key, value in item.items() if key != "response"}
                                    for item in discovered],
              "skipped_discovery": skipped_discovery,
              "discovery_resources": discovery_resources,
              "discovery_summary": {"enabled": args.discover, "javascript": args.discover_js,
                                    "sitemaps": args.discover_sitemaps,
                                    "parse_prefix_characters": BODY_LIMIT, "prefix_only_pages": prefix_pages,
                                    "partial": bool(prefix_pages) or bool(skipped_discovery) or any(row["state"] != "read" for row in discovery_resources),
                                    "next_step": "Review skipped resources/routes; supply known-safe application URLs for anything not discovered. Bounded discovery cannot enumerate the whole application."},
              "cves_not_assessed": CVES_NOT_ASSESSED,
              "request_evidence": evidence_log,
              "possible_service_impact": impact_alert,
              "active_stop_reason": active_stop_reason,
              "react_error_triage_enabled": args.react_error_triage,
              "waku_probe_enabled": args.waku_probe,
              "observations": observations(response),
              "results": checks}
    attach_outcomes(report)
    if impact_alert:
        return report, 4
    if any(x["status"] == "vulnerable" for x in checks):
        return report, 1
    if not response["reachable"]:
        return report, 2
    if any(x["status"] == "unknown" for x in checks):
        return report, 3
    return report, 0


def print_report(report, as_json):
    if as_json:
        print(json.dumps(report, indent=2))
        return
    print(f"URL: {report['url']} | HTTP: {report['http_status'] or report['error']}")
    if report.get("network_error_kind"):
        print("Connection diagnostic: " + report["network_error_kind"])
    if report.get("redirect_stop_reason"):
        print("Redirect: " + report["redirect_stop_reason"] +
              ("; destination " + report["redirect_target"] if report.get("redirect_target") else ""))
    for item in report["results"]:
        print(f"{item['cve']} ({item['family']}): {item['outcome'].upper()} — {item['outcome_reason']}")
        print("  Detection: " + item["detection"]["result"].upper() + " — " + item["detection"]["reason"])
        print("  Coverage: " + ("LIMITED" if item["coverage"]["limited"] else item["coverage"]["state"].upper())
              + " — " + item["coverage"]["summary"])
        print("  Applicability: " + item["applicability"]["state"].replace("_", " ").upper()
              + " (" + item["applicability"]["basis"] + ") — " + item["applicability"]["reason"])
        for covered_route in item["coverage"]["routes"]:
            print("    " + covered_route["url"] + ": " + covered_route["state"] + " (" + covered_route["reason"] + ")")
    for note in report["observations"]:
        print(f"Observation: {note}")
    for item in report["cves_not_assessed"]:
        print("NOT ASSESSED: " + item["cve"] + " — " + item["reason"])
    if report["discovery_summary"]["partial"]:
        print("Discovery incomplete: " + report["discovery_summary"]["next_step"])
    for key, name in (("php_probe", "PHP"), ("react_probe", "React")):
        if report[key]:
            print(name + " probe: " + report[key]["reason"])
    if report["possible_service_impact"]:
        print("ALERT: service health GET failed after an active probe; further probes stopped.")
    elif report["active_stop_reason"]:
        print("Active checks stopped: " + report["active_stop_reason"])


if __name__ == "__main__":
    if sys.argv[1:] == ["--internal-http-worker"]:
        http_worker()
    else:
        sys.exit(main())
