# Usage and report interpretation

Run `python3 twoshell.py --help` for the complete CLI. Python 3.10+ is
required for the scanner; fixture builders require newer Node.js separately.
The scanner needs no pip packages.

## Choose the assessment scope

Use the final application URL, including its base path. A marketing homepage
and an application behind a different hostname are separate targets. Scope
is based on scheme, hostname and port. Cross-origin redirects are not
followed. Credentials in URLs are rejected; there is no login or cookie
import option. Environment and platform proxy settings are explicitly ignored.
There is no TLS-verification bypass, automatic retry or concurrent scanning.

Without an active flag, the tool makes a baseline GET and evaluates any
supplied inventory. `--php-probe` enables the PHP request, `--react-probe`
enables the Next.js request and conditional benign control, and `--active`
enables both. Every active request is followed by a GET health check. The
request cap reserves capacity for health checks. A failed health check stops
further active work, and stops a batch entirely.

The conservative command in the README permits at most seven request
attempts to one route. A seven-request cap cannot also support extensive
discovery. Increase bounds deliberately when adding routes; inspect skipped
coverage rather than assuming that all configured checks ran.

`--profile expanded` explicitly enables `--active --discover --discover-js
--discover-sitemaps --react-error-triage --waku-probe`, with defaults of
`--samples 2 --max-requests 60 --request-interval 1`. It retains the three-route
and eight-discovered-page defaults. Any explicit numeric setting takes
precedence, including a smaller request cap. Every GET, POST and health GET
shares the same cap. The profile works with a single URL or `--urls-file`.
It can close discovery gaps and expose review signals; it cannot clear a
blocked backend, a hidden PHP warning or an unreached replica.

## Limits

| Option | Default | Allowed range / purpose |
| --- | --- | --- |
| `--timeout` | 5 seconds | More than 0, at most 60 seconds per request |
| `--max-get-bytes` | 1 MiB (1048576) | 65536–1048576 bytes for GET and health responses |
| `--max-post-bytes` | 64 KiB (65536) | 65536–1048576 bytes for POST responses; does not change request payloads |
| `--request-interval` | 0.2 seconds | 0–5 seconds minimum gap between requests |
| `--max-requests` | 40 | 1–120 total attempts per target, including discovery and health |
| `--max-active-routes` | 3 | 1–6 paths receiving probes |
| `--samples` | 1 | 1–3 samples per enabled check and route; stops after a finding |
| `--max-discovery-pages` | 8 | 1–20 discovered pages, excluding supplied URLs |
| `--site-interval` | 1 second | Batch only; 0–60 seconds between targets |

GET responses, including health checks, are capped at 1 MiB before and after
supported decompression. `--max-get-bytes 65536` restores the smaller GET cap.
POST responses default to 64 KiB. Use `--max-post-bytes 1048576` to opt into
a 1 MiB POST read cap, also bounded before and after supported decompression.
These are read limits, not request payload sizes. Larger reads can increase
downloaded bytes and time spent receiving a response, while the total request
deadline remains unchanged. A readable baseline or probe response can allow
existing checks, controls and repeat samples to continue where they previously
stopped; request caps, spacing, health checks and access/redirect stops remain
in force. Responses still exceeding the selected limit are incomplete and
cannot establish either a supported positive or a completed negative check.

For a bounded reassessment of an authorized URL with truncated POST responses:

```bash
python3 twoshell.py https://app.example.com/ --profile expanded \
  --max-post-bytes 1048576 --request-interval 1 --json
```
Truncated, unsupported-encoding and otherwise unreadable responses cannot
produce a clean assessment. The process enforces request deadlines as well
as socket timeouts. A timeout does not cancel work already received by the
remote server.

## Optional route discovery

`--discover` permits bounded same-origin GET redirects and HTML links up to
two levels. `--discover-js` additionally reads at most two linked same-origin
JavaScript files for static URL hints. `--discover-sitemaps` reads at most
two same-origin sitemap files beginning at `/sitemap.xml`. The latter two
flags require `--discover`. None execute JavaScript.
Static HTML and JavaScript parsing still examines at most 65536 characters
per response. Larger readable pages may therefore have incomplete discovery;
`prefix_only_pages` and resource states record this limitation.

For a single-target assessment, `--routes-file routes.txt` imports at most
ten approved full same-origin URLs or absolute paths; `--probe-path /PATH`
adds at most two paths. Both support the same request and route caps. Avoid
state-changing paths. Discovery excludes query-bearing and action-like URLs,
but a supplied URL still requires operator review.

`--react-error-triage` requires `--react-probe` or `--active`. It compares a
benign control following a readable Next.js 500 response without the usual
digest marker. A difference is a **review signal**, never a vulnerability
verdict by itself. More samples cannot prove that every replica was reached.

`--waku-probe` requires `--react-probe` or `--active`. On a root URL with
Waku generator metadata and hydration markers, it selects a separate
component-parser sequence. A random missing `/RSC/R/` component must first
return the expected 404. Up to five tiny POSTs then compare two candidates
with three benign controls, including the same reference with its missing
property supplied. Each POST has a landing-page health GET. A complete
sequence uses 12 requests including the landing baseline, excluding any PHP
checks or discovery. It runs once, even with `--samples 3`.

This sequence supplies no action identifier and never selects an `/RSC/F/`
function path. It does not submit the page's forms. Custom RSC prefixes,
non-root app URLs, missing metadata and rewritten responses are unsupported.
A Waku finding applies to **CVE-2025-55182 only**. CVE-2025-66478 is specific
to Next.js and is not inferred from Waku evidence. Inspect the probe protocol,
preflight and control evidence in JSON; an absent difference is not clearance.

## Batch runs

```sh
mkdir -p reports
python3 twoshell.py --urls-file targets.txt \
  --active --samples 1 --max-active-routes 1 --max-requests 7 \
  --request-interval 1 --site-interval 2 --timeout 10 \
  --output-dir reports/run-001
```

The output directory must not already exist. Input is validated in full
before requests begin. Use UTF-8, one full HTTP(S) URL per line, with optional
blank lines or `#` comments. The limit is 1 MiB and 1,000 targets. Credentials,
queries and fragments are rejected. Canonically equivalent URLs are
deduplicated; distinct application paths are retained. `--inventory`,
`--routes-file` and `--probe-path` are single-target options and cannot be
combined with `--urls-file`.

The run saves per-target JSON, `summary.json`, `summary.csv` and
`remaining.txt`. Summaries are checkpointed between targets. A block,
rate-limit or unresolved redirect prevents later active checks against that
origin in the same batch. There is no automatic retry/resume. After reviewing
an interrupted run, use `remaining.txt` as a new input with a new output
directory. Completed but inconclusive targets need separate review.

Use `--json` for JSON on standard output. Keep reports private: URL paths,
hostnames and inventory evidence can identify a client even though response
bodies, request payloads, credentials and cookies are not recorded.

## Connection and redirect diagnostics

Reports and request evidence contain `network_error_kind`, with categories
such as `dns`, `tls_certificate`, `tls_handshake`, `connection_refused`,
`network_unreachable`, `timeout`, and `request_deadline`. The legacy `error`
field remains available. Exception messages are not retained. These categories
describe the failed request; they do not establish application vulnerability.

Redirect evidence includes a validated `redirect_target` with query values
redacted, plus a reason such as `cross_origin`, `missing_location`,
`invalid_location`, `redirect_loop`, `hop_limit`, `discovery_scope`, or
`request_budget`. Each followed GET hop is marked `followed`. A direct GET
without discovery is marked `not_followed`; POST redirects are never followed.
Invalid or credential-bearing destinations are omitted. Recording a destination
does not authorize scanning it: confirm the client and scope before selecting
a new target. Diagnostics do not enable retries, TLS bypasses or extra requests.

## Outcomes and evidence

Read `results`, `detection`, `coverage`, `applicability`, `outcome`, `outcome_reason`, `request_evidence`,
`health_checks`, `possible_service_impact` and `limits` together. A behavioral
finding establishes a matching signature, not successful code execution.
An inventory finding relies on the supplied deployment evidence.

`detection.result` describes the remote check: `vulnerability detected`,
`no vulnerability detected`, `blocked`, `check failed`, `inconclusive`, or
`not assessed`. `detection.reason` explains the observation. It does not imply
that an inventory assessment came from a remote probe. For example, verified
inventory can produce overall `outcome: vulnerable` while remote detection is
`not assessed` because no active check was enabled.

`no vulnerability detected` also covers a mixture of completed negative probes
and discovered pages skipped solely for `no_technology_indicator`. At least one
completed negative probe is required. These skipped pages remain in coverage;
the raw coverage state can still be `partial`. A blocked/failed route, ambiguous
control, request-budget skip, or failed health check does not qualify for this
exception. Discovery-only runs remain `not assessed`.

`coverage.summary` and `coverage.limited` provide a readable account of the
limits. HTTP 405 means the POST was not accepted at that URL, so the relevant
backend may not have processed the check. Resource caps and skipped routes
remain visible even when no signature was detected.

`applicability.state` records `applicable`, `not_applicable`, or `unknown` with
`basis` and `reason`. A supported behavioral signature establishes applicability
on a tested route; verified deployment inventory can establish presence or
absence of the component/input path. `applicable` does not mean vulnerable:
a patched but exposed component is still applicable to assessment. Technology
fingerprints, rejected POSTs, and missing indicators alone never produce
`not_applicable`. Absence claims retain the inventory freshness, scope and
completeness requirements in [INVENTORY.md](INVENTORY.md).

The existing overall `outcome`, deployment `status`, coverage states and exit
codes remain available. No negative URL-only outcome is a patch-status clearance.
Batch JSON includes the three dimensions; CSV adds detection, coverage summary,
and applicability columns without removing the previous columns.

`coverage.state` can be `detected`, `completed_no_signature`, `blocked`,
`inconclusive`, `error`, `skipped`, `not_enabled` or
`no_supported_remote_check`. Aggregate coverage can be partial. Review the
per-route entries and skipped discovery details; the headline alone does
not describe every route.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | All five assessed CVEs have an inventory-supported `not vulnerable` result |
| 1 | At least one `vulnerable` result |
| 2 | Invalid input, network failure, internal error or report-storage failure |
| 3 | At least one unresolved result; normal for URL-only scans without findings |
| 4 | A post-probe health check failed; stop and investigate |
| 130 | Interrupted batch |

In a batch, health failures and interruptions take precedence, followed by
storage/internal failures, positive findings, network errors, then unresolved
results. A code 1 batch can also contain failed or incomplete targets. Read
the saved summary instead of interpreting the process code as a complete
assessment. CVE-2026-115560 is recorded as unassessed separately; it is not
one of the five covered CVEs.
