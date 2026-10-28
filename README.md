# 2Shell Detector

A detection-only command-line tool from **Tuik Security Group** for targeted
PHP2Shell and React2Shell assessments. Runs with Python 3.10+ and its standard
library. No account, API key, or external scanning service is required.

**A URL-only result of “No vulnerability detected” is not proof that the
application is patched.** The tool reports blocked, incomplete and unsupported
checks separately. HTTP2Shell is assessed through supplied deployment
inventory only; there is no active HTTP2Shell probe.

## Coverage

| Family | Remote check | Inventory support | Principal limitation |
| --- | --- | --- | --- |
| PHP2Shell: CVE-2026-109618 / CVE-2026-109619 | Small upload-progress request and session-warning sequence | PHP version, exposure and vendor patch evidence | Hidden warnings, configuration and request filtering can hide affected deployments |
| React2Shell: CVE-2025-55182 / CVE-2025-66478 | Next.js parser response plus benign control; opt-in Waku component parser check for CVE-2025-55182 | React Server Components packages, Next.js and other supported RSC frameworks | Waku requires a fingerprinted root application using the default RSC base; other frameworks and masked errors can remain inconclusive |
| HTTP2Shell: CVE-2026-111497 | **Not implemented** | Supported Brotli decoder versions and exposure | Normal HTTP behavior cannot establish decoder patch status |

CVE-2026-115560 is a separate PHP issue and is explicitly not assessed.
The version rules concern the named CVEs, not every vulnerability affecting
a release. Consult current vendor advisories when choosing upgrade versions.

## Quick start

Run commands from this repository's root. Substitute an authorized, final
application URL for the reserved example domain.

One ordinary GET, with no active probes:

```sh
python3 twoshell.py https://app.example/ --json
```

Opt into the two small detection probes with conservative limits:

```sh
python3 twoshell.py https://app.example/ \
  --active --samples 1 --max-active-routes 1 --max-requests 7 \
  --request-interval 1 --timeout 10 --json
```

Each POST is followed by a health GET. A changed/failing health response
stops further active requests. The tool sends no code-execution payload,
out-of-band callback, memory-exhaustion payload or malformed Brotli stream.
Unexpected POSTs can still produce application errors or side effects;
passing health checks only establish continued responsiveness.

For broader bounded coverage, opt into this profile:

```sh
python3 twoshell.py https://app.example/ --profile expanded --json
```

It enables HTML/JavaScript/sitemap discovery, both active families, the Waku
component check and review-only masked-error comparisons. Defaults are two
samples, three active routes, at most 60 total requests, and one-second
spacing. Explicit limits override those defaults. For 100 input URLs, that
cap permits up to 6,000 request attempts. The standard profile enables only
the checks explicitly requested.
See [USAGE.md](docs/USAGE.md) before choosing the larger scope.

GET and health responses are read up to 1 MiB; POST responses default to
64 KiB. For previously truncated POST responses, opt into
`--max-post-bytes 1048576` to read up to 1 MiB. Both limits apply before and
after supported decompression. This changes response reads, not probe payloads;
it can increase downloaded bytes and allow existing controls or samples to
complete within the same request budget. Use `--max-get-bytes 65536` for the
smaller GET limit. Reports
include sanitized redirect destinations and connection-error categories to
help resolve coverage gaps without automatic retries or wider redirect scope.

## Scan a URL list

Copy `targets.example.txt` to a private file named `targets.txt`. Use one
authorized full URL per line. Blank lines and `#` comments are supported.
Equivalent URLs are deduplicated; different paths remain separate targets.

```sh
mkdir -p reports
python3 twoshell.py --urls-file targets.txt \
  --active --samples 1 --max-active-routes 1 --max-requests 7 \
  --request-interval 1 --site-interval 2 --timeout 10 \
  --output-dir reports/run-001
```

Create the parent `reports` directory first. The run directory must be new.
The input supports up to 1,000 URLs and 1 MiB. Batch URLs must not contain
credentials, queries or fragments. The input is validated before any request.

Only one target runs at a time. Limits apply **per input URL**, so 100 URLs
with a seven-request cap permit at most 700 request attempts. No automatic
retry is performed. A failed post-probe health check stops the whole batch.

The output contains per-target JSON reports, `summary.json`, `summary.csv`
and `remaining.txt`. Reports are checkpointed as the scan proceeds.
`remaining.txt` contains targets not started, not targets proven safe.
Review interrupted or blocked targets before arranging another run.

## Read the results

| Outcome | Meaning |
| --- | --- |
| `vulnerable` | A supported behavioral signature or supplied inventory indicates exposure; inspect the supporting evidence |
| `no vulnerability detected` | Completed probes did not match; discovered pages skipped solely for missing technology indicators remain separate coverage limits |
| `blocked` | Access controls, rate limiting or an unresolved redirect prevented assessment |
| `check failed` | A required request failed |
| `inconclusive` | Ambiguous/unreadable responses, health failures, or other incomplete checks prevented a reliable decision |
| `not assessed` | The check was disabled, skipped or is unsupported remotely |
| `not vulnerable` | Adequate operator-supplied deployment inventory supports that conclusion for the named CVE and scope |

Each result separates three questions:

- **Detection:** `detection.result` describes the remote checks and whether a
  supported signature was found. Inventory conclusions are reported separately
  through the existing overall `outcome` and deployment `status`.
- **Coverage:** `coverage.summary`, `coverage.limited`, and the per-route evidence
  describe rejected POSTs, skipped pages, resource limits, blocks and failures.
- **Applicability:** `applicability.state` is `applicable`, `not_applicable`, or
  `unknown`, with a reason and evidence basis. A framework fingerprint or HTTP
  405 does not establish that the affected technology is absent.

For example, a homepage returning HTTP 405 plus a discovered static page without
PHP/RSC indicators reports **No vulnerability detected**, **limited coverage**,
and **unknown applicability**. It does not claim the backend was exercised or
patched. Verified inventory can establish **not applicable** when the affected
component or input path is absent within its attested scope. A patched component
can remain applicable to assessment while its deployment status is not vulnerable.

An HTTP 405 rejection remains an explicit coverage limit. Review all three fields.
The JSON `status` retains `unknown` when the deployment's patch status is
unverified. `negative_is_clearance` is always false.

Report evidence includes request methods, redacted URLs, statuses, response
hashes, durations and health checks. It omits response bodies, request
payloads and cookies. Reports can still identify private applications;
keep them out of public repositories and issue reports.

Exit codes are documented in [USAGE.md](docs/USAGE.md). In particular,
exit 3 is expected for URL-only checks with unresolved patch status; it
does not mean that a vulnerability was found.

## Optional discovery and inventory

`--discover` follows same-origin GET redirects and a bounded set of HTML
links. `--discover-js` and `--discover-sitemaps` add small, bounded resource
reads. They do not execute JavaScript, log in, submit discovered forms or
enumerate every application route. All requests share the configured cap.
Discovery can improve path coverage but increases requests and still misses
unlinked or authenticated application surfaces.

Use `--routes-file` or `--probe-path` for known, approved application paths
in a single-target run. Use `--inventory` only with deployment evidence tied
to the live target. See [usage](docs/USAGE.md),
[inventory format](docs/INVENTORY.md) and [limitations](docs/LIMITATIONS.md).

## Tests

The default tests use temporary loopback response simulators and no
vulnerable runtime or Internet target:

```sh
python3 -B -m unittest discover -s tests -p 'test_*.py' -v
```

Optional integration runners exercise affected and patched PHP/Next.js
releases, older Next.js controls and other RSC frameworks on loopback.
Instructions and the meaning of expected inconclusive results are in
[TESTING.md](docs/TESTING.md). Do not expose those fixture applications to a
network. Successful fixture tests are not a real-world detection-rate estimate.
The local release-preparation results are recorded in
[VALIDATION.md](docs/VALIDATION.md).

## License

LGPL-3.0-only. See [LICENSE](LICENSE), the incorporated GPLv3 terms in
[COPYING](COPYING), and [NOTICE](NOTICE) for the adapted probe portions.

## Vendor advisories

- [PHP security releases](https://www.php.net/archive/2026.php)
- [PHP CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [PHP CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [React Server Components advisory](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
- [Next.js advisory](https://nextjs.org/blog/CVE-2025-66478)
- [Brotli release](https://github.com/google/brotli/releases/tag/v1.2.1)
