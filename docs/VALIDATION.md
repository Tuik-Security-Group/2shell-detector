# Version 1.9.0 detection expansion validation — October 28, 2026

Validation used Python 3.15.0, Node.js 24.22.1 and npm 11.19.1 on macOS.
All requests were to local fixtures. No client scan was performed.

| Check | Result |
| --- | --- |
| Automated regressions, including packaging and transport isolation | 147 passed |
| Next.js runtime cases, including expanded-profile boundaries | 64 expectations passed |
| Older Next.js controls | 3 expectations passed |
| PHP discovery, Next.js discovery, Waku and React Router cases | 38 expectations passed |
| Total runtime cases | 105 expectations passed |
| Unaffected runtime cases | 52; zero false positives |
| Known-affected runtime cases | 21 detected; 32 undetected |
| Runtime request attempts / POSTs / healthy post-probe GETs | 718 / 243 / 243 |
| Direct React decoder contract tests | Affected and patched pairs passed |

An expected unknown result on an affected runtime is a detection miss. The
expanded suite repeats some deployments under different configurations;
its totals are not a production detection rate or a like-for-like rate
comparison with the previous 80-case suite.

## The original 23 missed scenarios

Three now have a validated detection path when the new options are used:

- The affected Waku 0.27.1 / React 19.2.0 root application, using the opt-in
  component-parser check. Waku 0.27.3 / React 19.2.1 is a negative control.
- The affected Next.js application hidden from HTML-only discovery, using
  the expanded profile's existing bounded JavaScript/sitemap readers.
- The affected PHP application with visible warnings hidden from HTML-only
  discovery, using the same expanded discovery options.

Twenty original scenarios remain undetected: six blocked cases, six masked
error cases, three cases whose requests reach only a patched replica, one
React Router case, and four PHP hidden-warning cases. The repeated masked
error differences remain review signals, never confirmed CVE findings.
Some original cases differ only in sampling settings and now map to the
same expanded-profile follow-up; this is a scenario comparison, not 23
independent deployments. The React Router check remains unsupported.

## Controls and limits

The Waku check supplies no action identifier and selects only a random
missing component route. It requires a preflight, two matching candidate
errors, three benign controls and unchanged health. The present-property
control uses the same nested reference as the candidate. Synthetic tests
reject generic errors, request-shape filtering, wrong MIME types, inconsistent
samples, truncation, blocks and redirects, and verify health/budget stops.
Waku evidence marks only CVE-2025-55182, never the Next.js-specific CVE.

Direct tests of the installed official React 19.2.0 and 19.2.1 decoders
isolate the changed parser behavior without loading application actions.
Two additional cross-version Waku/framework combinations failed to serve
healthy landing pages and were excluded from runtime verdicts; no end-to-end
coverage is claimed for those combinations.

The profile retains strict same-origin discovery, existing response limits,
sequential requests and stop conditions. It does not bypass gateways, force
replica selection, reveal suppressed PHP warnings or add an HTTP2Shell probe.
The lab proxy now relays a bounded JavaScript prefix rather than aborting on
large static files, so expanded discovery exercises the scanner's size limit.

All three final runtime reports recorded scanner SHA-256
`4e73b9366c4119bcb8c97b145ea164f875068a66bcff910549cbe3073d8a4d0d`.
All 28 distinct recorded loopback ports were closed after testing. No fixture
process or container remained. These checks establish selected fixture
behavior and continued responsiveness, not absence of all side effects.

See [TESTING.md](TESTING.md) for reproduction and [LIMITATIONS.md](LIMITATIONS.md)
for the supported scope. This validation was completed on October 28, 2026,
while the repository was private.

## Version 1.9.1 reporting verification

The reporting update passed 152 automated regressions. New cases cover a
homepage rejecting POSTs plus discovered static pages, passive-only discovery,
evidence-backed non-applicability, incomplete/out-of-scope absence claims,
and mixed blocked/failed/budget-limited coverage. JSON, console and batch CSV
outputs retain the limitations while separating detection and applicability.

Transport, probe payloads, detection matchers, version rules, discovery,
request budgets, and health-check logic are unchanged. The 105 runtime cases
above belong to version 1.9.0 and were not rerun for this reporting-only update.

## Version 1.9.2 transport and diagnostic verification

The update passed 162 automated regression tests locally on Python 3.15.2.
The ten added tests cover larger readable baselines, gzip expansion bounds,
the configurable GET limit, the unchanged 64 KiB POST limit, health pairs,
access/challenge stops, bounded parsing disclosures, sanitized network-error
categories, and redirect scope/hop/budget diagnostics. The existing payload,
matcher, inventory, Waku, batch-stop, and release-boundary tests also passed.

The GET/health read cap defaults to 1 MiB and can be reduced to 64 KiB.
Larger readable baselines allow the existing checks to run where they were
previously skipped; that can increase actual requests within the unchanged
request-count and pacing limits. Oversized POST signatures remain inconclusive.
The broader framework runtime matrix above was not repeated for this update.
Local response simulators establish these specific behaviors, not production
detection sensitivity or absence of every possible side effect.

## Version 1.9.3 configurable POST response verification

The update passed 170 automated regression tests locally on Python 3.15.2.
Eight added tests cover the opt-in POST response limit: identical probe bodies
at both limits, positive signatures and benign controls beyond the old cap,
large compressed negatives, wire/decompression overflow, generic-error false
positive rejection, access/challenge/redirect and health stops, total response
deadlines, and invalid settings rejected before network requests.

The POST response default remains 64 KiB; `--max-post-bytes` permits up to
1 MiB before and after decompression. Payloads, matchers, discovery scope,
request budgets and pacing are unchanged. Larger readable responses can allow
existing controls and samples to complete within those limits. Tests confirm
the bounded transport and reporting behavior; the broader framework runtime
matrix above was not repeated for this update. Python 3.10 grammar compatibility
was checked, but the local suite was run on Python 3.15.2.
