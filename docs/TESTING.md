# Local verification

Run from the repository root. No test requires a client URL or public
vulnerable service. Keep runtime fixtures on loopback. The optional older and
affected releases are intentionally unsuitable for deployment.

## Regression suite

```sh
python3 -B -m unittest discover -s tests -p 'test_*.py' -v
```

The detector regressions exercise version boundaries, inventory provenance,
false-positive controls, platform/error responses, discovery scope, URL-list
validation, response limits, health stops and interrupted/report-failure
behavior. They use temporary response simulators rather than vulnerable
software. Release-packaging tests additionally verify that archives include
only explicitly listed files, reject unsafe paths and detect modified sources.

To inspect the synthetic fixture manually, start it in one terminal:

```sh
python3 tests/fixture_server.py --port 8765
```

In another terminal:

```sh
python3 twoshell.py http://127.0.0.1:8765/vulnerable --active --json
python3 twoshell.py http://127.0.0.1:8765/patched --active --json
```

The first should produce behavioral findings; the second should produce no
matching signature and retain unknown patch status without trusted inventory.
Stop the fixture with Ctrl-C. It emulates responses and executes no exploit.
The inventory examples in `tests/` contain synthetic evidence and fixed
timestamps; tests refresh them in a temporary directory. Do not submit them
as deployment evidence.

## Real PHP integration cases

Requirements: Docker and cached official images `php:8.5.11-apache` and
`php:8.5.12-apache`. Obtain those images separately if needed; the runner
uses `--pull=never`. Record their actual image IDs with the resulting report.
It binds each container to a random `127.0.0.1` port, mounts only generated
fixture files read-only, and removes its containers on exit.

```sh
mkdir -p reports
python3 -B real_fixtures/run_matrix.py --only-php \
  --work-dir reports/php-work --report reports/php-validation.json
```

Eight cases cover affected/fixed versions, visible/hidden warnings and repeat
sampling. The affected version with visible warnings should be detected.
Hidden warnings remain unknown even on the affected release. Fixed releases
should produce no false positives. The report separately counts expectations
passed, affected cases detected, affected cases missed and fixed false positives.

## Real Next.js integration cases

Requirements: Node.js 22 or 24 and npm. Preparation downloads the exact
dependencies in the committed lockfiles and builds the minimal applications.
Use a fresh work directory; install scripts are disabled, while framework
build commands execute intentionally. No external scanner is required.

```sh
mkdir -p reports
python3 -B real_fixtures/prepare_matrix.py --work-dir reports/next-work
python3 -B real_fixtures/run_matrix.py --skip-php \
  --work-dir reports/next-work --report reports/next-validation.json
```

Pairs: Next.js 15.1.8/15.1.9, 15.5.6/15.5.7 and 16.0.6/16.0.7.
Cases include direct nested paths, discovered/imported paths, simulated WAF
blocks, masked errors, generic-digest controls and mixed/sticky replicas.
These are real framework runtimes behind controlled local proxy simulations,
not tests of a real hosting platform's current defenses. Omitting `--skip-php`
also runs the eight PHP cases.

Older unaffected controls are separate:

```sh
python3 -B real_fixtures/prepare_matrix.py --only-older --work-dir reports/older-work
python3 -B real_fixtures/run_matrix.py --only-older \
  --work-dir reports/older-work --report reports/older-validation.json
```

This checks Next.js 13.5.11, 14.2.33 and 14.2.35 without expecting a positive
React2Shell finding. These versions may have unrelated vulnerabilities.

## Discovery and non-Next RSC coverage

```sh
python3 -B real_fixtures/prepare_coverage.py --work-dir reports/coverage-work
python3 -B real_fixtures/run_coverage.py \
  --work-dir reports/coverage-work --output reports/coverage-validation.json
```

This needs the same Docker images and Node/npm prerequisites. It tests JS
and sitemap discovery into real PHP/Next.js routes and affected/patched Waku
and React Router RSC fixtures. It compares HTML-only discovery with the
expanded profile, and tests the opt-in Waku component check against the
affected and fixed runtime pair. Waku evidence must not mark the Next.js CVE.
The older experimental missing-action requests remain observations and are
not used as production detectors. Unknown results on affected runtimes are
detection misses, even when expected by the test.

The local decoder contract test isolates the property-reference behavior
from framework and proxy behavior, using the installed official React
package. It sends no network requests and loads no application action:

```sh
node --conditions=react-server real_fixtures/verify_decoder.mjs reports/coverage-work/waku-19.2.0
node --conditions=react-server real_fixtures/verify_decoder.mjs reports/coverage-work/waku-19.2.1
```

Synthetic Waku tests additionally cover generic errors, request-shape filters,
inconsistent samples, preflight redirects, blocks, truncation, failed health,
budgets, opt-in gating, and absence of action identifiers in outgoing requests.

All runtime processes and containers started by the runners are cleaned up
in `finally` blocks during ordinary completion/errors. After a forced process
kill or machine failure, verify that no fixture process or container remains.
Generated dependencies, builds and local reports remain in the chosen work
directories; remove those directories when finished. Do not publish them.

## Release checks

```sh
python3 tools/build_source_zip.py --check
python3 tools/build_source_zip.py --check-repo
python3 tools/build_source_zip.py --output ../2shell-detector-source.zip
```

The archive command refuses to overwrite an existing file. It verifies the
reviewed `RELEASE_FILES.json` hashes and packages only those paths plus the
manifest. `.git`, ignored local files and unlisted files are never exported.
After an intentional source edit, review it and run `--refresh` to update
hashes for the existing allowlist. New public files require explicitly adding
their path to the manifest before refresh. Do not bulk-add a workspace.

`--check-repo` additionally requires a Git checkout at the release root and
an index containing exactly the manifest's paths plus `RELEASE_FILES.json`.
Stage reviewed source additions/removals before running it. CI uses this mode
to reject accidentally tracked reports or other unlisted files. Untracked
local files remain allowed and are excluded from the ZIP. `--check` and ZIP
creation also work on extracted source archives without Git.
