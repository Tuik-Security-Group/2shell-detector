# Contributing

Use synthetic or loopback-only examples in issues and pull requests.
Remove client URLs, credentials, tokens and captured application content
before sharing evidence.

Run the regression suite from the project root:

```sh
python3 -B -m unittest discover -s tests -p 'test_*.py' -v
```

For source changes, update the reviewed release manifest hashes with
`python3 tools/build_source_zip.py --refresh`. Explicitly add or remove
manifest entries when changing the public file list, stage only reviewed
source paths, then run `python3 tools/build_source_zip.py --check-repo`.
The repository check fails on tracked files outside the release allowlist.

Detection changes need an affected-runtime case, a patched control and
generic-error/blocked-response controls where applicable. Add tests for
request counts and health-stop behavior. Preserve the distinction between
no signature, incomplete coverage and verified deployment evidence.

New checks must retain explicit active opt-in, bounded request sizes and
counts, deadlines, sequential pacing and health checks. This project does
not accept code-execution proofs, large memory/CPU oracles, credential
attacks, callback-based probes or WAF-bypass features.

Document material limitations alongside improvements. Do not describe a
simulated response as an affected-runtime validation or infer broad
accuracy from a curated fixture matrix.

Contributions are provided under the project's LGPL-3.0-only license.
Preserve applicable copyright and license notices for adapted code.
