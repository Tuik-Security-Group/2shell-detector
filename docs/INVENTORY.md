# Evidence-backed inventory

The inventory's `target_url` must exactly match the requested URL. To apply
the same deployment evidence to redirected or additional routes, explicitly
list their exact same-origin URLs in `covered_urls`. A clean result cannot
spread to other routes by implication. Its
`deployment_evidence` needs a nonempty `deployment_id`, a SHA-256
`running_artifact` identity. `all_instances_audited: true` is required for a
clean verdict; a known affected component remains reportable when the audit
of other instances is incomplete. Every component
and every decoder copy needs its own `evidence` object. A clean RSC verdict
also needs `all_rsc_packages_audited: true`; a clean Brotli verdict needs
`all_decoders_audited: true`. These are operator attestations, so make the
files and claims correspond to every serving replica, edge, worker, and
vendored decoder. Unverified or omitted claims yield `unknown`. Mistyped
booleans, conflicting presence/exposure claims, ambiguous component lists,
duplicate JSON keys, and inventories larger than 1 MiB are rejected before
any network request.

Each evidence object has this shape:

```json
{
  "source": "local_file",
  "source_ref": "evidence/runtime-export.json",
  "artifact_digest": "sha256:REPLACE_WITH_64_HEX_CHARACTERS",
  "observed_at": "2026-10-27T18:00:00Z"
}
```

`source_ref` is relative to the inventory file's directory. The checker
reads at most 4 MiB per referenced file and verifies its SHA-256 before any
network request. Evidence timestamps must be within the last 30 days. Use an
actual runtime export, SBOM, image manifest, package
lockfile, vendor patch record, or deployment manifest. Record how the artifact
was tied to the running URL and instances in the referenced file. A
`vendor_patch: true` or `rsc_vendor_patch: true` assertion additionally needs
`patch_reference` inside its evidence object. An affected upstream version
with unknown backport status stays `unknown`.

The complete synthetic examples are [fixture_vulnerable.json](../tests/fixture_vulnerable.json)
and [fixture_patched.json](../tests/fixture_patched.json). Their shared
[fixture_evidence.json](../tests/fixture_evidence.json) explicitly says they are test
fixtures, not real deployment evidence. The unit test refreshes their
`observed_at` fields in a temporary copy so the 30-day freshness rule remains
testable. For an actual deployment, use separate
artifacts for PHP, React packages, each Brotli decoder, and the deployment
association. Hash each file with `shasum -a 256 FILE` (or `sha256sum FILE`).

For React, set `framework` to `next`, `react-router`, `waku`, `parcel-rsc`,
`vite-rsc`, or `rwsdk`. The [React advisory](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
names these integrations. Set `rsc_package` and `rsc_version` for a single
copy, or `rsc_components` to list all copies, each with `present`,
`rsc_exposed`, package name, version, optional backport status, and evidence.
An explicit `next_app_router: false` attestation is required to exclude
the Next.js input path; a framework name alone is insufficient. Non-Next
frameworks can be `not vulnerable` to the Next-specific
CVE-2025-66478 while remaining vulnerable to the core React CVE.

For Brotli, list every decoder under `brotli.decoders` with `name`,
`implementation` (`google-brotli-c`, `nodejs-brotli`, or `dotnet-brotli`),
`version`, `decodes_untrusted_data`, and evidence. A normal `br` HTTP response
only shows encoding; it does not establish server-side decoder exposure. The
[PHP Windows rebuild notice](https://www.php.net/archive/2026.php#2026-10-21-5)
illustrates why the decoder's binary/package identity matters separately
from the PHP source version.

