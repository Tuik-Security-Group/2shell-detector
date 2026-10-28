# Detection limits

This is a targeted signature and inventory checker. It does not establish
that an application is free of vulnerabilities or safe from exploitation.
An affected deployment can return no matching signature.

Detection, coverage and applicability are separate report dimensions. A 405
response confirms that the tested URL rejected the POST; it does not prove
that every application route lacks the affected component. Discovered pages
without technology indicators can be left unprobed without changing completed
negative checks to an ambiguous detection result. Their coverage stays limited.
Framework hints alone cannot establish non-applicability. Confirmed component
or input-path absence requires the existing deployment inventory evidence.

## PHP

The small upload-progress request looks for a sequence of session warnings.
It does not trigger memory corruption or execute PHP code. Error suppression,
PHP configuration, middleware and request filtering can hide the sequence.
Known affected PHP with `display_errors=Off` remains a documented detection
miss in the real-runtime fixtures. Repeating the request does not solve this.
A fixed release can also produce no signature, so those two deployments
cannot be distinguished reliably using this response alone.

## React Server Components

The standard active classifier is specific to tested Next.js behavior.
A candidate HTTP 500 response needs the expected Flight response type and
digest structure, absence of the signature in the baseline, and a qualifying
benign control. A generic 500 or digest string is insufficient. Controls
reduce false positives but do not provide an execution-based proof.

Custom error pages, proxies, caching and platform mitigations can remove or
rewrite the distinction. Masked-error triage is review-only.

The opt-in Waku check has been tested on Waku 0.27.1 with React 19.2.0 and
Waku 0.27.3 with React 19.2.1. It requires root HTML metadata/hydration
markers, the default component endpoint and exact missing-route/error
responses. Two candidate errors must agree with three controls. A
same-reference/present-property control rejects simple request-shape filters.
These are behavioral indicators, not proof of code execution; middleware
that exactly imitates the complete difference could still produce a false
positive. Custom base paths or RSC prefixes are not covered. The check never
uses the application's action IDs or function endpoints.

React Router and other RSC frameworks have no supported positive active
classifier here. Their affected fixtures can still remain unknown. Do not
extend the Next.js or Waku rule to generic HTTP 500/404 differences.

Older Next.js controls and synthetic platform tests guard against misleading
positives. A blocked request or a platform mitigation does not establish that
the origin was patched, and the scanner does not bypass access controls.

## HTTP2Shell

There is no active HTTP2Shell probe. A `br` response demonstrates compression,
not that a server accepts attacker-controlled input into an affected Brotli
decoder. A normal HTTP exchange cannot establish the decoder's build or
patch state. Supply verified deployment inventory to assess this family.

## Scope and operations

- URL checks cover only the routes and instances reached. Unlinked apps,
  authenticated routes and cross-origin deployments require separate scope.
- Sampling cannot prove coverage of a load-balanced fleet or sticky sessions.
- Response-size limits, timeouts, encoding limits, authentication and request
  caps can leave a route unassessed or inconclusive.
- Health GETs check responsiveness. They cannot detect every application side
  effect, resource increase or delayed failure caused by an unexpected POST.
- Inventory attestations are validated for structure, hash, freshness and
  scope. The tool cannot independently verify that a supplied artifact really
  represents every live replica.
- Version rules apply to the named CVEs only. Vendor backports and newer
  vulnerabilities require current vendor guidance. CVE-2026-115560 is not
  assessed by this release.

The test matrix is a deliberately selected set of cases, not a random sample
of production applications. Passing tests demonstrates the specified behavior
on those cases; it is not a sensitivity, specificity or universal coverage
claim. Known affected cases with an expected unknown result remain misses.
