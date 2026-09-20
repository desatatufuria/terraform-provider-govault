# Provider public repository publication

## Objective

Publish the complete standalone Terraform provider safely as the initial public
`desatatufuria/terraform-provider-govault` repository.

## Problem and why

The provider is complete and reviewed locally, but has no remote repository.
A pre-publication audit found local workstation paths in historical task
evidence and no explicit software license. Publishing those bytes unchanged
would disclose non-portable local details and leave reuse rights undefined.

## Authorized scope

- Add the user-approved Apache-2.0 license.
- Replace tracked absolute workstation paths with portable placeholders.
- Preserve test evidence, hashes, behavior, and Git history.
- Publish the complete candidate as remote `main` and retain the tracker branch.
- Do not create a release, tag, pull request, or Terraform Registry entry.

## Constraints

- No application behavior changes.
- No credentials, local paths, binaries, Terraform state, or build artifacts.
- Do not rewrite existing history; sanitize in a new work-unit commit.
- The complete Phase F candidate, not the older local `main`, becomes remote
  `main`.

## Route and delivery

- Route: delegated direct.
- Trigger: publication hygiene spans two existing ledgers plus repository
  licensing.
- TDD: not applicable; this is metadata/documentation-only. Ordinary repository
  checks still apply.
- Delivery strategy: single-pr vocabulary retained; initial repository
  publication is a user-authorized direct push, not a pull request.
- Forecast: fewer than 250 authored changed lines, primarily the canonical
  Apache-2.0 license text.

## Tasks

- [-] PPR-001 Add licensing and sanitize non-portable evidence.
  - Acceptance: canonical Apache-2.0 license is tracked.
  - Acceptance: no tracked file contains an absolute workstation path.
  - Checks: formatting, diff check, Go tests, race tests, vet, build, and a
    full reachable-history credential audit.
  - Evidence: pending.
- [ ] PPR-002 Review and publish the exact candidate.
  - Acceptance: native review is resolved for the publication commit.
  - Acceptance: public remote `main` and tracker branch resolve to the exact
    approved commit.
  - Acceptance: repository visibility and default branch are verified.
  - Evidence: pending.

## Progress and next step

PPR-001 is active. The next step is the delegated hygiene work unit.
