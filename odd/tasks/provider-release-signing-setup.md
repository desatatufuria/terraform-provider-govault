# Provider release signing setup

## Objective

Create a dedicated encrypted OpenPGP identity for Terraform provider releases,
configure the GitHub Actions signing secrets, and retain recoverable local
material without exposing secrets in the repository or command output.

## Authorized scope

- Generate one RSA 4096 release-signing identity locally.
- Store its encrypted keyring and passphrase temporarily under separate
  protected directories in the current user's home.
- Configure `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE` for
  `desatatufuria/terraform-provider-govault` using the current GitHub session.
- Verify signing and secret metadata without printing private material.
- Do not create a tag, release, or Terraform Registry registration.

## Constraints

- No private key, passphrase, exported secret, or generated release artifact
  may enter Git.
- Local secret directories must be mode `0700`; secret files must be `0600`.
- The release identity is dedicated to this provider and uses RSA 4096.
- The public key and fingerprint may be retained for later Registry setup.
- GitHub secret values are write-only and must be submitted through stdin.

## Delivery and verification

- Route: direct inline; repository work is one small, understood ledger file.
- Effective TDD: not applicable to operational key provisioning.
- Functional checks: permissions, key capabilities, detached-signature
  round-trip, GitHub secret metadata readback, and repository secret scan.
- Delivery strategy: `single-pr`; forecast below 150 authored lines.
- RDD mode: enabled globally; assess the ledger commit.

## Tasks

- [x] **SIGN-001 — Generate and validate release identity**
  - Create the encrypted RSA 4096 identity and protected recovery files.
  - Export the public key and record its non-secret fingerprint.
  - Prove a detached signature verifies with the public identity.
  - Evidence:
    - RSA 4096 signing identity fingerprint:
      `B2D8C930DE314A3C7E664692628DE903585094A2`.
    - Identity: `GoVault Terraform Provider Release
      <desatatufuria@users.noreply.github.com>`; expires 2028-09-19.
    - Encrypted keyring and private backup are under
      `~/.local/share/govault-release/`; the passphrase is separate under
      `~/.config/govault-release/`.
    - Directories are mode `0700`; exported key/passphrase files are `0600`.
    - Detached-signature round-trip passed using a fresh verification keyring
      containing only the exported public key.

- [x] **SIGN-002 — Configure GitHub Actions secrets**
  - Set `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE` through stdin.
  - Confirm both secret names and update timestamps without reading values.
  - Rescan tracked and untracked repository files for accidental key material.
  - Evidence:
    - `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE` were submitted through stdin to
      repository-scoped GitHub Actions secrets without printing their values.
    - GitHub metadata lists both secret names with update date 2026-09-20;
      values remain unreadable by design.
    - A content scan across all 41 tracked and untracked repository files found
      neither the passphrase nor an OpenPGP private-key block.
    - No tag, workflow release run, GitHub release, or Registry mutation was
      performed.

## Progress

- GnuPG 2.2.40 and OpenSSL 3.0.20 are available.
- The repository currently has no Actions secrets.
- The dedicated key exists locally; no tag, release, or Registry registration
  has been created.
- Both GitHub Actions signing secrets are configured for the provider
  repository.
- Work-unit commit: `a793ff8` (`docs(odd): record provider release signing
  setup`). RDD classified it passive (`non_executable_only`), so no review was
  due.

## Next step

Move the recovery material to offline or password-manager storage before the
temporary local copies are removed. Then separately authorize the first RC tag.
