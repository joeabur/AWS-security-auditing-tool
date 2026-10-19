# Report signing

Reports can be signed with **Ed25519** (via the `cryptography` library). A signature proves that
the manifest, and through its SHA-256 entries every report file it lists, is exactly what the
holder of the private key signed.

## What it proves, and what it does not

| Proves | Does not prove |
|---|---|
| The files were not modified after signing (any byte change fails) | *When* signing happened: `signed_at` is self-asserted, there is no trusted timestamp |
| The signer held the private key whose public key you verified against | That the audit ran correctly, or that the AWS data was accurate |
| A stripped signature is detected (verifying with `--public-key` requires one) | That the public key you hold is the right one: distribute it out of band |

## Workflow

```bash
# once, on a trusted machine: generate the key pair (encrypt the private key!)
export AWSAUDITOR_SIGNING_KEY_PASSPHRASE='...'          # read from the environment only
awsauditor keys generate --private-key audit-signing.pem --public-key audit-signing.pub
# keep audit-signing.pem secret (mode 0600, offline backup); share audit-signing.pub

# sign during an audit (key path from --signing-key or $AWSAUDITOR_SIGNING_KEY)
awsauditor audit run --sign --signing-key audit-signing.pem ...

# or sign an existing, intact manifest afterwards
awsauditor report sign audit-<stamp>.sha256

# verify anywhere, with only the public key
awsauditor report verify audit-<stamp>.sha256 --public-key audit-signing.pub
```

`audit run --sign` writes `audit-<stamp>.json|html|...`, `audit-<stamp>.sha256` (the manifest) and
`audit-<stamp>.sig.json` (the signature envelope). Verification exit codes: `0` everything valid,
`1` any hash mismatch, missing file, missing/invalid signature, or wrong key.

## Design

- **Signed bytes:** a fixed domain tag (`awsauditor-report-signature-v1`) followed by canonical JSON
  (`sorted keys`, no whitespace) of `{version, algorithm, key_id, signed_at, manifest_sha256}`. The
  timestamp and manifest hash are therefore covered, and the signature cannot be replayed as a
  signature over arbitrary data. Ed25519 signing is deterministic.
- **`key_id`** is the SHA-256 fingerprint of the raw public key. A mismatch is reported as "different
  key" rather than a generic failure.
- **Strictness:** unknown envelope fields, wrong version/algorithm, non-canonical base64, wrong
  signature length and non-Ed25519 keys are all rejected.
- **Secrets handling:** the private key is never accepted on the command line or in config files.
  Only its *path* may be passed (`--signing-key` or `AWSAUDITOR_SIGNING_KEY`); the passphrase is read
  only from `AWSAUDITOR_SIGNING_KEY_PASSPHRASE`. A key readable by group/others is refused (POSIX).
  Key loading happens before any AWS call, so a bad key fails the run immediately.
- Keys generated without a passphrase are unencrypted; the CLI warns.

## Operational guidance

- Prefer a dedicated signing key per environment; rotate by generating a new pair and publishing
  the new public key; old reports still verify against the old public key.
- For stronger protection, generate and keep the key on a hardware token or HSM and sign the
  manifest bytes out of band (the envelope format is plain JSON documented above). Direct AWS KMS
  signing is not built in: `kms:Sign` is not a read-only operation and would require widening the
  client guard and the IAM policy.
- If the private key may be compromised, treat every report signed since the suspected date as
  unverified.
