"""Ed25519 signing of report manifests.

What a valid signature proves: the manifest (and therefore, through its SHA-256 entries, every
report file it lists) is byte-for-byte what the holder of the private key signed. What it does
not prove: *when* it was signed (``signed_at`` is self-asserted; there is no trusted timestamp),
that the audit itself was run correctly, or that the public key you verified against is the
right one - distribute it out of band.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import stat
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, ValidationError

from .errors import AuditorError

KEY_ENV = "AWSAUDITOR_SIGNING_KEY"
PASSPHRASE_ENV = "AWSAUDITOR_SIGNING_KEY_PASSPHRASE"  # noqa: S105 - env var *name*, not a secret
ALGORITHM = "ed25519"
VERSION = 1
_DOMAIN = (
    b"awsauditor-report-signature-v1\n"  # domain separation: never a valid signature elsewhere
)


class SignatureError(AuditorError):
    """A signature is missing, malformed, or does not verify."""


class SignatureEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int
    algorithm: str
    key_id: str
    signed_at: str
    manifest_sha256: str
    signature: str


def public_key_id(key: Ed25519PublicKey) -> str:
    """SHA-256 fingerprint of the raw public key (hex)."""
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


def _signed_bytes(header: dict[str, Any]) -> bytes:
    canonical = json.dumps(header, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return _DOMAIN + canonical.encode("ascii")


def generate_keypair(passphrase: bytes | None = None) -> tuple[bytes, bytes]:
    """Return ``(private_pem, public_pem)``; the private key is encrypted given a passphrase."""
    private = Ed25519PrivateKey.generate()
    encryption: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase
        else serialization.NoEncryption()
    )
    private_pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
    )
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem


def _check_private_key_permissions(path: Path) -> None:
    if os.name == "nt":  # POSIX permission bits are not meaningful on Windows
        return
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise AuditorError(
            f"signing key {path} is accessible by group/others (mode {mode:o}); run: chmod 600"
        )


def load_private_key(path: Path, passphrase: bytes | None = None) -> Ed25519PrivateKey:
    try:
        _check_private_key_permissions(path)
        data = path.read_bytes()
    except OSError as exc:
        raise AuditorError(f"cannot read signing key {path}: {type(exc).__name__}") from exc
    try:
        key = serialization.load_pem_private_key(data, password=passphrase or None)
    except TypeError as exc:  # encrypted key, no passphrase supplied (or the reverse)
        raise AuditorError(
            f"signing key needs a passphrase: set {PASSPHRASE_ENV} (or the key is not encrypted)"
        ) from exc
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise AuditorError("signing key is not a valid PEM key or the passphrase is wrong") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise AuditorError("signing key must be an Ed25519 private key")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise AuditorError(f"cannot read public key {path}: {type(exc).__name__}") from exc
    try:
        key = serialization.load_pem_public_key(data)
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise AuditorError("public key is not a valid PEM key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise AuditorError("public key must be an Ed25519 public key")
    return key


def sign_manifest(manifest: bytes, key: Ed25519PrivateKey, signed_at: datetime) -> str:
    """Return the JSON signature envelope for ``manifest`` bytes."""
    header = {
        "version": VERSION,
        "algorithm": ALGORITHM,
        "key_id": public_key_id(key.public_key()),
        "signed_at": signed_at.isoformat(),
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
    }
    signature = base64.b64encode(key.sign(_signed_bytes(header))).decode("ascii")
    return json.dumps({**header, "signature": signature}, indent=2) + "\n"


def verify_signature(
    manifest: bytes, envelope_text: str, public: Ed25519PublicKey
) -> SignatureEnvelope:
    """Verify ``manifest`` against the envelope and public key; raises SignatureError."""
    try:
        env = SignatureEnvelope.model_validate(json.loads(envelope_text))
    except (json.JSONDecodeError, ValidationError) as exc:
        raise SignatureError("signature file is malformed") from exc
    if env.version != VERSION or env.algorithm != ALGORITHM:
        raise SignatureError(
            f"unsupported signature version/algorithm: {env.version}/{env.algorithm}"
        )
    if env.key_id != public_key_id(public):
        raise SignatureError("signature was made by a different key than the one supplied")
    if env.manifest_sha256 != hashlib.sha256(manifest).hexdigest():
        raise SignatureError("manifest does not match the signed manifest hash (modified?)")
    try:
        raw = base64.b64decode(env.signature, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SignatureError("signature is not valid base64") from exc
    header = env.model_dump(exclude={"signature"})
    try:
        public.verify(raw, _signed_bytes(header))
    except InvalidSignature as exc:
        raise SignatureError("signature does not verify") from exc
    return env
