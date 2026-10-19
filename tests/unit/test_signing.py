"""Ed25519 report signing: keys, envelope verification, tamper cases and CLI flows."""

from __future__ import annotations

import base64
import json
import os
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from typer.testing import CliRunner

from awsauditor import cli
from awsauditor.cli import app
from awsauditor.errors import AuditorError
from awsauditor.reporting import build_manifest
from awsauditor.signing import (
    KEY_ENV,
    PASSPHRASE_ENV,
    SignatureError,
    generate_keypair,
    load_private_key,
    load_public_key,
    public_key_id,
    sign_manifest,
    verify_signature,
)

from .conftest import ACCOUNT, NOW, Harness

runner = CliRunner()
MANIFEST = build_manifest({"a.json": "{}\n", "b.csv": "x\n"}).encode()


def report_json(out: Path) -> Path:
    """The JSON report (not the .sig.json signature envelope)."""
    (found,) = [p for p in out.glob("audit-*.json") if not p.name.endswith(".sig.json")]
    return found


def write_keys(tmp_path: Path, passphrase: bytes | None = None) -> tuple[Path, Path]:
    priv_pem, pub_pem = generate_keypair(passphrase)
    priv, pub = tmp_path / "k.pem", tmp_path / "k.pub"
    priv.write_bytes(priv_pem)
    priv.chmod(0o600)
    pub.write_bytes(pub_pem)
    return priv, pub


# ------------------------------------------------------------- keys


def test_generate_load_sign_verify_roundtrip(tmp_path: Path) -> None:
    priv, pub = write_keys(tmp_path)
    key, public = load_private_key(priv), load_public_key(pub)
    assert public_key_id(key.public_key()) == public_key_id(public)
    env = verify_signature(MANIFEST, sign_manifest(MANIFEST, key, NOW), public)
    assert env.algorithm == "ed25519" and env.signed_at == NOW.isoformat()
    assert env.key_id == public_key_id(public) and len(env.key_id) == 64


def test_signatures_are_deterministic_and_bound_to_content(tmp_path: Path) -> None:
    priv, _pub = write_keys(tmp_path)
    key = load_private_key(priv)
    assert sign_manifest(MANIFEST, key, NOW) == sign_manifest(MANIFEST, key, NOW)
    assert sign_manifest(MANIFEST, key, NOW) != sign_manifest(MANIFEST + b"x", key, NOW)


def test_encrypted_private_key_needs_the_passphrase(tmp_path: Path) -> None:
    priv, _pub = write_keys(tmp_path, b"correct horse")
    assert b"ENCRYPTED" in priv.read_bytes()
    assert load_private_key(priv, b"correct horse")
    with pytest.raises(AuditorError, match="needs a passphrase"):
        load_private_key(priv, None)
    with pytest.raises(AuditorError, match="passphrase is wrong"):
        load_private_key(priv, b"wrong")


def test_unencrypted_key_with_unneeded_passphrase_is_rejected_cleanly(tmp_path: Path) -> None:
    priv, _ = write_keys(tmp_path)
    with pytest.raises(AuditorError):
        load_private_key(priv, b"unneeded")


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644, 0o666, 0o660])
def test_group_or_world_accessible_private_key_is_refused(tmp_path: Path, mode: int) -> None:
    priv, _ = write_keys(tmp_path)
    priv.chmod(mode)
    with pytest.raises(AuditorError, match="chmod 600"):
        load_private_key(priv)
    priv.chmod(0o400)
    assert load_private_key(priv)  # read-only owner access is fine


def test_only_ed25519_keys_are_accepted(tmp_path: Path) -> None:
    for name, key in (
        ("rsa", rsa.generate_private_key(65537, 2048)),
        ("ec", ec.generate_private_key(ec.SECP256R1())),
    ):
        priv = tmp_path / f"{name}.pem"
        priv.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        priv.chmod(0o600)
        pub = tmp_path / f"{name}.pub"
        pub.write_bytes(
            key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        with pytest.raises(AuditorError, match="Ed25519"):
            load_private_key(priv)
        with pytest.raises(AuditorError, match="Ed25519"):
            load_public_key(pub)


def test_missing_or_garbage_key_files(tmp_path: Path) -> None:
    with pytest.raises(AuditorError, match="cannot read"):
        load_private_key(tmp_path / "nope.pem")
    with pytest.raises(AuditorError, match="cannot read"):
        load_public_key(tmp_path / "nope.pub")
    bad = tmp_path / "bad.pem"
    bad.write_text("not a key")
    bad.chmod(0o600)
    with pytest.raises(AuditorError, match="not a valid PEM"):
        load_private_key(bad)
    with pytest.raises(AuditorError, match="not a valid PEM"):
        load_public_key(bad)


# ------------------------------------------------------------- envelope tampering


def envelope(tmp_path: Path) -> tuple[dict[str, str], object, object]:
    priv, pub = write_keys(tmp_path)
    key, public = load_private_key(priv), load_public_key(pub)
    return json.loads(sign_manifest(MANIFEST, key, NOW)), key, public


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("signed_at", "2020-01-01T00:00:00+00:00"),  # timestamp is covered by the signature
        ("manifest_sha256", "0" * 64),
        ("key_id", "f" * 64),
        ("algorithm", "rsa"),
        ("version", 2),
        ("signature", base64.b64encode(b"x" * 64).decode()),
        ("signature", "!!!notbase64!!!"),
        ("signature", base64.b64encode(b"short").decode()),
    ],
)
def test_any_modified_envelope_field_fails(tmp_path: Path, field: str, value: object) -> None:
    env, _key, public = envelope(tmp_path)
    env[field] = value  # type: ignore[assignment]
    with pytest.raises(SignatureError):
        verify_signature(MANIFEST, json.dumps(env), public)  # type: ignore[arg-type]


def test_modified_manifest_wrong_key_and_malformed_envelopes_fail(tmp_path: Path) -> None:
    env, _key, public = envelope(tmp_path)
    text = json.dumps(env)
    with pytest.raises(SignatureError, match="modified"):
        verify_signature(MANIFEST + b"\n", text, public)  # type: ignore[arg-type]
    other_priv, other_pub = (
        write_keys(tmp_path / "x") if (tmp_path / "x").mkdir() is None else (0, 0)
    )
    with pytest.raises(SignatureError, match="different key"):
        verify_signature(MANIFEST, text, load_public_key(other_pub))  # type: ignore[arg-type]
    for bad in ("not json", "[]", json.dumps({**env, "extra": 1}), json.dumps({"version": 1})):
        with pytest.raises(SignatureError, match="malformed"):
            verify_signature(MANIFEST, bad, public)  # type: ignore[arg-type]
    assert other_priv


def test_signature_for_one_manifest_cannot_validate_another(tmp_path: Path) -> None:
    env, key, public = envelope(tmp_path)
    other = build_manifest({"a.json": "{ }\n"}).encode()
    forged = {
        **json.loads(sign_manifest(other, key, NOW)),
        "manifest_sha256": env["manifest_sha256"],
    }  # type: ignore[arg-type]
    with pytest.raises(SignatureError):
        verify_signature(MANIFEST, json.dumps(forged), public)  # type: ignore[arg-type]


# ------------------------------------------------------------- CLI


def test_keys_generate_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    priv, pub = tmp_path / "s.pem", tmp_path / "s.pub"
    monkeypatch.delenv(PASSPHRASE_ENV, raising=False)
    res = runner.invoke(
        app, ["keys", "generate", "--private-key", str(priv), "--public-key", str(pub)]
    )
    assert res.exit_code == 0 and "NOT encrypted" in res.output
    assert stat.S_IMODE(os.stat(priv).st_mode) == 0o600 and b"PRIVATE KEY" in priv.read_bytes()
    assert public_key_id(load_public_key(pub)) in res.output
    again = runner.invoke(
        app, ["keys", "generate", "--private-key", str(priv), "--public-key", str(pub)]
    )
    assert again.exit_code == 2 and "--force" in again.output
    monkeypatch.setenv(PASSPHRASE_ENV, "s3cret-pass")
    enc = runner.invoke(
        app, ["keys", "generate", "--private-key", str(priv), "--public-key", str(pub), "--force"]
    )
    assert (
        enc.exit_code == 0
        and "NOT encrypted" not in enc.output
        and b"ENCRYPTED" in priv.read_bytes()
    )
    assert "s3cret-pass" not in enc.output


CONFIG = (
    '[audit]\nprofile = "tiny"\nregions = ["us-east-1"]\nworkers = 1\n'
    '[profiles.tiny]\ninclude = ["IAM-002"]\n'
)


def wire(monkeypatch: pytest.MonkeyPatch) -> Harness:
    h = Harness()
    h.ok(
        "sts",
        "get_caller_identity",
        {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/a", "UserId": "x"},
        region=None,
    )
    h.ok(
        "ec2", "describe_regions", {"Regions": [{"RegionName": "us-east-1"}]}, {"AllRegions": False}
    )
    h.ok(
        "iam",
        "get_account_summary",
        {"SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}},
    )
    monkeypatch.setattr(cli, "make_factory", lambda *_a, **_k: h.factory)
    return h


@pytest.fixture
def audit(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[Path, Path, Path]:
    """A signed audit: returns (output dir, private key, public key)."""
    priv, pub = write_keys(tmp_path)
    cfg = tmp_path / "c.toml"
    cfg.write_text(CONFIG)
    wire(monkeypatch)
    out = tmp_path / "out"
    res = runner.invoke(
        app,
        [
            "audit",
            "run",
            "-c",
            str(cfg),
            "--output-dir",
            str(out),
            "--formats",
            "json,html",
            "--sign",
            "--signing-key",
            str(priv),
            "--confirm-account",
            ACCOUNT,
        ],
    )
    assert res.exit_code == 0, res.output
    return out, priv, pub


def test_signed_audit_verifies_with_the_public_key(audit: tuple[Path, Path, Path]) -> None:
    out, _priv, pub = audit
    manifest = next(out.glob("*.sha256"))
    assert manifest.with_suffix(".sig.json").is_file()
    assert stat.S_IMODE(os.stat(manifest.with_suffix(".sig.json")).st_mode) == 0o600
    res = runner.invoke(app, ["report", "verify", str(manifest), "--public-key", str(pub)])
    assert res.exit_code == 0 and "SIGNATURE VALID" in res.output and res.output.count("OK") == 2


def test_tampering_with_any_artifact_is_detected(audit: tuple[Path, Path, Path]) -> None:
    out, _priv, pub = audit
    manifest = next(out.glob("*.sha256"))
    sig = manifest.with_suffix(".sig.json")
    original = {
        p: p.read_bytes() for p in (manifest, sig, *out.glob("*.json"), *out.glob("*.html"))
    }

    def check(expected_code: int, needle: str) -> None:
        res = runner.invoke(app, ["report", "verify", str(manifest), "--public-key", str(pub)])
        assert res.exit_code == expected_code and needle in res.output, res.output
        for p, data in original.items():  # restore
            p.write_bytes(data)

    report_json(out).write_text('{"tampered": true}')
    check(1, "MISMATCH")
    # attacker also rewrites the manifest to match the tampered report: signature catches it
    report = next(out.glob("audit-*.html"))
    report.write_text("<html>forged</html>")
    manifest.write_text(build_manifest({p.name: p.read_text() for p in (report, report_json(out))}))
    check(1, "SIGNATURE INVALID")
    # attacker strips the signature
    sig.unlink()
    check(1, "SIGNATURE MISSING")


def test_unsigned_verify_notes_unchecked_signature(audit: tuple[Path, Path, Path]) -> None:
    out, _priv, _pub = audit
    res = runner.invoke(app, ["report", "verify", str(next(out.glob("*.sha256")))])
    assert res.exit_code == 0 and "was not checked" in res.output


def test_verify_with_wrong_public_key_fails(audit: tuple[Path, Path, Path], tmp_path: Path) -> None:
    out, _priv, _pub = audit
    (tmp_path / "other").mkdir()
    _p, other_pub = write_keys(tmp_path / "other")
    res = runner.invoke(
        app, ["report", "verify", str(next(out.glob("*.sha256"))), "--public-key", str(other_pub)]
    )
    assert res.exit_code == 1 and "different key" in res.output


def test_sign_after_the_fact_and_refuses_inconsistent_manifest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    priv, pub = write_keys(tmp_path)
    cfg = tmp_path / "c.toml"
    cfg.write_text(CONFIG)
    wire(monkeypatch)
    out = tmp_path / "o"
    assert (
        runner.invoke(
            app,
            [
                "audit",
                "run",
                "-c",
                str(cfg),
                "--output-dir",
                str(out),
                "--formats",
                "json",
                "--confirm-account",
                ACCOUNT,
            ],
        ).exit_code
        == 0
    )
    manifest = next(out.glob("*.sha256"))
    assert not manifest.with_suffix(".sig.json").exists()
    monkeypatch.setenv(KEY_ENV, str(priv))
    res = runner.invoke(app, ["report", "sign", str(manifest)])
    assert res.exit_code == 0, res.output
    assert (
        runner.invoke(app, ["report", "verify", str(manifest), "--public-key", str(pub)]).exit_code
        == 0
    )
    assert runner.invoke(app, ["report", "sign", str(manifest)]).exit_code == 2  # no overwrite
    report_json(out).write_text("changed")
    manifest.with_suffix(".sig.json").unlink()
    refused = runner.invoke(app, ["report", "sign", str(manifest)])
    assert refused.exit_code == 2 and "refusing to sign" in refused.output


def test_sign_without_a_key_fails_before_any_aws_call(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv(KEY_ENV, raising=False)
    cfg = tmp_path / "c.toml"
    cfg.write_text(CONFIG)
    h = wire(monkeypatch)
    res = runner.invoke(
        app,
        [
            "audit",
            "run",
            "-c",
            str(cfg),
            "--output-dir",
            str(tmp_path / "o"),
            "--sign",
            "--confirm-account",
            ACCOUNT,
        ],
    )
    assert res.exit_code == 2 and KEY_ENV in res.output and not (tmp_path / "o").exists()
    with pytest.raises(AssertionError):
        h.assert_all_consumed()  # sts/ec2/iam responses untouched: no AWS call was made


def test_sign_with_insecure_key_permissions_fails_early(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    priv, _pub = write_keys(tmp_path)
    priv.chmod(0o644)
    cfg = tmp_path / "c.toml"
    cfg.write_text(CONFIG)
    wire(monkeypatch)
    res = runner.invoke(
        app,
        [
            "audit",
            "run",
            "-c",
            str(cfg),
            "--sign",
            "--signing-key",
            str(priv),
            "--confirm-account",
            ACCOUNT,
        ],
    )
    assert res.exit_code == 2 and "chmod 600" in res.output


def test_signing_key_never_appears_in_outputs(audit: tuple[Path, Path, Path]) -> None:
    out, priv, _pub = audit
    secret_body = priv.read_text().splitlines()[1]
    for f in out.iterdir():
        assert secret_body not in f.read_text()
