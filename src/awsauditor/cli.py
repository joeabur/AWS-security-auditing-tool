"""Command-line interface."""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Annotated, NamedTuple, NoReturn

import typer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import __version__
from .catalog import load_catalog, select_controls
from .config import REPORT_FORMATS, AuditConfig, RedactionSettings, load_config
from .errors import AccountMismatch, AuditorError, ConfigError
from .models import Control, Severity, Status, utcnow
from .organizations import list_accounts
from .policy import build_policy
from .redaction import Redactor
from .regions import RegionPlan, plan_regions
from .reporting import (
    RENDERERS,
    build_manifest,
    build_report,
    diff_reports,
    filter_findings,
    load_report,
    verify_manifest,
    write_report_file,
)
from .runner import run_audit
from .session import ClientFactory, Identity, build_session, resolve_identity
from .signing import (
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
from .suppressions import apply_suppressions

app = typer.Typer(help="Read-only AWS security auditing tool.", no_args_is_help=True)
controls_app = typer.Typer(help="Inspect the control catalog.", no_args_is_help=True)
config_app = typer.Typer(help="Configuration utilities.", no_args_is_help=True)
audit_app = typer.Typer(help="Run audits.", no_args_is_help=True)
findings_app = typer.Typer(help="Query saved reports.", no_args_is_help=True)
report_app = typer.Typer(help="Export saved reports.", no_args_is_help=True)
policy_app = typer.Typer(help="Least-privilege IAM policy.", no_args_is_help=True)
org_app = typer.Typer(help="Optional AWS Organizations discovery.", no_args_is_help=True)
keys_app = typer.Typer(help="Report-signing keys.", no_args_is_help=True)
for name, sub in [
    ("controls", controls_app),
    ("config", config_app),
    ("audit", audit_app),
    ("findings", findings_app),
    ("keys", keys_app),
    ("report", report_app),
    ("policy", policy_app),
    ("org", org_app),
]:
    app.add_typer(sub, name=name)

EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_INCOMPLETE = 3
EXTERNAL_ID_ENV = "AWSAUDITOR_EXTERNAL_ID"
_DEFAULT_HOME = {"aws": "us-east-1", "aws-cn": "cn-north-1", "aws-us-gov": "us-gov-west-1"}

ConfigOpt = Annotated[Path | None, typer.Option("--config", "-c", help="TOML configuration file.")]


def _fail(message: str, code: int = EXIT_ERROR) -> NoReturn:
    typer.secho(f"error: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code)


def _csv_list(value: str | None) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()] if value else []


def make_factory(
    config: AuditConfig, aws_profile: str | None, role_arn: str | None
) -> ClientFactory:
    """Build the client factory (seam for tests). Credentials never pass through arguments."""
    session = build_session(
        aws_profile or config.aws.profile,
        role_arn or config.aws.role_arn,
        config.aws.role_session_name,
        config.aws.role_duration_seconds,
        os.environ.get(EXTERNAL_ID_ENV),
    )
    return ClientFactory(
        session,
        max_attempts=config.aws.max_attempts,
        connect_timeout=config.aws.connect_timeout,
        read_timeout=config.aws.read_timeout,
    )


def _load_signing_key(path: Path | None) -> Ed25519PrivateKey:
    """Key path from --signing-key or the environment; passphrase only from the environment."""
    chosen = path or (Path(os.environ[KEY_ENV]) if os.environ.get(KEY_ENV) else None)
    if chosen is None:
        raise AuditorError(f"no signing key: pass --signing-key PATH or set {KEY_ENV}")
    passphrase = os.environ.get(PASSPHRASE_ENV)
    return load_private_key(chosen, passphrase.encode() if passphrase else None)


def _selected(config: AuditConfig, audit_profile: str | None) -> tuple[str, list[Control]]:
    name = audit_profile or config.audit.profile
    spec = config.all_profiles().get(name)
    if spec is None:
        raise ConfigError(f"unknown audit profile '{name}'")
    catalog = load_catalog()
    return name, select_controls(
        catalog,
        services=spec.services or None,
        include=spec.include or None,
        exclude=spec.exclude or None,
        min_severity=spec.min_severity,
    )


# ---------------------------------------------------------------- controls


@controls_app.command("list")
def controls_list(
    service: Annotated[str | None, typer.Option(help="Filter by service.")] = None,
    severity: Annotated[Severity | None, typer.Option(help="Minimum severity.")] = None,
    fmt: Annotated[str, typer.Option("--format", help="table or json.")] = "table",
) -> None:
    """List catalog controls."""
    catalog = load_catalog()
    items = select_controls(catalog, services=[service] if service else None, min_severity=severity)
    if fmt == "json":
        typer.echo(json.dumps([c.model_dump(mode="json") for c in items], indent=2))
        return
    if fmt != "table":
        _fail("--format must be 'table' or 'json'")
    typer.echo(f"Catalog {catalog.catalog_version} ({len(items)} controls)")
    for c in items:
        typer.echo(f"{c.id:8} {c.severity.value:8} {c.scope.value:8} {c.title}")


@controls_app.command("show")
def controls_show(control_id: str) -> None:
    """Show one control in full."""
    for c in load_catalog().controls:
        if c.id == control_id.upper():
            typer.echo(json.dumps(c.model_dump(mode="json"), indent=2))
            return
    _fail(f"unknown control '{control_id}'")


# ---------------------------------------------------------------- config


@config_app.command("validate")
def config_validate(path: Annotated[Path, typer.Argument(help="Config file.")]) -> None:
    """Validate a configuration file (no AWS calls are made)."""
    try:
        cfg = load_config(path)
        name, controls = _selected(cfg, None)
        known = {c.id for c in load_catalog().controls}
        unknown = sorted({s.control_id for s in cfg.suppressions} - known)
        if unknown:
            raise ConfigError(f"suppressions reference unknown control id(s): {', '.join(unknown)}")
    except AuditorError as exc:
        _fail(str(exc))
    typer.echo(
        f"OK: profile '{name}' selects {len(controls)} controls; "
        f"{len(cfg.suppressions)} suppression(s)."
    )


# ---------------------------------------------------------------- audit


class Prepared(NamedTuple):
    name: str
    controls: list[Control]
    factory: ClientFactory
    identity: Identity
    home: str
    plan: RegionPlan


def _prepare(
    config: AuditConfig,
    aws_profile: str | None,
    role_arn: str | None,
    regions: str | None,
    audit_profile: str | None,
) -> Prepared:
    name, controls = _selected(config, audit_profile)
    factory = make_factory(config, aws_profile, role_arn)
    identity = resolve_identity(factory, config.aws.home_region)
    home = (
        config.aws.home_region
        or factory.default_region
        or _DEFAULT_HOME.get(identity.partition, "us-east-1")
    )
    requested = _csv_list(regions) or config.audit.regions
    plan = plan_regions(factory, requested, home, identity.partition)
    return Prepared(name, controls, factory, identity, home, plan)


@audit_app.command("plan")
def audit_plan(
    config_path: ConfigOpt = None,
    aws_profile: Annotated[str | None, typer.Option(help="AWS shared-config profile name.")] = None,
    role_arn: Annotated[str | None, typer.Option(help="IAM role to assume.")] = None,
    regions: Annotated[str | None, typer.Option(help="Comma-separated regions or 'all'.")] = None,
    audit_profile: Annotated[str | None, typer.Option(help="Audit profile name.")] = None,
) -> None:
    """Resolve identity, regions and controls, then print them. Audits nothing."""
    try:
        cfg = load_config(config_path)
        name, controls, _f, identity, home, plan = _prepare(
            cfg, aws_profile, role_arn, regions, audit_profile
        )
    except AuditorError as exc:
        _fail(str(exc))
    typer.echo(f"Account:   {identity.account_id}\nPrincipal: {identity.arn}")
    typer.echo(f"Home region: {home}\nRegions ({len(plan.audited)}): {', '.join(plan.audited)}")
    typer.echo(f"Profile '{name}': {len(controls)} controls")
    for w in plan.warnings:
        typer.secho(f"warning: {w}", fg=typer.colors.YELLOW, err=True)


@audit_app.command("run")
def audit_run(
    config_path: ConfigOpt = None,
    aws_profile: Annotated[str | None, typer.Option(help="AWS shared-config profile name.")] = None,
    role_arn: Annotated[str | None, typer.Option(help="IAM role to assume.")] = None,
    regions: Annotated[str | None, typer.Option(help="Comma-separated regions or 'all'.")] = None,
    audit_profile: Annotated[str | None, typer.Option(help="Audit profile name.")] = None,
    confirm_account: Annotated[
        str | None, typer.Option(help="Account ID that must match the resolved account.")
    ] = None,
    output_dir: Annotated[Path | None, typer.Option(help="Report directory.")] = None,
    formats: Annotated[str | None, typer.Option(help="Comma list of json,csv,html.")] = None,
    redact: Annotated[bool | None, typer.Option("--redact/--no-redact")] = None,
    force: Annotated[bool, typer.Option(help="Overwrite existing report files.")] = False,
    fail_on: Annotated[
        Severity | None, typer.Option(help="Exit 1 if a FAIL at/above this severity exists.")
    ] = None,
    strict: Annotated[bool, typer.Option(help="Exit 3 if any control result is unknown.")] = False,
    workers: Annotated[
        int | None, typer.Option(min=1, max=16, help="Parallel API workers (default: config).")
    ] = None,
    sign: Annotated[bool, typer.Option(help="Sign the report manifest (Ed25519).")] = False,
    signing_key: Annotated[
        Path | None,
        typer.Option(help=f"Ed25519 private key PEM (default: ${KEY_ENV}); mode 0600 required."),
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Run an audit after explicit account confirmation."""
    logging.basicConfig(level=logging.INFO if verbose else logging.WARNING, stream=sys.stderr)
    try:
        cfg = load_config(config_path)
        if redact is not None:
            cfg.redaction.enabled = redact
        if workers is not None:
            cfg.audit.workers = workers
        signer = _load_signing_key(signing_key) if sign else None  # fail before any AWS call
        name, controls, factory, identity, home, plan = _prepare(
            cfg, aws_profile, role_arn, regions, audit_profile
        )
        typer.echo(f"Account:   {identity.account_id}\nPrincipal: {identity.arn}")
        typer.echo(f"Regions ({len(plan.audited)}): {', '.join(plan.audited)}")
        typer.echo(f"Profile '{name}': {len(controls)} controls (read-only API calls only)")
        for w in plan.warnings:
            typer.secho(f"warning: {w}", fg=typer.colors.YELLOW, err=True)
        _confirm(identity.account_id, confirm_account)
        result = run_audit(
            factory,
            identity,
            cfg,
            load_catalog(),
            controls,
            plan,
            home_region=home,
            profile_name=name,
        )
        result.warnings += apply_suppressions(
            result.findings, cfg.suppressions, result.started_at.date()
        )
        for w in result.warnings[len(plan.warnings) :]:
            typer.secho(f"warning: {w}", fg=typer.colors.YELLOW, err=True)
        report = build_report(result)
        fmts = _csv_list(formats) or cfg.output.formats
        bad = set(fmts) - set(REPORT_FORMATS)
        if bad:
            raise ConfigError(f"unsupported formats: {sorted(bad)}")
        out = output_dir or cfg.output.directory
        stamp = result.started_at.strftime("%Y%m%dT%H%M%SZ")
        redactor = Redactor(cfg.redaction)
        written: dict[str, str] = {}
        for fmt in fmts:
            path = out / f"audit-{stamp}.{fmt}"
            written[path.name] = RENDERERS[fmt](report, redactor)
            write_report_file(path, written[path.name], overwrite=force)
            typer.echo(f"wrote {path}")
        manifest = out / f"audit-{stamp}.sha256"
        manifest_text = build_manifest(written)
        write_report_file(manifest, manifest_text, overwrite=force)
        typer.echo(f"wrote {manifest} (verify with: awsauditor report verify {manifest})")
        if signer is not None:
            sig = manifest.with_suffix(".sig.json")
            envelope = sign_manifest(manifest_text.encode("utf-8"), signer, result.finished_at)
            write_report_file(sig, envelope, overwrite=force)
            typer.echo(f"wrote {sig} (key id {public_key_id(signer.public_key())[:16]}...)")
    except AuditorError as exc:
        _fail(str(exc))
    s = report.summary
    typer.echo(f"Result: {s['by_status']}")
    if s["suppressed_failures"]:
        typer.echo(f"{s['suppressed_failures']} failing finding(s) are suppressed (still shown).")
    if s["controls_with_unknown_results"]:
        typer.secho(
            "Some results are unknown (ERROR/NOT_ASSESSED): "
            + ", ".join(s["controls_with_unknown_results"]),
            fg=typer.colors.YELLOW,
        )
    if fail_on and any(
        f.status is Status.FAIL and f.suppression is None and f.severity.rank >= fail_on.rank
        for f in report.findings
    ):
        raise typer.Exit(EXIT_FINDINGS)
    if strict and s["controls_with_unknown_results"]:
        raise typer.Exit(EXIT_INCOMPLETE)


def _interactive() -> bool:
    return sys.stdin.isatty()


def _confirm(resolved: str, supplied: str | None) -> None:
    if supplied is None:
        if not _interactive():
            raise AccountMismatch(
                "non-interactive run: pass --confirm-account with the account ID shown above"
            )
        supplied = typer.prompt("Type the account ID to confirm the audit")
    if supplied.strip() != resolved:
        raise AccountMismatch("confirmation does not match the resolved account; aborting")


# ---------------------------------------------------------------- findings / report


def _status_list(values: str | None) -> list[Status]:
    try:
        return [Status(v.upper()) for v in _csv_list(values)]
    except ValueError as exc:
        raise ConfigError(f"invalid status: {exc}") from exc


@findings_app.command("filter")
def findings_filter(
    report_path: Path,
    status: Annotated[str | None, typer.Option(help="Comma list, e.g. FAIL,ERROR.")] = None,
    min_severity: Annotated[Severity | None, typer.Option()] = None,
    control: Annotated[str | None, typer.Option(help="Comma list of control IDs.")] = None,
    region: Annotated[str | None, typer.Option(help="Comma list of regions.")] = None,
    resource_contains: Annotated[str | None, typer.Option()] = None,
    fmt: Annotated[str, typer.Option("--format", help="table or json.")] = "table",
) -> None:
    """Filter findings from a saved JSON report."""
    try:
        rep = load_report(report_path)
        found = filter_findings(
            rep.findings,
            statuses=_status_list(status),
            min_severity=min_severity,
            control_ids=_csv_list(control),
            regions=_csv_list(region),
            resource_contains=resource_contains,
        )
    except AuditorError as exc:
        _fail(str(exc))
    if fmt == "json":
        typer.echo(json.dumps([json.loads(f.model_dump_json()) for f in found], indent=2))
        return
    for f in found:
        typer.echo(
            f"{f.status.value:14} {f.severity.value:8} {f.control_id:8} {f.region:14} "
            f"{f.resource_id}  {f.message}"
        )
    typer.echo(f"{len(found)} finding(s)")


@report_app.command("export")
def report_export(
    report_path: Path,
    fmt: Annotated[str, typer.Option("--format", help="json, csv, html or sarif.")],
    output: Annotated[Path, typer.Option(help="Destination file.")],
    redact: Annotated[bool, typer.Option(help="Apply account/key/IP redaction.")] = False,
    ip_addresses: Annotated[bool, typer.Option(help="Also mask IPv4 addresses.")] = False,
    force: Annotated[bool, typer.Option()] = False,
) -> None:
    """Convert a saved JSON report to another format, optionally redacted."""
    if fmt not in RENDERERS:
        _fail(f"--format must be one of: {', '.join(RENDERERS)}")
    try:
        rep = load_report(report_path)
        redactor = Redactor(RedactionSettings(enabled=redact, ip_addresses=ip_addresses))
        write_report_file(output, RENDERERS[fmt](rep, redactor), overwrite=force)
    except AuditorError as exc:
        _fail(str(exc))
    typer.echo(f"wrote {output}")


@report_app.command("verify")
def report_verify(
    manifest: Path,
    public_key: Annotated[
        Path | None,
        typer.Option(help="Ed25519 public key PEM. If given, a valid signature is REQUIRED."),
    ] = None,
) -> None:
    """Check report files against their SHA-256 manifest and, with --public-key, its signature.

    Without --public-key only the file hashes are checked (tamper evidence). Supplying the key
    makes a missing or invalid signature a failure, so stripping the signature cannot pass.
    """
    sig_path = manifest.with_suffix(".sig.json")
    failed = False
    try:
        results = verify_manifest(manifest)
        pub = load_public_key(public_key) if public_key else None
    except AuditorError as exc:
        _fail(str(exc))
    for name, state in results:
        typer.echo(f"{state:9} {name}")
        failed |= state != "OK"
    if pub is not None:
        if not sig_path.is_file():
            typer.secho(f"SIGNATURE MISSING ({sig_path.name} not found)", fg=typer.colors.RED)
            failed = True
        else:
            try:
                env = verify_signature(manifest.read_bytes(), sig_path.read_text("utf-8"), pub)
                typer.echo(f"SIGNATURE VALID (key {env.key_id[:16]}..., signed_at {env.signed_at})")
            except (SignatureError, OSError) as exc:
                typer.secho(f"SIGNATURE INVALID: {exc}", fg=typer.colors.RED)
                failed = True
    elif sig_path.is_file():
        typer.secho(
            "note: a signature file exists but was not checked; pass --public-key to verify it",
            fg=typer.colors.YELLOW,
        )
    if failed:
        raise typer.Exit(EXIT_FINDINGS)


@report_app.command("sign")
def report_sign(
    manifest: Path,
    signing_key: Annotated[
        Path | None, typer.Option(help=f"Private key PEM (default: ${KEY_ENV}).")
    ] = None,
    force: Annotated[bool, typer.Option()] = False,
) -> None:
    """Sign an existing report manifest (after verifying its file hashes)."""
    try:
        if any(state != "OK" for _n, state in verify_manifest(manifest)):
            raise AuditorError("refusing to sign: manifest does not match the report files")
        key = _load_signing_key(signing_key)
        sig = manifest.with_suffix(".sig.json")
        envelope = sign_manifest(manifest.read_bytes(), key, utcnow())
        write_report_file(sig, envelope, overwrite=force)
    except AuditorError as exc:
        _fail(str(exc))
    typer.echo(f"wrote {sig} (key id {public_key_id(key.public_key())})")


@keys_app.command("generate")
def keys_generate(
    private_key: Annotated[Path, typer.Option(help="Where to write the private key (0600).")],
    public_key: Annotated[Path, typer.Option(help="Where to write the public key.")],
    force: Annotated[bool, typer.Option()] = False,
) -> None:
    """Generate an Ed25519 signing key pair. Set the passphrase via the environment."""
    passphrase = os.environ.get(PASSPHRASE_ENV)
    try:
        private_pem, public_pem = generate_keypair(passphrase.encode() if passphrase else None)
        write_report_file(private_key, private_pem.decode("ascii"), overwrite=force)
        write_report_file(public_key, public_pem.decode("ascii"), overwrite=force)
        os.chmod(public_key, 0o644)
        key_id = public_key_id(load_public_key(public_key))
    except AuditorError as exc:
        _fail(str(exc))
    typer.echo(f"private key: {private_key} (keep secret, back it up offline)")
    typer.echo(f"public key:  {public_key} (distribute to verifiers out of band)")
    typer.echo(f"key id (SHA-256 fingerprint): {key_id}")
    if not passphrase:
        typer.secho(
            f"warning: private key is NOT encrypted; set {PASSPHRASE_ENV} before "
            "generating to encrypt it",
            fg=typer.colors.YELLOW,
            err=True,
        )


@report_app.command("diff")
def report_diff(
    old_report: Path,
    new_report: Path,
    fmt: Annotated[str, typer.Option("--format", help="table or json.")] = "table",
    fail_on_regression: Annotated[
        bool, typer.Option(help="Exit 1 if any control newly fails.")
    ] = False,
) -> None:
    """Show what changed between two saved JSON reports (matched by finding_id)."""
    try:
        result = diff_reports(load_report(old_report), load_report(new_report))
    except AuditorError as exc:
        _fail(str(exc))
    if fmt == "json":
        typer.echo(json.dumps(result, indent=2))
    elif fmt == "table":
        for note in result["notes"]:
            typer.secho(f"note: {note}", fg=typer.colors.YELLOW, err=True)
        labels = {
            "regressions": "NEW FAILURES",
            "resolved": "RESOLVED",
            "became_unknown": "BECAME UNKNOWN (not an improvement)",
            "not_reported": "NO LONGER REPORTED (cannot confirm resolved)",
        }
        for key, label in labels.items():
            typer.echo(f"{label}: {result['counts'][key]}")
            for item in result[key]:
                typer.echo(
                    f"  {item['control_id']:8} {item['severity']:8} {item['region']:12} "
                    f"{item['resource_id']}"
                )
        typer.echo(f"unchanged: {result['counts']['unchanged']}")
    else:
        _fail("--format must be 'table' or 'json'")
    if fail_on_regression and result["counts"]["regressions"]:
        raise typer.Exit(EXIT_FINDINGS)


# ---------------------------------------------------------------- policy / org


@policy_app.command("generate")
def policy_generate(
    config_path: ConfigOpt = None,
    audit_profile: Annotated[str | None, typer.Option(help="Audit profile name.")] = None,
) -> None:
    """Print the IAM policy needed for the selected controls."""
    try:
        _name, controls = _selected(load_config(config_path), audit_profile)
    except AuditorError as exc:
        _fail(str(exc))
    typer.echo(json.dumps(build_policy(controls), indent=2))


@org_app.command("list-accounts")
def org_list_accounts(
    config_path: ConfigOpt = None,
    aws_profile: Annotated[str | None, typer.Option()] = None,
    role_arn: Annotated[str | None, typer.Option()] = None,
) -> None:
    """List member accounts (needs organizations:DescribeOrganization and ListAccounts)."""
    try:
        cfg = load_config(config_path)
        factory = make_factory(cfg, aws_profile, role_arn)
        identity = resolve_identity(factory)
        home = (
            cfg.aws.home_region
            or factory.default_region
            or _DEFAULT_HOME.get(identity.partition, "us-east-1")
        )
        for acct in list_accounts(factory, home):
            typer.echo(f"{acct.account_id}  {acct.status:10} {acct.name}")
    except AuditorError as exc:
        _fail(str(exc))
    except Exception as exc:
        _fail(f"Organizations discovery failed: {type(exc).__name__}")


@app.command("version")
def version() -> None:
    """Print the tool version."""
    typer.echo(__version__)
