"""Command-line interface."""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Annotated, NamedTuple, NoReturn

import typer

from . import __version__
from .catalog import load_catalog, select_controls
from .config import AuditConfig, load_config
from .errors import AccountMismatch, AuditorError, ConfigError
from .models import Control, Severity, Status
from .organizations import list_accounts
from .policy import build_policy
from .redaction import Redactor
from .regions import RegionPlan, plan_regions
from .reporting import (
    build_report,
    filter_findings,
    load_report,
    to_csv,
    to_html,
    to_json,
    write_report_file,
)
from .runner import run_audit
from .session import ClientFactory, Identity, build_session, resolve_identity

app = typer.Typer(help="Read-only AWS security auditing tool.", no_args_is_help=True)
controls_app = typer.Typer(help="Inspect the control catalog.", no_args_is_help=True)
config_app = typer.Typer(help="Configuration utilities.", no_args_is_help=True)
audit_app = typer.Typer(help="Run audits.", no_args_is_help=True)
findings_app = typer.Typer(help="Query saved reports.", no_args_is_help=True)
report_app = typer.Typer(help="Export saved reports.", no_args_is_help=True)
policy_app = typer.Typer(help="Least-privilege IAM policy.", no_args_is_help=True)
org_app = typer.Typer(help="Optional AWS Organizations discovery.", no_args_is_help=True)
for name, sub in [
    ("controls", controls_app),
    ("config", config_app),
    ("audit", audit_app),
    ("findings", findings_app),
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
    except AuditorError as exc:
        _fail(str(exc))
    typer.echo(f"OK: profile '{name}' selects {len(controls)} controls.")


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
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Run an audit after explicit account confirmation."""
    logging.basicConfig(level=logging.INFO if verbose else logging.WARNING, stream=sys.stderr)
    try:
        cfg = load_config(config_path)
        if redact is not None:
            cfg.redaction.enabled = redact
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
        report = build_report(result)
        fmts = _csv_list(formats) or cfg.output.formats
        bad = set(fmts) - {"json", "csv", "html"}
        if bad:
            raise ConfigError(f"unsupported formats: {sorted(bad)}")
        out = output_dir or cfg.output.directory
        stamp = result.started_at.strftime("%Y%m%dT%H%M%SZ")
        redactor = Redactor(cfg.redaction)
        renderers = {"json": to_json, "csv": to_csv, "html": to_html}
        for fmt in fmts:
            path = out / f"audit-{stamp}.{fmt}"
            write_report_file(path, renderers[fmt](report, redactor), overwrite=force)
            typer.echo(f"wrote {path}")
    except AuditorError as exc:
        _fail(str(exc))
    s = report.summary
    typer.echo(f"Result: {s['by_status']}")
    if s["controls_with_unknown_results"]:
        typer.secho(
            "Some results are unknown (ERROR/NOT_ASSESSED): "
            + ", ".join(s["controls_with_unknown_results"]),
            fg=typer.colors.YELLOW,
        )
    if fail_on and any(
        f.status is Status.FAIL and f.severity.rank >= fail_on.rank for f in report.findings
    ):
        raise typer.Exit(EXIT_FINDINGS)
    if strict and s["controls_with_unknown_results"]:
        raise typer.Exit(EXIT_INCOMPLETE)


def _confirm(resolved: str, supplied: str | None) -> None:
    if supplied is None:
        if not sys.stdin.isatty():
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
    fmt: Annotated[str, typer.Option("--format", help="json, csv or html.")],
    output: Annotated[Path, typer.Option(help="Destination file.")],
    redact: Annotated[bool, typer.Option(help="Apply account/key/IP redaction.")] = False,
    ip_addresses: Annotated[bool, typer.Option(help="Also mask IPv4 addresses.")] = False,
    force: Annotated[bool, typer.Option()] = False,
) -> None:
    """Convert a saved JSON report to another format, optionally redacted."""
    from .config import RedactionSettings

    renderers = {"json": to_json, "csv": to_csv, "html": to_html}
    if fmt not in renderers:
        _fail("--format must be json, csv or html")
    try:
        rep = load_report(report_path)
        redactor = Redactor(RedactionSettings(enabled=redact, ip_addresses=ip_addresses))
        write_report_file(output, renderers[fmt](rep, redactor), overwrite=force)
    except AuditorError as exc:
        _fail(str(exc))
    typer.echo(f"wrote {output}")


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
