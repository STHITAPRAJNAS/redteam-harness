"""Command-line interface.

    rtharness list                     # show probes and their tiers/mappings
    rtharness run --config cfg.yaml    # run an assessment from a config file
    rtharness run --target openai --model gpt-4o-mini --tier 2
    rtharness demo                     # run against the built-in mock agent

Reports are written to the output directory in the requested formats, and the
process exit code reflects ``--fail-on`` for CI gating.
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import __version__
from . import api
from .config import RunConfig
from .core import registry
from .core.result import RunResult, Severity
from .core.runner import Runner, console_reporter
from .core.tier import Tier
from . import probes as _probes  # noqa: F401  (populates the registry)
from . import report as _report
from .targets import from_config


# --------------------------------------------------------------------------
def _build_target(cfg: RunConfig):
    return from_config(cfg.target)


def _run(cfg: RunConfig, quiet: bool = False) -> RunResult:
    try:
        return api.execute_scan(cfg, on_event=console_reporter(verbose=not quiet))
    except ValueError as exc:
        raise SystemExit(str(exc))


def _write_reports(result: RunResult, cfg: RunConfig) -> List[str]:
    os.makedirs(cfg.output_dir, exist_ok=True)
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in result.target_name)
    stem = os.path.join(cfg.output_dir, "rtharness-%s" % safe)
    written = []
    fmts = set(cfg.formats)
    if "all" in fmts:
        fmts = {"json", "md", "html", "sarif", "junit"}
    if "json" in fmts:
        written.append(_report.write_json(result, stem + ".report.json"))
    if "md" in fmts or "markdown" in fmts:
        written.append(_report.write_markdown(result, stem + ".report.md"))
    if "html" in fmts:
        written.append(_report.write_html(result, stem + ".report.html"))
    if "sarif" in fmts:
        written.append(_report.write_sarif(result, stem + ".sarif"))
    if "junit" in fmts:
        written.append(_report.write_junit(result, stem + ".junit.xml"))
    return written


def _exit_code(result: RunResult, fail_on: Optional[str]) -> int:
    if not fail_on:
        return 0
    threshold = Severity.parse(fail_on)
    if result.highest_severity() >= threshold and result.vulnerable_findings:
        return 2
    return 0


# --------------------------------------------------------------------------
def cmd_list(args) -> int:
    tier = Tier.parse(args.tier) if args.tier else Tier.ADAPTIVE
    probes = registry.select(tier, tags=args.tag or None)
    print("Probes available up to tier %d (%s):\n" % (int(tier), tier.label))
    for p in probes:
        print("  %-28s  min-tier %d  sev=%-8s  %s"
              % (p.id, int(p.min_tier), p.severity.label, p.title))
        print("      OWASP: %-22s ATLAS: %s"
              % (", ".join(p.owasp) or "-", ", ".join(p.atlas) or "-"))
    from .corpus import builtin_packs
    print("\nBuilt-in corpus packs (run with the probe set, disable via --no-builtin-corpus):")
    for pk in builtin_packs():
        print("  corpus.%-16s %3d payloads  sev=%-7s  %s"
              % (pk.name, len(pk.payloads), pk.severity.label, pk.description))
    print("  (add your own with --corpus <path to .jsonl/.json/.yaml/.txt/dir>)")
    print("\n%d probe(s). Tiers: 1 basic, 2 intermediate, 3 advanced, 4 adaptive."
          % len(probes))
    return 0


def cmd_run(args) -> int:
    from ._optional import load_yaml_or_json
    if args.config:
        data = load_yaml_or_json(args.config)
    else:
        if not args.target:
            raise SystemExit("Provide --config or --target.")
        target_cfg = {"type": args.target}
        for key in ("name", "model", "base_url", "url", "app_name",
                    "api_key_env", "response_path"):
            val = getattr(args, key, None)
            if val:
                target_cfg[key] = val
        data = {"target": target_cfg}
    # A --preset flag applies unless the config already names one.
    if args.preset and not data.get("preset"):
        data["preset"] = args.preset
    try:
        cfg = RunConfig.from_dict(data)
    except KeyError as exc:
        raise SystemExit(str(exc))
    # CLI overrides (highest priority).
    if args.tier:
        cfg.tier = Tier.parse(args.tier)
    if args.include:
        cfg.include = args.include
    if args.exclude:
        cfg.exclude = args.exclude
    if args.tag:
        cfg.tags = args.tag
    if args.out:
        cfg.output_dir = args.out
    if args.format:
        cfg.formats = args.format
    if args.fail_on:
        cfg.fail_on = args.fail_on
    if args.rate_limit:
        cfg.rate_limit_s = args.rate_limit
    if args.effort:
        cfg.profile["effort"] = args.effort
    if args.exhaustive:
        cfg.profile["stop_on_first"] = False
    if args.corpus:
        cfg.profile["corpus"] = args.corpus
    if args.no_builtin_corpus:
        cfg.profile["corpus_builtin"] = False
    if args.corpus_expand:
        cfg.profile["corpus_expand"] = True

    print("[*] %s" % api.capability_line(cfg), file=sys.stderr)
    result = _run(cfg, quiet=args.quiet)
    if args.with_tools:
        from . import integrations
        ext, notes = integrations.run_external(args.with_tools, cfg.target, cfg.profile)
        for n in notes:
            print("[*] %s" % n, file=sys.stderr)
        result.findings.extend(ext)
    written = _write_reports(result, cfg)
    print("\nReports written:")
    for p in written:
        print("  %s" % p)
    print("\nRisk score: %d/100  |  highest severity: %s  |  %d confirmed finding(s)"
          % (result.risk_score(), result.highest_severity().label,
             len(result.vulnerable_findings)))
    return _exit_code(result, cfg.fail_on)


def cmd_demo(args) -> int:
    """Run against the bundled intentionally-vulnerable mock agent."""
    from examples.mock_agent import build_callable_target, DEFAULT_PROFILE
    cfg = RunConfig(
        target={"type": "callable"},  # placeholder; replaced below
        tier=Tier.parse(args.tier or 3),
        profile=dict(DEFAULT_PROFILE),
        output_dir=args.out or "reports",
        formats=args.format or ["json", "md", "html"],
    )
    target = build_callable_target()
    selected = registry.select(cfg.tier, profile=cfg.profile)
    runner = Runner(target, tier=cfg.tier, on_event=console_reporter(True))
    result = runner.run(selected)
    written = _write_reports(result, cfg)
    print("\nDemo reports written:")
    for p in written:
        print("  %s" % p)
    return 0


def cmd_selftest(args) -> int:
    """Prove the harness works: it should break the vulnerable mock and leave
    the secure mock standing. No external services required."""
    from examples.mock_agent import (
        build_callable_target, build_secure_target, DEFAULT_PROFILE,
    )
    from .core.tier import Tier as _T
    tier = Tier.parse(args.tier or 3)
    profile = dict(DEFAULT_PROFILE)

    def _non_a2a_vuln(target):
        probes = registry.select(tier, exclude=["a2a"], profile=profile)
        res = Runner(target, tier=tier).run(probes)
        return res, [f.probe_id for f in res.vulnerable_findings]

    vres, vfired = _non_a2a_vuln(build_callable_target())
    sres, sfired = _non_a2a_vuln(build_secure_target())

    print("\n== selftest (tier %d) ==" % int(tier))
    print("vulnerable mock : %d/%d probes fired, risk %d/100, %d attempts"
          % (len(vfired), len([p for p in registry.select(tier, exclude=['a2a'])]),
             vres.risk_score(), vres.total_attempts))
    print("                  fired: %s" % ", ".join(sorted(vfired)))
    print("secure mock     : %d probes fired, risk %d/100, %d attempts"
          % (len(sfired), sres.risk_score(), sres.total_attempts))
    if sfired:
        print("                  UNEXPECTED fires: %s" % ", ".join(sorted(sfired)))

    ok_vuln = len(vfired) >= 8
    ok_secure = len(sfired) == 0
    verdict = ok_vuln and ok_secure
    print("\nRESULT: %s  (detects vulns=%s, no false positives on secure=%s)"
          % ("PASS" if verdict else "FAIL", ok_vuln, ok_secure))
    return 0 if verdict else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rtharness",
        description="Red-team harness for LLM agents (chat / A2A). "
                    "For authorised testing only.")
    p.add_argument("--version", action="version", version="rtharness " + __version__)
    sub = p.add_subparsers(dest="command", required=True)

    pl = sub.add_parser("list", help="list available probes")
    pl.add_argument("--tier", help="show probes up to this tier (default: all)")
    pl.add_argument("--tag", action="append", help="filter by tag (repeatable)")
    pl.set_defaults(func=cmd_list)

    pr = sub.add_parser("run", help="run an assessment")
    pr.add_argument("--config", help="path to a YAML/JSON config file")
    pr.add_argument("--target", help="target type: openai|http|a2a|adk|callable")
    pr.add_argument("--name", help="target display name")
    pr.add_argument("--model", help="model id (openai targets)")
    pr.add_argument("--base-url", dest="base_url", help="base URL")
    pr.add_argument("--url", help="endpoint URL (http target)")
    pr.add_argument("--app-name", dest="app_name", help="ADK app name")
    pr.add_argument("--api-key-env", dest="api_key_env", help="env var holding the API key")
    pr.add_argument("--response-path", dest="response_path", help="JSON path to reply text (http)")
    pr.add_argument("--preset", help="named profile: quick|standard|deep|owasp-llm|"
                    "owasp-agentic|mitre-atlas|mcp|a2a|chat|injection|exfil|jailbreak "
                    "(see `rtharness presets`)")
    pr.add_argument("--tier", help="attack tier 1-4 (basic..adaptive)")
    pr.add_argument("--include", action="append", help="only these probe ids/prefixes")
    pr.add_argument("--exclude", action="append", help="skip these probe ids/prefixes")
    pr.add_argument("--tag", action="append", help="only probes with these tags")
    pr.add_argument("--out", help="output directory (default: reports)")
    pr.add_argument("--format", action="append",
                    help="report format: json|md|html|sarif|junit|all (repeatable)")
    pr.add_argument("--fail-on", dest="fail_on",
                    help="exit non-zero if a finding of this severity+ is confirmed")
    pr.add_argument("--rate-limit", dest="rate_limit", type=float,
                    help="seconds to sleep between attempts")
    pr.add_argument("--effort", type=float,
                    help="attack-intensity multiplier (default 1.0; e.g. 0.3 light, "
                         "3 heavy) — scales attempts per objective")
    pr.add_argument("--exhaustive", action="store_true",
                    help="don't stop an objective at first success; try the whole budget")
    pr.add_argument("--corpus", action="append",
                    help="path to an external attack corpus (.jsonl/.json/.yaml/.txt/dir), "
                         "e.g. a local garak data dir or promptfoo export (repeatable)")
    pr.add_argument("--no-builtin-corpus", dest="no_builtin_corpus", action="store_true",
                    help="skip the built-in benign corpus packs")
    pr.add_argument("--corpus-expand", dest="corpus_expand", action="store_true",
                    help="also run each corpus payload through the full attack engine")
    pr.add_argument("--with", dest="with_tools", action="append",
                    choices=["garak", "mcp-scan"],
                    help="also run an external scanner and merge its findings "
                         "(if installed): garak | mcp-scan (repeatable)")
    pr.add_argument("--quiet", action="store_true", help="less progress output")
    pr.set_defaults(func=cmd_run)

    pd = sub.add_parser("demo", help="run against the bundled mock vulnerable agent")
    pd.add_argument("--tier", help="attack tier (default 3)")
    pd.add_argument("--out", help="output directory")
    pd.add_argument("--format", action="append", help="report format(s)")
    pd.set_defaults(func=cmd_demo)

    ps = sub.add_parser("selftest",
                        help="verify the harness against the bundled mocks")
    ps.add_argument("--tier", help="tier to self-test at (default 3)")
    ps.set_defaults(func=cmd_selftest)

    pp = sub.add_parser("presets", help="list named scan presets / compliance profiles")
    pp.set_defaults(func=cmd_presets)

    pc = sub.add_parser("coverage",
                        help="show framework coverage (OWASP LLM/Agentic/MCP, NIST AML)")
    pc.add_argument("--report", help="a *.report.json to show per-run coverage for "
                    "(default: capability coverage of the whole probe library)")
    pc.add_argument("--format", choices=["text", "md", "json"], default="text")
    pc.set_defaults(func=cmd_coverage)

    pdf = sub.add_parser("diff", help="compare two JSON reports (regression gate for CI)")
    pdf.add_argument("baseline", help="baseline *.report.json")
    pdf.add_argument("current", help="current *.report.json")
    pdf.add_argument("--no-fail", action="store_true",
                     help="don't exit non-zero on new regressions")
    pdf.set_defaults(func=cmd_diff)

    pw = sub.add_parser("serve", help="run the local web service (REST API + dashboard)")
    pw.add_argument("--host", default="127.0.0.1", help="bind host (default 127.0.0.1)")
    pw.add_argument("--port", type=int, default=8900, help="bind port (default 8900)")
    pw.set_defaults(func=cmd_serve)
    return p


def cmd_serve(args) -> int:
    from .service import serve
    serve(host=args.host, port=args.port)
    return 0


def _load_findings(path: str) -> dict:
    import json
    with open(path, "r", encoding="utf-8") as fh:
        d = json.load(fh)
    res = d.get("result", d)
    out = {}
    for f in res.get("findings", []):
        out[f["probe_id"]] = f
    return out


def cmd_diff(args) -> int:
    """Compare two JSON reports: regressions (new), fixed, and still-vulnerable."""
    a = _load_findings(args.baseline)
    b = _load_findings(args.current)
    a_vuln = {k for k, f in a.items() if f.get("vulnerable")}
    b_vuln = {k for k, f in b.items() if f.get("vulnerable")}
    new = sorted(b_vuln - a_vuln)
    fixed = sorted(a_vuln - b_vuln)
    persisting = sorted(a_vuln & b_vuln)

    print("Regression diff: %s -> %s" % (args.baseline, args.current))
    print("  NEW (regressions): %d" % len(new))
    for k in new:
        print("    + %s [%s]" % (k, b[k].get("severity", "?")))
    print("  FIXED: %d" % len(fixed))
    for k in fixed:
        print("    - %s" % k)
    print("  STILL VULNERABLE: %d" % len(persisting))
    if new and not args.no_fail:
        print("\nNew vulnerabilities introduced -> exit 2 (use --no-fail to suppress).")
        return 2
    return 0


def cmd_coverage(args) -> int:
    from . import coverage
    if args.report:
        print(coverage.render_run(args.report, args.format))
    else:
        print(coverage.render_capability(args.format))
    return 0


def cmd_presets(args) -> int:
    from . import presets
    print("Named presets (use with `rtharness run --preset <name>`):\n")
    for name in presets.names():
        print("  %-14s %s" % (name, presets.describe(name)))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
