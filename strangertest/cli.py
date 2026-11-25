"""Command-line interface for Stranger Test.

For now the CLI runs the bundled local practice server end-to-end:

    python3 -m strangertest practice          # the leaky server: should find a leak
    python3 -m strangertest practice --safe    # the isolated server: should be clean
    python3 -m strangertest practice --json     # full JSON report

``scan`` runs the same probe against an authorized HTTP server.

Every command shares one exit-code scheme, so any of them works as a CI check:
0 = OK, 1 = LEAK or FAIL, 2 = INCONCLUSIVE (including transport errors where
nothing could be observed), 3 = usage error or authorization refusal.

``survey <path>`` is the static side: it reads MCP server source code and lists
low-confidence candidates. It exits 0 even with candidates (they are not
confirmed leaks); a missing path is a usage error (3).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from typing import List, Optional

from . import __version__
from .guard import AuthorizationError
from .handle import (
    CLIENT_CAPABILITIES_WITH_TASKS,
    TasksHTTPTransport,
    run_handle_probe,
)
from .mcp_client import MCPClient
from .probe import Identity, ProbeError, ProbePlan, run_probe
from .source_audit import survey
from .transports import HTTPTransport, HTTPTransportError, StdioTransport

# One exit-code scheme for every command:
#   0 OK, 1 LEAK or FAIL, 2 INCONCLUSIVE (including transport errors where
#   nothing could be observed), 3 usage error or authorization refusal.
EXIT_OK = 0
EXIT_FINDING = 1
EXIT_INCONCLUSIVE = 2
EXIT_USAGE = 3


class _Parser(argparse.ArgumentParser):
    """ArgumentParser whose usage errors exit 3, not argparse's default 2."""

    def error(self, message: str):  # noqa: D401
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def _grade_exit(grade: str) -> int:
    """Map a probe grade to the shared exit-code scheme."""
    if grade in ("LEAK", "FAIL"):
        return EXIT_FINDING
    if grade == "OK":
        return EXIT_OK
    return EXIT_INCONCLUSIVE  # INCONCLUSIVE or anything not observed


def _refuse(exc: "AuthorizationError") -> int:
    """Print an authorization refusal and return the usage exit code.

    ``exc`` carries the library wording (which names the Python ``authorized=True``
    argument); the command line adds how to do the same from the shell.
    """
    print(f"refused: {exc}", file=sys.stderr)
    print("re-run with --authorized if you are permitted to test this target "
          "(and --authorization-note to record who authorized it).",
          file=sys.stderr)
    return EXIT_USAGE


def _practice_identity(label: str, identity_id: str, mode: str, store_path: str) -> Identity:
    command = [sys.executable, "-m", "strangertest.practice_server"]
    env = {
        "STRANGERTEST_MODE": mode,
        "STRANGERTEST_IDENTITY": identity_id,
        "STRANGERTEST_STORE": store_path,
    }
    return Identity(label=label, connect=lambda: MCPClient(StdioTransport(command, env=env)))


def cmd_practice(args: argparse.Namespace) -> int:
    mode = "safe" if args.safe else "leaky"
    plan = ProbePlan.key_value("kv_set", "kv_get", "secret")
    with tempfile.TemporaryDirectory() as tmp:
        store = os.path.join(tmp, "store.json")
        report = run_probe(
            "http://localhost/practice",
            _practice_identity("A", "alice", mode, store),
            _practice_identity("B", "bob", mode, store),
            plan,
        )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.summary())
    return 1 if report.leaked else 0


def cmd_crosscheck(args: argparse.Namespace) -> int:
    def http_identity(label: str, token) -> Identity:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return Identity(
            label=label,
            connect=lambda: MCPClient(HTTPTransport(args.url, headers=headers)),
        )

    plan = ProbePlan.key_value(args.plant_tool, args.read_tool, args.key)
    try:
        report = run_probe(
            args.url,
            http_identity("A", args.token_a),
            http_identity("B", args.token_b),
            plan,
            authorized=args.authorized,
            authorization_note=args.authorization_note,
        )
    except AuthorizationError as exc:
        return _refuse(exc)
    except ProbeError as exc:
        print(f"inconclusive: {exc}", file=sys.stderr)
        return EXIT_INCONCLUSIVE
    except HTTPTransportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INCONCLUSIVE

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.summary())
    return EXIT_FINDING if report.leaked else EXIT_OK


# --------------------------------------------------------------------------- #
# `scan` — the one-command fingerprint scanner (mcp-scan-style wedge).
# --------------------------------------------------------------------------- #

def _load_scan_api():
    """Return ``(profile_target, run_checks)``.

    Prefers the sibling agents' real modules; falls back to the bundled mock so
    the CLI and renderers work before they land. INTEGRATION NOTE: once the
    adapter and check-catalog agents merge, this import resolves to the real
    modules automatically — no code change is needed here. To force the mock
    (e.g. in CI before the siblings land), set STRANGERTEST_SCAN_MOCK=1.
    """
    import os as _os

    if not _os.environ.get("STRANGERTEST_SCAN_MOCK"):
        try:
            from .scan.adapter import profile_target  # type: ignore
            from .scan.checks import run_checks  # type: ignore
            return profile_target, run_checks
        except Exception:
            pass
    from .scan._mock import mock_profile_target, mock_run_checks
    return mock_profile_target, mock_run_checks


def cmd_scan(args: argparse.Namespace) -> int:
    from .guard import extract_host, is_local_target
    from .scan import report as scan_report

    # Choose output format (human unless --json/--sarif).
    if getattr(args, "sarif", False):
        fmt = "sarif"
    elif getattr(args, "json", False):
        fmt = "json"
    else:
        fmt = "human"

    # Safe by default: refuse a non-loopback target unless --allow-nonloopback.
    host = extract_host(args.url)
    if host is None:
        print(f"error: could not read a host from {args.url!r}", file=sys.stderr)
        return scan_report.EXIT_ERROR
    if not is_local_target(host) and not args.allow_nonloopback:
        print(
            f"refused: {host} is not a loopback target. Re-run with "
            f"--allow-nonloopback to scan it.",
            file=sys.stderr,
        )
        print("only scan servers you are authorized to test.", file=sys.stderr)
        return scan_report.EXIT_ERROR
    if not is_local_target(host) and args.allow_nonloopback:
        print("only scan servers you are authorized to test.", file=sys.stderr)

    profile_target, run_checks = _load_scan_api()

    # One read-only pass. Any failure to build the profile is exit 2.
    try:
        profile = profile_target(
            args.url,
            bearer=args.bearer,
            timeout=args.timeout,
            allow_nonloopback=args.allow_nonloopback,
        )
    except Exception as exc:  # adapter failure -> unreachable/error
        print(f"error: {exc}", file=sys.stderr)
        return scan_report.EXIT_ERROR

    reachable = scan_report.field_of(profile, "reachable", False)
    findings = []
    if reachable:
        try:
            findings = run_checks(profile, live=None)
        except Exception as exc:
            print(f"error: running checks: {exc}", file=sys.stderr)
            return scan_report.EXIT_ERROR

    code = scan_report.render(profile, findings, fmt=fmt)

    # Unreachable target is always exit 2, whatever the renderer returned.
    if not reachable:
        return scan_report.EXIT_ERROR
    return code


def _add_scan_parser(sub) -> None:
    scan = sub.add_parser(
        "scan",
        help="One-command read-only fingerprint scan of an MCP server.",
        description=(
            "Profiles an MCP server in a single read-only pass and flags "
            "authorization risk signals (session handling, cache scope, "
            "advertised delegation, auth posture). Safe by default: loopback "
            "targets only unless --allow-nonloopback. This flags risk signals; "
            "it does not confirm a leak — run the lab deep-check (the A/B "
            "probes) to confirm the XID auth-leak classes."
        ),
    )
    scan.add_argument("url", help="MCP server endpoint, e.g. http://localhost:4600/mcp")
    scan.add_argument("--bearer", default=None, help="Bearer token to present (fingerprinted, never echoed).")
    scan.add_argument("--json", action="store_true", help="Emit the {profile, findings} report as JSON (fingerprints only).")
    scan.add_argument("--sarif", action="store_true", help="Emit a SARIF 2.1.0 log (CI code-scanning drop-in).")
    scan.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds (default: 10).")
    scan.add_argument(
        "--allow-nonloopback",
        dest="allow_nonloopback",
        action="store_true",
        help="Permit a non-loopback target (only scan servers you are authorized to test).",
    )
    scan.set_defaults(func=cmd_scan)


def _tasks_identity(url: str, token, label: str) -> Identity:
    """A task-capable (modern, tasks extension) identity, like scan's but for
    the task-handle probe. ``token`` None means an anonymous caller."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return Identity(
        label=label,
        connect=lambda: MCPClient(
            TasksHTTPTransport(
                url,
                headers=headers,
                modern=True,
                client_capabilities=CLIENT_CAPABILITIES_WITH_TASKS,
            )
        ),
    )


def cmd_handle(args: argparse.Namespace) -> int:
    try:
        report = run_handle_probe(
            args.url,
            _tasks_identity(args.url, args.token_a, "A"),
            _tasks_identity(args.url, args.token_b, "B"),
            authorized=args.authorized,
            authorization_note=args.authorization_note,
        )
    except AuthorizationError as exc:
        return _refuse(exc)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.summary())
    return _grade_exit(report.grade)


def cmd_survey(args: argparse.Namespace) -> int:
    # Static only: reads source files, never connects to anything, so there is
    # no target to authorize. Exit code is 0 even with candidates, because a
    # candidate is a low-confidence hit to read by hand, not a confirmed leak.
    try:
        report = survey(args.path, include_tests=args.include_tests)
    except FileNotFoundError:
        print(f"error: no such path: {args.path}", file=sys.stderr)
        return EXIT_USAGE
    if args.json:
        print(json.dumps(report.to_dict(include_all=args.all), indent=2))
    else:
        print(report.summary())
    return 0


def _http_identity(url: str, token, label: str) -> Identity:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return Identity(
        label=label,
        connect=lambda: MCPClient(HTTPTransport(url, headers=headers, modern=True)),
    )


def _demo_exit(reports) -> int:
    # The demo is a self-check: the leaky server must leak and the safe one
    # must not. 0 when that contrast holds, 1 (FAIL) when it does not.
    return EXIT_OK if (reports["leaky"].leaked and not reports["safe"].leaked) else EXIT_FINDING


def _print_demo(probe: str, reports, as_json: bool) -> None:
    if as_json:
        payload = {"demo": probe}
        payload.update({mode: reports[mode].to_dict() for mode in ("leaky", "safe")})
        print(json.dumps(payload, indent=2))
    else:
        for mode in ("leaky", "safe"):
            print(f"[{mode}]")
            print(reports[mode].summary())


def _demo_cache(as_json: bool) -> int:
    plan = ProbePlan.key_value("kv_set", "kv_get", "secret")
    reports = {}
    for mode in ("leaky", "safe"):
        with tempfile.TemporaryDirectory() as tmp:
            store = os.path.join(tmp, "store.json")
            reports[mode] = run_probe(
                "http://localhost/practice",
                _practice_identity("A", "alice", mode, store),
                _practice_identity("B", "bob", mode, store),
                plan,
            )
    _print_demo("cache", reports, as_json)
    return _demo_exit(reports)


def _demo_handle(as_json: bool) -> int:
    import threading

    from .practice_handle_http import build_server

    reports = {}
    for mode in ("leaky", "safe"):
        server = build_server(mode)
        thread = threading.Thread(
            target=lambda s=server: s.serve_forever(poll_interval=0.01), daemon=True
        )
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/mcp"
            reports[mode] = run_handle_probe(
                url,
                _tasks_identity(url, "alice", "A"),
                _tasks_identity(url, "bob", "B"),
            )
        finally:
            server.shutdown()
            server.server_close()
    _print_demo("handle", reports, as_json)
    return _demo_exit(reports)


def _demo_cachescope(as_json: bool) -> int:
    from .cachescope import run_cachescope_probe
    from .practice_cache_http import CacheStack, UpstreamConfig

    uri = "note://shared/inbox"
    reports = {}
    for mode in ("leaky", "safe"):
        with CacheStack(UpstreamConfig(), mode) as stack:
            reports[mode] = run_cachescope_probe(
                stack.proxy_url,
                stack.upstream_url,
                _http_identity(stack.proxy_url, "alice", "A"),
                _http_identity(stack.proxy_url, "bob", "B"),
                direct_a=_http_identity(stack.upstream_url, "alice", "A-direct"),
                direct_b=_http_identity(stack.upstream_url, "bob", "B-direct"),
                uri=uri,
                upstream_calls=stack.upstream_calls,
            )
    _print_demo("cachescope", reports, as_json)
    return _demo_exit(reports)


_DEMO_PROBES = {
    "cache": _demo_cache,
    "handle": _demo_handle,
    "cachescope": _demo_cachescope,
}


def cmd_demo(args: argparse.Namespace) -> int:
    return _DEMO_PROBES[args.probe](args.json)


def _confirm_print(rep, as_json: bool) -> None:
    if as_json:
        import json as _json
        print(_json.dumps(rep.to_dict(), indent=2, default=str))
    else:
        print(rep.summary())


# Short, legible labels for the compact demo summary (display only; the VERDICT
# line and --json still use the fixture keys).
_DEMO_LABELS = {
    "prefixbug": "prefix-id bug",
    "dotbug": "dot-id bug",
    "separatorbug": "separator-id bug",
    "wildcardbug": "wildcard-id bug",
    "casebug": "case-id bug",
    "whitespacebug": "whitespace-id bug",
    "writeleak": "write-path leak",
}


def _demo_label(key: str) -> str:
    return _DEMO_LABELS.get(key, key.replace("_", " "))


def _demo_drivers(rep) -> str:
    """The path(s) that drove a report's grade, for the one-line summary."""
    from .deep_tests import _LEAK_GRADES

    paths = getattr(rep, "paths", None) or []
    names = [p["name"] for p in paths if p.get("outcome") in _LEAK_GRADES]
    return f" ({', '.join(names)})" if names else ""


# Per-test guidance for running against a real target. This is the single source
# for the post-demo "run against your own server" block (Fix ②) and the per-test
# --help / epilog guidance (Fix ③). It reuses what already exists elsewhere: the
# URL shapes come from the `url` positional help (agent-memory wants a LangGraph
# base URL, semantic-cache a cache/gateway base URL, the rest an MCP endpoint),
# the doc links from the docs/ files, and the invocation form from
# deep_tests.confirm_hint. A test absent here falls back to the generic MCP
# endpoint and the three universal flags; a lab-only test (run_target is None)
# shows its target_note instead of a target command.
_DEFAULT_TARGET_URL = "http://127.0.0.1:PORT/mcp"
_UNIVERSAL_FLAGS = ("--demo", "--token-a", "--token-b")
_TEST_HELP = {
    "state-handle": {"url": _DEFAULT_TARGET_URL},
    "tasks-idor": {"url": _DEFAULT_TARGET_URL},
    "elicitation": {"url": _DEFAULT_TARGET_URL},
    "agent-memory": {
        "url": "http://127.0.0.1:2024",
        "flags": _UNIVERSAL_FLAGS + ("--namespace-a", "--write-paths"),
        "note": "two users' bearer tokens for a LangGraph server you run or are "
                "authorized to test",
        "doc": "docs/AGENT-MEMORY.md",
    },
    "semantic-cache": {
        "url": "http://127.0.0.1:8000",
        "flags": _UNIVERSAL_FLAGS + ("--cache-mode", "--identity-as", "--edge-cases"),
        "note": "two caller identities for a cache or LLM gateway you run or are "
                "authorized to test",
        "doc": "docs/CACHE.md",
    },
}


def _target_example(t) -> str:
    """The real-target command line for a test (matches confirm_hint's form)."""
    url = _TEST_HELP.get(t.id, {}).get("url", _DEFAULT_TARGET_URL)
    return f"stranger-test confirm {t.id} {url} --token-a <A> --token-b <B>"


def _print_run_against_your_own(t) -> None:
    """Fix ②: after a --demo run, tell a newcomer how to run the real thing.

    Three lines at most, tailored to the test just demoed. For a lab-only test
    (no real target) we point at its target_note instead of a target command.
    """
    meta = _TEST_HELP.get(t.id, {})
    print("\nTo run this against your own server:")
    if t.run_target is None:
        note = getattr(t, "target_note", "") or "lab-only test; run it with --demo."
        print(f"  {note}")
        return
    print(f"  {_target_example(t)}")
    note, doc = meta.get("note"), meta.get("doc")
    if note and doc:
        print(f"  ({note}; see {doc})")
    elif note:
        print(f"  ({note})")
    elif doc:
        print(f"  (see {doc})")


def _test_help_block(t) -> str:
    """One curated help block for a test: the demo command, the real-target
    command (unless lab-only), and the handful of flags that matter for it."""
    meta = _TEST_HELP.get(t.id, {})
    lab = t.run_target is None
    tag = "   [lab only: use --demo]" if lab else ""
    lines = [f"{t.id} — {t.title}{tag}",
             f"    demo:    stranger-test confirm {t.id} --demo"]
    if not lab:
        lines.append(f"    target:  {_target_example(t)}")
    flags = ("--demo",) if lab else meta.get("flags", _UNIVERSAL_FLAGS)
    doc = meta.get("doc")
    tail = f"   (see {doc})" if doc else ""
    lines.append(f"    flags:   {' '.join(flags)}{tail}")
    return "\n".join(lines)


def _confirm_epilog() -> str:
    """Fix ③ (confirm --help): a per-test quickstart under the flag reference."""
    from . import deep_tests as dt

    lines = ["", "per-test quickstart (the flags that matter for each test):", ""]
    for t in dt.DEEP_TESTS.values():
        lines.append(_test_help_block(t))
        lines.append("")
    lines.append("`confirm <test> --help` prints that one test's block first, "
                 "above this full flag list.")
    return "\n".join(lines)


def _maybe_print_confirm_test_help(argv) -> None:
    """Fix ③ (confirm <test> --help): print that test's curated block above
    argparse's full help, so the few flags that matter are visible without
    scrolling the whole flag list. A no-op for anything that is not
    `confirm <known-test> ... --help`; argparse still prints its complete help.
    """
    if not argv or argv[0] != "confirm" or not ("-h" in argv or "--help" in argv):
        return
    from . import deep_tests as dt

    test_id = next((a for a in argv[1:] if not a.startswith("-")), None)
    t = dt.get(test_id) if test_id else None
    if t is None:
        return
    print(_test_help_block(t))
    print()


def cmd_confirm(args: argparse.Namespace) -> int:
    """Tier-2: confirm a cross-user leak with a two-identity lab run."""
    from . import deep_tests as dt

    if getattr(args, "list", False) or not args.test:
        print("Deep (two-identity) tests. Run one with:")
        print("  stranger-test confirm <test> --demo                      (bundled fixtures)")
        print("  stranger-test confirm <test> <url> --token-a A --token-b B  (a target you may test)")
        for t in dt.DEEP_TESTS.values():
            mode = "target+demo" if t.run_target else "demo only (lab)"
            print(f"\n  {t.id}  [{mode}]\n    {t.title} — {t.summary}")
        return 0

    t = dt.get(args.test)
    if t is None:
        print(f"error: unknown test {args.test!r}; see `confirm --list`", file=sys.stderr)
        return 3

    if getattr(args, "demo", False):
        res = t.demo()
        leaky, safe = res["leaky"], res["safe"]
        # --full (and --json) keep today's complete output: every scenario in
        # full. The default is compact — the two headline scenarios in full, the
        # rest one line each. Every scenario still RUNS either way (see VERDICT).
        compact = not getattr(args, "full", False) and not args.json
        print(f"== {t.title} — demo (bundled loopback fixtures) ==\n")
        print("-- against a KNOWN-LEAKY server (the test must catch it):")
        _confirm_print(leaky, args.json)
        print("\n-- against a SAFE server (must come back clean):")
        _confirm_print(safe, args.json)
        works = dt.leaked(leaky) and str(getattr(safe, "grade", "")) == "OK"
        seen = [f"leaky -> {dt._grade_of(leaky)}", f"safe -> {dt._grade_of(safe)}"]
        extra = list(getattr(t, "demo_extra", ()))
        if extra and compact:
            print("\n-- the remaining scenarios (each still run; --full shows them in full):")
        for key, what, expected in extra:
            rep = res[key]
            grade = dt._grade_of(rep)
            if compact:
                print(f"  {_demo_label(key):<20}-> {grade}{_demo_drivers(rep)}")
            else:
                print(f"\n-- against {what}:")
                _confirm_print(rep, args.json)
            works = works and grade == expected
            seen.append(f"{key.replace('_', ' ')} -> {grade}")
        print(f"\nVERDICT: the test {'WORKS' if works else 'did NOT behave as expected'} "
              f"({', '.join(seen)}).")
        if compact:
            print("Pass --full to print every scenario in full (all 9 scenarios, every path).")
        if not args.json:
            _print_run_against_your_own(t)
        return 0 if works else 2

    if not args.url:
        print("error: give <url> with --token-a/--token-b, or use --demo", file=sys.stderr)
        return 3
    if t.run_target is None:
        print(f"{t.id} is a lab test: {t.target_note}", file=sys.stderr)
        return 3

    from .guard import extract_host, is_local_target
    host = extract_host(args.url)
    if host is None:
        print(f"error: could not read a host from {args.url!r}", file=sys.stderr)
        return 2
    if not is_local_target(host) and not args.allow_nonloopback:
        print(f"refused: {host} is not a loopback target. Re-run with --allow-nonloopback.",
              file=sys.stderr)
        print("only run deep tests against servers you are authorized to test.", file=sys.stderr)
        return 3
    if not is_local_target(host):
        print("only run deep tests against servers you are authorized to test.", file=sys.stderr)

    # Options only some tests use; each test ignores the ones it does not know.
    opts = {name: getattr(args, name, None)
            for name in ("namespace_a", "namespace_b", "assistant_id", "save_input",
                         "recall_input", "whoami_field", "base_query", "reworded_query",
                         "threshold", "cache_mode", "identity_as", "identity_header",
                         "token_header", "token_sibling", "api_key", "user_a", "user_b",
                         "user_sibling", "store_path", "query_path", "chat_path", "model",
                         "cache_hit_header", "edge_cases", "edge_identity", "edge_user",
                         "route", "stream")}
    from datetime import datetime, timezone

    run_started = datetime.now(timezone.utc)
    if t.id == "agent-memory":
        opts.update(edge_identities=getattr(args, "edge_identity", None),
                    write_paths=getattr(args, "write_paths", None) or None)
    try:
        rep = t.run_target(args.url, args.token_a, args.token_b,
                           **{k: v for k, v in opts.items() if v is not None})
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    _confirm_print(rep, args.json)
    if getattr(args, "evidence", None) or getattr(args, "evidence_summary", None):
        from .evidence import write_evidence

        try:
            done = write_evidence(
                args.evidence or [], rep, save_result=True,
                summary=getattr(args, "evidence_summary", None), run_started=run_started,
                run_finished=datetime.now(timezone.utc),
                system_name=args.evidence_system, system_version=args.evidence_system_version,
                environment=args.evidence_environment, operator=args.evidence_operator,
                notes=args.evidence_notes, identity_a=args.evidence_identity_a,
                identity_b=args.evidence_identity_b,
                command=getattr(args, "_argv", None))
        except (OSError, ValueError) as exc:
            print(f"error: could not write the evidence file: {exc}", file=sys.stderr)
            return 3
        for item in done["written"]:
            print("evidence written: %s  sha256:%s" % (item["path"], item["sha256"]),
                  file=sys.stderr)
    hint = getattr(rep, "hint", None)
    if not args.json and callable(hint) and hint():
        print(hint())
    g = str(getattr(rep, "grade", "INCONCLUSIVE"))
    return 1 if g in ("LEAK", "FAIL") else (0 if g == "OK" else 2)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="strangertest",
        description="Tests MCP servers for cross-identity and delegated-authority (RFC 8693) authorization leaks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "The delegation, scope and issuer checks need a login server and a\n"
            "recording upstream; the private-cache check needs a recording upstream.\n"
            "They are run from the integration gates, not from this command line.\n"
            "See integration/RESULTS.md and the gate guides (integration/*_GATE.md).\n"
            "`demo --probe cachescope` shows the cache check locally against a\n"
            "bundled practice upstream.\n\n"
            "Exit codes: 0 OK, 1 LEAK or FAIL, 2 INCONCLUSIVE, 3 usage or "
            "authorization refusal."
        ),
    )
    parser.add_argument("--version", action="version", version=f"stranger-test {__version__}")
    sub = parser.add_subparsers(dest="command")

    practice = sub.add_parser(
        "practice", help="Run the probe against the bundled local practice server."
    )
    practice.add_argument(
        "--safe",
        action="store_true",
        help="Use the correctly-isolated server instead of the leaky one.",
    )
    practice.add_argument(
        "--json", action="store_true", help="Print the full JSON report."
    )
    practice.set_defaults(func=cmd_practice)

    _add_scan_parser(sub)

    crosscheck = sub.add_parser(
        "crosscheck",
        help="Two-identity read/marker probe against an authorized MCP server.",
        description=(
            "Plants a marker as identity A (via --token-a) and checks whether "
            "identity B (--token-b, or anonymous if omitted) can read it back. "
            "Non-local targets require --authorized and are your responsibility "
            "to be permitted to test. (This is the manual A/B probe; for the "
            "one-command fingerprint scan, see `scan`.)"
        ),
    )
    crosscheck.add_argument("url", help="MCP server endpoint, e.g. https://mcp.example.com/mcp")
    crosscheck.add_argument("--token-a", dest="token_a", default=None, help="Bearer token for identity A (the planter).")
    crosscheck.add_argument("--token-b", dest="token_b", default=None, help="Bearer token for identity B (the reader); omit for an anonymous B.")
    crosscheck.add_argument("--plant-tool", dest="plant_tool", required=True, help="Tool name A calls to store the marker.")
    crosscheck.add_argument("--read-tool", dest="read_tool", required=True, help="Tool name B calls to read it back.")
    crosscheck.add_argument("--key", default="secret", help="Key the marker is stored under (default: secret).")
    crosscheck.add_argument("--authorized", action="store_true", help="Confirm you are authorized to test this target (required for non-local hosts).")
    crosscheck.add_argument("--authorization-note", dest="authorization_note", default=None, help="Who authorized this test; recorded in the report.")
    crosscheck.add_argument("--json", action="store_true", help="Print the full JSON report.")
    crosscheck.set_defaults(func=cmd_crosscheck)

    handle = sub.add_parser(
        "handle",
        help="Probe an authorized MCP server's task handles as two identities.",
        description=(
            "Identity A (--token-a) starts tasks (tasks extension, SEP-2663); "
            "identity B (--token-b, or anonymous if omitted) is given their "
            "taskIds and tries tasks/get, tasks/update and tasks/cancel on "
            "them. Non-local targets require --authorized."
        ),
    )
    handle.add_argument("url", help="MCP server endpoint, e.g. https://mcp.example.com/mcp")
    handle.add_argument("--token-a", dest="token_a", default=None, help="Bearer token for identity A (the task owner).")
    handle.add_argument("--token-b", dest="token_b", default=None, help="Bearer token for identity B (the other caller); omit for an anonymous B.")
    handle.add_argument("--authorized", action="store_true", help="Confirm you are authorized to test this target (required for non-local hosts).")
    handle.add_argument("--authorization-note", dest="authorization_note", default=None, help="Who authorized this test; recorded in the report.")
    handle.add_argument("--json", action="store_true", help="Print the full JSON report.")
    handle.set_defaults(func=cmd_handle)

    demo = sub.add_parser(
        "demo",
        help="Demonstrate a probe locally in both leaky and safe mode.",
        description=(
            "Starts the matching bundled practice server in leaky and then safe "
            "mode and prints both results. No network target is needed. Exits 0 "
            "when the leaky server leaks and the safe one does not."
        ),
    )
    demo.add_argument(
        "--probe",
        choices=["cache", "handle", "cachescope"],
        default="cache",
        help="Which probe to demonstrate (default: cache).",
    )
    demo.add_argument("--json", action="store_true", help="Print both reports as JSON.")
    demo.set_defaults(func=cmd_demo)

    surv = sub.add_parser(
        "survey",
        help="Statically triage MCP server source code (reads files only).",
        description=(
            "Parses Python source under PATH and lists tool handlers that touch "
            "stored/shared state but reference no caller identity. This is "
            "coarse, low-confidence triage: every hit needs reading by hand. "
            "Nothing is executed and nothing is connected to."
        ),
    )
    surv.add_argument("path", help="A source file or a directory of MCP server source.")
    surv.add_argument("--json", action="store_true", help="Print the full JSON report.")
    surv.add_argument("--all", action="store_true", help="With --json, include every handler found, not only the candidates.")
    surv.add_argument("--include-tests", dest="include_tests", action="store_true", help="Also scan test files and tests/ directories.")
    surv.set_defaults(func=cmd_survey)

    confirm = sub.add_parser(
        "confirm",
        help="Tier-2: confirm a cross-user leak with a two-identity lab run.",
        description=(
            "Run a deep two-identity test. --demo runs it against bundled leaky+safe "
            "fixtures (no target or credentials). Otherwise give a URL and two bearer "
            "tokens for a server you are authorized to test. `confirm --list` lists the tests."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_confirm_epilog(),
    )
    confirm.add_argument("test", nargs="?", help="which test (see --list)")
    confirm.add_argument("url", nargs="?", default=None, help="server URL for real-target mode: the MCP endpoint, or for "
                              "agent-memory the agent server's base URL (e.g. http://127.0.0.1:2024), "
                              "or for semantic-cache the cache's or gateway's base URL")
    confirm.add_argument("--demo", action="store_true", help="run against bundled loopback fixtures")
    confirm.add_argument("--full", action="store_true",
                         help="with --demo, print every scenario in full (the default shows the "
                              "two headline scenarios in full and the rest one line each); "
                              "no effect on a real-target run")
    confirm.add_argument("--list", action="store_true", help="list the deep tests")
    confirm.add_argument("--token-a", dest="token_a", default=None, help="bearer token for identity A")
    confirm.add_argument("--token-b", dest="token_b", default=None, help="bearer token for identity B")
    confirm.add_argument("--allow-nonloopback", dest="allow_nonloopback", action="store_true",
                         help="permit a non-loopback target (authorized testing only)")
    confirm.add_argument("--json", action="store_true", help="JSON output")
    confirm.add_argument("--evidence", action="append", default=None, metavar="FILE",
                         help="also write the evidence page (.md or .json); repeat to "
                              "write both from the same run. The raw result is saved beside "
                              "it as FILE.result.json. See docs/EVIDENCE.md")
    confirm.add_argument("--evidence-summary", action="append", default=None, metavar="FILE",
                         help="also write the short summary of the evidence page (Markdown, "
                              "under half its length). Can be used with or without --evidence")
    confirm.add_argument("--evidence-system", default=None, metavar="TEXT",
                         help="evidence page: name of the system tested")
    confirm.add_argument("--evidence-system-version", default=None, metavar="TEXT",
                         help="evidence page: its version or build")
    confirm.add_argument("--evidence-environment", default=None, metavar="TEXT",
                         help="evidence page: for example 'staging'")
    confirm.add_argument("--evidence-operator", default=None, metavar="TEXT",
                         help="evidence page: who ran the test")
    confirm.add_argument("--evidence-notes", default=None, metavar="TEXT",
                         help="evidence page: one line of context")
    confirm.add_argument("--evidence-identity-a", default=None, metavar="TEXT",
                         help="evidence page: a few words describing test account A "
                              "(never a credential)")
    confirm.add_argument("--evidence-identity-b", default=None, metavar="TEXT",
                         help="evidence page: a few words describing test account B")
    memory = confirm.add_argument_group(
        "agent-memory options",
        "For `confirm agent-memory <base-url>`. All optional: two tokens alone test the "
        "thread and Store paths. --assistant, --save-input and --recall-input together add "
        "the through-the-agent paths. See docs/AGENT-MEMORY.md.")
    memory.add_argument("--namespace-a", dest="namespace_a", default=None,
                        help="a Store namespace identity A may write to, dotted (e.g. alice.notes)")
    memory.add_argument("--namespace-b", dest="namespace_b", default=None,
                        help="identity B's own Store namespace, dotted; when B's id is a string "
                             "prefix of A's (ali / alice) this also checks namespace boundaries")
    memory.add_argument("--edge-identity", dest="edge_identity", action="append", default=None,
                        metavar="KIND=TOKEN[@NAMESPACE]",
                        help="(agent-memory and semantic-cache) an extra test identity whose id is "
                             "an awkward relative of A's, sent the way --token-a is; repeatable; "
                             "a case with no identity given is not run; KIND is "
                             "prefix, dot, separator, wildcard, case or whitespace; NAMESPACE is "
                             "its own Store namespace (one label as written, or a JSON list). "
                             "Repeatable")
    memory.add_argument("--write-paths", dest="write_paths", action="store_true",
                        help="also let B try to update and delete A's thread and Store item "
                             "(only this run's own throwaway data; off by default)")
    memory.add_argument("--assistant", dest="assistant_id", default=None,
                        help="assistant (graph) id to run")
    memory.add_argument("--save-input", dest="save_input", default=None,
                        help="JSON run input that makes the agent save; {marker} is replaced")
    memory.add_argument("--recall-input", dest="recall_input", default=None,
                        help="JSON run input that makes the agent recall; must not contain {marker}")
    memory.add_argument("--whoami-field", dest="whoami_field", default=None,
                        help="field of the run output that carries the caller's identity, if any")
    cache = confirm.add_argument_group(
        "semantic-cache options",
        "For `confirm semantic-cache <base-url>`. --token-a/--token-b are the two caller "
        "identities. In store mode they are sent in the x-identity header unless you "
        "say otherwise; in chat mode as bearer tokens. See docs/CACHE.md.")
    cache.add_argument("--cache-mode", dest="cache_mode", default=None, choices=("store", "chat"),
                       help="store (default): a cache with POST /store and POST /query. "
                            "chat: an LLM gateway that caches POST /v1/chat/completions")
    cache.add_argument("--identity-as", dest="identity_as", default=None,
                       choices=("header", "bearer"),
                       help="how --token-a/--token-b are sent: in the identity header, or as "
                            "a bearer token / API key")
    cache.add_argument("--identity-header", dest="identity_header", default=None,
                       help="header that carries each identity's id (default: x-identity), "
                            "e.g. x-tenant-id")
    cache.add_argument("--token-header", dest="token_header", default=None,
                       help="header that carries a token or API key (default: Authorization, "
                            "sent as 'Bearer <token>'; any other header gets the raw value)")
    cache.add_argument("--token-sibling", dest="token_sibling", default=None,
                       help="a third identity whose id at the cache is a string prefix of A's "
                            "(ali / alice); without it the prefix-sibling path is not run "
                            "when tokens are used")
    cache.add_argument("--api-key", dest="api_key", default=None,
                       help="one credential shared by every request, for a cache that takes "
                            "a key plus a tenant header or user field")
    cache.add_argument("--user-a", dest="user_a", default=None,
                       help="chat mode: identity A's value for the OpenAI 'user' body field")
    cache.add_argument("--user-b", dest="user_b", default=None,
                       help="chat mode: identity B's value for the 'user' body field")
    cache.add_argument("--user-sibling", dest="user_sibling", default=None,
                       help="chat mode: the prefix-sibling identity's 'user' value")
    cache.add_argument("--store-path", dest="store_path", default=None,
                       help="store mode: path of the store call (default: /store)")
    cache.add_argument("--query-path", dest="query_path", default=None,
                       help="store mode: path of the query call (default: /query)")
    cache.add_argument("--chat-path", dest="chat_path", default=None,
                       help="chat mode: path of the chat call (default: /v1/chat/completions)")
    cache.add_argument("--model", dest="model", default=None,
                       help="chat mode: model name to request (default: gpt-4o-mini)")
    cache.add_argument("--cache-hit-header", dest="cache_hit_header", default=None,
                       help="chat mode: response header that tells a cache hit; without it a "
                            "few common ones are tried (x-litellm-cache-key, x-cache, ...)")
    cache.add_argument("--edge-cases", dest="edge_cases", default=None, metavar="all|KIND,...",
                       help="awkward-id cases to run: all, or a list of prefix, dot, separator, "
                            "wildcard, case, whitespace. With plain header ids this also says "
                            "they are free-form test tenants, and the ids are made from A's")
    cache.add_argument("--edge-user", dest="edge_user", action="append", default=None,
                       metavar="KIND=USER",
                       help="chat mode: the extra identity's 'user' value for one awkward-id "
                            "case; repeatable")
    cache.add_argument("--route", dest="route", action="append", default=None,
                       metavar="NAME[=PATH]",
                       help="chat mode: a route to run, repeatable: chat, responses "
                            "(/v1/responses) or messages (/v1/messages). Each is graded on "
                            "its own, plus a cross-route path")
    cache.add_argument("--stream", dest="stream", action="store_true", default=None,
                       help="chat mode: send every request with \"stream\": true and read "
                            "the answer from the event stream")
    cache.add_argument("--base-query", dest="base_query", default=None,
                       help="the question A caches (default: a built-in one)")
    cache.add_argument("--reworded-query", dest="reworded_query", default=None,
                       help="a near-match paraphrase of --base-query for the semantic path")
    cache.add_argument("--threshold", dest="threshold", default=None,
                       help="store mode: similarity threshold to send with each query "
                            "(default: the cache's own)")
    confirm.set_defaults(func=cmd_confirm)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    effective = list(argv) if argv is not None else list(sys.argv[1:])
    _maybe_print_confirm_test_help(effective)
    parser = build_parser()
    args = parser.parse_args(argv)
    args._argv = effective
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help(sys.stderr)
        return EXIT_USAGE
    return func(args)


if __name__ == "__main__":
    raise SystemExit(main())
