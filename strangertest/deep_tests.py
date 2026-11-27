"""Registry of the Tier-2 "deep" cross-user tests, and the glue that lets the CLI
run them and the Tier-1 scanner point at them.

Tier 1 (``strangertest scan``) is a single-identity, read-only risk scan of any
MCP server. Tier 2 (``strangertest confirm``) is the dynamic, two-identity lab
test that *confirms* a cross-user leak (LEAK), clears it (OK), or can't tell
(INCONCLUSIVE) — the thing a static scanner structurally cannot do.

Each registered test exposes:
  - ``demo()``  — stand up the bundled leaky + safe practice servers on loopback
                  and run the probe against each; proves the test catches a real
                  leak and clears a safe server. Needs no target or credentials.
  - ``run_target(url, token_a, token_b, **opts)`` — run against a real server you
                  are authorized to test, with two identities' bearer tokens.
                  ``None`` for the lab-only tests (they need a controlled upstream
                  or a target-specific mutation; use ``demo`` as the reference).

Everything here is loopback-only for demos, fingerprints-only, and starts nothing
on a forbidden port.
"""

from __future__ import annotations

import socket
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

PORT_LO, PORT_HI = 4600, 4699
FORBIDDEN_PORTS = {4000, 4444, 8790}

# A leak verdict may be spelled "LEAK" or (confused-deputy) "FAIL".
_LEAK_GRADES = {"LEAK", "FAIL"}


def _free_port() -> int:
    for port in range(PORT_LO, PORT_HI + 1):
        if port in FORBIDDEN_PORTS:
            continue
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Like the servers themselves: a port whose last listener just closed is
        # free again. A port something is still listening on stays refused.
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
        finally:
            s.close()
    raise RuntimeError("no free loopback port in 4600-4699")


@contextmanager
def _serve(server):
    """Serve a ThreadingHTTPServer in a background thread; url in, shut down after."""
    addr = server.server_address
    assert PORT_LO <= addr[1] <= PORT_HI and addr[1] not in FORBIDDEN_PORTS, addr
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{addr[1]}/mcp"
    finally:
        server.shutdown()
        server.server_close()


def _grade_of(report: Any) -> str:
    return str(getattr(report, "grade", "INCONCLUSIVE"))


def leaked(report: Any) -> bool:
    return _grade_of(report) in _LEAK_GRADES


# --------------------------------------------------------------------------- #
# Per-test demo + real-target runners (mirror each probe's own test harness).  #
# --------------------------------------------------------------------------- #

def _demo_statehandle() -> Dict[str, Any]:
    from .statehandle import run_statehandle_probe, statehandle_identity, statehandle_canary
    from .practice_statehandle_http import build_server

    def canary_against(leaky_url):
        return lambda: statehandle_canary(
            statehandle_identity(leaky_url, "canary-a", "CA"),
            statehandle_identity(leaky_url, "canary-b", "CB"),
        )

    with _serve(build_server("leaky", port=_free_port())) as leaky_url:
        leaky = run_statehandle_probe(
            leaky_url, statehandle_identity(leaky_url, "alice", "A"),
            statehandle_identity(leaky_url, "bob", "B"), authorized=True)
        with _serve(build_server("safe", port=_free_port())) as safe_url:
            safe = run_statehandle_probe(
                safe_url, statehandle_identity(safe_url, "alice", "A"),
                statehandle_identity(safe_url, "bob", "B"),
                canary=canary_against(leaky_url), authorized=True)
    return {"leaky": leaky, "safe": safe}


def _target_statehandle(url: str, token_a: str, token_b: str, **_) -> Any:
    from .statehandle import run_statehandle_probe, statehandle_identity, statehandle_canary
    from .practice_statehandle_http import build_server
    # A local known-leaky canary so an OK can't be vacuous.
    with _serve(build_server("leaky", port=_free_port())) as leaky_url:
        canary = lambda: statehandle_canary(  # noqa: E731
            statehandle_identity(leaky_url, "canary-a", "CA"),
            statehandle_identity(leaky_url, "canary-b", "CB"))
        return run_statehandle_probe(
            url, statehandle_identity(url, token_a, "A"),
            statehandle_identity(url, token_b, "B"), canary=canary,
            authorized=True, authorization_note="operator-confirmed target")


def _demo_tasks() -> Dict[str, Any]:
    from .tasks_idor import run_tasks_idor_probe, tasks_identity
    from .practice_tasks_http import build_server
    with _serve(build_server("leaky", host="127.0.0.1", port=_free_port())) as leaky_url:
        leaky = run_tasks_idor_probe(
            leaky_url, tasks_identity(leaky_url, "alice", "A"),
            tasks_identity(leaky_url, "bob", "B"), authorized=True)
    with _serve(build_server("safe", host="127.0.0.1", port=_free_port())) as safe_url:
        safe = run_tasks_idor_probe(
            safe_url, tasks_identity(safe_url, "alice", "A"),
            tasks_identity(safe_url, "bob", "B"), authorized=True)
    return {"leaky": leaky, "safe": safe}


def _target_tasks(url: str, token_a: str, token_b: str, **_) -> Any:
    from .tasks_idor import run_tasks_idor_probe, tasks_identity
    return run_tasks_idor_probe(
        url, tasks_identity(url, token_a, "A"), tasks_identity(url, token_b, "B"),
        authorized=True, authorization_note="operator-confirmed target")


def _elicit_identity(url: str, token: str, label: str):
    from .probe import Identity
    from .mcp_client import MCPClient
    from .transports import HTTPTransport
    return Identity(label=label, connect=lambda: MCPClient(
        HTTPTransport(url, headers={"Authorization": f"Bearer {token}"}, modern=True)))


def _demo_elicitation() -> Dict[str, Any]:
    from .elicitation_takeover import run_elicitation_takeover_probe
    from .practice_elicitation_http import build_server, make_test_jwt
    a, b = make_test_jwt("alice"), make_test_jwt("bob")
    with _serve(build_server("leaky", port=_free_port())) as leaky_url:
        leaky = run_elicitation_takeover_probe(
            leaky_url, _elicit_identity(leaky_url, a, "A"),
            _elicit_identity(leaky_url, b, "B"), authorized=True)
    with _serve(build_server("safe", port=_free_port())) as safe_url:
        safe = run_elicitation_takeover_probe(
            safe_url, _elicit_identity(safe_url, a, "A"),
            _elicit_identity(safe_url, b, "B"), authorized=True)
    return {"leaky": leaky, "safe": safe}


def _target_elicitation(url: str, token_a: str, token_b: str, **_) -> Any:
    from .elicitation_takeover import run_elicitation_takeover_probe
    return run_elicitation_takeover_probe(
        url, _elicit_identity(url, token_a, "A"), _elicit_identity(url, token_b, "B"),
        authorized=True, authorization_note="operator-confirmed target")


def _demo_subscriptions() -> Dict[str, Any]:
    from .probe import Identity
    from .mcp_client import MCPClient
    from .transports import HTTPTransport
    from .subscriptions_leak import run_subscriptions_leak_probe
    from .practice_subscriptions_http import build_server
    a_uri, b_uri = "note://alice/private-secret", "note://bob/own-note"

    def ident(url, token, label):
        return Identity(label=label, connect=lambda: MCPClient(
            HTTPTransport(url, headers={"Authorization": f"Bearer {token}"})))

    def change(uri, value):
        return lambda client: client.call_tool("set_resource", {"uri": uri, "value": value})

    def run(url):
        return run_subscriptions_leak_probe(
            url, ident(url, "alice", "A"), ident(url, "bob", "B"),
            resource_uri=a_uri, change=change(a_uri, "a-value"),
            b_own_uri=b_uri, b_change=change(b_uri, "b-value"),
            idle_timeout=2.0, authorized=True)

    with _serve(build_server("leaky", host="127.0.0.1", port=_free_port())) as leaky_url:
        leaky = run(leaky_url)
    with _serve(build_server("safe", host="127.0.0.1", port=_free_port())) as safe_url:
        safe = run(safe_url)
    return {"leaky": leaky, "safe": safe}


def _demo_confused_deputy() -> Dict[str, Any]:
    from .confused_deputy import run_confused_deputy_probe, CallerSpec, token_fingerprint
    from .probe import Identity
    from .mcp_client import MCPClient
    from .transports import HTTPTransport
    from .practice_confused_deputy_http import (
        HTTPMockUpstream, build_confused_deputy_server, make_caller_token)
    aud = "https://api.myserver.example/mcp"

    def caller(url, subject):
        token = make_caller_token(subject)
        return CallerSpec(
            identity=Identity(label=subject, connect=lambda: MCPClient(
                HTTPTransport(url, headers={"Authorization": f"Bearer {token}"}))),
            subject=subject, inbound_token_fp=token_fingerprint(token))

    def sensitive(client):
        client.call_tool("call_upstream", {})

    def benign(client):
        client.call_tool("benign_upstream", {})

    @contextmanager
    def harness(mode):
        upstream = HTTPMockUpstream(aud, port=_free_port()).start()
        server = build_confused_deputy_server(mode, upstream.url, upstream.expected_audience,
                                              port=_free_port())
        with _serve(server) as url:
            yield url, upstream
        upstream.stop()

    def broken_fixture():
        with harness("leaky") as (burl, bup):
            return run_confused_deputy_probe(
                burl, caller(burl, "alice"), caller(burl, "bob"), upstream=bup,
                sensitive_trigger=sensitive, benign_trigger=benign,
                expected_audience=aud, broken_fixture=None, authorized=True)

    with harness("leaky") as (url, up):
        leaky = run_confused_deputy_probe(
            url, caller(url, "alice"), caller(url, "bob"), upstream=up,
            sensitive_trigger=sensitive, benign_trigger=benign,
            expected_audience=aud, broken_fixture=None, authorized=True)
    with harness("safe") as (url, up):
        safe = run_confused_deputy_probe(
            url, caller(url, "alice"), caller(url, "bob"), upstream=up,
            sensitive_trigger=sensitive, benign_trigger=benign,
            expected_audience=aud, broken_fixture=broken_fixture, authorized=True)
    return {"leaky": leaky, "safe": safe}


# The bundled practice agent's run inputs ({marker} is filled in by the probe).
_PRACTICE_AGENT = {
    "assistant_id": "memory",
    "save_input": {"action": "save", "key": "st-probe", "value": "{marker}"},
    "recall_input": {"action": "recall", "key": "st-probe"},
    "whoami_field": "whoami",
}


# Extra practice identities for the awkward-id cases, each with its own token.
# The practice server reads the id from the token (percent-decoded).
_PRACTICE_EDGES = {
    "prefix": ("ali",),
    "dot": ("alice.notes", "alice.no"),
    "separator": ("alice:notes", "alice/notes", "alice|notes"),
    "wildcard": ("al_ce", "al%", "al*"),
    "case": ("Alice",),
    "whitespace": ("alice ", " alice"),
}
_PRACTICE_EDGE_BUGS = (("prefix", "prefixbug"), ("dot", "dotbug"), ("separator", "separatorbug"),
                       ("wildcard", "wildcardbug"), ("case", "casebug"),
                       ("whitespace", "whitespacebug"))


def _practice_edge_identities(*kinds: str) -> list:
    from urllib.parse import quote
    return [{"kind": kind, "token": "tok-" + quote(name, safe=""), "namespace": [name]}
            for kind in (kinds or tuple(_PRACTICE_EDGES)) for name in _PRACTICE_EDGES[kind]]


def _demo_agent_memory() -> Dict[str, Any]:
    from .agent_memory import run_agent_memory_probe
    from .practice_agent_memory_http import build_server

    def run(mode, token_b="tok-bob", **options):
        with _serve(build_server(mode, port=_free_port())) as mcp_url:
            base = mcp_url[: -len("/mcp")]      # this API lives at the server root
            return run_agent_memory_probe(base, "tok-alice", token_b,
                                          namespace_a=["alice", "notes"], authorized=True, **options)

    out = {"leaky": run("leaky", write_paths=True, **_PRACTICE_AGENT),
           # The safe server gets everything at once: every awkward-id identity and
           # the write paths. All of it must come back clean.
           "safe": run("safe", write_paths=True, edge_identities=_practice_edge_identities(),
                       namespace_b=["bob"], **_PRACTICE_AGENT)}
    # The namespace-boundary shape needs prefix-sibling ids: B is "ali", A is "alice".
    out["prefixbug"] = run("prefixbug", token_b="tok-ali", namespace_b=["ali"])
    for kind, mode in _PRACTICE_EDGE_BUGS[1:]:
        out[mode] = run(mode, edge_identities=_practice_edge_identities(kind))
    out["writeleak"] = run("writeleak", write_paths=True)
    return out


_AGENT_MEMORY_DEMO_EXTRA = tuple(
    (mode, f"a store with the {kind} id bug (the test must catch it)", "LEAK")
    for kind, mode in _PRACTICE_EDGE_BUGS) + (
    ("writeleak", "a server that checks reads but not writes (the test must catch it)", "LEAK"),)


def _json_opt(value: Any, name: str) -> Any:
    """A CLI option that carries JSON (a run input); None stays None."""
    if value is None or isinstance(value, (dict, list)):
        return value
    import json
    try:
        return json.loads(value)
    except ValueError as exc:
        raise ValueError(f"--{name} is not valid JSON: {exc}")


def _target_agent_memory(url: str, token_a: str, token_b: str, **opts) -> Any:
    from .agent_memory import parse_edge_identity, parse_namespace, run_agent_memory_probe
    return run_agent_memory_probe(
        url, token_a, token_b, namespace_a=parse_namespace(opts.get("namespace_a")),
        namespace_b=parse_namespace(opts.get("namespace_b")),
        assistant_id=opts.get("assistant_id"),
        save_input=_json_opt(opts.get("save_input"), "save-input"),
        recall_input=_json_opt(opts.get("recall_input"), "recall-input"),
        whoami_field=opts.get("whoami_field"),
        edge_identities=[parse_edge_identity(spec) if isinstance(spec, str) else spec
                         for spec in opts.get("edge_identities") or ()],
        write_paths=bool(opts.get("write_paths")),
        authorized=True, authorization_note="operator-confirmed target")


@dataclass
class DeepTest:
    id: str
    title: str
    summary: str
    tier1_check: Optional[str]            # scanner check_id this confirms (or None)
    demo: Callable[[], Dict[str, Any]]
    run_target: Optional[Callable[..., Any]] = None   # None = lab-only (use demo)
    target_note: str = ""
    # More demo runs beyond "leaky" and "safe": (key in demo()'s result, what the
    # fixture is, the grade the test must give it).
    demo_extra: tuple = ()


def _demo_semantic_cache() -> Dict[str, Any]:
    from .semantic_cache import run_semantic_cache_probe
    from .practice_semantic_cache_http import build_server

    out = {}
    for mode in ("leaky", "safe"):
        with _serve(build_server(mode, port=_free_port())) as url:
            out[mode] = run_semantic_cache_probe(
                url[: -len("/mcp")], "alice", "bob", authorized=True)
    # Prefix-sibling ids (ali is a prefix of alice) against a string-prefix cache.
    with _serve(build_server("prefixbug", port=_free_port())) as url:
        out["prefixbug"] = run_semantic_cache_probe(
            url[: -len("/mcp")], "alice", "ali", authorized=True)
    # The chat-completions shape: a stand-in LLM gateway with a response cache,
    # two bearer tokens. "broken" never serves from cache, so nothing can be told.
    for mode in ("leaky", "safe", "broken"):
        with _serve(build_server(mode, port=_free_port(), auth="token")) as url:
            out["chat_" + mode] = run_semantic_cache_probe(
                url[: -len("/mcp")], "tok-alice", "tok-bob", mode="chat", authorized=True)
    # Awkward ids: header ids made from A's (edge_cases), one cache per key bug.
    for key, mode in (("edges_safe", "safe"), ("dotbug", "dotbug"),
                      ("separatorbug", "separatorbug"), ("wildcardbug", "wildcardbug"),
                      ("casebug", "casebug")):
        with _serve(build_server(mode, port=_free_port())) as url:
            out[key] = run_semantic_cache_probe(
                url[: -len("/mcp")], "alice", "bob", edge_cases="all", authorized=True)
    # A space cannot travel in a header id, so that case uses given credentials.
    with _serve(build_server("whitespacebug", port=_free_port(), auth="token")) as url:
        out["whitespacebug"] = run_semantic_cache_probe(
            url[: -len("/mcp")], "tok-alice", "tok-bob", mode="chat", authorized=True,
            edge_identity=["whitespace=tok-space", "case=tok-case"])
    # Three routes in one run, then the same over event streams.
    routes = ["chat", "responses", "messages"]
    for key, mode, stream in (("routes_routebug", "routebug", False),
                              ("routes_safe", "safe", False),
                              ("stream_routebug", "routebug", True),
                              ("stream_safe", "safe", True)):
        with _serve(build_server(mode, port=_free_port(), auth="token")) as url:
            out[key] = run_semantic_cache_probe(
                url[: -len("/mcp")], "tok-alice", "tok-bob", mode="chat", route=routes,
                stream=stream, authorized=True)
    return out


_SEMANTIC_CACHE_OPTIONS = (
    "base_query", "reworded_query", "identity_as", "identity_header", "token_header",
    "api_key", "user_a", "user_b", "user_sibling", "store_path", "query_path",
    "chat_path", "model", "cache_hit_header", "edge_cases", "edge_identity", "edge_user",
    "route", "stream")


def _target_semantic_cache(url: str, token_a: str, token_b: str, **opts) -> Any:
    from .semantic_cache import run_semantic_cache_probe
    threshold = opts.get("threshold")
    try:
        threshold = float(threshold) if threshold is not None else None
    except (TypeError, ValueError):
        raise ValueError("--threshold must be a number")
    return run_semantic_cache_probe(
        url, token_a, token_b, threshold=threshold, mode=opts.get("cache_mode"),
        sibling=opts.get("token_sibling"),
        authorized=True, authorization_note="operator-confirmed target",
        **{name: opts.get(name) for name in _SEMANTIC_CACHE_OPTIONS})


DEEP_TESTS: Dict[str, DeepTest] = {
    "state-handle": DeepTest(
        "state-handle", "State-handle hijacking",
        "Replay identity A's server-minted state handle as identity B; a server that "
        "treats the handle as authentication lets B reach A's state.",
        tier1_check="session-id-as-bearer", demo=_demo_statehandle,
        run_target=_target_statehandle),
    "confused-deputy": DeepTest(
        "confused-deputy", "Confused deputy / token passthrough",
        "Does the server forward the caller's token to a wrong-audience upstream, or act "
        "with its own authority on an under-scoped request?",
        tier1_check="token-exchange-present", demo=_demo_confused_deputy,
        run_target=None,
        target_note="Lab test: point the deputy's upstream at the bundled recorder "
                    "(run with --demo for the reference run)."),
    "tasks-idor": DeepTest(
        "tasks-idor", "Tasks-extension cross-tenant IDOR",
        "As identity B, read/update/cancel identity A's task by its id, and test whether "
        "task ids are guessable/enumerable.",
        tier1_check=None, demo=_demo_tasks, run_target=_target_tasks),
    "elicitation": DeepTest(
        "elicitation", "Elicitation cross-user binding / account takeover",
        "Identity A starts an elicitation, identity B completes the authorization — does "
        "the grant bind to A? Also flags secrets requested in form mode.",
        tier1_check=None, demo=_demo_elicitation, run_target=_target_elicitation),
    "subscriptions": DeepTest(
        "subscriptions", "Subscriptions/listen notification leakage",
        "Does identity B's listen stream receive notifications scoped to identity A?",
        tier1_check="cachescope-mislabel-signal", demo=_demo_subscriptions,
        run_target=None,
        target_note="Lab/target test needs a resource A can mutate; run with --demo for "
                    "the reference run."),
    "agent-memory": DeepTest(
        "agent-memory", "Agent memory isolation (threads and long-term Store)",
        "Identity A saves a marker in an agent server's memory; can identity B read it "
        "back from A's thread, from the Store, or by asking the agent? Speaks the "
        "LangGraph Server API; give the server's base URL, not an MCP endpoint.",
        tier1_check=None, demo=_demo_agent_memory, run_target=_target_agent_memory,
        demo_extra=_AGENT_MEMORY_DEMO_EXTRA),
    "semantic-cache": DeepTest(
        "semantic-cache", "Semantic cache cross-user leak",
        "Identity A caches an answer; can identity B read it back from the cache by the "
        "same question, a reworded (near-match) question, or (with a prefix-sibling id) "
        "B's own scope? For response/LLM caches and LLM gateways that cache "
        "chat completions (--cache-mode chat); give the base URL.",
        tier1_check=None, demo=_demo_semantic_cache, run_target=_target_semantic_cache,
        demo_extra=(
            ("chat_leaky", "a KNOWN-LEAKY gateway cache, chat-completions shape "
                           "(the test must catch it)", "LEAK"),
            ("chat_safe", "a SAFE gateway cache, chat-completions shape "
                          "(must come back clean)", "OK"),
            ("chat_broken", "a gateway that never serves from cache "
                            "(the test must say it cannot tell)", "INCONCLUSIVE"),
            ("edges_safe", "a SAFE cache, every awkward-id case (--edge-cases all)", "OK"),
            ("dotbug", "a cache that compares ids up to the first dot", "LEAK"),
            ("separatorbug", "a cache that joins id and question with ':'", "LEAK"),
            ("wildcardbug", "a cache that uses the caller's id as a pattern", "LEAK"),
            ("casebug", "a cache that ignores letter case in ids", "LEAK"),
            ("whitespacebug", "a gateway cache that trims ids, identities given by token "
                              "(--edge-identity)", "LEAK"),
            ("routes_routebug", "a gateway that applies identity on chat-completions only, "
                                "three routes (--route)", "LEAK"),
            ("routes_safe", "a SAFE gateway cache, three routes", "OK"),
            ("stream_routebug", "the same route bug over event streams (--stream)", "LEAK"),
            ("stream_safe", "a SAFE gateway cache over event streams", "OK"))),
}

# Scanner Tier-1 check_id -> the Tier-2 test that confirms it.
CONFIRM_FOR_CHECK: Dict[str, str] = {
    t.tier1_check: t.id for t in DEEP_TESTS.values() if t.tier1_check
}


def get(test_id: str) -> Optional[DeepTest]:
    return DEEP_TESTS.get(test_id)


def confirm_hint(check_id: str) -> Optional[str]:
    """For a scanner finding's check_id, the `confirm` command that proves it, if any."""
    tid = CONFIRM_FOR_CHECK.get(check_id)
    return f"stranger-test confirm {tid} <url> --token-a <A> --token-b <B>" if tid else None


__all__ = ["DEEP_TESTS", "DeepTest", "get", "confirm_hint", "CONFIRM_FOR_CHECK", "leaked"]
