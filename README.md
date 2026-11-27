# Stranger Test

**Can user B read user A's data in your AI app? A two-user test that finds out.**

[![PyPI](https://img.shields.io/pypi/v/stranger-test)](https://pypi.org/project/stranger-test/)
[![Python](https://img.shields.io/pypi/pyversions/stranger-test)](https://pypi.org/project/stranger-test/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![selftest](https://github.com/strangertest-labs/stranger-test/actions/workflows/selftest.yml/badge.svg)](https://github.com/strangertest-labs/stranger-test/actions/workflows/selftest.yml)

Tenant isolation testing for **LangGraph agent servers**, **MCP servers and
gateways**, and **LLM semantic caches**. It is the two-account access check that
a penetration tester does by hand (IDOR / BOLA, cross-tenant access), made
repeatable: sign in as two test users and see whether one can read the other's
threads, memory, tool state or cached answers.

See it catch a leak, with nothing to set up. This starts two small practice
servers on your own machine, one leaky and one safe:

```bash
pip install stranger-test
stranger-test confirm agent-memory --demo
```

```
-- against a KNOWN-LEAKY server (the test must catch it):
LEAK: another identity reached identity A's memory on 15 of 15 paths: ...
  LEAK           thread_get: B reads A's thread by id (B got HTTP 200)
  LEAK           store_get: B reads A's memory item by namespace and key (B got HTTP 200)
  LEAK           agent_recall: B asks the agent for A's memory (B got HTTP 200)
  ...
-- against a SAFE server (must come back clean):
OK: identity B could not read identity A's memory on any of the 21 exercised paths.
  OK             thread_get: B reads A's thread by id (B got HTTP 404)
  OK             store_get: B reads A's memory item by namespace and key (B got HTTP 403)
  ...
VERDICT: the test WORKS (leaky -> LEAK, safe -> OK, ...)
```

(Output shortened; `...` marks lines left out.) Then point it at a LangGraph
server you run, with two test users' tokens:

```bash
stranger-test confirm agent-memory http://127.0.0.1:2024 --token-a <A's token> --token-b <B's token>
```

Free, Apache-2.0, standard-library-only Python (3.9+). Test only systems you
run or are authorized to test.

## How it decides

An AI application keeps many users' data behind one endpoint: in an agent's
memory, in an MCP server or gateway, in a cache of model answers. Stranger Test
signs in as two test users. User A stores a unique marker, and the test tries
each way user B might get it. Each path is graded **LEAK**, **OK** or
**INCONCLUSIVE**, and a path is only OK if A could read her own data back
first, so a broken test never passes for a safe system.

What it tests:

- **LangGraph agent memory**: threads and the long-term Store, over the
  LangGraph Server API (`confirm agent-memory`). Guide:
  [docs/AGENT-MEMORY.md](docs/AGENT-MEMORY.md). Results on each new LangGraph
  server release: [docs/LANGGRAPH-RELEASE-CHECKS.md](docs/LANGGRAPH-RELEASE-CHECKS.md).
- **MCP servers and gateways**: a quick single-user `scan`, and two-user
  `confirm` tests for state handles, tasks and elicitation.
- **LLM semantic caches and gateways**: exact and similar-question lookups in a
  response cache (`confirm semantic-cache`). Shared caches have leaked between
  customers in production;
  [two public incidents](docs/CACHE.md#why-it-matters-two-public-incidents).

Each `confirm` run can write an **evidence page** (`--evidence`): what
was tested, by whom, when, each path's result, what was not tested, and how to
repeat it. `--evidence-summary` writes a **short summary** of the same run,
under half the length, to hand to someone who will not read four pages. It supplements an independent penetration test; it does not replace
one. See [docs/EVIDENCE.md](docs/EVIDENCE.md).

## Who it is for

- **Security and platform engineers** who run a multi-tenant AI product: a
  tenant isolation check you can run on every release (there is a
  [GitHub Action](docs/CI.md)). "Tenant" here means whatever your system keeps
  apart: customers, users, teams, API keys, or agents acting for different
  users. Each is an identity, and the test checks the boundary between two of
  them.
- **Teams asked to show customer data segregation**, by an auditor or in a
  customer's security review: the evidence file records one dated test run in
  plain language. Whether it counts toward a control is the auditor's
  judgement; see [what it does and does not prove](docs/EVIDENCE.md).
- **Penetration testers** who already check this by hand with two accounts: a
  repeatable version of that test, with a baseline check so that a refusal to
  the second account means something.

For an MCP server, the quickest start is the read-only scan:

```bash
# scan any MCP server you run, in ~30s — no third-party dependencies:
pip install stranger-test
stranger-test scan http://localhost:4600/mcp
# (or, zero-install with pipx: pipx run stranger-test scan http://localhost:4600/mcp)
```

---

## Why it's different

Most MCP security tools are **static**: they read config or source and flag
*risk signals*. That's useful — Stranger Test does it too (`scan`) — but a signal
is a thing to look at, not a proven leak. And a single-identity scanner
**structurally cannot** tell you whether identity B can actually reach identity
A's data, because it only ever connects as one identity.

Stranger Test adds a **dynamic, two-identity confirmation lab** (`confirm`).
It connects as A *and* B, performs the real protocol dance, and grades the result **LEAK / OK / INCONCLUSIVE** — with a
built-in positive control so "no leak" can never be a silently broken test.

|                         | Static scanners / guardrails | **Stranger Test** |
|-------------------------|:---:|:---:|
| Flags config/source risk signals | ✓ | ✓ (`scan`) |
| Connects as **two** identities    | — | ✓ |
| **Confirms** a cross-user leak dynamically | — | ✓ (`confirm`) |
| Positive control (catches a broken test)   | — | ✓ |
| Explicit `INCONCLUSIVE` (never a false "clean") | — | ✓ |

Guardrails and prompt-firewalls sit in one user's session, so cross-user
authority is a permanent blind spot for them. That blind spot is the whole point
of this tool.

---

## 1. Scan (Tier 1) — one command, read-only

```bash
pipx run stranger-test scan http://localhost:4600/mcp          # or: pip install stranger-test
stranger-test scan http://localhost:4600/mcp --bearer "$TOKEN" # scan as an authenticated caller
stranger-test scan http://localhost:4600/mcp --sarif > out.sarif
```

A single read-only pass. It fingerprints the server — transport, protocol
version, auth posture, session handling, cache scope, advertised delegation —
and flags authorization **risk signals** by severity. Tokens are fingerprinted
(sha256), never printed. It **never writes** to the target.

- `--json` → a `{profile, findings}` document · `--sarif` → SARIF 2.1.0 for CI
  code-scanning.
- **Exit codes drop straight into a CI gate:** `0` no signal · `1` ≥1 signal ·
  `2` unreachable.
- **Safe by default:** refuses any non-loopback target unless you pass
  `--allow-nonloopback` for a server you're authorized to test.

A finding whose class has a confirmer prints the exact `confirm` command to run
next.

## 2. Confirm (Tier 2) — prove it with two identities

`scan` flags a signal; `confirm` **runs a two-identity lab test** that proves it
`LEAK`, clears it `OK`, or returns `INCONCLUSIVE`. Every test ships a bundled
leaky + safe practice server, so `--demo` proves the test works with no target:

```bash
stranger-test confirm --list
stranger-test confirm state-handle --demo          # leaky -> LEAK, safe -> OK
stranger-test confirm state-handle http://127.0.0.1:4600/mcp --token-a <A> --token-b <B>
```

The seven dynamic cross-user tests (two identities, loopback, fingerprints only):

| Test | What it proves |
|---|---|
| `state-handle`    | B replays A's server-minted state handle and reaches A's state (the 2026-07-28 stateless core: a handle **MUST NOT** be treated as authentication) |
| `confused-deputy` | the server forwards the caller's token to a wrong-audience upstream, or acts with its own authority on an under-scoped request (RFC 8693) |
| `tasks-idor`      | B reads / updates / cancels A's task by id, and whether task ids are enumerable (tasks extension, SEP-2663) |
| `elicitation`     | A starts an elicitation, B completes the authorization — does the grant bind to A? (account takeover); plus secrets requested in form mode |
| `subscriptions`   | B's `subscriptions/listen` stream receives notifications scoped to A |
| `agent-memory`    | B reads what A saved in an agent server's memory — threads, long-term Store, or by asking the agent. Speaks the **LangGraph Server** API; give the server's base URL. With prefix-sibling ids it also catches the store namespace-boundary bugs (CVE-2026-71433 / -115883). |
| `semantic-cache`  | B gets the answer a response cache stored for A — by the same question, a reworded one, or from a prefix-sibling id. For a cache with store/query calls, or an **LLM gateway that caches chat completions** (`--cache-mode chat`); give the base URL. |

`agent-memory` needs only a running LangGraph server and two test users' tokens;
nothing about your agent:

```bash
stranger-test confirm agent-memory http://127.0.0.1:2024 --token-a <A> --token-b <B>
```

Guide, with a copy-paste test-user auth snippet: [docs/AGENT-MEMORY.md](docs/AGENT-MEMORY.md).
Background and results on affected and fixed store versions:
[docs/LANGGRAPH-MEMORY-ISOLATION.md](docs/LANGGRAPH-MEMORY-ISOLATION.md).
Results on each new LangGraph server release:
[docs/LANGGRAPH-RELEASE-CHECKS.md](docs/LANGGRAPH-RELEASE-CHECKS.md).

`semantic-cache` needs a running cache or gateway and two test users' ids or
keys:

```bash
stranger-test confirm semantic-cache http://127.0.0.1:4000 --cache-mode chat --token-a <A> --token-b <B> --model <model>
```

Guide, for both kinds of cache: [docs/CACHE.md](docs/CACHE.md).

Every `confirm` grade requires **provably distinct principals** before it will
call anything a LEAK — on a server that collapses both callers to one identity
it reports `OBSERVATION`, not a false positive.

---

## Install

Python 3.9+. Standard library only — **no third-party dependencies.**

```bash
pip install stranger-test             # the CLI + library
pipx run stranger-test scan <url>     # or zero-install, one-off (needs pipx)
```

## Try it (no target needed)

See a leak caught in under a minute. This starts the bundled practice MCP
subscription server on a loopback port and runs the XID-13 subscription probe
against it — first in `leaky` mode, then in `safe` mode:

```
python3 -m strangertest.demo
```

```
Subscription-leak probe (XID-13) against the bundled practice server.
B subscribes to A's resource; A changes it; did B hear about it?

[leaky] LEAK: identity 'B' received update notifications for 'note://alice/secret', a resource owned by identity 'A' — cross-identity subscription/notification leak.
[safe] OK: identity 'B' received no notifications for 'A''s resource 'note://alice/secret'.
```

The `leaky` line is the detection; the `safe` line is the same probe reporting a
correctly-scoped server clean. `demo` exits **0** when the contrast holds (leaky
leaks **and** safe does not) — so a printed `LEAK` with exit `0` is the demo
working, not a finding against you. Other probes: `python3 -m strangertest demo
--probe {cache,handle,cachescope}`.

## Run it on every release (CI)

A leak between users usually arrives with a change: a new handler, a dependency
upgrade, a refactor of the auth code. So the check is most useful as a build
step. Your job starts the server on the runner's loopback with two test
accounts, and the step fails on `LEAK`.

For a LangGraph server, with the GitHub Action:

```yaml
- uses: strangertest-labs/stranger-test@v0.4
  with:
    mode: confirm
    test: agent-memory
    url: http://127.0.0.1:2024
    token-a: ${{ secrets.AGENT_TEST_TOKEN_A }}
    token-b: ${{ secrets.AGENT_TEST_TOKEN_B }}
    namespace-a: alice.notes      # a Store namespace user A may write to
```

Or in any CI system, as a plain command:

```bash
pip install stranger-test
stranger-test confirm agent-memory http://127.0.0.1:2024 \
  --token-a "$A" --token-b "$B" --namespace-a alice.notes --write-paths
```

Exit codes: `0` OK, `1` leak, `2` inconclusive, `3` usage error or refused
target. `--write-paths` adds the update, delete and owner-field paths; it
writes throwaway objects, so use a test server. The same pattern works for an
MCP server (`state-handle`, `tasks-idor`, `elicitation`) and a response cache
(`semantic-cache`): see [docs/CI.md](docs/CI.md).

The same check is run against each new LangGraph server release with a sample
app; the results are in
[docs/LANGGRAPH-RELEASE-CHECKS.md](docs/LANGGRAPH-RELEASE-CHECKS.md).

## How it works

Every probe is an **A/B probe**: act as identity **A**, observe as identity
**B**, and check whether the line between them held.

- **Positive controls.** A probe first proves its observer actually works, so
  that "no leak" cannot be a false negative caused by a broken observer.
- **An explicit `inconclusive` grade.** When the probe cannot observe what it
  needs — an undecodable delegated token, a stream that will not open, a server
  too old to carry the channel — it reports *inconclusive*, distinct from *no
  leak*. It never reports a leak it could not actually see, and never calls an
  unobservable server clean.
- **Authorized-first.** Every probe passes the target through an authorization
  guard before any connection is made (see *Scope and safety*).
- **Fingerprints only.** Tokens and session ids are recorded as sha256
  fingerprints, never in the clear.

**Transports** (`strangertest.transports`), standard library only: **stdio**
(subprocess, newline-delimited JSON-RPC) and **Streamable HTTP** (JSON or SSE),
including the 2026-07-28 "modern" per-request envelope.

Identity is `(issuer, subject)`, so two users named the same from different
providers are never conflated.

## Integration gates

The gates in `integration/` exercise the probes end-to-end against real servers.
They need extra dependencies (`pyjwt[crypto]`, plus the target server itself),
are **not** run by `python3 -m unittest discover`, and skip cleanly when their
dependencies are absent. Everything in the gates runs on localhost only.

- **XID-13 subscription gate** — drives the subscription probe against the
  official MCP SDK subscriptions example server.
- **XID-10 thin-deputy gate** (`integration/xid10_thin_deputy_gate.py`) — runs
  the delegation probe over a real RFC 8693 token exchange against
  deliberately-broken deputy fixtures (`static_credential`, `token_passthrough`,
  `cached_token_reuse`, a conflated-issuer case), plus the scope-narrowing and
  issuer-binding fixtures. Each is a known leak the probe must flag, for the
  right reason. Ports via `THIN_PORT_BASE=N` (local AS on N, lax AS N+1,
  recording upstream N+2, deputy N+3, all 127.0.0.1); it refuses 8790 and 4444.
- **XID-10 ContextForge gate** (`integration/xid10_contextforge_gate.py`) —
  drives the delegation probe through a real IBM ContextForge gateway doing
  RFC 8693 token exchange.
- **XID-10 agentgateway gate** — the same probe/checks through a second,
  unrelated gateway: **agentgateway v1.7.0** (official release binary).
- **XID-10 LiteLLM gate** — the same probe/checks through **LiteLLM 1.109.1**,
  plus exchange-failure and cache checks.

Setup recipes: [`integration/CONTEXTFORGE_GATE.md`](integration/CONTEXTFORGE_GATE.md),
[`integration/AGENTGATEWAY_GATE.md`](integration/AGENTGATEWAY_GATE.md),
[`integration/LITELLM_GATE.md`](integration/LITELLM_GATE.md).

## Findings

Stranger Test is built to find real cross-user leaks and disclose them
responsibly. Confirmed advisories are listed here as they are published.

The detection engine is validated end-to-end against real third-party gateways
on loopback — **agentgateway v1.7.0, LiteLLM 1.109.1, IBM ContextForge** — plus
the deliberately-broken fixtures above, each of which the probe flags for the
right reason. In the delegation scenarios run so far, the checks passed on those
versions: faithful delegation grades clean, impersonation (no `act` claim) is
flagged, and two users named `alice` from different providers are kept distinct.
A passing check covers only that check on that version; it is not a verdict on
the product. The probe's ability to *detect* is demonstrated by the broken
fixtures. See the [results at a glance](docs/RESULTS-SUMMARY.md) and the full
[`integration/RESULTS.md`](integration/RESULTS.md). To run it in your own CI,
see [`docs/CI.md`](docs/CI.md).

## Scope and safety

Point Stranger Test only at **localhost, servers you run, or targets you are
explicitly authorized to test.** The authorization guard allows local
development hosts (loopback, `.localhost`, `.test`) automatically and refuses
every other target unless you pass explicit authorization recording who
permitted the test. There is deliberately no "scan everything" mode: one target,
one authorization. Any real finding is for **private, responsible disclosure**
to the server's owner. Do not name-and-shame.

## What's new

Version 0.4, maintained by one person. Changes by release are in
[CHANGELOG.md](CHANGELOG.md).

## License

Apache-2.0 (see [`LICENSE`](LICENSE)).
