# Changelog

## 0.4.9

- The GitHub Action is now named "Stranger Test Tenant Isolation Check".
  GitHub Marketplace needs a name that no other action, user or organization
  has. Workflows that use `strangertest-labs/stranger-test@v0.4` need no change.
  No change to any test.

## 0.4.8

- **`agent_recall_store`**: a new agent-memory path (with the agent flags and
  `--namespace-b`). After user B's run it searches the Store as B, and reports
  `LEAK` if the run saved a copy of user A's data where B can read it later.
  See [docs/AGENT-MEMORY.md](docs/AGENT-MEMORY.md).
- The LangGraph server gate passes B's namespace, so it runs the new path. The
  sample app has a new agent that is wrong on purpose (`memory_saves`), used as
  the control: with `ST_GATE_SAVES_CONTROL=1` the gate shows the path reporting
  `LEAK` on a real server.
- The action's description is shorter, to fit GitHub Marketplace.

## 0.4.7

- **A new README first screen**: what the tool answers, one demo command and
  its output, then how it decides. No change to any test.
- Release notes moved out of the README into this file.
- Package description, keywords and links updated for PyPI.

## 0.4.6

- **Run it on every release.** A CI section in the README, and a
  [page of results](docs/LANGGRAPH-RELEASE-CHECKS.md) from running the
  agent-memory check against each new LangGraph server release.
- `docs/CI.md` now pins the action at `@v0.4`. The `@v0.3` it named before
  does not have the `semantic-cache` test.
- The LangGraph server gate waits up to a minute for its port to be free
  before it gives up. No change to any test.

## 0.4.5

- **`agent_recall_steps`**: a new agent-memory path. It reads every step of
  user B's run (the stream, the state and the history), not only the final
  answer, so data that one step wrote to the graph's state and a later step
  removed is still seen. See [docs/AGENT-MEMORY.md](docs/AGENT-MEMORY.md).

## 0.4.3 and 0.4.4

- **Owner-field paths** (`owner_in_body_thread_create`,
  `owner_in_body_store_put`, with `--write-paths`): catch a handler that takes
  the owner from the request body instead of from the signed-in user.
- **A short evidence summary** (`--evidence-summary`) beside the full evidence
  page.
- Shorter `--demo` output and clearer first-run guidance.

## 0.4.2

- **The evidence page names the nearest SOC 2 criterion.** CC6.1 is listed with
  the plain statement that no Trust Services Criterion names tenant
  segregation, so it is the nearest one and not an exact match. Whether a page
  counts toward it is the auditor's judgement.
- **A security policy** ([SECURITY.md](SECURITY.md)) and a clearer description
  of what the tool tests. No change to any test.

## 0.4.1


- **Connects to current MCP gateways.** The client opened connections with the
  older `initialize` handshake while naming the newest protocol version, which
  has no handshake; some gateways refused it. It now settles on a form the
  server accepts: the per-request form (2026-07-28) or an older handshake
  version, with the `MCP-Protocol-Version` header those versions require.
- **`scan` no longer calls an unexamined server clean.** When a server refuses
  every form, the verdict is "not examined", not "no risk signals". `scan` can
  also examine servers that speak only the per-request form, and it now
  completes the handshake and keeps the session a server issues.
- **The evidence page stands on its own.** `confirm` takes the operator's own
  words (`--evidence-system`, `--evidence-system-version`,
  `--evidence-environment`, `--evidence-operator`, `--evidence-notes`,
  `--evidence-identity-a`, `--evidence-identity-b`). `--evidence` can be given
  twice to write Markdown and JSON from one run, and the raw result is saved
  beside them. The page shows the command that was run with credentials
  replaced, counts tested and untested paths in every summary, explains each
  grade, and shows the HTTP status seen on each path. See
  [docs/EVIDENCE.md](docs/EVIDENCE.md).

## 0.4.0

- **`confirm semantic-cache`** — a seventh deep test, for **response caches**:
  can identity B get the answer a cache stored for identity A, by the same
  question, a reworded one, or from a prefix-sibling id? Bundled `--demo`.
- **Works against real caches and gateways.** Choose how each identity is sent
  (`--identity-header`, a bearer token or API key with `--identity-as bearer` /
  `--token-header`, a shared `--api-key`, the OpenAI `user` field), set the
  paths (`--store-path`, `--query-path`), and give a third identity for the
  prefix-sibling path (`--token-sibling`).
- **Chat mode for LLM gateways** (`--cache-mode chat`): no store call; A asks
  through `POST /v1/chat/completions`, must get a cache hit on her repeat, and
  then B asks. A hit is recognised by a cache-hit header when there is one,
  else by the response body. See [docs/CACHE.md](docs/CACHE.md).
- **Several API routes in one run.** `--route chat|responses|messages[=PATH]`
  (repeatable) tests each route and adds a cross-route path: A fills the cache
  on one route, B asks on another. `--stream` repeats the check with streamed
  responses.
- **Awkward identifiers.** `--edge-identity KIND=TOKEN[@NAMESPACE]` (and
  `--edge-user` for caches) adds identities whose ids are close to A's: a
  prefix, a dotted label, a separator, a wildcard character, a case variant, a
  whitespace variant. Works with `agent-memory` and `semantic-cache`.
- **Write paths for `agent-memory`** (`--write-paths`): can B update, overwrite
  or delete what A stored? Off by default against real targets, because these
  calls change data; on in `--demo`. See
  [docs/AGENT-MEMORY.md](docs/AGENT-MEMORY.md).
- **An evidence file per run.** `confirm ... --evidence FILE` (`.md` or `.json`)
  writes the page: the system, the run times, the two identities as
  fingerprints, the positive-control result, each path's outcome and the
  verdict. An inconclusive run is stated as "not a pass".
  `--evidence-summary FILE` writes the short version of the same run. See
  [docs/EVIDENCE.md](docs/EVIDENCE.md).
- **The GitHub Action runs `semantic-cache`**, in both modes; see
  [docs/CI.md](docs/CI.md).

## 0.3.2

- **The GitHub Action runs `agent-memory`.** New inputs `namespace-a`,
  `namespace-b`, `assistant`, `save-input`, `recall-input` and `whoami-field`;
  see [docs/CI.md](docs/CI.md).
- **Verified on the Postgres store too.** Through a real LangGraph dev server on
  PostgreSQL 16, `agent-memory` grades `LEAK` on `langgraph-checkpoint-postgres`
  3.1.0 and `OK` on 3.1.1, the same as on SQLite. The gate takes
  `ST_STORE_KIND=postgres` and refuses a database that is not empty.

## 0.3.1

- **Name for the failure:** an *agent memory spill* is one user of an agent app
  reading memory stored for another user because a per-user access check is
  missing or wrong. Defined in [docs/AGENT-MEMORY.md](docs/AGENT-MEMORY.md).
- **Stronger evidence:** `agent-memory` now also runs through a real LangGraph
  dev server whose Store is LangGraph's SQLite store
  (`integration/langgraph/real_server_store_gate.py`): `LEAK` on
  `langgraph-checkpoint-sqlite` 3.1.0, `OK` on 3.1.1. No change to the tool's
  behaviour.

## 0.3.0

- **`confirm agent-memory`** — a sixth deep test (of seven today), for **agent servers** rather
  than MCP servers: can identity B read what A saved in the agent's memory
  (LangGraph threads, long-term Store, or via the agent)? Bundled `--demo`, and
  a real-LangGraph gate in `integration/langgraph/`. Two tokens are enough to
  run it on your own app: see [docs/AGENT-MEMORY.md](docs/AGENT-MEMORY.md).
- **Store namespace-boundary catch.** With two prefix-sibling identities
  (`--namespace-b`), `agent-memory` catches the LangGraph store bugs fixed in
  2026 (CVE-2026-71433, CVE-2026-115883): it grades `LEAK` against the real
  `langgraph-checkpoint-sqlite` 3.1.0 and `OK` against 3.1.1.

## 0.2.0

- **`scan`** (Tier 1) one-command read-only scanner, SARIF/JSON, CI exit codes.
- **`confirm`** (Tier 2) five dynamic cross-user tests at the time (seven today), each with a `--demo`.
- **Precision:** a `LEAK` needs provably distinct principals, else `OBSERVATION`.
- **One exit-code scheme:** `0` OK, `1` LEAK/FAIL, `2` INCONCLUSIVE, `3` usage.

Unit tests, from a clone of the repository root:

```
python3 -m unittest discover
```

(The tests in `tests/test_gen_results.py`, `tests/test_cf_provider_api.py` and
most of `tests/test_local_as_client_auth.py` are skipped unless `pyjwt[crypto]`
is installed.)
