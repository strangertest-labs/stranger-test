# LangGraph server releases: the agent-memory check, release by release

When a new release of `langgraph-api`, `langgraph` or
`langgraph-checkpoint-sqlite` appears on PyPI, the two-user agent-memory check
is run again against a real LangGraph dev server with that release installed.
This page records each run.

Last updated: 2026-11-27. The page is updated by hand after a run, so it can be
a few days behind PyPI.

## What a row means, and what it does not

Each row is one run of `stranger-test confirm agent-memory` through
`langgraph dev` on loopback, serving the sample app in
`integration/langgraph/app/` with its `@auth.on` handlers on and LangGraph's own
SQLite store behind it. User A is `alice`, user B is `bob`, and the extra test
users have ids that are awkward relatives of `alice` (a prefix, a wildcard
character, a different letter case, a separator, whitespace).

- `OK` means user B could not reach user A's memory on any path the run
  exercised, with that server release and that sample app.
- It is **not a verdict on your app**. In LangGraph, isolation depends on the
  handlers each app adds. The sample app's handlers are correct; yours are what
  you need to test. [Run the same check in your own CI](CI.md).
- It is not a verdict on LangGraph's hosted or self-hosted platform, or on the
  Postgres store. Neither is covered here.
- A run that could not complete is written down as not tested. It is never
  counted as `OK`.

## Runs

LangGraph 1.2.24 in every row.

| Date | `langgraph-api` | `langgraph-checkpoint-sqlite` | Result | Compared with the run before |
|---|---|---|---|---|
| 2026-11-24 | 0.18.4 | 3.1.0 (affected by CVE-2026-71433) | `LEAK` on the prefix, wildcard, case and separator (parent form) cases | control run: shows the check can fail |
| 2026-11-24 | 0.18.4 | 3.1.3 | `OK` | first clean run |
| 2026-11-24 | 0.18.5 | 3.1.3 | `OK` | no change |
| 2026-11-25 | 0.18.6 | 3.1.3 | `OK` | no change |
| 2026-11-25 | 0.19.0 | 3.1.3 | `OK` | no change |
| 2026-11-27 | 0.19.1 | 3.1.3 | `OK` | no change |

Notes:

- **The 3.1.0 row is deliberate.** That store version has a public, fixed bug
  ([CVE-2026-71433](https://github.com/langchain-ai/langgraph/security/advisories/GHSA-47pj-3jcm-6whg),
  reported by other researchers). Running the check against it shows `LEAK`,
  which is the evidence that an `OK` in the rows below is not an empty pass.
  Details in [LANGGRAPH-MEMORY-ISOLATION.md](LANGGRAPH-MEMORY-ISOLATION.md).
- **0.18.6 onward** also runs `agent_recall_steps`, a path added to the check
  in stranger-test 0.4.5.
- **0.19.0 took four attempts.** The first three could not start the server and
  were recorded as not tested. The cause was on the test side: from 0.19.0 the
  local dev runtime is installed with `langgraph-api[inmem]`, and the bare
  package no longer starts `langgraph dev`. With the extra installed the run
  completed.
- **0.19.1** also runs `agent_recall_store`, a path added to the check in
  stranger-test 0.4.8. In the same run the gate's control was on: through a
  sample agent that saves what it fetches (`memory_saves`), the path reported
  `LEAK`. That agent also returns the data in its answer, so `agent_recall`
  and `agent_recall_steps` reported `LEAK` for it too.

## The latest run, path by path

`langgraph-api` 0.19.1, `langgraph` 1.2.24, `langgraph-checkpoint-sqlite` 3.1.3,
run on 2026-11-27. A = `alice`, B = `bob`.

| Path | Result |
|---|---|
| `thread_get` | `OK` |
| `thread_state` | `OK` |
| `thread_history` | `OK` |
| `thread_search` | `OK` |
| `store_get` | `OK` |
| `store_search_namespace` | `OK` |
| `store_search_all` | not exercised |
| `owner_in_body_thread_create` | `OK` |
| `owner_in_body_store_put` | `OK` |
| `store_search_own_prefix` | `OK` |
| `store_edge_dot` | not exercised |
| `store_edge_separator` | `OK` |
| `store_edge_wildcard` | `OK` |
| `store_edge_case` | `OK` |
| `store_edge_whitespace` | `OK` |
| `agent_recall` | `OK` |
| `agent_recall_steps` | `OK` |
| `agent_recall_store` | `OK` |
| `thread_update` | `OK` |
| `store_put_overwrite` | `OK` |
| `thread_delete` | `OK` |
| `store_delete` | `OK` |

20 paths exercised, 2 not exercised:

- `store_search_all`: the sample app refuses a Store search with no namespace
  for everyone, including user A (HTTP 403). A could not read her own marker
  that way, so there was nothing for B to reach and the path cannot count as a
  pass.
- `store_edge_dot`: the server refuses a Store label that contains a dot
  (HTTP 422), so a user whose id has a dot cannot use the Store at all.

The same run repeats the check with two more pairs of users. With A =
`team:alice` and the other user `team`, 5 paths were exercised and all were
`OK`. With A = `acme.alice` and the other user `acme`, only the two thread
paths could be exercised (both `OK`); the Store paths were not, for the dot
reason above.

`agent_recall_steps` checks what a node wrote to the graph's state at any step
of B's run. A node that fetches data and writes none of it to state is not
visible from outside the server.

`agent_recall_store` searches the Store as B before and after each of B's
runs. It only sees a copy saved where B can search.

## Repeat a row yourself

In a fresh virtual environment, with the versions from the row:

```bash
pip install "langgraph-cli[inmem]" "langgraph-api[inmem]==0.19.1" \
  "langgraph==1.2.24" "langgraph-checkpoint-sqlite==3.1.3"
LANGGRAPH_BIN=<env>/bin/langgraph ST_GATE_SCRATCH=<an empty dir> ST_GATE_PORT=4645 \
  python3 integration/langgraph/real_server_store_gate.py
```

Run it from a checkout of this repository. Everything stays on 127.0.0.1. For
releases before 0.19.0, `langgraph-api==<version>` without the extra is enough.

## Limits

- One sample app, one store (SQLite), the local dev server, one machine.
- The check covers what it can reach over the server's HTTP API. A clean result
  is not a proof of isolation.
- It does not test leaks through semantic (similarity) search.
- A release that changes how the server is installed or started can make a run
  fail for reasons that have nothing to do with isolation, as 0.19.0 did. Those
  runs are listed as not tested until they are repeated.
