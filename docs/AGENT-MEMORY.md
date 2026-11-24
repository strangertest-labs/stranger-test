# Test your own LangGraph app for cross-user memory leaks

## What the test checks

An agent server that serves many users keeps memory for them: saved
conversations (threads) and long-term memory (the Store). `confirm agent-memory`
signs in as two users, has user A save a unique marker, and then checks whether
user B can read it back. In LangGraph, threads and Store items are only
protected per user if the app adds its own authorization handlers, so a `LEAK`
here normally means the app is missing them, not that the framework is broken.

We call the failure an **agent memory spill**: one user of an agent app can read
memory the app stored for another user, through the server's ordinary read
paths, because a per-user access check is missing or wrong.

## 1. Try the demo (no setup)

```bash
pip install stranger-test
stranger-test confirm agent-memory --demo
```

This starts two small practice servers on your own machine, one leaky and one
safe, and runs the test against both. You should see `LEAK` for the first, `OK`
for the second, and `VERDICT: the test WORKS`.

## 2. Run it against your own app with two tokens

You need:

- a running LangGraph server that you own, on localhost (for example
  `langgraph dev`, which listens on `http://127.0.0.1:2024` by default);
- bearer tokens for two different test users.

That is all. You do not have to tell the test anything about your agent:

```bash
stranger-test confirm agent-memory http://127.0.0.1:2024 --token-a <A's token> --token-b <B's token>
```

Give the server's base URL, not a path under it.

In this mode the test runs the paths it can drive through the server's HTTP API
alone:

| Path | What B tries |
|---|---|
| `thread_get` | read A's thread by its id |
| `thread_search` | list threads and find A's |
| `store_get` | read A's Store item by namespace and key |
| `store_search_namespace` | search A's Store namespace |
| `store_search_all` | search the whole Store with no namespace |

These are reported `NOT_RUN`, because they need more input from you (section 4):
`thread_state`, `thread_history`, `agent_recall`, `store_search_own_prefix`, the
awkward-id cases (`store_edge_...`) and the four write paths. The last line of
the output names the flags that would turn them on.

If your app limits each user to their own part of the Store, also pass a
namespace user A is allowed to write to, with dots between the parts:

```bash
stranger-test confirm agent-memory http://127.0.0.1:2024 --token-a <A's token> --token-b <B's token> \
  --namespace-a alice.notes
```

Without it the test writes to a throwaway namespace. A well-scoped app refuses
that, and the Store paths then show `NOT_EXERCISED` instead of `OK`.

## 3. No auth in your dev app yet? Add two test users

**This snippet is for local testing only.** The tokens are fixed strings in the
source. Never deploy it.

Save this as `auth.py` next to your graph:

```python
"""Test-user auth for LOCAL TESTING ONLY: two fixed tokens, two users."""
from langgraph_sdk import Auth

TOKENS = {"tok-alice": "alice", "tok-bob": "bob"}

auth = Auth()


@auth.authenticate
async def authenticate(authorization: str | None) -> Auth.types.MinimalUserDict:
    """Who is calling? Unknown or missing tokens are refused."""
    token = (authorization or "").removeprefix("Bearer ").strip()
    user = TOKENS.get(token)
    if user is None:
        raise Auth.exceptions.HTTPException(status_code=401, detail="unknown token")
    return {"identity": user}


@auth.on
async def owner_only(ctx: Auth.types.AuthContext, value: dict):
    """Threads and runs: stamp the owner on create, filter by owner on read."""
    owner = {"owner": ctx.user.identity}
    value.setdefault("metadata", {}).update(owner)
    return owner


@auth.on.store()
async def own_namespace_only(ctx: Auth.types.AuthContext, value: dict):
    """Store: a caller may only touch namespaces that start with their own id."""
    namespace = tuple(value.get("namespace") or ())
    if not namespace or namespace[0] != ctx.user.identity:
        raise Auth.exceptions.HTTPException(status_code=403, detail="not your namespace")
```

Then point `langgraph.json` at it by adding this line:

```json
"auth": {"path": "./auth.py:auth"}
```

Restart the server and run:

```bash
stranger-test confirm agent-memory http://127.0.0.1:2024 --token-a tok-alice --token-b tok-bob \
  --namespace-a alice.notes
```

The snippet has two parts, and they do different jobs. `authenticate` only
decides who the caller is. The `@auth.on` and `@auth.on.store()` handlers are
what keep one user out of another user's data. To see the difference, delete
those two handlers and run the test again: the grade changes from `OK` to
`LEAK`. An app that authenticates callers but has no such handlers is the most
common way to get a `LEAK`.

Note that the Store handler only checks the HTTP API. Inside your graph, your
own code chooses the namespace, so make sure it includes the user there too.

## 4. Optional: deeper paths

- `--namespace-a alice.notes` is a Store namespace A may write to (see
  section 2).
- `--assistant`, `--save-input` and `--recall-input` together test through the
  agent itself. `--assistant` is the graph id from your `langgraph.json`.
  `--save-input` is a JSON run input that makes your agent save something; the
  test replaces `{marker}` in it with its own unique marker. `--recall-input` is
  a JSON run input that makes your agent recall it, and must not contain
  `{marker}`. This turns on `thread_state`, `thread_history` and `agent_recall`.
- `--whoami-field` names a field in your agent's run output that carries the
  caller's identity, if your app has one. The test uses it to make sure the two
  tokens really are two different users.

For the sample app in `integration/langgraph/app/` the full command is:

```bash
stranger-test confirm agent-memory http://127.0.0.1:2024 --token-a tok-alice --token-b tok-bob \
  --namespace-a alice.notes \
  --assistant memory \
  --save-input '{"action": "save", "key": "st-probe", "value": "{marker}"}' \
  --recall-input '{"action": "recall", "key": "st-probe"}' \
  --whoami-field whoami
```

A namespace option is labels joined by dots (`alice.notes`). If a label itself
contains a dot, write the namespace as a JSON list instead:
`--namespace-a '["acme.alice", "notes"]'`.

### Awkward-id pairs (`--edge-identity`)

Code that scopes data per user often compares ids loosely: as text instead of
part by part, without regard to case, or inside a SQL `LIKE`. Two users whose
ids are *almost* the same can then reach each other's data even though the
app's own checks are correct. To test this you provision an extra test user
whose id is an awkward relative of A's, and tell the test about it:

```bash
--edge-identity KIND=TOKEN@NAMESPACE      # repeatable
```

`TOKEN` is that user's bearer token and `NAMESPACE` is that user's own Store
namespace: one label taken exactly as written (it is not split on dots), or a
JSON list of labels. The extra user then searches and reads **its own**
namespace, and must not get A's marker.

| `KIND` | Path in the report | The extra user's id, for A = `alice` with `--namespace-a alice.notes` |
|---|---|---|
| `prefix` | `store_search_own_prefix` | the beginning of A's id: `ali` |
| `dot` | `store_edge_dot` | meets A's namespace at a `.`: `alice.notes`, `alice.no` (or A is `acme.alice` and the extra user is `acme`) |
| `separator` | `store_edge_separator` | the same with `/`, `:` or `|`: `alice:notes` (or A is `team:alice` and the extra user is `team`) |
| `wildcard` | `store_edge_wildcard` | holds `%`, `_` or `*`: `al_ce`, `al%`, `al*` |
| `case` | `store_edge_case` | differs only in letter case: `Alice` |
| `whitespace` | `store_edge_whitespace` | differs only in surrounding whitespace: `"alice "` |

For example:

```bash
stranger-test confirm agent-memory http://127.0.0.1:2024 --token-a tok-alice --token-b tok-bob \
  --namespace-a alice.notes \
  --edge-identity prefix=tok-ali@ali \
  --edge-identity case=tok-case@Alice \
  --edge-identity wildcard=tok-wild-underscore@al_ce
```

Rules the test keeps:

- It never makes up an identity and never tries to get around authentication.
  It uses only the tokens you give it, through the same documented API calls as
  every other path. You can give several identities of one kind; they share one
  line in the report.
- A kind you gave no identity for is `NOT_RUN`. So is an identity whose
  namespace does not have the relationship its kind names.
- Each extra user has its own positive control: it must be able to store an
  item in its own namespace and read it back. If it cannot, for example because
  the server refuses ids of that shape, the case is `NOT_EXERCISED`, not `OK`.
  (A current LangGraph server refuses a Store label that contains a dot, so the
  `dot` case comes back `NOT_EXERCISED` there: such a user cannot use the Store
  at all, and nothing was shown either way.)
- The report names an extra user only by its kind and a token fingerprint. Its
  id is never printed.

`--namespace-b` still works as before and is the `prefix` case run with B's own
token: it does something when B's id is the beginning of A's id, such as `ali`
and `alice` (`--namespace-a alice.notes --namespace-b ali`).

The `prefix` path catches a store that compares
namespaces as plain text rather than part by part, so that B's search of `ali`
also returns items under `alice`. This is the shape of the store
namespace-boundary bugs that were fixed in `langgraph-checkpoint-sqlite` and
`langgraph-checkpoint-postgres` 3.1.1 to 3.1.3 (CVE-2026-71433 and
CVE-2026-115883); they were found by other researchers and are fixed and
public.

### Write paths (`--write-paths`)

The read paths ask whether B can see A's data. These ask whether B can change
it, by naming it directly:

| Path | What B tries |
|---|---|
| `thread_update` | update the metadata of A's thread, by its id |
| `store_put_overwrite` | put an item at A's namespace and key |
| `thread_delete` | delete A's thread, by its id |
| `store_delete` | delete A's item, by namespace and key |

**They are off by default**, because they send real update and delete calls to
your server. Without `--write-paths` they are listed as `NOT_RUN` and no such
call is made. With it:

- Every attempt aims at a fresh thread or item that this run created for that
  one attempt. Nothing else is named. The two deletes run last.
- First A does the same kind of write to an object of her own. If that does not
  work, the path is `NOT_EXERCISED`.
- After B's attempt, A reads her object again. That re-read decides the result:
  unchanged and B refused is `OK`; changed or gone is `LEAK` (the note says
  "write crossed identities"); B's call answered with success but A's data
  unchanged is `OBSERVATION`.
- No write is attempted against a server that does not authenticate callers.

The demo (`--demo`) runs with the write paths on. Use a development server: on
a server that fails this check, the throwaway objects really are changed or
deleted.

### Owner-field paths (also `--write-paths`)

The read paths find a missing or mis-scoped check. These two find a different
failure: a handler that trusts an owner value in the request body instead of
the authenticated caller. If `--namespace-a alice` is given:

| Path | What B tries |
|---|---|
| `owner_in_body_thread_create` | `POST /threads` with `metadata.owner = "alice"` and A then reads the thread as hers |
| `owner_in_body_store_put` | `PUT /store/items` naming A's namespace (the first label is `"alice"`) and A then reads the item |

They are also gated by `--write-paths`, because each sends a create or a
store write. They are listed as `NOT_RUN` without it.

With `--write-paths`:

- First A does the same action with no claim: she creates a thread and writes
  her own item and reads both back. If that control does not hold, the path is
  `NOT_EXERCISED`.
- Then B sends the call with A's id in the body or namespace. The oracle is A:
  if she reads back what B's call made, the path is a `LEAK`. If the server
  refused B's call, `OK`. If the call was accepted but A does not see it,
  `OBSERVATION`.

If you do not give `--namespace-a`, both paths are `NOT_RUN` with a note
saying so.

## 5. Reading the result

The first line is the overall grade:

| Grade | Meaning | Exit code |
|---|---|---|
| `OK` | B could not read A's memory on any path that was exercised. | 0 |
| `LEAK` | B read A's marker on at least one path. | 1 |
| `INCONCLUSIVE` | Nothing could be tested: the server was unreachable, A could not create a thread, or A could not read her own marker anywhere. | 2 |
| `OBSERVATION` | Worth knowing, but not a cross-user leak: the server accepts callers with no token or a made-up token, both tokens are the same user, or B can see that A's namespace exists but not what is in it. | 2 |

Exit code 3 means a usage error or a refused target; no test was run.

Then one line per path:

| Outcome | Meaning |
|---|---|
| `LEAK` | B (or an extra identity) got A's marker this way, or B's write changed A's data. |
| `OK` | The positive control held and the attempt failed: A could read her own marker this way and B could not; or the extra identity could use its own namespace and did not get A's item; or A could do the write herself, B was refused and A's data is unchanged. |
| `OBSERVATION` | Write paths only: the server answered B's write with success, but A's data did not change. |
| `NOT_EXERCISED` | A positive control did not hold, so the path proves nothing. It never counts as `OK`. |
| `NOT_RUN` | The path was skipped because it needs an option you did not give. |

An `OK` grade only covers the paths marked `OK`. Check how many there were.

What `OK` does and does not mean for the newer paths:

- An `OK` awkward-id case means that *this* extra user, with *this* id, did not
  get A's item by searching or reading its own namespace. It says nothing about
  other id shapes, and nothing about a kind that was `NOT_RUN` or
  `NOT_EXERCISED`.
- An `OK` write path means B's call was refused and A's object was still intact
  when A read it back. It covers thread metadata and Store items addressed by
  id. It does not cover other write routes (runs on A's thread, state updates,
  bulk operations).

Add `--json` for the full report. Tokens and markers appear only as short
`sha256:` fingerprints, never in clear.

## 6. Limits

- The test covers only what it can drive over the server's HTTP API. It does
  not read your code, and it cannot see data paths that never go through that
  API.
- There is no semantic-search leak test yet.
- Only test servers you run or are authorized to test. Anything that is not on
  localhost is refused unless you pass `--allow-nonloopback`.
- The awkward-id cases only cover the Store, and only the id shapes you supply
  test users for.
- The test creates a few threads and Store items tagged `st-probe-...` and does
  not delete them (each extra identity adds one item in its own namespace;
  `--write-paths` adds a few more threads and items). Use a development server.
