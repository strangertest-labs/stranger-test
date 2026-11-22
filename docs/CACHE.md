# Test your own response cache for cross-user leaks

## What the test checks

A response cache (often called a semantic cache) saves the answer to one
question and serves it again when a similar question comes in. That saves time
and model cost. It also creates a risk: if the cache does not check who is
asking, user B can ask a similar question and get the answer that was produced
for user A.

`confirm semantic-cache` acts as two users. User A puts an answer with a unique
marker into the cache. The test then checks whether user B can get that answer
back:

| Path | What happens |
|---|---|
| `exact` | B asks exactly the question A asked. |
| `reworded` | B asks the same thing in different words. |
| `prefix_sibling` | A third user, whose id is the beginning of A's id (`ali` and `alice`), asks A's question. This catches a cache that compares user ids as plain text. |

Before each path counts, A must be able to get her own answer back that way. If
she cannot, the path proves nothing and is not counted as clean.

Three optional additions, each with its own section below:

- **Awkward ids** (section 4): more cases like `prefix_sibling`, for ids that
  careless cache-key code mixes up (`edge_dot`, `edge_separator`,
  `edge_wildcard`, `edge_case`, `edge_whitespace`).
- **More than one route** (section 5, chat mode): the same checks on the
  OpenAI Responses and Anthropic Messages routes, and a `cross_route` path.
- **Streaming** (section 5, chat mode): the same checks with `"stream": true`.

The test works with two kinds of cache:

- **store mode** (the default): a cache with its own "store" and "query" calls.
- **chat mode**: an LLM gateway that caches chat completions. There is no store
  call. A asks a question through the gateway and the gateway caches the answer.

## 1. Try the demo (no setup)

```bash
pip install stranger-test
stranger-test confirm semantic-cache --demo
```

This starts small practice caches on your own machine and runs the test against
each one, in both modes. You should see `LEAK` for the leaky ones, `OK` for the
safe ones, `INCONCLUSIVE` for a gateway that never serves from its cache, and
`VERDICT: the test WORKS`. The later runs show the awkward-id cases (one
practice cache per key bug), three routes in one run, and streaming.

## 2. Store mode: a cache with store and query calls

The test sends two kinds of request to the base URL you give:

```
POST /store   {"query": "...", "response": "..."}
POST /query   {"query": "...", "threshold": 0.8}
```

If your cache uses other paths, pass `--store-path` and `--query-path`. The
answer to a query can have any shape: the test only looks for A's marker in it.
`--threshold` is optional and is sent with each query.

Then say how your cache tells users apart.

**A header with the user's or tenant's id.** By default the two values are sent
in an `x-identity` header. To use another header:

```bash
stranger-test confirm semantic-cache http://127.0.0.1:8081 \
  --token-a tenant-one --token-b tenant-two --identity-header x-tenant-id
```

**One token or API key per user.**

```bash
stranger-test confirm semantic-cache http://127.0.0.1:8081 \
  --token-a <A's token> --token-b <B's token> --identity-as bearer
```

This sends `Authorization: Bearer <token>`. If your cache reads the key from
another header, name it with `--token-header x-api-key`; the key is then sent
as it is, without `Bearer`.

**One shared key plus a tenant header.** Add `--api-key <key>`. It is sent with
every request in the token header, next to the identity header.

**The prefix-sibling path.** With header ids, the path runs by itself when B's
id is the beginning of A's id (`--token-a alice --token-b ali`). With tokens,
the test cannot see the ids behind them, so give a third user whose id at the
cache is the beginning of A's id:

```bash
  --token-sibling <the third user's token>
```

Without it the path is reported `NOT_RUN`. It is never counted as clean.
`--token-sibling` is the same as `--edge-identity prefix=<token>` (section 4).

## 3. Chat mode: an LLM gateway with a response cache

```bash
stranger-test confirm semantic-cache http://127.0.0.1:4000 --cache-mode chat \
  --token-a <A's key> --token-b <B's key> --model my-model
```

The test sends OpenAI-style requests to `POST /v1/chat/completions` (change the
path with `--chat-path`). In chat mode `--token-a` and `--token-b` are sent as
bearer tokens unless you say otherwise. All the identity options from section 2
work here too.

Some gateways tell users apart by the `user` field in the request body. Set it
with `--user-a` and `--user-b` (and `--user-sibling` for the third user). You
can combine it with one shared key:

```bash
stranger-test confirm semantic-cache http://127.0.0.1:4000 --cache-mode chat \
  --api-key <the shared key> --user-a alice --user-b bob --model my-model
```

What the test does, in order:

1. It sends one request with no identity, to see whether the gateway requires
   one.
2. A asks an unrelated question, then the test question. The test question ends
   with a random marker, so it cannot already be in the cache.
3. A asks the test question again. This is the positive control: it must come
   back from the cache.
4. A asks the reworded question. If that also comes from the cache, B asks the
   reworded question.
5. B asks the exact question, and so does the third user if you gave one.

That is about eight short requests. Point the gateway at a mock or a cheap
model. Awkward-id cases add three requests each, and every extra route repeats
the whole list (sections 4 and 5).

### How the test knows an answer came from the cache

It tries two things, in this order.

**1. A cache-hit header.** Some gateways add a response header on a cache hit.
Name yours with `--cache-hit-header`. Without the option the test tries
`x-litellm-cache-key`, `x-cache`, `x-cache-status`, `x-cache-hit` and
`cf-cache-status`. The header is only used if its value changed between A's
first request (which cannot be a hit) and A's repeat (which should be one). A
header that looks the same both times says nothing and is ignored.

**2. The response body.** Each chat completion has an `id`. If two separate
answers have different ids, and A's repeat came back with the same id as her
first answer, then the id shows a cache hit: B getting an answer with A's id
means B got A's cached answer. For the reworded question there is a second
sign: that question does not contain the marker, so if the marker is in B's
answer, the answer was produced for A.

The header only says that some cached answer was served. On a safe cache B's
second question can match B's own first one. So when the ids are usable and B's
answer has a different id than A's, a header hit is not counted as a leak. When
there are no usable ids and the test cannot rule this out, the path is reported
`NOT_EXERCISED`.

If neither sign works, the test cannot recognise a cache hit at all and the
grade is `INCONCLUSIVE`.

### Your own questions

`--base-query` and `--reworded-query` replace the built-in pair. In chat mode
the marker is added to the end of the base question; write `{marker}` to put it
somewhere else. The reworded question gets no marker unless you write
`{marker}` in it. Putting the marker in both makes the two questions more alike,
which helps when your cache only matches very similar questions.

## 4. Awkward ids

Cache keys are often built by hand from the user's id and the question. Some
ids break such code. In each case below an extra user, whose id is related to
A's in an awkward way, asks A's exact question in its own scope. It must not
get A's answer.

| Case | Path | The extra user's id | The mistake it catches |
|---|---|---|---|
| `prefix` | `prefix_sibling` | `ali` next to `alice` | ids compared with "starts with" |
| `dot` | `edge_dot` | `acme` next to `acme.alice` | only part of a dotted id is used |
| `separator` | `edge_separator` | `alice:x` (also `/` and `\|`) | id and question joined with a separator, so `a:b` + `c` and `a` + `b:c` give one key |
| `wildcard` | `edge_wildcard` | `alic%` (also `_` and `*`) | the id used as a pattern in a `LIKE` or key scan |
| `case` | `edge_case` | `Alice` next to `alice` | ids compared without regard to case |
| `whitespace` | `edge_whitespace` | `alice` with a space before or after | ids trimmed in one place and not in another |

Each case has its own positive control. After asking A's question, the extra
user stores an answer of its own and reads it back (store mode), or repeats a
request of its own and must get a cache hit (chat mode). If that fails, the
case is `NOT_EXERCISED`, with the reason.

The test only ever uses identities you gave it or said it may use, through the
cache's normal calls. It does not forge credentials and does not go around
authentication.

**Ids in a header (store or chat mode).** If your cache takes any tenant id
you send, the test can make the related ids itself from A's id. Ask for that
with `--edge-cases`:

```bash
stranger-test confirm semantic-cache http://127.0.0.1:8081 \
  --token-a alice --token-b bob --identity-header x-tenant-id --edge-cases all
```

`--edge-cases` takes `all` or a list such as `prefix,dot,case`. Giving it says
that these header ids are free-form test tenants: the test will send ids like
`alic`, `alice.st`, `alice:st`, `alic%` and `ALICE`, and they will be left in
your cache as new tenants. Use a development cache. Without `--edge-cases`
nothing is made up and the test behaves as before.

For `separator` and `wildcard` three characters are tried; the note on the
path says which one leaked. In store mode the `separator` case also moves part
of the key between id and question (A stores `st:<question>`, the extra user
`alice:st` asks `<question>`), which is what a key of `id + ":" + question`
gets wrong.

A header cannot carry a space at the start or end of its value, so with header
ids `edge_whitespace` is `NOT_RUN`. Use a token or the `user` field for it.

**Tokens or API keys.** The test cannot see the id behind a key and never
makes a key up. Create the extra users yourself and pass one credential per
case:

```bash
stranger-test confirm semantic-cache http://127.0.0.1:4000 --cache-mode chat \
  --token-a <A's key> --token-b <B's key> \
  --edge-identity case=<key of user "Alice"> \
  --edge-identity dot=<key of user "alice.x">
```

`--edge-identity KIND=VALUE` can be repeated. The value is sent the same way
as `--token-a` (so with header ids it is a header id, and it wins over a
made-up one). Only the cases you gave are listed. A case you named with
`--edge-cases` but gave no credential for is `NOT_RUN`, never `OK`.

An `@` in the value starts a namespace, which this test ignores:
`case=<key>@notes` is the same as `case=<key>`. If the value itself contains
an `@`, end it with one more `@`.

**The `user` field (chat mode).** `--edge-user KIND=VALUE` sets the extra
user's `user` value, like `--user-sibling` does for the prefix case:

```bash
  --edge-user case=ALICE --edge-user "whitespace=alice "
```

Reports name a case by its kind only. The extra ids and credentials never
appear, not even the made-up ones.

## 5. More routes and streaming (chat mode)

A gateway can apply the caller's identity to its cache on one API route and
forget it on another. `--route` runs the whole sequence on each route you
name:

```bash
stranger-test confirm semantic-cache http://127.0.0.1:4000 --cache-mode chat \
  --token-a <A's key> --token-b <B's key> --model my-model \
  --route chat --route responses --route messages
```

| Route | Request | Default path |
|---|---|---|
| `chat` | OpenAI chat completions (`messages`) | `/v1/chat/completions` |
| `responses` | OpenAI Responses (`input`) | `/v1/responses` |
| `messages` | Anthropic Messages (`messages`, `max_tokens`) | `/v1/messages` |

Write `--route responses=/openai/v1/responses` for another path. `--chat-path`
still sets the path of the `chat` route. Only the routes you list are run. On
the `messages` route the `user` value goes in `metadata.user_id`, and an
`anthropic-version` header is added; if your gateway wants the key in
`x-api-key`, say `--token-header x-api-key`.

With `--route`, every path name gets the route after an `@`: `exact@chat`,
`reworded@responses`, `prefix_sibling@messages`, `edge_case@responses`. Each
route is graded on its own, with its own positive control and its own marker.
A route the server answers with 404, 405 or 501 is `NOT_RUN`.

One more path is added for every route after the first:
`cross_route@<route>`. A asks a new question on the first route you listed,
then B asks the same question on the other route. The positive control is A
asking it there herself: if her own answer does not come back across routes,
the path is `NOT_EXERCISED`.

Each route uses a different built-in question, so that an answer cached on one
route is not mistaken for a hit on the next. If you give your own
`--base-query`, the same question (with a new marker) is used on every route,
and a cache that matches loosely may serve one route from another's entry; the
report says so.

**Streaming.** Add `--stream` and every request is sent with `"stream": true`.
The test reads the server-sent events of the route's format, puts the text
back together and applies the same checks (hit header, response id, marker).

```bash
stranger-test confirm semantic-cache http://127.0.0.1:4000 --cache-mode chat \
  --token-a <A's key> --token-b <B's key> --model my-model --stream
```

Path names stay the same; the JSON report has `"stream": true` under
`controls`. If the server answers with plain JSON, the paths are `NOT_RUN`.
Run once with and once without `--stream` to cover both: many gateways cache
the two differently.

## 6. Reading the result

The first line is the overall grade:

| Grade | Meaning | Exit code |
|---|---|---|
| `OK` | B could not get A's cached answer on any path that was exercised. | 0 |
| `LEAK` | B got A's cached answer on at least one path. | 1 |
| `INCONCLUSIVE` | Nothing could be tested: the cache was unreachable, A could not store or get an answer, or A could not get her own answer back from the cache. | 2 |
| `OBSERVATION` | Worth knowing, but not a cross-user leak: the cache answers callers who give no identity, or it reports the same user for both identities. | 2 |

Exit code 3 means a usage error or a refused target; no test was run.

Then one line per path:

| Outcome | Meaning |
|---|---|
| `LEAK` | The other user got A's cached answer this way. |
| `OK` | A got her own answer back this way and the other user did not. |
| `NOT_EXERCISED` | A could not get her own answer back this way, the extra user of an awkward-id case could not get its own entry back, or a hit could not be tied to A's entry. It never counts as `OK`. |
| `NOT_RUN` | The path was skipped: it needs an option you did not give, the server does not serve the route, or it does not stream. |

An `OK` grade only covers the paths marked `OK`. Check how many there were.

What `OK` on an awkward-id case means: with that one extra id, asking that one
question, the extra user did not get A's answer, and the extra user could get
an entry of its own. It does not mean every id of that kind is handled
correctly, and it says nothing about ids your system would refuse to create.
`OK` on a route covers that route only, and only streamed or only unstreamed
requests, whichever you ran.

Add `--json` for the full report. Tokens, keys, ids, the marker and response
ids never appear in it. Identities and the marker are shown only as short
`sha256:` fingerprints. With `--route`, the per-route checks are under
`controls.routes`.

## 7. Limits

- In chat mode the gateway does not tell the test who each caller is. The test
  takes your word that the two identities are two different users. If both keys
  belong to one user or one team, and your cache is scoped per user or team on
  purpose, a `LEAK` here is your design and not a bug.
- If the two users differ only in the `user` field and the gateway also accepts
  requests without that field, the result is still graded, with a note. Whether
  the gateway is meant to separate users by that field is for you to decide.
- Header detection is a best effort. A header that is present on every answer,
  hit or not, is ignored. A gateway that gives a cached answer a new `id` and
  sends no header leaves only the marker sign, which covers the reworded path
  and needs a model that repeats the marker in its answer.
- If your model gives two separate answers the same `id`, or your gateway
  rewrites ids, the id sign is not used.
- The reworded path depends on your cache's similarity setting. If A's own
  reworded question does not hit, the path is `NOT_EXERCISED`. Try your own
  `--reworded-query`, closer to the base question.
- Run it against a cache without old test entries when you can. Entries left by
  an earlier run are similar to the new questions, and a cache with a loose
  similarity setting may serve them.
- The test leaves a few cached entries behind and does not delete them. Use a
  development cache. With `--edge-cases` and header ids it also leaves entries
  under the made-up tenant ids.
- An awkward-id case tries one to six ids, not every id of that kind. In chat
  mode the `separator` case does not move part of the key into the question;
  only store mode does that.
- All routes use the one `--model` you give. The Responses and Messages bodies
  are the plain text form only (no tools, no images).
- With `--stream` the server must answer with `text/event-stream`. A gateway
  that refuses `"stream": true` with an error is reported like any other
  failed request, not as `NOT_RUN`.
- It covers only what goes through the HTTP calls above. It does not read your
  code or your cache's configuration.
- Only test caches you run or are authorized to test. Anything that is not on
  localhost is refused unless you pass `--allow-nonloopback`.

## 8. The practice cache

The demo's stand-in is also a server you can start yourself, on localhost only:

```bash
STRANGERTEST_MODE=leaky STRANGERTEST_PORT=4660 STRANGERTEST_AUTH=token \
  python3 -m strangertest.practice_semantic_cache_http

stranger-test confirm semantic-cache http://127.0.0.1:4660 --cache-mode chat \
  --token-a tok-alice --token-b tok-bob --token-sibling tok-ali
```

`STRANGERTEST_MODE` is `leaky`, `safe`, `prefixbug`, `broken`, `open` or
`collapse`, or one of the key bugs from sections 4 and 5: `dotbug`,
`separatorbug`, `wildcardbug`, `casebug`, `whitespacebug`, and `routebug`
(identity applied on the chat-completions route only). `STRANGERTEST_AUTH` is
`header` (the default), `token` or `user`. The fixed practice tokens are
`tok-alice`, `tok-ali` and `tok-bob`, plus one per awkward id of `alice`:
`tok-dot`, `tok-sep`, `tok-wild`, `tok-case` and `tok-space`. So this shows
every case:

```bash
stranger-test confirm semantic-cache http://127.0.0.1:4660 --cache-mode chat \
  --token-a tok-alice --token-b tok-bob --route chat --route responses --route messages \
  --edge-identity prefix=tok-ali --edge-identity dot=tok-dot \
  --edge-identity separator=tok-sep --edge-identity wildcard=tok-wild \
  --edge-identity case=tok-case --edge-identity whitespace=tok-space --stream
```

The practice server serves all three routes from one cache and streams when
asked. `STRANGERTEST_ROUTES=chat,messages` serves only those routes,
`STRANGERTEST_NO_STREAMING=1` makes it ignore `"stream": true`, and
`STRANGERTEST_PER_ROUTE_CACHE=1` keeps each route's entries apart. Its "model"
just repeats the question back. It is for practice and must never be put on a
network.
