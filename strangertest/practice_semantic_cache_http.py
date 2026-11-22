"""LOCAL practice semantic cache for the cross-user cache-leak probe.

A standard-library stand-in for a semantic LLM/response cache: it stores
``query -> response`` and answers a later query from cache when a stored query
is similar enough. The point is to exercise
:mod:`strangertest.semantic_cache` against a cache whose cross-user behaviour we
control; it is NOT a real embedding cache (similarity is a stdlib token-overlap
cosine, enough to make a paraphrase a near-match).

HTTP, two shapes over one set of modes:

    GET  /ok
    POST /store   {"query": q, "response": r}
    POST /query   {"query": q, "threshold": t?}   -> {hit, response, similarity, whoami}
    POST /v1/chat/completions  {"model": m, "messages": [...], "user": u?}
    POST /v1/responses         {"model": m, "input": q, "user": u?}
    POST /v1/messages          {"model": m, "max_tokens": n, "messages": [...]}

The three model routes (OpenAI chat-completions, OpenAI Responses, Anthropic
Messages) are a stand-in LLM gateway with one response cache behind them.
There is no store call: a miss "generates" an answer (it echoes the question
back, with a fresh response ``id`` per generation) and caches it; a later
similar question, in scope, gets the cached answer back unchanged, same ``id``,
on whichever route it is asked. ``"stream": true`` gets the answer as
server-sent events in the route's own event format.

Who the caller is (``auth``; a real cache would do the same from its own keys):

* ``header`` (default) -- the ``x-identity`` header (name configurable).
* ``token``  -- ``Authorization: Bearer <token>`` (header name configurable),
  looked up in a fixed table of practice tokens (``tok-alice``, ``tok-ali``,
  ``tok-bob``, and one per awkward id: ``tok-dot``, ``tok-sep``, ``tok-wild``,
  ``tok-case``, ``tok-space``). Unknown or missing tokens get 401.
* ``user``   -- the ``user`` field of a model-route body (``metadata.user_id``
  on the Messages route), taken as it is, spaces included; a body without it
  gets 400. With ``api_key`` set, every request must also carry that key.

Modes (how the cache scopes a lookup):

* ``leaky``    -- the identity never enters the lookup: any caller matches any
  stored entry. Caller B gets caller A's cached answer (the shape found in a
  real open cache in 2026). whoami is still per-identity, so the leak is
  provably cross-user.
* ``safe``     -- a lookup only matches entries stored by the same identity.
* ``prefixbug``-- like safe, but identity scoping is a STRING prefix match, so a
  caller whose id is a prefix of another's (``ali`` vs ``alice``) matches that
  other's entries.
* ``dotbug``   -- like safe, but only the part of an id before its first ``.``
  is compared (``alice`` and ``alice.st`` are one scope).
* ``separatorbug`` -- the cache key is ``id + ":" + query`` and is split again
  at the FIRST ``:``, so an id that contains ``:`` lands in another id's scope
  (``alice:st`` + ``q`` reads as ``alice`` + ``st:q``).
* ``wildcardbug`` -- the caller's id is used as a pattern: ``%`` and ``*`` match
  any run of characters, ``_`` any one (``alic%`` matches ``alice``).
* ``casebug``  -- ids are compared without regard to letter case.
* ``whitespacebug`` -- ids are compared after trimming spaces.
* ``routebug`` -- safe on the chat-completions route (and store/query), but the
  other model routes never apply the caller's identity to the lookup.
* ``broken``   -- like safe, but ``/query`` never returns a hit, even to the
  owner, so the probe's positive control fails -> INCONCLUSIVE, never OK.
* ``open``     -- no identity at all: every caller is ``anonymous`` (one
  principal), so a cross-caller hit is not a cross-user leak -> OBSERVATION.
* ``collapse`` -- leaky matching, but whoami reports one shared principal for
  all callers: a cross-caller hit is again one principal -> OBSERVATION.

In the chat shape ``broken`` never serves from cache, so a repeat is a fresh
generation with a new ``id``; and nothing reports who the caller is, so
``collapse`` behaves like ``leaky`` there.

NEVER expose this on a network. It stores unauthenticated data by design.

    STRANGERTEST_MODE=leaky STRANGERTEST_PORT=4660 python3 -m strangertest.practice_semantic_cache_http

Other environment variables: ``STRANGERTEST_AUTH`` (header | token | user),
``STRANGERTEST_IDENTITY_HEADER``, ``STRANGERTEST_TOKEN_HEADER``,
``STRANGERTEST_API_KEY``, ``STRANGERTEST_HIT_HEADER`` (send this header with
HIT / MISS on chat responses), ``STRANGERTEST_FRESH_ID_ON_HIT=1`` (a cached chat
answer gets a new ``id``, as some gateways do), ``STRANGERTEST_ROUTES`` (the
model routes to serve, e.g. ``chat,responses``; default all three),
``STRANGERTEST_NO_STREAMING=1`` (ignore ``"stream": true``),
``STRANGERTEST_PER_ROUTE_CACHE=1`` (an entry is only served on the route that
made it).
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple

MODES = ("leaky", "safe", "prefixbug", "broken", "open", "collapse",
         "dotbug", "separatorbug", "wildcardbug", "casebug", "whitespacebug", "routebug")
AUTHS = ("header", "token", "user")
CHAT_PATHS = ("/v1/chat/completions", "/chat/completions")
ROUTES = ("chat", "responses", "messages")
ROUTE_PATHS = {"/v1/chat/completions": "chat", "/chat/completions": "chat",
               "/v1/responses": "responses", "/responses": "responses",
               "/v1/messages": "messages", "/messages": "messages"}
_ID_PREFIX = {"chat": "chatcmpl-", "responses": "resp_", "messages": "msg_"}
# Practice credentials -> identity, for auth="token". Not secrets. The last five
# are ids that sloppy cache-key code confuses with "alice".
PRACTICE_TOKENS = {"tok-alice": "alice", "tok-ali": "ali", "tok-bob": "bob",
                   "tok-dot": "alice.st", "tok-sep": "alice:st", "tok-wild": "alic%",
                   "tok-case": "Alice", "tok-space": "alice "}
FORBIDDEN_PORTS = {4000, 4444, 8790}
_STOP = {"the", "a", "an", "of", "for", "to", "is", "what", "how", "does", "do",
         "the", "in", "on", "by", "and", "or", "can", "much"}

__all__ = ["MODES", "AUTHS", "ROUTES", "PRACTICE_TOKENS", "SemanticCacheState", "build_server",
           "main", "similarity"]


def _tokens(text: str) -> List[str]:
    return [w for w in re.findall(r"[a-z0-9]+", (text or "").lower()) if w not in _STOP]


def similarity(a: str, b: str) -> float:
    """Token-frequency cosine of two strings (1.0 identical, 0.0 disjoint)."""
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return 1.0 if ta == tb else 0.0
    va: Dict[str, int] = {}
    vb: Dict[str, int] = {}
    for w in ta:
        va[w] = va.get(w, 0) + 1
    for w in tb:
        vb[w] = vb.get(w, 0) + 1
    if va == vb:
        return 1.0
    dot = sum(va[w] * vb.get(w, 0) for w in va)
    na = math.sqrt(sum(v * v for v in va.values()))
    nb = math.sqrt(sum(v * v for v in vb.values()))
    return min(1.0, dot / (na * nb)) if na and nb else 0.0


class SemanticCacheState:
    def __init__(self, mode: str, default_threshold: float = 0.6, *, auth: str = "header",
                 identity_header: str = "x-identity", token_header: str = "authorization",
                 tokens: Optional[Dict[str, str]] = None, api_key: Optional[str] = None,
                 hit_header: Optional[str] = None, fresh_id_on_hit: bool = False,
                 routes: Optional[Any] = None, streaming: bool = True,
                 per_route_cache: bool = False):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}, got {mode!r}")
        if auth not in AUTHS:
            raise ValueError(f"auth must be one of {AUTHS}, got {auth!r}")
        self.mode = mode
        self.default_threshold = default_threshold
        self.auth = auth
        self.identity_header = identity_header
        self.token_header = token_header
        self.tokens = dict(PRACTICE_TOKENS if tokens is None else tokens)
        self.api_key = api_key
        self.hit_header = hit_header
        self.fresh_id_on_hit = fresh_id_on_hit
        self.routes = tuple(ROUTES if routes is None else routes)
        if any(r not in ROUTES for r in self.routes):
            raise ValueError(f"routes must be among {ROUTES}, got {routes!r}")
        self.streaming = streaming
        self.per_route_cache = per_route_cache
        # (scope, query, response)
        self.entries: List[Tuple[str, str, str]] = []
        # (scope, model, prompt, record, route); record = {id, created, text}
        self.chat_entries: List[Tuple[str, str, str, Dict[str, Any], str]] = []
        self._lock = threading.Lock()

    def _credential(self, headers) -> str:
        value = (headers.get(self.token_header) or "").strip()
        if self.token_header.lower() == "authorization":
            return value[len("bearer "):].strip() if value.lower().startswith("bearer ") else ""
        return value

    def identify(self, headers, body: Optional[Dict[str, Any]] = None) -> Tuple[Optional[str], int, str]:
        """(identity, status, detail). identity is None when the caller is refused."""
        if self.mode == "open":
            return "anonymous", 200, ""
        if self.api_key is not None and self._credential(headers) != self.api_key:
            return None, 401, "api key required"
        if self.auth == "token":
            ident = self.tokens.get(self._credential(headers))
            return (ident, 200, "") if ident else (None, 401, "unknown or missing token")
        if self.auth == "user":
            user = (body or {}).get("user")
            if user is None and isinstance((body or {}).get("metadata"), dict):
                user = body["metadata"].get("user_id")
            if isinstance(user, str) and user.strip():
                return user, 200, ""
            return None, 400, "the user field is required"
        ident = (headers.get(self.identity_header) or "").strip()
        return (ident, 200, "") if ident else (None, 401, f"{self.identity_header} required")

    def whoami(self, identity: str) -> str:
        if self.mode == "open":
            return "anonymous"
        if self.mode == "collapse":
            return "shared-principal"
        return "sha256:" + hashlib.sha256(identity.encode()).hexdigest()[:12]

    def _in_scope(self, caller: str, stored_identity: str, route: Optional[str] = None) -> bool:
        if self.mode in ("leaky", "open", "collapse"):
            return True
        if self.mode == "routebug" and route not in (None, "chat"):
            return True     # identity is only applied on the chat-completions route
        if self.mode == "prefixbug":
            # string-prefix scoping: the caller matches any id it is a prefix of
            return stored_identity == caller or stored_identity.startswith(caller)
        if self.mode == "dotbug":
            return stored_identity.split(".")[0] == caller.split(".")[0]
        if self.mode == "wildcardbug":
            pattern = "".join(".*" if c in "%*" else "." if c == "_" else re.escape(c)
                              for c in caller)
            return stored_identity == caller or re.fullmatch(pattern, stored_identity) is not None
        if self.mode == "casebug":
            return stored_identity.lower() == caller.lower()
        if self.mode == "whitespacebug":
            return stored_identity.strip() == caller.strip()
        return stored_identity == caller  # safe, broken, separatorbug, routebug

    def _key(self, identity: str, query: str) -> Tuple[str, str]:
        """(scope, query) as the cache keeps them. ``separatorbug`` joins the two
        with ":" and splits the joined key again at the first ":"."""
        if self.mode == "separatorbug":
            scope, _, rest = f"{identity}:{query}".partition(":")
            return scope, rest
        return identity, query

    def store(self, identity: str, query: str, response: str) -> None:
        scope, query = self._key(identity, query)
        with self._lock:
            self.entries.append((scope, query, response))

    def query(self, identity: str, query: str, threshold: Optional[float]) -> Dict[str, Any]:
        t = self.default_threshold if threshold is None else threshold
        if self.mode == "broken":
            return {"hit": False, "response": None, "similarity": None,
                    "whoami": self.whoami(identity)}
        scope, query = self._key(identity, query)
        best = None
        best_sim = 0.0
        with self._lock:
            for stored_id, q, r in self.entries:
                if not self._in_scope(scope, stored_id):
                    continue
                sim = similarity(query, q)
                if sim >= t and sim >= best_sim:
                    best, best_sim = r, sim
        return {"hit": best is not None, "response": best,
                "similarity": best_sim if best is not None else None,
                "whoami": self.whoami(identity)}


    # -- model routes: chat-completions, responses, messages --
    def lookup(self, identity: str, model: str, prompt: str,
               route: str = "chat") -> Tuple[Dict[str, Any], bool]:
        """(record, was_cache_hit); record = {id, created, text}. A miss generates
        an answer (the stand-in "LLM" echoes the question) and caches it."""
        scope, prompt = self._key(identity, prompt)
        best, best_sim = None, 0.0
        with self._lock:
            if self.mode != "broken":
                for stored_id, stored_model, stored_prompt, record, made_on in self.chat_entries:
                    if stored_model != model or not self._in_scope(scope, stored_id, route):
                        continue
                    if self.per_route_cache and made_on != route:
                        continue
                    sim = similarity(prompt, stored_prompt)
                    if sim >= self.default_threshold and sim >= best_sim:
                        best, best_sim = record, sim
            if best is not None:
                hit = dict(best)
                if self.fresh_id_on_hit:
                    hit["id"] = _ID_PREFIX[route] + secrets.token_hex(12)
                return hit, True
            record = {"id": _ID_PREFIX[route] + secrets.token_hex(12),
                      "created": int(time.time()),
                      "text": f"[practice answer {secrets.token_hex(4)}] You asked: {prompt}"}
            self.chat_entries.append((scope, model, prompt, record, route))
            return record, False

    def chat(self, identity: str, model: str, prompt: str) -> Tuple[Dict[str, Any], bool]:
        """(chat completion, was_cache_hit) on the chat-completions route."""
        record, hit = self.lookup(identity, model, prompt, "chat")
        return render(record, model, "chat"), hit


def render(record: Dict[str, Any], model: str, route: str) -> Dict[str, Any]:
    """The answer body in the route's own shape."""
    rid, text = record["id"], record["text"]
    if route == "responses":
        return {"id": rid, "object": "response", "created_at": record["created"],
                "model": model, "status": "completed",
                "output": [{"type": "message", "id": "msg_" + rid[-12:], "role": "assistant",
                            "status": "completed",
                            "content": [{"type": "output_text", "text": text,
                                         "annotations": []}]}],
                "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}}
    if route == "messages":
        return {"id": rid, "type": "message", "role": "assistant", "model": model,
                "content": [{"type": "text", "text": text}],
                "stop_reason": "end_turn", "stop_sequence": None,
                "usage": {"input_tokens": 0, "output_tokens": 0}}
    return {"id": rid, "object": "chat.completion", "created": record["created"],
            "model": model,
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": text}}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}


def stream_events(record: Dict[str, Any], model: str, route: str) -> List[Tuple[Optional[str], Any]]:
    """The same answer as (event name, data) pairs, the text cut in three pieces."""
    rid, text = record["id"], record["text"]
    cut = max(1, len(text) // 3)
    pieces = [text[:cut], text[cut:2 * cut], text[2 * cut:]]
    if route == "responses":
        events: List[Tuple[Optional[str], Any]] = [("response.created", {
            "type": "response.created", "response": {"id": rid, "status": "in_progress"}})]
        events += [("response.output_text.delta", {"type": "response.output_text.delta",
                                                   "delta": p}) for p in pieces if p]
        return events + [("response.completed", {
            "type": "response.completed", "response": {"id": rid, "status": "completed"}})]
    if route == "messages":
        events = [("message_start", {"type": "message_start", "message": {
                      "id": rid, "type": "message", "role": "assistant", "model": model,
                      "content": []}}),
                  ("content_block_start", {"type": "content_block_start", "index": 0,
                                           "content_block": {"type": "text", "text": ""}})]
        events += [("content_block_delta", {"type": "content_block_delta", "index": 0,
                                            "delta": {"type": "text_delta", "text": p}})
                   for p in pieces if p]
        return events + [("content_block_stop", {"type": "content_block_stop", "index": 0}),
                         ("message_stop", {"type": "message_stop"})]

    def chunk(delta: Dict[str, Any], finish: Optional[str]) -> Dict[str, Any]:
        return {"id": rid, "object": "chat.completion.chunk", "created": record["created"],
                "model": model, "choices": [{"index": 0, "delta": delta,
                                             "finish_reason": finish}]}
    events = [(None, chunk({"role": "assistant", "content": ""}, None))]
    events += [(None, chunk({"content": p}, None)) for p in pieces if p]
    return events + [(None, chunk({}, "stop")), (None, "[DONE]")]


def _text_of(content: Any) -> str:
    if isinstance(content, list):       # content parts: [{"type": ..., "text": ...}]
        return " ".join(str(p.get("text", "")) for p in content if isinstance(p, dict))
    return "" if content is None else str(content)


def _prompt_of(body: Dict[str, Any], route: str = "chat") -> str:
    messages = body.get("input") if route == "responses" else body.get("messages")
    if isinstance(messages, str):
        return messages
    if not isinstance(messages, list):
        return ""
    return "\n".join(_text_of(m.get("content")) for m in messages
                     if isinstance(m, dict) and m.get("role") == "user")


def _make_handler(state: SemanticCacheState):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def _send(self, status: int, payload: Any = None,
                  headers: Optional[Dict[str, str]] = None) -> None:
            body = b"" if payload is None else json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def _send_events(self, events, headers: Optional[Dict[str, str]] = None) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.close_connection = True
            for name, data in events:
                line = data if isinstance(data, str) else json.dumps(data)
                head = f"event: {name}\n" if name else ""
                self.wfile.write(f"{head}data: {line}\n\n".encode("utf-8"))
                self.wfile.flush()

        def _body(self) -> Dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(length) if length else b""
            if not raw:
                return {}
            return json.loads(raw)

        def do_GET(self):
            if self.path.rstrip("/") == "/ok":
                return self._send(200, {"ok": True})
            self._send(404, {"detail": "not found"})

        def do_POST(self):
            path = self.path.rstrip("/")
            try:
                body = self._body()
            except ValueError:
                body = None
            identity, status, detail = state.identify(
                self.headers, body if isinstance(body, dict) else None)
            if identity is None:
                return self._send(status, {"detail": detail})
            if not isinstance(body, dict):
                return self._send(422, {"detail": "body is not a JSON object"})
            if path == "/store":
                state.store(identity, str(body.get("query")), str(body.get("response")))
                return self._send(200, {"stored": True})
            if path == "/query":
                threshold = body.get("threshold")
                return self._send(200, state.query(identity, str(body.get("query")),
                                                   float(threshold) if threshold is not None else None))
            route = ROUTE_PATHS.get(path)
            if route in state.routes:
                model = str(body.get("model"))
                record, hit = state.lookup(identity, model, _prompt_of(body, route), route)
                extra = {state.hit_header: "HIT" if hit else "MISS"} if state.hit_header else None
                if body.get("stream") is True and state.streaming:
                    return self._send_events(stream_events(record, model, route), extra)
                return self._send(200, render(record, model, route), extra)
            self._send(404, {"detail": "not found"})

    return Handler


def build_server(mode: str, host: str = "127.0.0.1", port: int = 0, **options: Any) -> ThreadingHTTPServer:
    """``options`` go to :class:`SemanticCacheState` (auth, identity_header, token_header,
    tokens, api_key, hit_header, fresh_id_on_hit, routes, streaming, per_route_cache)."""
    server = ThreadingHTTPServer((host, port), _make_handler(SemanticCacheState(mode, **options)))
    server.daemon_threads = True
    return server


def main() -> None:
    env = os.environ
    mode = env.get("STRANGERTEST_MODE", "leaky")
    port = int(env.get("STRANGERTEST_PORT", "0"))
    if port in FORBIDDEN_PORTS:
        raise SystemExit(f"ERROR: refusing reserved port {port}")
    options: Dict[str, Any] = {"auth": env.get("STRANGERTEST_AUTH", "header")}
    for key, name in (("identity_header", "STRANGERTEST_IDENTITY_HEADER"),
                      ("token_header", "STRANGERTEST_TOKEN_HEADER"),
                      ("api_key", "STRANGERTEST_API_KEY"),
                      ("hit_header", "STRANGERTEST_HIT_HEADER")):
        if env.get(name):
            options[key] = env[name]
    if env.get("STRANGERTEST_FRESH_ID_ON_HIT") == "1":
        options["fresh_id_on_hit"] = True
    if env.get("STRANGERTEST_ROUTES"):
        options["routes"] = [r.strip() for r in env["STRANGERTEST_ROUTES"].split(",") if r.strip()]
    if env.get("STRANGERTEST_NO_STREAMING") == "1":
        options["streaming"] = False
    if env.get("STRANGERTEST_PER_ROUTE_CACHE") == "1":
        options["per_route_cache"] = True
    server = build_server(mode, port=port, **options)
    host, bound = server.server_address[0], server.server_address[1]
    print(f"practice-semantic-cache [{mode}, auth={options['auth']}] on http://{host}:{bound}",
          flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
