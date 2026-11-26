"""LOCAL practice server for the agent-memory isolation probe.

A standard-library stand-in for the part of an agent server's HTTP API that
holds per-user memory: threads (saved conversation state) and a key-value Store
(long-term memory). The endpoint shapes follow the LangGraph Server API closely
enough for :mod:`strangertest.agent_memory` to drive both this and a real
LangGraph server with the same code:

    GET  /ok
    POST /threads                         {"metadata": {...}}
    GET  /threads/{id}
    GET  /threads/{id}/state
    GET  /threads/{id}/history
    POST /threads/search                  {"limit": n}
    POST /threads/{id}/runs/wait          {"assistant_id": ..., "input": {...}}
    POST /threads/{id}/runs/stream        the same, plus "stream_mode": [...]; answers
                                          with server-sent events, one group per step
    PUT  /store/items                     {"namespace": [...], "key": k, "value": {...}}
    GET  /store/items?namespace=a.b&key=k
    POST /store/items/search              {"namespace_prefix": [...]}
    POST /store/namespaces                {"prefix": [...]}
    PATCH  /threads/{id}                  {"metadata": {...}}
    DELETE /threads/{id}
    DELETE /store/items                   {"namespace": [...], "key": k}

The bundled "agents" all take
``{"action": "save", "key": k, "value": v}`` or ``{"action": "recall", "key": k}``:

* ``memory`` -- one step; the recalled value is in the answer.
* ``retrieval`` -- two steps: ``retrieve`` writes what it fetched to ``docs``,
  ``answer`` clears ``docs``. The final state never holds the fetched text.
* ``retrieval_hidden`` -- two steps; ``docs`` stays in the thread's state, but
  the run's answer and its ``updates`` / ``values`` events leave it out (an
  output schema). The ``debug`` events and the thread state still show it.

As on a LangGraph dev server, a thread's history holds the state after the
run, not one entry per step.

Callers authenticate with ``Authorization: Bearer tok-<name>``; the identity is
``<name>``, percent-decoded, so that a test id can hold a character a header
cannot carry at its edge (``tok-alice%20`` is the id ``"alice "``). Modes:

* ``leaky``  -- authenticates callers but authorizes nothing: any user can read
  any thread or Store item, and the agent keeps one shared memory namespace.
* ``safe``   -- threads belong to their creator; Store access is limited to
  namespaces whose first label is the caller's identity.
* ``meta``   -- like ``safe``, but ``/store/namespaces`` lists every user's
  namespaces (existence is visible, contents are not).
* ``open``   -- no authentication at all: every caller is ``anonymous``.
* ``broken`` -- like ``safe``, but nothing can be read back even by its owner,
  so the probe's positive controls fail and it must grade INCONCLUSIVE.
* ``prefixbug`` -- like ``safe`` (the app checks namespace ownership), but the
  Store matches a namespace prefix as a *string*, not segment by segment (the
  shape of CVE-2026-71433). A user whose id is a string prefix of another user's
  id sees that user's items in their own-namespace search.
* ``dotbug`` -- like ``safe``, but the Store keeps a namespace as dot-joined
  text, so a label that contains ``.`` addresses another namespace: the id
  ``alice.notes`` reaches ``("alice", "notes")``.
* ``separatorbug`` -- the same, for a Store that flattens namespaces on ``/``,
  ``:`` or ``|``.
* ``wildcardbug`` -- like ``safe``, but a Store search treats ``%``, ``_`` and
  ``*`` in the prefix as wildcards (an unescaped SQL ``LIKE`` / glob).
* ``casebug`` -- like ``safe``, but the Store compares labels without regard to
  letter case.
* ``whitespacebug`` -- like ``safe``, but the Store trims whitespace from labels.
* ``strictids`` -- like ``safe``, and the Store refuses (422) a label that is
  empty, contains ``.`` or has whitespace at either end. An awkward id of that
  shape cannot use the Store at all, so its case is not exercised.
* ``writeleak`` -- reads are scoped like ``safe``, but updates and deletes are
  not checked: any user can change or delete another user's thread or item.
* ``writeack`` -- like ``safe``, but a write to someone else's data is answered
  with success and silently dropped.
* ``nowrites`` -- like ``safe``, but nobody can update or delete anything (405),
  so the write paths' own controls fail.
* ``nostream`` -- like ``leaky``, but there is no ``runs/stream`` endpoint (404).
* ``nosteps`` -- like ``leaky``, with no ``runs/stream`` and no readable thread
  state or history (404), so a run's steps cannot be read at all.
* ``aliceruns`` -- like ``safe``, but only the user ``alice`` may start a run
  (403 for anyone else), so a second user's run never completes.
* ``bodyowner`` -- like ``safe``, but the ownership check trusts an ``owner``
  field the caller supplies in the request body, and a Store write trusts the
  first namespace label the caller sends, instead of the authenticated
  identity. A caller who puts another user's id in those fields reaches that
  user's data; without the field the behaviour is like ``safe``.

NEVER expose this on a network. It stores unauthenticated data by design.

    STRANGERTEST_MODE=leaky STRANGERTEST_PORT=4650 python3 -m strangertest.practice_agent_memory_http
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

MODES = ("leaky", "safe", "meta", "open", "broken", "prefixbug", "dotbug", "separatorbug",
         "wildcardbug", "casebug", "whitespacebug", "strictids", "writeleak", "writeack",
         "nowrites", "bodyowner", "nostream", "nosteps", "aliceruns")
FORBIDDEN_PORTS = {4000, 4444, 8790}
ASSISTANT_ID = "memory"
ASSISTANTS = ("memory", "retrieval", "retrieval_hidden")
# Modes with no per-user scoping at all (one shared memory, every thread readable).
_UNSCOPED = ("leaky", "open", "nostream", "nosteps")
_OUTPUT_KEYS = ("result", "whoami")       # what ``retrieval_hidden`` lets out

__all__ = ["MODES", "ASSISTANT_ID", "ASSISTANTS", "AgentMemoryState", "build_server", "main"]


class _HTTPError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


class AgentMemoryState:
    """Threads and Store items for every user of one practice server."""

    def __init__(self, mode: str):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}, got {mode!r}")
        self.mode = mode
        self.threads: Dict[str, Dict[str, Any]] = {}
        self.items: Dict[Tuple[Tuple[str, ...], str], Dict[str, Any]] = {}
        self._lock = threading.Lock()

    # -- who is calling ---------------------------------------------------

    def identify(self, authorization: Optional[str]) -> str:
        if self.mode == "open":
            return "anonymous"
        token = (authorization or "")
        token = token[len("Bearer "):] if token.startswith("Bearer ") else ""
        if not token.startswith("tok-") or len(token) <= 4:
            raise _HTTPError(401, "unknown token")
        return unquote(token[4:])

    @property
    def _owner_scoped(self) -> bool:
        return self.mode not in _UNSCOPED

    def _canon(self, namespace: Tuple[str, ...]) -> Tuple[str, ...]:
        """The namespace as this mode's Store keys it (the bug modes fold ids together)."""
        if self.mode == "dotbug":
            return tuple(part for label in namespace for part in label.split("."))
        if self.mode == "separatorbug":
            return tuple(part for label in namespace for part in re.split(r"[/:|]", label))
        if self.mode == "casebug":
            return tuple(label.lower() for label in namespace)
        if self.mode == "whitespacebug":
            return tuple(label.strip() for label in namespace)
        return tuple(namespace)

    def _write_guard(self, allowed: bool) -> bool:
        """True when a write may go ahead; False when it must be silently dropped."""
        if self.mode == "nowrites":
            raise _HTTPError(405, "Method Not Allowed")
        if allowed or self.mode == "writeleak":
            return True
        if self.mode == "writeack":
            return False
        raise _HTTPError(404, "Not Found")

    # -- threads ----------------------------------------------------------

    def _claimed(self, user: str, metadata: Dict[str, Any]) -> str:
        """In ``bodyowner`` mode the server trusts ``metadata.owner`` from the
        request body when it is a non-empty string; otherwise the caller's own
        identity is used. This is the ``bodyowner`` mode's single flaw: a
        broken handler that filters by a client-supplied field."""
        if self.mode == "bodyowner" and isinstance(metadata, dict):
            claimed = metadata.get("owner")
            if isinstance(claimed, str) and claimed:
                return claimed
        return user

    def create_thread(self, user: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        owner = self._claimed(user, metadata)
        thread = {"thread_id": str(uuid.uuid4()), "owner": owner,
                  "metadata": dict(metadata), "values": {}, "history": []}
        with self._lock:
            self.threads[thread["thread_id"]] = thread
        return self._thread_view(thread)

    def _thread_view(self, thread: Dict[str, Any]) -> Dict[str, Any]:
        metadata = {} if self.mode == "broken" else dict(thread["metadata"])
        return {"thread_id": thread["thread_id"], "metadata": metadata, "status": "idle"}

    def _thread_for(self, user: str, thread_id: str) -> Dict[str, Any]:
        thread = self.threads.get(thread_id)
        if thread is None or (self._owner_scoped and thread["owner"] != user):
            raise _HTTPError(404, f"Thread with ID {thread_id} not found")
        return thread

    def get_thread(self, user: str, thread_id: str) -> Dict[str, Any]:
        return self._thread_view(self._thread_for(user, thread_id))

    def get_state(self, user: str, thread_id: str) -> Dict[str, Any]:
        if self.mode == "nosteps":
            raise _HTTPError(404, "Not Found")
        thread = self._thread_for(user, thread_id)
        values = {} if self.mode == "broken" else dict(thread["values"])
        return {"values": values, "next": [], "tasks": []}

    def get_history(self, user: str, thread_id: str) -> List[Dict[str, Any]]:
        if self.mode == "nosteps":
            raise _HTTPError(404, "Not Found")
        thread = self._thread_for(user, thread_id)
        if self.mode == "broken":
            return []
        return [{"values": dict(v), "next": [], "tasks": []} for v in reversed(thread["history"])]

    def _thread_for_write(self, user: str, thread_id: str) -> Optional[Dict[str, Any]]:
        thread = self.threads.get(thread_id)
        if thread is None:
            raise _HTTPError(404, f"Thread with ID {thread_id} not found")
        owned = not self._owner_scoped or thread["owner"] == user
        return thread if self._write_guard(owned) else None

    def update_thread(self, user: str, thread_id: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        thread = self._thread_for_write(user, thread_id)
        if thread is None:
            return {"thread_id": thread_id, "metadata": {}, "status": "idle"}
        with self._lock:
            thread["metadata"].update(metadata)
        return self._thread_view(thread)

    def delete_thread(self, user: str, thread_id: str) -> None:
        if self._thread_for_write(user, thread_id) is not None:
            with self._lock:
                self.threads.pop(thread_id, None)

    def search_threads(self, user: str) -> List[Dict[str, Any]]:
        with self._lock:
            threads = list(self.threads.values())
        return [self._thread_view(t) for t in threads
                if not self._owner_scoped or t["owner"] == user]

    # -- the agent --------------------------------------------------------

    def _execute(self, user: str, thread_id: str, body: Dict[str, Any]
                 ) -> Tuple[Dict[str, Any], List[Tuple[str, Dict[str, Any], Dict[str, Any]]], bool]:
        """Run one agent. Returns the final state, the steps as
        ``(node, what it wrote, state after it)``, and whether an output schema
        hides everything but ``_OUTPUT_KEYS``."""
        thread = self._thread_for(user, thread_id)
        if self.mode == "aliceruns" and user != "alice":
            raise _HTTPError(403, "runs are not enabled for this user")
        assistant = body.get("assistant_id")
        if assistant not in ASSISTANTS:
            raise _HTTPError(404, "Thread or assistant not found.")
        state = dict(body.get("input") or {})
        label = "memories" if assistant == ASSISTANT_ID else "retrieval"
        namespace = (label,) if self.mode in _UNSCOPED else (user, label)
        namespace = self._canon(namespace)
        key = str(state.get("key"))
        saving = state.get("action") == "save"
        if saving:
            with self._lock:
                self.items[(namespace, key)] = {"text": state.get("value")}
            found = None
        else:
            item = self.items.get((namespace, key))
            found = item.get("text") if item else None
        steps: List[Tuple[str, Dict[str, Any], Dict[str, Any]]] = []

        def step(node: str, wrote: Dict[str, Any]) -> None:
            state.update(wrote)
            steps.append((node, dict(wrote), dict(state)))

        if assistant == ASSISTANT_ID:
            step("memory", {"result": "saved" if saving else found, "whoami": user})
        else:
            docs = [] if found is None else [found]
            step("retrieve", {"docs": docs, "whoami": user})
            answer = {"value": None, "result": "answered from %d document(s)" % len(docs)}
            if assistant == "retrieval":
                answer["docs"] = []
            step("answer", answer)
        with self._lock:
            thread["values"] = dict(state)
            thread["history"].append(dict(state))
        return state, steps, assistant == "retrieval_hidden"

    @staticmethod
    def _visible(values: Dict[str, Any], hidden: bool) -> Dict[str, Any]:
        return {k: v for k, v in values.items() if k in _OUTPUT_KEYS} if hidden else dict(values)

    def run(self, user: str, thread_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
        state, _, hidden = self._execute(user, thread_id, body)
        if self.mode == "broken":
            return {"result": None, "whoami": user}
        return self._visible(state, hidden)

    def run_stream(self, user: str, thread_id: str, body: Dict[str, Any]) -> List[Tuple[str, Any]]:
        """The run as ``(event name, data)`` pairs, shaped like a LangGraph stream."""
        if self.mode in ("nostream", "nosteps"):
            raise _HTTPError(404, "Not Found")
        modes = body.get("stream_mode") or ["values"]
        modes = [modes] if isinstance(modes, str) else list(modes)
        state, steps, hidden = self._execute(user, thread_id, body)
        events: List[Tuple[str, Any]] = [("metadata", {"run_id": uuid.uuid4().hex, "attempt": 1})]
        if self.mode == "broken":
            return events + [("values", {"result": None, "whoami": user})]
        for number, (node, wrote, after) in enumerate(steps, start=1):
            if "debug" in modes:
                events.append(("debug", {"step": number, "type": "task_result",
                                         "payload": {"name": node, "error": None, "result": wrote}}))
            if "updates" in modes:
                events.append(("updates", {node: self._visible(wrote, hidden)}))
            if "values" in modes:
                events.append(("values", self._visible(after, hidden)))
        return events

    # -- the Store --------------------------------------------------------

    def _owns(self, user: str, namespace: Tuple[str, ...]) -> bool:
        return not self._owner_scoped or (bool(namespace) and namespace[0] == user)

    def _write_owns(self, user: str, namespace: Tuple[str, ...]) -> bool:
        """Like :meth:`_owns`, but for writes to the Store. In ``bodyowner`` the
        handler trusts the first namespace label the caller sent, so any
        non-empty namespace passes."""
        if self.mode == "bodyowner" and namespace:
            return True
        return self._owns(user, namespace)

    def _check_namespace(self, user: str, namespace: Tuple[str, ...]) -> None:
        if self.mode == "strictids":
            for label in namespace:
                if not label or "." in label or label != label.strip():
                    raise _HTTPError(422, "namespace label not accepted")
        if not self._owns(user, namespace):
            raise _HTTPError(403, "not your namespace")

    def _check_namespace_for_write(self, user: str, namespace: Tuple[str, ...]) -> None:
        if self.mode == "strictids":
            for label in namespace:
                if not label or "." in label or label != label.strip():
                    raise _HTTPError(422, "namespace label not accepted")
        if not self._write_owns(user, namespace):
            raise _HTTPError(403, "not your namespace")

    def put_item(self, user: str, namespace: Tuple[str, ...], key: str, value: Dict[str, Any]) -> None:
        if self._write_owns(user, namespace) or self.mode not in ("writeleak", "writeack"):
            self._check_namespace_for_write(user, namespace)
        elif self.mode == "writeack":
            return
        with self._lock:
            self.items[(self._canon(namespace), key)] = dict(value)

    def delete_item(self, user: str, namespace: Tuple[str, ...], key: str) -> None:
        if self._write_guard(self._owns(user, namespace)):
            with self._lock:
                self.items.pop((self._canon(namespace), key), None)

    def get_item(self, user: str, namespace: Tuple[str, ...], key: str) -> Dict[str, Any]:
        self._check_namespace(user, namespace)
        item = self.items.get((self._canon(namespace), key))
        if item is None or self.mode == "broken":
            raise _HTTPError(404, "Item not found")
        return {"namespace": list(namespace), "key": key, "value": dict(item)}

    def _matcher(self, prefix: Tuple[str, ...]):
        prefix = self._canon(prefix)
        if self.mode == "prefixbug":
            def matches(ns):  # string match on the dotted form: crosses segment boundaries
                return ".".join(ns).startswith(".".join(prefix))
        elif self.mode == "wildcardbug":
            patterns = [re.compile("".join(".*" if ch in "%*" else "." if ch == "_" else re.escape(ch)
                                           for ch in label) + r"\Z", re.S) for label in prefix]

            def matches(ns):  # each label of the prefix is used as a pattern
                return len(ns) >= len(patterns) and all(
                    pattern.match(label) for pattern, label in zip(patterns, ns))
        else:
            def matches(ns):  # segment-by-segment match
                return ns[:len(prefix)] == prefix
        return matches

    def search_items(self, user: str, prefix: Tuple[str, ...]) -> Dict[str, Any]:
        self._check_namespace(user, prefix)
        if self.mode == "broken":
            return {"items": []}
        matches = self._matcher(prefix)
        with self._lock:
            found = [{"namespace": list(ns), "key": key, "value": dict(value)}
                     for (ns, key), value in self.items.items() if matches(ns)]
        return {"items": found}

    def list_namespaces(self, user: str, prefix: Tuple[str, ...] = ()) -> Dict[str, Any]:
        with self._lock:
            names = sorted({ns for ns, _ in self.items})
        if self._owner_scoped and self.mode != "meta":
            names = [ns for ns in names if ns and ns[0] == user]
        if prefix:
            matches = self._matcher(prefix)
            names = [ns for ns in names if matches(ns)]
        return {"namespaces": [list(ns) for ns in names]}


def _make_handler(state: AgentMemoryState):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):  # keep output quiet
            pass

        def _send(self, status: int, payload: Any = None) -> None:
            body = b"" if payload is None else json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def _send_events(self, events: List[Tuple[str, Any]]) -> None:
            body = "".join("event: %s\ndata: %s\n\n" % (name, json.dumps(data))
                           for name, data in events).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> Dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(length) if length else b""
            if not raw:
                return {}
            try:
                parsed = json.loads(raw)
            except ValueError:
                raise _HTTPError(422, "body is not JSON")
            if not isinstance(parsed, dict):
                raise _HTTPError(422, "body must be an object")
            return parsed

        def _dispatch(self, method: str) -> None:
            url = urlparse(self.path)
            parts = [p for p in url.path.split("/") if p]
            try:
                body = self._body() if method in ("POST", "PUT", "PATCH", "DELETE") else {}
                if method == "GET" and parts == ["ok"]:
                    return self._send(200, {"ok": True})
                user = state.identify(self.headers.get("Authorization"))
                if parts and parts[0] == "threads":
                    return self._threads(method, parts[1:], user, body)
                if parts and parts[0] == "store":
                    return self._store(method, parts[1:], user, body, parse_qs(url.query))
                raise _HTTPError(404, "Not Found")
            except _HTTPError as exc:
                self._send(exc.status, {"detail": exc.detail})

        def _threads(self, method, rest, user, body) -> None:
            if method == "POST" and not rest:
                return self._send(200, state.create_thread(user, body.get("metadata") or {}))
            if method == "POST" and rest == ["search"]:
                return self._send(200, state.search_threads(user))
            if method == "GET" and len(rest) == 1:
                return self._send(200, state.get_thread(user, rest[0]))
            if method == "GET" and len(rest) == 2 and rest[1] == "state":
                return self._send(200, state.get_state(user, rest[0]))
            if method == "GET" and len(rest) == 2 and rest[1] == "history":
                return self._send(200, state.get_history(user, rest[0]))
            if method == "PATCH" and len(rest) == 1:
                return self._send(200, state.update_thread(user, rest[0], body.get("metadata") or {}))
            if method == "DELETE" and len(rest) == 1:
                state.delete_thread(user, rest[0])
                return self._send(204)
            if method == "POST" and len(rest) == 3 and rest[1:] == ["runs", "wait"]:
                return self._send(200, state.run(user, rest[0], body))
            if method == "POST" and len(rest) == 3 and rest[1:] == ["runs", "stream"]:
                return self._send_events(state.run_stream(user, rest[0], body))
            raise _HTTPError(404, "Not Found")

        def _store(self, method, rest, user, body, query) -> None:
            if method == "PUT" and rest == ["items"]:
                state.put_item(user, tuple(body.get("namespace") or ()), str(body.get("key")),
                               body.get("value") or {})
                return self._send(204)
            if method == "GET" and rest == ["items"]:
                namespace = tuple(p for p in (query.get("namespace") or [""])[0].split(".") if p)
                return self._send(200, state.get_item(user, namespace, (query.get("key") or [""])[0]))
            if method == "POST" and rest == ["items", "search"]:
                return self._send(200, state.search_items(user, tuple(body.get("namespace_prefix") or ())))
            if method == "DELETE" and rest == ["items"]:
                state.delete_item(user, tuple(body.get("namespace") or ()), str(body.get("key")))
                return self._send(204)
            if method == "POST" and rest == ["namespaces"]:
                return self._send(200, state.list_namespaces(user, tuple(body.get("prefix") or ())))
            raise _HTTPError(404, "Not Found")

        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

        def do_PUT(self):
            self._dispatch("PUT")

        def do_PATCH(self):
            self._dispatch("PATCH")

        def do_DELETE(self):
            self._dispatch("DELETE")

    return Handler


def build_server(mode: str, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    state = AgentMemoryState(mode)
    server = ThreadingHTTPServer((host, port), _make_handler(state))
    server.daemon_threads = True
    server.state = state  # type: ignore[attr-defined]
    return server


def main() -> None:
    mode = os.environ.get("STRANGERTEST_MODE", "leaky")
    port = int(os.environ.get("STRANGERTEST_PORT", "0"))
    if port in FORBIDDEN_PORTS:
        raise SystemExit(f"ERROR: refusing reserved port {port}")
    server = build_server(mode, port=port)
    host, bound = server.server_address[0], server.server_address[1]
    print(f"practice-agent-memory-http [{mode}] on http://{host}:{bound}")
    server.serve_forever()


if __name__ == "__main__":
    main()
