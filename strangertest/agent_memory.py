"""Cross-user agent-memory isolation probe.

An agent server that serves many users keeps memory for them: saved
conversation state (threads) and long-term memory (a key-value Store). This
probe asks one question: **can user B read what user A stored?**

It speaks the LangGraph Server HTTP API (threads, runs, Store) with the standard
library only. In that framework, access to threads and Store items is authorized
only if the application adds its own handlers, so a LEAK here is normally an
application misconfiguration, not a framework defect.

Steps:

1. **Auth posture.** Call with no token and with a made-up token. If either is
   accepted, every caller is one principal: OBSERVATION, never LEAK.
2. **A plants** a unique marker in a thread's metadata, in the Store, and (when
   the operator supplies ``save_input``) through the agent itself.
3. **Positive control per path.** A reads the marker back through each path. A
   path A cannot read herself is *not exercised*: it can never count as OK.
4. **B reads** every path with A's identifiers, and lists/searches without them.
5. **Awkward-id pairs** (only with identities the operator supplies). An extra
   identity whose id is related to A's in a way sloppy scoping code confuses
   (a string prefix, a ``.`` or other separator inside a label, a wildcard
   character, letter case, surrounding whitespace) searches and reads *its own*
   namespace and must not get A's marker. The probe never invents an identity.
6. **Write paths** (only with ``write_paths=True``). B tries to update or
   delete A's thread and to overwrite or delete A's Store item, each on a fresh
   throwaway object the probe created for that one attempt; A then re-reads it.

Grades: ``LEAK`` (B obtained A's marker on a path whose control held, and auth
is enforced), ``OK`` (no path leaked and at least one was exercised),
``INCONCLUSIVE`` (nothing could be exercised or the server was unreachable),
``OBSERVATION`` (no authentication, the two callers map to one principal, or
only the existence of A's data is visible to B).

Tokens and markers appear in reports only as ``sha256:`` fingerprints.

Design record: amem-adr/471cead694a97fc9dc67746963f0f872 (path list and grading rules).
"""

from __future__ import annotations

import hashlib
import json
import secrets
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .guard import authorize

LEAK = "LEAK"
OBSERVATION = "OBSERVATION"
OK = "OK"
INCONCLUSIVE = "INCONCLUSIVE"

# Per-path outcomes.
P_LEAK = "LEAK"
P_OK = "OK"
P_NOT_EXERCISED = "NOT_EXERCISED"
P_NOT_RUN = "NOT_RUN"
P_OBSERVATION = "OBSERVATION"      # B's write call was accepted, A's data did not change

# Awkward-id relationships between an extra identity and identity A.
EDGE_KINDS = ("prefix", "dot", "separator", "wildcard", "case", "whitespace")
EDGE_PATHS = {
    "prefix": "store_search_own_prefix",
    "dot": "store_edge_dot",
    "separator": "store_edge_separator",
    "wildcard": "store_edge_wildcard",
    "case": "store_edge_case",
    "whitespace": "store_edge_whitespace",
}
_EDGE_WHAT = {
    "prefix": "B searches B's own namespace and gets A's item",
    "dot": "a dotted-id identity gets A's item from its own namespace",
    "separator": "a separator-id ( / : | ) identity gets A's item from its own namespace",
    "wildcard": "a wildcard-id ( % _ * ) identity gets A's item from its own namespace",
    "case": "a case-variant-id identity gets A's item from its own namespace",
    "whitespace": "a whitespace-variant-id identity gets A's item from its own namespace",
}
_NO_EDGE_IDENTITY = ("no identity of this kind was supplied "
                     "(--edge-identity KIND=TOKEN@NAMESPACE)")
_WRITES_OFF = ("write paths are off; --write-paths sends update and delete calls at this "
               "run's own throwaway data")
_SEPARATORS = "/:|"
_WILDCARDS = "%_*?["

# By-id write attempts, in the order they run (the two deletes last).
WRITE_PATHS = ("thread_update", "store_put_overwrite", "thread_delete", "store_delete")
_WRITE_WHAT = {
    "thread_update": "B updates A's thread by id",
    "store_put_overwrite": "B overwrites A's memory item by namespace and key",
    "thread_delete": "B deletes A's thread by id",
    "store_delete": "B deletes A's memory item by namespace and key",
}

__all__ = [
    "LEAK", "OBSERVATION", "OK", "INCONCLUSIVE", "EDGE_KINDS", "EDGE_PATHS", "WRITE_PATHS",
    "AgentMemoryReport", "run_agent_memory_probe", "parse_edge_identity", "parse_namespace",
]


def parse_namespace(text: Any) -> Optional[List[str]]:
    """A namespace option: a JSON list of labels, or labels joined by dots.

    ``alice.notes`` is ``["alice", "notes"]``. A label that itself contains a
    dot can only be written as JSON: ``["acme.alice", "notes"]``.
    """
    if text is None or isinstance(text, (list, tuple)):
        return list(text) if text is not None else None
    text = str(text)
    if text.lstrip().startswith("["):
        try:
            labels = json.loads(text)
        except ValueError as exc:
            raise ValueError(f"namespace is not a valid JSON list: {exc}")
        if not isinstance(labels, list) or not all(isinstance(x, str) for x in labels):
            raise ValueError("namespace JSON must be a list of strings")
        return labels
    return [p for p in text.split(".") if p]


def parse_edge_identity(spec: str) -> Dict[str, Any]:
    """Parse ``KIND=TOKEN[@NAMESPACE]`` (the ``--edge-identity`` syntax).

    ``KIND`` is one of :data:`EDGE_KINDS`. ``NAMESPACE`` is that identity's own
    Store namespace: a JSON list of labels, or otherwise ONE label taken exactly
    as written (it is not split on dots, because the label is the point).
    """
    kind, eq, rest = str(spec).partition("=")
    kind = kind.strip().lower()
    if not eq or kind not in EDGE_KINDS:
        raise ValueError("--edge-identity must look like KIND=TOKEN[@NAMESPACE], with KIND "
                         "one of: " + ", ".join(EDGE_KINDS))
    token, at, namespace = rest.partition("@")
    if not token:
        raise ValueError(f"--edge-identity {kind}=... has no token")
    labels: Optional[List[str]] = None
    if at:
        labels = parse_namespace(namespace) if namespace.lstrip().startswith("[") else [namespace]
    return {"kind": kind, "token": token, "namespace": labels}


def _edge_shape_problem(kind: str, own: List[str], base: List[str]) -> Optional[str]:
    """Why ``own`` (the extra identity's namespace) is not a ``kind`` relative of
    ``base`` (the namespace A was given); None when it is."""
    if not own:
        return "no namespace was given for this identity"
    head = base[:len(own)]
    if head == own:
        return "that namespace is inside A's own, so it is not another identity's"
    if kind == "prefix":
        if not ".".join(base).startswith(".".join(own)):
            return ("the namespace is not a string-but-not-segment prefix of A's namespace; "
                    "give prefix-sibling ids (e.g. ali / alice) to run this")
    elif kind == "dot":
        if not any("." in label for label in own + base):
            return "neither namespace has a label containing '.'"
    elif kind == "separator":
        if not any(ch in label for label in own + base for ch in _SEPARATORS):
            return "neither namespace has a label containing '/', ':' or '|'"
    elif kind == "wildcard":
        if not any(ch in label for label in own for ch in _WILDCARDS):
            return "the identity's namespace has no wildcard character (% _ * ? [)"
    elif kind == "case":
        if [x.casefold() for x in own] != [x.casefold() for x in head]:
            return "the namespace does not differ from A's only in letter case"
    elif kind == "whitespace":
        if [x.strip() for x in own] != [x.strip() for x in head]:
            return "the namespace does not differ from A's only in whitespace"
    return None


def _fp(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _fill(template: Any, marker: str) -> Any:
    """Copy ``template`` with every ``{marker}`` in a string replaced."""
    if isinstance(template, str):
        return template.replace("{marker}", marker)
    if isinstance(template, dict):
        return {k: _fill(v, marker) for k, v in template.items()}
    if isinstance(template, list):
        return [_fill(v, marker) for v in template]
    return template


@dataclass
class _Response:
    status: int            # 0 = no HTTP answer at all
    body: str
    error: Optional[str] = None

    def json(self) -> Any:
        try:
            return json.loads(self.body)
        except ValueError:
            return None


class _Caller:
    """One identity's HTTP access to the agent server."""

    def __init__(self, base: str, token: Optional[str], timeout: float):
        self.base = base.rstrip("/")
        self.token = token
        self.timeout = timeout

    def call(self, method: str, path: str, body: Any = None) -> _Response:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.token is not None:
            headers["Authorization"] = f"Bearer {self.token}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return _Response(response.status, response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            return _Response(exc.code, exc.read().decode("utf-8", "replace"))
        except Exception as exc:  # connection refused, timeout, bad URL
            return _Response(0, "", f"{type(exc).__name__}: {exc}")


@dataclass
class AgentMemoryReport:
    target: str
    grade: str
    detail: str
    paths: List[Dict[str, Any]] = field(default_factory=list)
    controls: Dict[str, Any] = field(default_factory=dict)
    observations: List[str] = field(default_factory=list)
    fingerprints: Dict[str, Any] = field(default_factory=dict)
    # Flags the operator left out that would turn NOT_RUN paths on. Text output
    # only: this is deliberately not part of to_dict().
    missing_inputs: Dict[str, List[str]] = field(default_factory=dict)

    @property
    def leaked(self) -> bool:
        return self.grade == LEAK

    def to_dict(self) -> Dict[str, Any]:
        return {
            "probe": "agent-memory",
            "target": self.target,
            "grade": self.grade,
            "detail": self.detail,
            "paths": self.paths,
            "controls": self.controls,
            "observations": self.observations,
            "fingerprints": self.fingerprints,
        }

    def summary(self) -> str:
        lines = [f"{self.grade}: {self.detail}"]
        # Paths left out for one shared reason (no extra identity, writes off)
        # are listed on one line, where the first of them would have been.
        shared: Dict[str, List[str]] = {}
        for path in self.paths:
            if path["outcome"] == P_NOT_RUN and path.get("note") in (_NO_EDGE_IDENTITY, _WRITES_OFF):
                shared.setdefault(path["note"], []).append(path["name"])
        for path in self.paths:
            names = shared.get(path.get("note") or "") if path["outcome"] == P_NOT_RUN else None
            if names and len(names) > 1:
                if path["name"] == names[0]:
                    lines.append(f"  {P_NOT_RUN:<14} {', '.join(names)} ({path['note']})")
                continue
            note = f" ({path['note']})" if path.get("note") else ""
            lines.append(f"  {path['outcome']:<14} {path['name']}: {path['what']}{note}")
        for observation in self.observations:
            lines.append(f"  note: {observation}")
        return "\n".join(lines)

    def hint(self) -> str:
        """One closing line naming the flags that would run the NOT_RUN paths.

        Empty when no path was left out for want of an optional input.
        """
        parts = []
        agent = self.missing_inputs.get("agent")
        if agent:
            parts.append("to also test through the agent: " + ", ".join(agent))
        if self.missing_inputs.get("namespace_b"):
            parts.append("to also test the Store namespace boundary: --namespace-b "
                         "(with prefix-sibling ids)")
        edge = self.missing_inputs.get("edge")
        if edge:
            parts.append("to also test awkward-id pairs (" + ", ".join(edge) + "): "
                         "--edge-identity KIND=TOKEN@NAMESPACE")
        if self.missing_inputs.get("write_paths"):
            parts.append("to also test writes to A's data: --write-paths")
        if not parts:
            return ""
        return "hint: " + "; ".join(parts) + "; see docs/AGENT-MEMORY.md"


def run_agent_memory_probe(
    url: str,
    token_a: Optional[str],
    token_b: Optional[str],
    *,
    namespace_a: Optional[Sequence[str]] = None,
    namespace_b: Optional[Sequence[str]] = None,
    assistant_id: Optional[str] = None,
    save_input: Optional[Dict[str, Any]] = None,
    recall_input: Optional[Dict[str, Any]] = None,
    whoami_field: Optional[str] = None,
    edge_identities: Optional[Sequence[Dict[str, Any]]] = None,
    write_paths: bool = False,
    timeout: float = 20.0,
    authorized: bool = False,
    authorization_note: Optional[str] = None,
) -> AgentMemoryReport:
    """Run the probe against the agent server at ``url`` (its base URL).

    ``namespace_a`` is a Store namespace user A is allowed to write to (an app
    that scopes the Store per user will refuse any other); when omitted a
    throwaway namespace is used. ``namespace_b`` is B's own namespace; when it
    is given and its dotted form is a *string* prefix of A's but not a
    segment-by-segment prefix (``ali`` vs ``alice.notes``), the probe also
    checks that B's own-namespace search does not return A's item. That is the
    shape of the namespace-boundary bugs fixed in LangGraph's SQLite/Postgres
    stores in 2026; it needs two accounts whose ids are prefix siblings.
    ``save_input`` / ``recall_input`` are run
    inputs for the operator's own agent, with ``{marker}`` replaced by the
    probe's marker; without them the through-the-agent paths are not run.
    ``whoami_field`` names a field of the run output that carries the caller's
    identity, if the app has one.

    ``edge_identities`` is a list of ``{"kind", "token", "namespace"}`` dicts
    (see :func:`parse_edge_identity`): extra test identities the operator has
    provisioned whose ids are awkward relatives of A's. Each is used only as
    itself, in its own namespace, through the same documented calls; a kind
    with no identity is reported NOT_RUN. ``namespace_b`` with prefix-sibling
    ids keeps working and is the same thing as a ``prefix`` edge identity that
    uses B's token.

    ``write_paths`` turns on the four by-id write attempts
    (:data:`WRITE_PATHS`). They are off by default because they send update and
    delete calls; they only ever name objects this run created for the purpose.
    """
    authorize(url, authorized=authorized, authorization_note=authorization_note)

    marker = "st-mem-" + secrets.token_hex(8)
    tag = "st-probe-" + secrets.token_hex(4)          # distinctive, carries no secret
    namespace = list(namespace_a) if namespace_a else [tag]
    if namespace_a:
        namespace = namespace + [tag]
    item_key = "st-item"
    fingerprints = {"token_a": _fp(token_a), "token_b": _fp(token_b), "marker": _fp(marker)}
    controls: Dict[str, Any] = {}
    observations: List[str] = []
    paths: List[Dict[str, Any]] = []

    missing_inputs: Dict[str, List[str]] = {}

    def report(grade: str, detail: str) -> AgentMemoryReport:
        # Only name a flag when a path it would enable was actually left NOT_RUN.
        not_run = {p["name"] for p in paths if p["outcome"] == P_NOT_RUN}
        relevant = {}
        if missing_inputs.get("agent") and not_run & {"thread_state", "thread_history", "agent_recall"}:
            relevant["agent"] = missing_inputs["agent"]
        if missing_inputs.get("namespace_b") and "store_search_own_prefix" in not_run:
            relevant["namespace_b"] = missing_inputs["namespace_b"]
        unsupplied = [k for k in missing_inputs.get("edge", []) if EDGE_PATHS[k] in not_run]
        if unsupplied:
            relevant["edge"] = unsupplied
        if missing_inputs.get("write_paths") and not_run & set(WRITE_PATHS):
            relevant["write_paths"] = missing_inputs["write_paths"]
        return AgentMemoryReport(url, grade, detail, paths, controls, observations, fingerprints,
                                 relevant)

    if token_a is None or token_b is None or token_a == token_b:
        return report(INCONCLUSIVE, "two different bearer tokens are needed (one per identity).")

    agent_flags = [flag for flag, given in (("--assistant", bool(assistant_id)),
                                            ("--save-input", save_input is not None),
                                            ("--recall-input", recall_input is not None))
                   if not given]
    if agent_flags:
        missing_inputs["agent"] = agent_flags
    if not namespace_b:
        missing_inputs["namespace_b"] = ["--namespace-b"]

    edges: Dict[str, List[Dict[str, Any]]] = {kind: [] for kind in EDGE_KINDS}
    for identity in edge_identities or ():
        if identity.get("kind") not in EDGE_KINDS:
            raise ValueError("edge identity kind must be one of: " + ", ".join(EDGE_KINDS))
        edges[identity["kind"]].append(identity)
    if namespace_b and not edges["prefix"]:      # the older spelling of the prefix case
        edges["prefix"].append({"kind": "prefix", "token": token_b, "namespace": list(namespace_b),
                                "is_b": True})
    missing_inputs["edge"] = [kind for kind in EDGE_KINDS if not edges[kind] and kind != "prefix"]
    if not write_paths:
        missing_inputs["write_paths"] = ["--write-paths"]
    fingerprints["edge_identities"] = [
        {"kind": identity["kind"], "token": _fp(identity.get("token"))}
        for kind in EDGE_KINDS for identity in edges[kind] if not identity.get("is_b")]

    a = _Caller(url, token_a, timeout)
    b = _Caller(url, token_b, timeout)

    # -- 1. auth posture ----------------------------------------------------
    anonymous = _Caller(url, None, timeout).call("POST", "/threads/search", {"limit": 1})
    made_up = _Caller(url, "st-unknown-" + secrets.token_hex(8), timeout).call(
        "POST", "/threads/search", {"limit": 1})
    controls["no_token_status"] = anonymous.status
    controls["made_up_token_status"] = made_up.status
    if anonymous.status == 0 and made_up.status == 0:
        return report(INCONCLUSIVE, f"the server could not be reached ({anonymous.error}).")
    auth_enforced = anonymous.status in (401, 403) and made_up.status in (401, 403)
    controls["auth_enforced"] = auth_enforced

    # -- 2. A plants --------------------------------------------------------
    created = a.call("POST", "/threads", {"metadata": {"st_probe": tag, "st_marker": marker}})
    thread_a = (created.json() or {}).get("thread_id") if created.status == 200 else None
    controls["a_create_thread_status"] = created.status
    if not thread_a:
        return report(INCONCLUSIVE, f"identity A could not create a thread (HTTP {created.status}).")

    run_planted = False
    whoami: Dict[str, Optional[str]] = {"a": None, "b": None}
    if assistant_id and save_input is not None:
        saved = a.call("POST", f"/threads/{thread_a}/runs/wait",
                       {"assistant_id": assistant_id, "input": _fill(save_input, marker)})
        controls["a_agent_save_status"] = saved.status
        run_planted = saved.status == 200
        if whoami_field and isinstance(saved.json(), dict):
            whoami["a"] = saved.json().get(whoami_field)

    put = a.call("PUT", "/store/items",
                 {"namespace": namespace, "key": item_key, "value": {"text": marker}})
    controls["a_store_put_status"] = put.status
    dotted = ".".join(namespace)
    dotted_q = urllib.parse.quote(dotted, safe=".")      # as it goes into a query string

    # -- 3 + 4. each path: A's control, then B ------------------------------
    def path(name: str, what: str, method: str, route: str, body: Any = None,
             *, enabled: bool = True, why_not: str = "") -> None:
        if not enabled:
            paths.append({"name": name, "what": what, "outcome": P_NOT_RUN, "note": why_not})
            return
        control = a.call(method, route, body)
        if marker not in control.body:
            paths.append({"name": name, "what": what, "outcome": P_NOT_EXERCISED,
                          "control_status": control.status,
                          "note": f"A could not read her own marker this way (HTTP {control.status})"})
            return
        attempt = b.call(method, route, body)
        seen = marker in attempt.body
        paths.append({"name": name, "what": what, "outcome": P_LEAK if seen else P_OK,
                      "control_status": control.status, "b_status": attempt.status,
                      "note": f"B got HTTP {attempt.status}"})

    path("thread_get", "B reads A's thread by id", "GET", f"/threads/{thread_a}")
    path("thread_state", "B reads A's saved conversation state", "GET", f"/threads/{thread_a}/state",
         enabled=run_planted, why_not="no save_input given, so nothing was saved through the agent")
    path("thread_history", "B reads A's conversation history", "GET", f"/threads/{thread_a}/history",
         enabled=run_planted, why_not="no save_input given, so nothing was saved through the agent")
    path("thread_search", "B lists threads and finds A's", "POST", "/threads/search", {"limit": 100})
    path("store_get", "B reads A's memory item by namespace and key", "GET",
         f"/store/items?namespace={dotted_q}&key={item_key}")
    path("store_search_namespace", "B searches A's memory namespace", "POST",
         "/store/items/search", {"namespace_prefix": namespace, "limit": 100})
    path("store_search_all", "B searches all memory with no namespace", "POST",
         "/store/items/search", {"namespace_prefix": [], "limit": 100})

    # Awkward-id pairs. Each extra identity acts only as itself, in its own
    # namespace: a store or scope check that compares ids loosely hands it A's item.
    a_item = a.call("GET", f"/store/items?namespace={dotted_q}&key={item_key}")
    if marker not in a_item.body:      # a dotted label cannot be named in a query string
        a_item = a.call("POST", "/store/items/search", {"namespace_prefix": namespace, "limit": 100})
    a_item_ok = marker in a_item.body
    base_namespace = list(namespace_a) if namespace_a else []

    def edge_attempt(kind: str, identity: Dict[str, Any]) -> Tuple[str, str, Optional[int]]:
        own_ns = list(identity.get("namespace") or [])
        who = "B" if identity.get("is_b") else "this identity"
        if not identity.get("token") or identity["token"] == token_a:
            return P_NOT_RUN, "the identity's token is missing or is identity A's", None
        problem = _edge_shape_problem(kind, own_ns, base_namespace or namespace)
        if problem:
            return P_NOT_RUN, problem, None
        if not a_item_ok:
            return (P_NOT_EXERCISED,
                    f"A could not read her own Store item (HTTP {a_item.status}), so there "
                    "was nothing to reach", None)
        caller = _Caller(url, identity["token"], timeout)
        own_marker = "st-own-" + secrets.token_hex(8)
        # Its own key, so that a store that folds the two namespaces together
        # keeps both items and the search can show A's.
        own_put = caller.call("PUT", "/store/items", {"namespace": own_ns + [tag], "key": "st-own",
                                                     "value": {"text": own_marker}})
        search = caller.call("POST", "/store/items/search",
                             {"namespace_prefix": own_ns, "limit": 100})
        # The same item addressed inside this identity's own namespace: its own
        # labels in place of A's leading ones, and A's dotted text where its
        # own dotted text is the beginning of it.
        candidates = []
        if len(own_ns) <= len(namespace):
            candidates.append(".".join(own_ns + namespace[len(own_ns):]))
        if dotted.startswith(".".join(own_ns)):
            candidates.append(dotted)
        by_key = [caller.call("GET", f"/store/items?namespace={urllib.parse.quote(c, safe='.')}"
                                     f"&key={item_key}")
                  for c in dict.fromkeys(candidates)]
        listing = caller.call("POST", "/store/namespaces", {"prefix": own_ns, "limit": 100})
        listed = listing.json() if isinstance(listing.json(), dict) else {}
        if put.status in (200, 204) and list(namespace) in [
                list(ns) for ns in (listed.get("namespaces") or []) if isinstance(ns, list)]:
            edge_sees_name.append(kind)
        if marker in search.body:
            return P_LEAK, f"{who}'s own-namespace search returned A's item", search.status
        if any(marker in got.body for got in by_key):
            return P_LEAK, f"{who}'s read by key inside its own namespace returned A's item", \
                search.status
        if own_marker not in search.body:
            return (P_NOT_EXERCISED,
                    f"{who} could not store and read back its own item (put HTTP "
                    f"{own_put.status}, search HTTP {search.status}); the server may not accept "
                    "an id of this shape", search.status)
        return P_OK, "own-namespace search and read by key returned only its own data", \
            search.status

    edge_sees_name: List[str] = []

    def edge_case(kind: str) -> None:
        name, what = EDGE_PATHS[kind], _EDGE_WHAT[kind]
        identities = edges[kind]
        if not identities:
            why = ("needs namespace_b (B's own namespace) with a prefix-sibling id"
                   if kind == "prefix" else _NO_EDGE_IDENTITY)
            paths.append({"name": name, "what": what, "outcome": P_NOT_RUN, "note": why})
            return
        results = [edge_attempt(kind, identity) for identity in identities]
        outcomes = [r[0] for r in results]
        for wanted in (P_LEAK, P_OK, P_NOT_EXERCISED, P_NOT_RUN):
            if wanted in outcomes:
                outcome = wanted
                break
        chosen = next(r for r in results if r[0] == outcome)
        note = chosen[1]
        if len(results) > 1:
            counts = ", ".join(f"{outcomes.count(o)} {o}" for o in dict.fromkeys(outcomes))
            note += f"; {len(results)} identities of this kind: {counts}"
        entry = {"name": name, "what": what, "outcome": outcome, "note": note,
                 "identities": len(results)}
        if chosen[2] is not None:
            entry["b_status"] = chosen[2]
        paths.append(entry)

    for kind in EDGE_KINDS:
        edge_case(kind)

    # Through the agent: B asks, in B's own thread, for what A saved.
    recall_name, recall_what = "agent_recall", "B asks the agent for A's memory"
    if assistant_id and recall_input is not None and run_planted:
        # Positive control: A, in a fresh thread of her own, must get the marker
        # back from the agent. Otherwise "B got nothing" would prove nothing.
        a_own = a.call("POST", "/threads", {"metadata": {"st_probe": tag}})
        a_thread2 = (a_own.json() or {}).get("thread_id") if a_own.status == 200 else None
        a_recall = (a.call("POST", f"/threads/{a_thread2}/runs/wait",
                           {"assistant_id": assistant_id, "input": _fill(recall_input, marker)})
                    if a_thread2 else _Response(a_own.status, ""))
        controls["a_agent_recall_sees_marker"] = marker in a_recall.body
        own = b.call("POST", "/threads", {"metadata": {"st_probe": tag}})
        thread_b = (own.json() or {}).get("thread_id") if own.status == 200 else None
        if marker in json.dumps(_fill(recall_input, marker)):
            paths.append({"name": recall_name, "what": recall_what,
                          "outcome": P_NOT_RUN, "note": "recall_input must not contain {marker}"})
        elif not controls["a_agent_recall_sees_marker"]:
            paths.append({"name": recall_name, "what": recall_what, "outcome": P_NOT_EXERCISED,
                          "control_status": a_recall.status,
                          "note": f"the agent did not return A's own marker to A (HTTP {a_recall.status})"})
        elif thread_b:
            recalled = b.call("POST", f"/threads/{thread_b}/runs/wait",
                              {"assistant_id": assistant_id, "input": _fill(recall_input, marker)})
            if whoami_field and isinstance(recalled.json(), dict):
                whoami["b"] = recalled.json().get(whoami_field)
            seen = marker in recalled.body
            paths.append({"name": recall_name, "what": recall_what,
                          "outcome": P_LEAK if seen else P_OK, "b_status": recalled.status,
                          "note": f"B got HTTP {recalled.status}"})
        else:
            paths.append({"name": recall_name, "what": recall_what, "outcome": P_NOT_EXERCISED,
                          "note": f"B could not create a thread (HTTP {own.status})"})
    else:
        paths.append({"name": recall_name, "what": recall_what,
                      "outcome": P_NOT_RUN, "note": "needs assistant_id, save_input and recall_input"})

    # Existence only: can B see that A's namespace exists?
    listing = b.call("POST", "/store/namespaces", {"limit": 100})
    listed = listing.json() if isinstance(listing.json(), dict) else {}
    listed_namespaces = [list(ns) for ns in (listed.get("namespaces") or []) if isinstance(ns, list)]
    namespace_visible = put.status in (200, 204) and list(namespace) in listed_namespaces
    controls["b_sees_a_namespace_name"] = namespace_visible

    # By-id writes. Each attempt gets its own fresh object, A proves she can do
    # the same write to her own data (the control), and A's re-read is the oracle.
    def write_result(name: str, control_ok: bool, control_note: str, attempt: _Response,
                     after: _Response, crossed: bool, readable: bool) -> None:
        what = _WRITE_WHAT[name]
        if not control_ok:
            paths.append({"name": name, "what": what, "outcome": P_NOT_EXERCISED,
                          "note": control_note})
        elif crossed:
            paths.append({"name": name, "what": what, "outcome": P_LEAK, "b_status": attempt.status,
                          "note": f"write crossed identities: B got HTTP {attempt.status} and "
                                  "A's data changed"})
        elif not readable:
            paths.append({"name": name, "what": what, "outcome": P_NOT_EXERCISED,
                          "b_status": attempt.status,
                          "note": f"A could not re-read her data afterwards (HTTP {after.status})"})
        elif 200 <= attempt.status < 300:
            paths.append({"name": name, "what": what, "outcome": P_OBSERVATION,
                          "b_status": attempt.status,
                          "note": f"B's call was accepted (HTTP {attempt.status}) but A's data "
                                  "did not change"})
        else:
            paths.append({"name": name, "what": what, "outcome": P_OK, "b_status": attempt.status,
                          "note": f"B got HTTP {attempt.status}; A's data is unchanged"})

    def new_thread() -> Optional[str]:
        made = a.call("POST", "/threads", {"metadata": {"st_probe": tag, "st_marker": marker}})
        return (made.json() or {}).get("thread_id") if made.status == 200 else None

    def item_route(key: str) -> str:
        return f"/store/items?namespace={dotted_q}&key={key}"

    def gone(response: _Response) -> bool:
        return response.status in (200, 404) and marker not in response.body

    why_no_writes = ""
    if not write_paths:
        why_no_writes = _WRITES_OFF
    elif not auth_enforced:
        why_no_writes = "the server does not authenticate callers, so no write was attempted"
    for name in WRITE_PATHS:
        if why_no_writes:
            paths.append({"name": name, "what": _WRITE_WHAT[name], "outcome": P_NOT_RUN,
                          "note": why_no_writes})
            continue
        touch = "st-touch-" + secrets.token_hex(8)
        proof = "st-ctl-" + secrets.token_hex(8)
        if name == "thread_update":
            target = new_thread()
            route = f"/threads/{target}"
            if target:
                a.call("PATCH", route, {"metadata": {"st_ctl": proof}})
            before = a.call("GET", route) if target else _Response(0, "")
            attempt = b.call("PATCH", route, {"metadata": {"st_touch": touch}}) if target \
                else _Response(0, "")
            after = a.call("GET", route) if target else _Response(0, "")
            write_result(name, bool(target) and proof in before.body and marker in before.body,
                         f"A could not update her own thread (HTTP {before.status})",
                         attempt, after, touch in after.body or gone(after),
                         marker in after.body)
        elif name == "store_put_overwrite":
            key = "st-item-put"
            a.call("PUT", "/store/items", {"namespace": namespace, "key": key,
                                          "value": {"text": marker}})
            before = a.call("GET", item_route(key))
            attempt = b.call("PUT", "/store/items", {"namespace": namespace, "key": key,
                                                    "value": {"text": touch}})
            after = a.call("GET", item_route(key))
            write_result(name, marker in before.body,
                         f"A could not write and read back her own item (HTTP {before.status})",
                         attempt, after, touch in after.body or gone(after),
                         marker in after.body)
        elif name == "thread_delete":
            spare, target = new_thread(), new_thread()
            if spare:
                a.call("DELETE", f"/threads/{spare}")
            spare_after = a.call("GET", f"/threads/{spare}") if spare else _Response(0, "")
            before = a.call("GET", f"/threads/{target}") if target else _Response(0, "")
            control_ok = bool(spare and target) and gone(spare_after) and marker in before.body
            attempt = b.call("DELETE", f"/threads/{target}") if control_ok else _Response(0, "")
            after = a.call("GET", f"/threads/{target}") if control_ok else _Response(0, "")
            write_result(name, control_ok,
                         f"A could not delete a thread of her own (re-read HTTP {spare_after.status})",
                         attempt, after, gone(after), marker in after.body)
        else:  # store_delete
            spare_key, key = "st-item-ctl", "st-item-del"
            for each in (spare_key, key):
                a.call("PUT", "/store/items", {"namespace": namespace, "key": each,
                                              "value": {"text": marker}})
            spare_before = a.call("GET", item_route(spare_key))
            a.call("DELETE", "/store/items", {"namespace": namespace, "key": spare_key})
            spare_after = a.call("GET", item_route(spare_key))
            before = a.call("GET", item_route(key))
            control_ok = (marker in spare_before.body and gone(spare_after)
                          and marker in before.body)
            attempt = b.call("DELETE", "/store/items", {"namespace": namespace, "key": key}) \
                if control_ok else _Response(0, "")
            after = a.call("GET", item_route(key)) if control_ok else _Response(0, "")
            write_result(name, control_ok,
                         f"A could not delete an item of her own (re-read HTTP {spare_after.status})",
                         attempt, after, gone(after), marker in after.body)

    controls["whoami_a"] = _fp(whoami["a"]) if whoami["a"] else None
    controls["whoami_b"] = _fp(whoami["b"]) if whoami["b"] else None

    # -- grade --------------------------------------------------------------
    leaked = [p["name"] for p in paths if p["outcome"] == P_LEAK]
    accepted = [p["name"] for p in paths if p["outcome"] == P_OBSERVATION]
    exercised = [p["name"] for p in paths if p["outcome"] in (P_LEAK, P_OK, P_OBSERVATION)]
    skipped = [p["name"] for p in paths if p["outcome"] == P_NOT_EXERCISED]
    if skipped:
        observations.append("not exercised (a positive control did not hold): " + ", ".join(skipped))
    controls["edge_sees_a_namespace_name"] = sorted(set(edge_sees_name))

    if not auth_enforced:
        observations.append(
            f"a request with no token got HTTP {anonymous.status} and one with a made-up token got "
            f"HTTP {made_up.status}")
        return report(OBSERVATION,
                      "the server does not authenticate callers, so A and B are the same principal; "
                      "nothing here can be called a cross-user leak. Add authentication first.")

    same_principal = whoami["a"] is not None and whoami["a"] == whoami["b"]
    if leaked and same_principal:
        return report(OBSERVATION,
                      "B read A's marker, but the app reports the same identity for both tokens, "
                      "so this is one principal reading its own data.")
    if leaked:
        written = [name for name in leaked if name in WRITE_PATHS]
        by_edge = [name for name in leaked if name in EDGE_PATHS.values()
                   and name != EDGE_PATHS["prefix"]]
        detail = (f"identity B read identity A's memory on {len(leaked)} of {len(exercised)} "
                  f"paths: {', '.join(leaked)}.")
        if written or by_edge:
            detail = (f"another identity reached identity A's memory on {len(leaked)} of "
                      f"{len(exercised)} paths: {', '.join(leaked)}.")
        if written:
            detail += " A write crossed identities on: " + ", ".join(written) + "."
        if by_edge:
            detail += " An awkward-id identity read A's item on: " + ", ".join(by_edge) + "."
        return report(LEAK, detail)
    if not exercised:
        return report(INCONCLUSIVE,
                      "no path could be exercised: A could not read her own marker back anywhere.")
    if accepted:
        return report(OBSERVATION,
                      "B could not read or change A's memory, but the server accepted B's write "
                      "call on: " + ", ".join(accepted) + " (A's data did not change).")
    if namespace_visible or edge_sees_name:
        return report(OBSERVATION,
                      "B could not read A's memory, but B can see that A's memory namespace exists.")
    return report(OK, f"identity B could not read identity A's memory on any of the "
                      f"{len(exercised)} exercised paths.")
