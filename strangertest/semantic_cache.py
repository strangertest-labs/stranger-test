"""Cross-user semantic-cache leak probe.

A semantic (LLM/response) cache remembers one caller's answer and serves it to a
later, similar query. If identity is not part of the lookup, caller B gets
caller A's cached answer -- a cross-user leak that fails quietly, because B asks
a *similar* question and never names A's data.

This probe acts as two identities against a cache you run. Identity A puts a
unique marker answer in the cache; the probe then checks whether identity B can
read it back: by the exact question, by a reworded (near-match) question, and --
with a prefix-sibling identity -- from that sibling's own scope. It never writes
anyone's real data and records tokens/markers only as ``sha256:`` fingerprints.

Grades: ``LEAK`` (B obtained A's answer on a path whose positive control held),
``OK`` (no path leaked and at least one was exercised), ``INCONCLUSIVE``
(nothing could be exercised or the cache was unreachable), ``OBSERVATION`` (no
identity / both callers map to one principal).

Two wire shapes (``mode``):

* ``store`` -- a cache with an explicit write: ``POST /store {query,response}``
  and ``POST /query {query,threshold}`` (paths configurable). Matches
  :mod:`strangertest.practice_semantic_cache_http` and a simple real cache.
* ``chat`` -- an LLM gateway with a response cache. There is no store call: A
  sends an OpenAI-style ``POST /v1/chat/completions`` and the gateway caches the
  answer. A repeats the request (positive control: it must be a cache hit), then
  B sends the reworded and the same question.

How each identity is presented is configurable: a header carrying the id
(``x-identity`` by default), a per-identity bearer token or API key
(``Authorization: Bearer <token>``; any other header name carries the raw
value), and in chat mode the OpenAI ``user`` body field.

Recognising a cache hit in chat mode, in this order:

1. A cache-hit response header, when the gateway exposes one. It is calibrated,
   not trusted: it only counts if its value changed between A's first (cold)
   request and A's repeat.
2. The response body: the same response ``id`` as the answer A received (when
   ids differ between separate generations and stay the same on a hit), or A's
   marker in the answer to a question that did not carry it.

A header hit is not counted as A's entry when the response ``id`` shows it is a
different one (B hitting its own earlier entry).

Awkward ids (``edge_cases``, ``edge_identity``, ``edge_user``): an extra
identity whose id sloppy cache-key code confuses with A's asks A's question in
its own scope. The kinds are ``prefix`` (``ali`` / ``alice``), ``dot``
(``acme`` / ``acme.alice``), ``separator`` (``:`` ``/`` ``|`` in the id),
``wildcard`` (``%`` ``_`` ``*``), ``case`` and ``whitespace``. The probe makes
such ids up itself only for plain header ids, and only when asked to
(``edge_cases``); a credential is never made up, it has to be given. Each case
has its own positive control: the extra identity must get its own entry back.

Chat mode can run the whole sequence on several routes (``route``): OpenAI
chat-completions, OpenAI Responses and Anthropic Messages, each graded on its
own, plus a cross-route path (A asks on the first route, B on another). With
``stream`` every request asks for server-sent events and the answer is put
back together before the same checks.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .guard import authorize

LEAK, OBSERVATION, OK, INCONCLUSIVE = "LEAK", "OBSERVATION", "OK", "INCONCLUSIVE"
P_LEAK, P_OK, P_NOT_EXERCISED, P_NOT_RUN = "LEAK", "OK", "NOT_EXERCISED", "NOT_RUN"

MODES = ("store", "chat")
IDENTITY_CARRIERS = ("header", "bearer")
DEFAULT_IDENTITY_HEADER = "x-identity"
DEFAULT_TOKEN_HEADER = "Authorization"
DEFAULT_STORE_PATH = "/store"
DEFAULT_QUERY_PATH = "/query"
DEFAULT_CHAT_PATH = "/v1/chat/completions"
ROUTE_SHAPES = ("chat", "responses", "messages")
DEFAULT_ROUTE_PATHS = {"chat": DEFAULT_CHAT_PATH, "responses": "/v1/responses",
                       "messages": "/v1/messages"}
EDGE_KINDS = ("prefix", "dot", "separator", "wildcard", "case", "whitespace")
DEFAULT_MODEL = "gpt-4o-mini"
# Tried in order when no header is named. LiteLLM returns x-litellm-cache-key.
CACHE_HIT_HEADERS = ("x-litellm-cache-key", "x-cache", "x-cache-status",
                     "x-cache-hit", "cf-cache-status")
_MISS_WORDS = {"", "miss", "false", "0", "no", "none", "bypass", "expired", "dynamic"}

_SSE_LIMIT = 4 * 1024 * 1024        # stop reading a stream after this many bytes

__all__ = ["LEAK", "OBSERVATION", "OK", "INCONCLUSIVE", "MODES", "EDGE_KINDS",
           "ROUTE_SHAPES", "SemanticCacheReport", "edge_path_name",
           "run_semantic_cache_probe"]


def _fp(value: Optional[str]) -> Optional[str]:
    return None if value is None else "sha256:" + hashlib.sha256(value.encode()).hexdigest()[:12]


@dataclass
class _Response:
    status: int
    body: str
    error: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    rid: Optional[str] = None          # response id read from an event stream
    streamed: bool = False

    def json(self) -> Any:
        try:
            return json.loads(self.body)
        except ValueError:
            return None

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def header(self, name: Optional[str]) -> Optional[str]:
        if not name:
            return None
        value = self.headers.get(name.lower())
        return None if value is None else value.strip().lower()

    def answer_id(self) -> Optional[str]:
        if self.streamed:
            return self.rid
        j = self.json()
        rid = j.get("id") if isinstance(j, dict) else None
        return rid if isinstance(rid, str) and rid else None


@dataclass(frozen=True)
class _Identity:
    """One caller: any of a credential, an id header value, and a ``user`` field."""
    token: Optional[str] = None
    header_id: Optional[str] = None
    user: Optional[str] = None

    def parts(self) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        return (self.token, self.header_id, self.user)

    @property
    def present(self) -> bool:
        return any(p is not None for p in self.parts())

    def fingerprint(self) -> Optional[str]:
        given = [p for p in self.parts() if p is not None]
        return _fp("\x00".join(given)) if given else None


@dataclass(frozen=True)
class _Wire:
    base: str
    identity_header: str
    token_header: str
    api_key: Optional[str]
    timeout: float

    def _credential(self, value: str) -> str:
        return f"Bearer {value}" if self.token_header.lower() == "authorization" else value

    def headers(self, who: Optional[_Identity]) -> Dict[str, str]:
        out = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.api_key is not None:
            out[self.token_header] = self._credential(self.api_key)
        if who is not None:
            if who.token is not None:
                out[self.token_header] = self._credential(who.token)
            if who.header_id is not None:
                out[self.identity_header] = who.header_id
        return out

    def post(self, who: Optional[_Identity], path: str, body: Any, *,
             extra: Optional[Dict[str, str]] = None, stream: bool = False) -> _Response:
        data = json.dumps(body).encode("utf-8")
        headers = self.headers(who)
        headers.update(extra or {})
        if stream:
            headers["Accept"] = "text/event-stream, application/json"
        req = urllib.request.Request(self.base + path, data=data, method="POST",
                                     headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                got = {k.lower(): v for k, v in r.headers.items()}
                if stream and "text/event-stream" in got.get("content-type", "").lower():
                    text, rid = _read_event_stream(r)
                    return _Response(r.status, text, headers=got, rid=rid, streamed=True)
                return _Response(r.status, r.read().decode("utf-8", "replace"), headers=got)
        except urllib.error.HTTPError as exc:
            return _Response(exc.code, exc.read().decode("utf-8", "replace"),
                             headers={k.lower(): v for k, v in exc.headers.items()})
        except Exception as exc:
            return _Response(0, "", f"{type(exc).__name__}: {exc}")


def _read_event_stream(lines) -> Tuple[str, Optional[str]]:
    """(reassembled answer text, response id) from a server-sent-event stream in
    the chat-completions, Responses or Messages event format."""
    pieces: List[str] = []
    rid: Optional[str] = None
    size = 0
    for raw in lines:
        size += len(raw)
        if size > _SSE_LIMIT:
            break
        line = raw.decode("utf-8", "replace").strip()
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if data == "[DONE]":
            break
        try:
            event = json.loads(data)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        if rid is None:
            for holder in (event.get("response"), event.get("message"), event):
                if isinstance(holder, dict) and isinstance(holder.get("id"), str) and holder["id"]:
                    rid = holder["id"]
                    break
        delta = event.get("delta")
        choices = event.get("choices")
        if isinstance(choices, list) and choices and isinstance(choices[0], dict):
            delta = choices[0].get("delta")
            delta = delta.get("content") if isinstance(delta, dict) else None
        elif isinstance(delta, dict):               # Messages: {"type": "text_delta", "text"}
            delta = delta.get("text")
        elif event.get("type") != "response.output_text.delta":
            delta = None
        if isinstance(delta, str):
            pieces.append(delta)
        if event.get("type") in ("message_stop", "response.completed"):
            break
    return "".join(pieces), rid


@dataclass
class SemanticCacheReport:
    target: str
    grade: str
    detail: str
    paths: List[Dict[str, Any]] = field(default_factory=list)
    controls: Dict[str, Any] = field(default_factory=dict)
    observations: List[str] = field(default_factory=list)
    fingerprints: Dict[str, Any] = field(default_factory=dict)

    @property
    def leaked(self) -> bool:
        return self.grade == LEAK

    def to_dict(self) -> Dict[str, Any]:
        return {"probe": "semantic-cache", "target": self.target, "grade": self.grade,
                "detail": self.detail, "paths": self.paths, "controls": self.controls,
                "observations": self.observations, "fingerprints": self.fingerprints}

    def summary(self) -> str:
        lines = [f"{self.grade}: {self.detail}"]
        for p in self.paths:
            note = f" ({p['note']})" if p.get("note") else ""
            lines.append(f"  {p['outcome']:<14} {p['name']}: {p['what']}{note}")
        for o in self.observations:
            lines.append(f"  note: {o}")
        return "\n".join(lines)


# A base question and a reworded near-match that shares its content words, so a
# token-overlap cache treats the second as a semantic hit on the first.
_BASE_QUERY = "What is the wire transfer limit for the Falcon account?"
_REWORDED = "How much can the Falcon account send by wire transfer?"
# Further routes get a pair on another subject, so that an entry made on one
# route is not a near-match for the question asked on the next.
_TOPICS = (
    (_BASE_QUERY, _REWORDED),
    ("What is the daily card withdrawal cap for the Osprey customer?",
     "How large is the Osprey customer daily card withdrawal cap?"),
    ("What is the yearly interest rate on the Heron business loan?",
     "Which yearly interest rate does the Heron business loan carry?"),
)
_CROSS_QUERY = "What is the monthly storage quota for the Kestrel archive?"

_HEADER_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
_SIBLING_WHAT = "a prefix-sibling identity asks A's question in its own scope"
_EDGE_WHAT = {
    "prefix": _SIBLING_WHAT,
    "dot": "an identity whose id differs from A's by a dotted part asks A's question "
           "in its own scope",
    "separator": "an identity whose id has a key separator (: / |) in it asks A's question "
                 "in its own scope",
    "wildcard": "an identity whose id has a wildcard (% _ *) that matches A's id asks A's "
                "question in its own scope",
    "case": "an identity whose id differs from A's only in letter case asks A's question "
            "in its own scope",
    "whitespace": "an identity whose id is A's with a leading or trailing space asks A's "
                  "question in its own scope",
}
_EDGE_RELATION = {
    "prefix": "is a string prefix of A's (ali / alice)",
    "dot": "differs from A's by a dotted part (acme / acme.alice)",
    "separator": "is A's with a key separator and more after it (alice / alice:x)",
    "wildcard": "has a wildcard that matches A's (alic% / alice)",
    "case": "differs from A's only in letter case (Alice / alice)",
    "whitespace": "is A's with a leading or trailing space",
}
_HEADER_WHITESPACE = ("an HTTP header cannot carry leading or trailing whitespace, so this "
                      "case needs an identity behind a credential (--edge-identity "
                      "whitespace=...) or in the user field (--edge-user whitespace=...)")
_ROUTE_HEADERS = {"messages": {"anthropic-version": "2023-06-01"}}
_NOT_SERVED = (404, 405, 501)


def edge_path_name(kind: str) -> str:
    """The report's path name for an awkward-id case."""
    return "prefix_sibling" if kind == "prefix" else "edge_" + kind


def _header_name(value: Optional[str], default: str, option: str) -> str:
    name = default if value is None else value.strip()
    if not _HEADER_NAME.match(name):
        raise ValueError(f"--{option} is not a valid header name")
    return name


def _path(value: Optional[str], default: str, option: str) -> str:
    path = default if value is None else value.strip()
    if not path.startswith("/") or any(c in path for c in " \r\n"):
        raise ValueError(f"--{option} must be a path starting with /")
    return path


# None of the option errors below repeat what was typed: it may be a credential.

def _edge_cases(value: Any) -> List[str]:
    if value is None:
        return []
    items = value.split(",") if isinstance(value, str) else list(value)
    names = [str(i).strip().lower() for i in items]
    if "all" in names:
        if len(names) > 1:
            raise ValueError("--edge-cases is either 'all' or a list of cases, not both")
        return list(EDGE_KINDS)
    if not names or any(n not in EDGE_KINDS for n in names):
        raise ValueError("--edge-cases must be 'all' or a comma-separated list of: "
                         + ", ".join(EDGE_KINDS))
    return [k for k in EDGE_KINDS if k in names]


def _edge_values(values: Any, option: str, namespaced: bool) -> Dict[str, str]:
    """``KIND=VALUE`` items (or a ready dict) -> {kind: value}."""
    if values is None:
        return {}
    usage = (f"--{option} must be KIND=VALUE, with KIND one of: " + ", ".join(EDGE_KINDS))
    pairs = list(values.items()) if isinstance(values, dict) else []
    if not isinstance(values, dict):
        for item in ([values] if isinstance(values, str) else values):
            kind, sep, value = str(item).partition("=")
            if not sep:
                raise ValueError(usage)
            if namespaced and "@" in value:     # KIND=TOKEN@NAMESPACE: no namespaces here
                value = value.rsplit("@", 1)[0]
            pairs.append((kind, value))
    out: Dict[str, str] = {}
    for kind, value in pairs:
        kind = str(kind).strip().lower()
        if kind not in EDGE_KINDS or not isinstance(value, str) or not value.strip():
            raise ValueError(usage)
        if kind in out:
            raise ValueError(f"--{option} was given more than once for the {kind} case")
        out[kind] = value
    return out


@dataclass(frozen=True)
class _Route:
    name: str           # also the body shape: chat | responses | messages
    path: str


def _routes(values: Any, chat_path: Optional[str]) -> List[_Route]:
    usage = ("--route must be NAME or NAME=PATH, with NAME one of: "
             + ", ".join(ROUTE_SHAPES))
    out: List[_Route] = []
    for item in ([values] if isinstance(values, str) else list(values)):
        name, sep, path = str(item).partition("=")
        name = name.strip().lower()
        if name not in ROUTE_SHAPES:
            raise ValueError(usage)
        if any(r.name == name for r in out):
            raise ValueError(f"--route was given more than once for the {name} route")
        if name == "chat" and chat_path is not None:
            if sep and path.strip() != chat_path.strip():
                raise ValueError("--chat-path and --route chat=PATH name two different paths")
            path, sep = chat_path, "="
        out.append(_Route(name, _path(path if sep else None, DEFAULT_ROUTE_PATHS[name], "route")))
    if not out:
        raise ValueError(usage)
    return out


def _chat_body(shape: str, model: str, text: str, user: Optional[str], stream: bool) -> Dict[str, Any]:
    if shape == "responses":
        body: Dict[str, Any] = {"model": model, "input": text}
    else:
        body = {"model": model, "messages": [{"role": "user", "content": text}]}
    if shape == "messages":
        body["max_tokens"] = 64
        if user is not None:
            body["metadata"] = {"user_id": user}
    elif user is not None:
        body["user"] = user
    if stream:
        body["stream"] = True
    return body


# --------------------------------------------------------------------------- #
# awkward ids                                                                  #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class _Variant:
    """One extra identity for a case. ``a_prefix`` / ``e_prefix`` (store shape)
    are put before the question A stores / the extra identity asks, to line up
    ``id + separator + question`` keys."""
    who: _Identity
    source: str
    label: str = ""
    a_prefix: str = ""
    e_prefix: str = ""


@dataclass
class _EdgePlan:
    kind: str
    variants: List[_Variant] = field(default_factory=list)
    reason: str = ""            # why the case is NOT_RUN, when there are no variants

    @property
    def name(self) -> str:
        return edge_path_name(self.kind)

    @property
    def what(self) -> str:
        return _EDGE_WHAT[self.kind]


def _derive(kind: str, aid: str) -> Any:
    """Ids related to header id ``aid``: [(label, id, a_prefix, e_prefix)], or
    the reason there is none."""
    if kind == "prefix":
        if len(aid) < 2:
            return "A's id is a single character, so it has no shorter prefix"
        return [("", aid[:-1], "", "")]
    if kind == "dot":
        out = [("longer id", aid + ".st", "", "")]
        if "." in aid and aid.split(".")[0]:
            out.append(("shorter id", aid.split(".")[0], "", ""))
        return out
    if kind == "separator":
        out = []
        for sep in ":/|":
            out.append((f"'{sep}'", aid + sep + "st", "st" + sep, ""))
            head, found, rest = aid.partition(sep)
            if found and head and rest:
                out.append((f"'{sep}' shorter id", head, "", rest + sep))
        return out
    if kind == "wildcard":
        return [(f"'{w}'", aid[:-1] + w, "", "") for w in "%_*"]
    if kind == "case":
        if aid.swapcase() == aid:
            return "A's id has no letters, so there is no other-case form of it"
        return [("", aid.swapcase(), "", "")]
    return _HEADER_WHITESPACE


def _plan_edges(mode: str, identity_as: str, a: _Identity, b: _Identity,
                requested: List[str], given_ids: Dict[str, str],
                given_users: Dict[str, str]) -> List[_EdgePlan]:
    """Which extra identity (if any) asks for each case. ``prefix`` is always
    listed; the other cases only when asked for or given an identity."""
    plans = []
    for kind in EDGE_KINDS:
        value, user = given_ids.get(kind), given_users.get(kind)
        given = value is not None or user is not None
        if kind != "prefix" and kind not in requested and not given:
            continue
        plan = _EdgePlan(kind)
        plans.append(plan)
        if given:
            who = (_Identity(token=value, user=user) if identity_as == "bearer"
                   else _Identity(header_id=value, user=user))
            if kind == "whitespace" and user is None and identity_as == "header":
                plan.reason = _HEADER_WHITESPACE
            elif who.parts() in (a.parts(), b.parts()):
                plan.reason = ("the prefix-sibling identity is the same as identity A or B"
                               if kind == "prefix" else
                               "the identity given for this case is the same as identity A or B")
            else:
                plan.variants.append(_Variant(who, "asked as the third (prefix-sibling) identity"
                                              if kind == "prefix" else
                                              "asked as the identity given for this case"))
        elif (kind == "prefix" and mode == "store" and a.header_id and b.header_id
              and a.header_id != b.header_id and a.header_id.startswith(b.header_id)):
            plan.variants.append(_Variant(b, "B's id is a string prefix of A's"))
        elif (kind in requested and a.header_id is not None and a.token is None
              and a.user is None):
            derived = _derive(kind, a.header_id)
            if isinstance(derived, str):
                plan.reason = derived
                continue
            for label, new_id, a_prefix, e_prefix in derived:
                if not new_id.strip() or new_id == a.header_id:
                    continue
                who = b if new_id == b.header_id else _Identity(header_id=new_id)
                plan.variants.append(_Variant(who, "the id was made from A's", label,
                                              a_prefix, e_prefix))
            if not plan.variants:
                plan.reason = "no id of this kind could be made from A's id"
        elif kind == "prefix" and a.token is not None:
            plan.reason = ("no third identity given: pass the token of an identity whose id "
                           "is a string prefix of A's (--token-sibling)")
        elif kind == "prefix":
            plan.reason = ("give a prefix-sibling pair (id_b a string prefix of id_a, e.g. "
                           "ali / alice), or a third identity with --token-sibling / "
                           "--user-sibling")
        else:
            option = (f"--edge-identity {kind}=..." if a.token is not None or a.header_id
                      is not None else f"--edge-user {kind}=...")
            plan.reason = (f"no identity given for this case: pass one whose id "
                           f"{_EDGE_RELATION[kind]} ({option})")
    return plans


def _merge_variants(plan: _EdgePlan, results: List[Tuple[str, Any, str]]) -> Dict[str, Any]:
    """One path entry from the (outcome, HTTP status, reason) of each variant."""
    outcomes = [r[0] for r in results]
    outcome = (P_LEAK if P_LEAK in outcomes else P_OK if P_OK in outcomes
               else P_NOT_EXERCISED)
    note = plan.variants[0].source
    if len(results) > 1:
        note += "; " + ", ".join(f"{v.label} {r[0]}" for v, r in zip(plan.variants, results))
    why = next((r[2] for r in results if r[0] == outcome and r[2]), "")
    if why:
        note += "; " + why
    entry = {"name": plan.name, "what": plan.what, "outcome": outcome, "note": note}
    status = next((r[1] for r in results if r[0] == outcome), None)
    if status is not None and outcome != P_NOT_EXERCISED:
        entry["b_status"] = status
    return entry


def run_semantic_cache_probe(
    url: str,
    id_a: Optional[str],
    id_b: Optional[str],
    *,
    base_query: Optional[str] = None,
    reworded_query: Optional[str] = None,
    threshold: Optional[float] = None,
    timeout: float = 20.0,
    authorized: bool = False,
    authorization_note: Optional[str] = None,
    mode: Optional[str] = None,
    identity_as: Optional[str] = None,
    identity_header: Optional[str] = None,
    token_header: Optional[str] = None,
    api_key: Optional[str] = None,
    sibling: Optional[str] = None,
    user_a: Optional[str] = None,
    user_b: Optional[str] = None,
    user_sibling: Optional[str] = None,
    store_path: Optional[str] = None,
    query_path: Optional[str] = None,
    chat_path: Optional[str] = None,
    model: Optional[str] = None,
    cache_hit_header: Optional[str] = None,
    edge_cases: Any = None,
    edge_identity: Any = None,
    edge_user: Any = None,
    route: Any = None,
    stream: Optional[bool] = None,
) -> SemanticCacheReport:
    """Run the probe against the cache at ``url`` as identities A and B.

    ``id_a`` / ``id_b`` are the two identities' values. ``identity_as`` says how
    they are sent: ``"header"`` (in ``identity_header``, default ``x-identity``)
    or ``"bearer"`` (a credential in ``token_header``: ``Authorization: Bearer
    <value>``, or the raw value in any other header). Left unset it is
    ``header`` in store mode and ``bearer`` in chat mode, unless
    ``identity_header`` is given (then ``header``) or only ``token_header`` is
    (then ``bearer``). ``api_key`` is a credential every request shares (for a
    cache that takes one key plus a tenant header or ``user`` field).
    ``user_a`` / ``user_b`` (chat mode) set the OpenAI ``user`` body field.

    Awkward-id cases (see ``EDGE_KINDS``). ``edge_identity`` gives the extra
    identity for a case: ``{kind: value}`` or ``["KIND=VALUE", ...]``, the value
    sent the way ``id_a`` is (``@NAMESPACE`` after it is dropped). ``edge_user``
    is the same for the ``user`` field (chat mode). ``sibling`` /
    ``user_sibling`` are the older names for the ``prefix`` case. ``edge_cases``
    (``"all"`` or a list of kinds) asks for cases by name; for plain header ids
    it also declares them free-form test tenants, and the probe then makes the
    related ids up from A's. It never makes up a credential: with tokens a case
    without a given identity is ``NOT_RUN``. With header ids the prefix case
    also runs when ``id_b`` itself is a prefix of ``id_a`` (store mode).

    Chat mode: ``route`` is a list of ``NAME`` or ``NAME=PATH`` with NAME one
    of ``chat``, ``responses``, ``messages``; each is run and graded on its own
    (path names get ``@NAME``), and a cross-route path is added. ``stream``
    sends every request with ``"stream": true``.

    ``base_query`` / ``reworded_query`` default to a built-in pair whose reworded
    form is a near (not exact) match of the base. In chat mode ``{marker}`` in
    either is replaced by the probe's marker; the base query gets the marker
    appended when it has no placeholder.
    """
    authorize(url, authorized=authorized, authorization_note=authorization_note)

    mode = mode or "store"
    if mode not in MODES:
        raise ValueError(f"--cache-mode must be one of {', '.join(MODES)}")
    if identity_as is None:
        if identity_header is not None:
            identity_as = "header"
        elif token_header is not None:
            identity_as = "bearer"
        else:
            identity_as = "bearer" if mode == "chat" else "header"
    if identity_as not in IDENTITY_CARRIERS:
        raise ValueError(f"--identity-as must be one of {', '.join(IDENTITY_CARRIERS)}")
    if identity_as == "bearer" and api_key is not None and (id_a is not None or id_b is not None):
        raise ValueError("--api-key is a shared credential; it cannot be combined with "
                         "per-identity tokens (--identity-as bearer)")
    if mode != "chat" and any(u is not None for u in (user_a, user_b, user_sibling)):
        raise ValueError("--user-a/--user-b/--user-sibling need --cache-mode chat")
    if mode != "chat" and (edge_user or route or stream):
        raise ValueError("--edge-user, --route and --stream need --cache-mode chat")
    requested = _edge_cases(edge_cases)
    given_ids = _edge_values(edge_identity, "edge-identity", namespaced=True)
    given_users = _edge_values(edge_user, "edge-user", namespaced=False)
    for given, old, option in ((given_ids, sibling, "--token-sibling and --edge-identity"),
                               (given_users, user_sibling, "--user-sibling and --edge-user")):
        if old is not None:
            if given.get("prefix", old) != old:
                raise ValueError(f"{option} prefix=... name two different identities")
            given["prefix"] = old
    wire = _Wire(url.rstrip("/"),
                 _header_name(identity_header, DEFAULT_IDENTITY_HEADER, "identity-header"),
                 _header_name(token_header, DEFAULT_TOKEN_HEADER, "token-header"),
                 api_key, timeout)
    hit_header = (None if cache_hit_header is None
                  else _header_name(cache_hit_header, "", "cache-hit-header"))
    store_path = _path(store_path, DEFAULT_STORE_PATH, "store-path")
    query_path = _path(query_path, DEFAULT_QUERY_PATH, "query-path")
    chat_path = None if chat_path is None else _path(chat_path, DEFAULT_CHAT_PATH, "chat-path")
    routes = (_routes(route, chat_path) if route
              else [_Route("chat", chat_path or DEFAULT_CHAT_PATH)])

    def identity(value: Optional[str], user: Optional[str]) -> _Identity:
        if identity_as == "bearer":
            return _Identity(token=value, user=user)
        return _Identity(header_id=value, user=user)

    a, b = identity(id_a, user_a), identity(id_b, user_b)
    marker = ("stcache" if mode == "chat" else "st-cache-") + secrets.token_hex(8)
    report = SemanticCacheReport(
        url, INCONCLUSIVE, "", fingerprints={
            "id_a": a.fingerprint(), "id_b": b.fingerprint(), "marker": _fp(marker)})
    report.controls["mode"] = mode
    report.controls["identity_carried_by"] = [n for n, used in (
        ("bearer token" if wire.token_header.lower() == "authorization"
         else f"{wire.token_header} header", a.token is not None),
        (f"{wire.identity_header} header", a.header_id is not None),
        ("user field", a.user is not None)) if used]

    def done(grade: str, detail: str) -> SemanticCacheReport:
        report.grade, report.detail = grade, detail
        return report

    if not a.present or not b.present or a.parts() == b.parts():
        return done(INCONCLUSIVE, "two different identities are needed (one per caller).")
    for kind in EDGE_KINDS:
        if kind in given_ids or kind in given_users:
            fp = identity(given_ids.get(kind), given_users.get(kind)).fingerprint()
            if kind == "prefix":
                report.fingerprints["id_sibling"] = fp
            else:
                report.fingerprints.setdefault("edge_ids", {})[kind] = fp
    plans = _plan_edges(mode, identity_as, a, b, requested, given_ids, given_users)

    if mode == "chat":
        return _run_chat(report, done, wire, a, b, plans, marker, routes, bool(route),
                         model or DEFAULT_MODEL, base_query, reworded_query,
                         hit_header, bool(stream))
    return _run_store(report, done, wire, a, b, plans, marker, store_path, query_path,
                      base_query or _BASE_QUERY, reworded_query or _REWORDED, threshold)


def _grade(report: SemanticCacheReport, done, no_control: str) -> SemanticCacheReport:
    """LEAK / OK / INCONCLUSIVE from the per-path outcomes."""
    leaked = [p["name"] for p in report.paths if p["outcome"] == P_LEAK]
    exercised = [p["name"] for p in report.paths if p["outcome"] in (P_LEAK, P_OK)]
    if leaked:
        return done(LEAK, f"identity B read identity A's cached answer on {len(leaked)} of "
                          f"{len(exercised)} paths: {', '.join(leaked)}.")
    if not exercised:
        return done(INCONCLUSIVE, no_control)
    return done(OK, f"identity B could not read identity A's cached answer on any of the "
                    f"{len(exercised)} exercised paths.")


# --------------------------------------------------------------------------- #
# store shape: POST /store, POST /query                                        #
# --------------------------------------------------------------------------- #

def _run_store(report, done, wire, a, b, plans, marker, store_path, query_path,
               base, reworded, threshold) -> SemanticCacheReport:
    controls, observations, paths = report.controls, report.observations, report.paths
    answer = f"{marker}: Falcon wire limit is 48210 USD"

    # -- auth posture (is the cache reachable, does it map callers to principals) --
    anon = wire.post(None, query_path, {"query": base})
    controls["no_identity_status"] = anon.status
    if anon.status == 0:
        return done(INCONCLUSIVE, f"the cache could not be reached ({anon.error}).")

    # -- A stores a private answer --
    stored = wire.post(a, store_path, {"query": base, "response": answer})
    controls["a_store_status"] = stored.status
    if stored.status not in (200, 201, 204):
        return done(INCONCLUSIVE, f"identity A could not store (HTTP {stored.status}).")

    def whoami_of(resp: _Response) -> Optional[str]:
        j = resp.json()
        return j.get("whoami") if isinstance(j, dict) else None

    # -- positive controls: A must read her own back, exact and reworded --
    a_exact = wire.post(a, query_path, {"query": base, "threshold": threshold})
    a_reworded = wire.post(a, query_path, {"query": reworded, "threshold": threshold})
    controls["a_exact_hit"] = marker in a_exact.body
    controls["a_reworded_hit"] = marker in a_reworded.body
    whoami_a = whoami_of(a_exact)

    def path(name: str, what: str, exercised: bool, attempt: _Response, why_not: str = "") -> None:
        if not exercised:
            paths.append({"name": name, "what": what, "outcome": P_NOT_EXERCISED, "note": why_not})
            return
        seen = marker in attempt.body
        paths.append({"name": name, "what": what, "outcome": P_LEAK if seen else P_OK,
                      "b_status": attempt.status, "note": f"B got HTTP {attempt.status}"})

    # -- B reads --
    path("exact", "B asks A's exact question",
         controls["a_exact_hit"], wire.post(b, query_path, {"query": base, "threshold": threshold}),
         "A could not read her own answer exactly")
    path("reworded", "B asks a reworded version of A's question",
         controls["a_reworded_hit"],
         wire.post(b, query_path, {"query": reworded, "threshold": threshold}),
         "A's own reworded query did not hit, so this path proves nothing")

    # -- awkward ids: an extra identity asks A's question in its own scope --
    def variant(v: _Variant, kind: str) -> Tuple[str, Any, str]:
        if v.a_prefix:      # line A's key up with the extra id: id + sep + question
            wire.post(a, store_path, {"query": v.a_prefix + base, "response": answer})
        attempt = None
        for question in [base] + ([v.e_prefix + base] if v.e_prefix else []):
            attempt = wire.post(v.who, query_path, {"query": question, "threshold": threshold})
            if marker in attempt.body:
                return P_LEAK, attempt.status, ""
        # its own positive control: the extra identity stores and reads back its own entry
        own_q, own_r = "unrelated " + secrets.token_hex(4), "st-own-" + secrets.token_hex(6)
        own = wire.post(v.who, store_path, {"query": own_q, "response": own_r})
        if kind == "prefix":
            controls["sibling_store_status"] = own.status
        back = wire.post(v.who, query_path, {"query": own_q, "threshold": threshold})
        if own.status in (200, 201, 204) and own_r in back.body:
            return P_OK, attempt.status, ""
        return P_NOT_EXERCISED, None, ("the extra identity could not store and read back an "
                                       f"entry of its own (HTTP {own.status}, {back.status})")

    for plan in plans:
        if not plan.variants:
            paths.append({"name": plan.name, "what": plan.what, "outcome": P_NOT_RUN,
                          "note": plan.reason})
        elif not controls["a_exact_hit"]:
            paths.append({"name": plan.name, "what": plan.what, "outcome": P_NOT_EXERCISED,
                          "note": "A could not read her own answer exactly"})
        else:
            entry = _merge_variants(plan, [variant(v, plan.kind) for v in plan.variants])
            controls.setdefault("edge_controls", {})[plan.name] = entry["outcome"] != P_NOT_EXERCISED
            paths.append(entry)

    whoami_b = whoami_of(wire.post(b, query_path, {"query": "ping " + secrets.token_hex(2),
                                                   "threshold": threshold}))
    controls["whoami_a"] = _fp(whoami_a) if whoami_a else None
    controls["whoami_b"] = _fp(whoami_b) if whoami_b else None
    no_identity = controls["no_identity_status"] not in (401, 403)
    controls["identity_required"] = not no_identity

    skipped = [p["name"] for p in paths if p["outcome"] == P_NOT_EXERCISED]
    if skipped:
        why = ("A could not read her own answer"
               if not (controls["a_exact_hit"] and controls["a_reworded_hit"])
               else "a positive control failed")
        observations.append(f"not exercised ({why}): " + ", ".join(skipped))

    if no_identity:
        observations.append(f"a query with no identity got HTTP {controls['no_identity_status']}")
        return done(OBSERVATION,
                    "the cache does not identify callers, so A and B are the same principal; "
                    "a shared hit here is not a cross-user leak.")
    leaked = any(p["outcome"] == P_LEAK for p in paths)
    if leaked and whoami_a is not None and whoami_a == whoami_b:
        return done(OBSERVATION,
                    "B got A's cached answer, but the cache reports one principal for both "
                    "identities, so this is one principal reading its own data.")
    return _grade(report, done,
                  "no path could be exercised: A could not read her own cached answer back.")


# --------------------------------------------------------------------------- #
# chat shape: POST /v1/chat/completions (and the other model routes) through a #
# caching gateway                                                              #
# --------------------------------------------------------------------------- #

def _question(template: str, marker: str, append: bool) -> Tuple[str, bool]:
    """(text, carries_marker). The base question always carries the marker."""
    if "{marker}" in template:
        return template.replace("{marker}", marker), True
    if append:
        return f"{template} (ref {marker})", True
    return template, False


def _fresh(text: str) -> str:
    return f"{text} (ref stcache{secrets.token_hex(8)})"


class _Unreachable(Exception):
    pass


class _RouteRun:
    """What one route's own A-then-B sequence established about recognising hits."""

    def __init__(self) -> None:
        self.served = False
        self.why = ""                   # why not, for the cross-route path
        self.not_run = False
        self.header: Optional[str] = None
        self.cold_value: Optional[str] = None
        self.hit_value: Optional[str] = None
        self.ids_mark_hits = False

    def header_hit(self, resp: _Response) -> bool:
        if self.header is None:
            return False
        value = resp.header(self.header)
        if value is None or value == self.cold_value or value in _MISS_WORDS:
            return False
        return value == self.hit_value or self.cold_value is None


def _run_chat(report, done, wire, a, b, plans, marker, routes, named, model,
              base, reworded, named_header, stream) -> SemanticCacheReport:
    """``named`` is True when routes were asked for by name: path names then get
    ``@route`` and the per-route controls go under ``controls["routes"]``."""
    controls, observations, paths = report.controls, report.observations, report.paths
    one_question = base is not None     # the caller's own question is used on every route
    if stream:
        controls["stream"] = True
    anon_ok: List[int] = []
    tried_control = False

    def ask(route: _Route, who: Optional[_Identity], text: str) -> _Response:
        body = _chat_body(route.name, model, text, who.user if who is not None else None, stream)
        return wire.post(who, route.path, body, extra=_ROUTE_HEADERS.get(route.name),
                         stream=stream)

    def add(name: str, what: str, outcome: str, note: str) -> None:
        paths.append({"name": name, "what": what, "outcome": outcome, "note": note})

    def run_route(index: int, route: _Route) -> Any:
        """A ``_RouteRun``, or a finished report in the one-route form."""
        nonlocal tried_control
        run = _RouteRun()
        rc: Dict[str, Any] = controls["routes"].setdefault(route.name, {}) if named else controls
        tag = f"@{route.name}" if named else ""
        topic = _TOPICS[index % len(_TOPICS)]
        route_marker = marker if index == 0 else "stcache" + secrets.token_hex(8)
        if index:
            report.fingerprints.setdefault("route_markers", {})[route.name] = _fp(route_marker)
        question, _ = _question(base or topic[0], route_marker, append=True)
        reworded_q, reworded_carries = _question(reworded or topic[1], route_marker, append=False)
        rows = ([("reworded", "B asks a reworded version of A's question"),
                 ("exact", "B asks A's exact question")]
                + [(plan.name, plan.what) for plan in plans])

        def blanket(outcome: str, note: str) -> _RouteRun:
            for name, what in rows:
                add(name + tag, what, outcome, note)
            run.why, run.not_run = note, outcome == P_NOT_RUN
            return run

        # -- auth posture: does the gateway answer a caller who presents no identity? --
        anon = ask(route, None, _fresh("Reply with the single word ready."))
        rc["no_identity_status"] = anon.status
        if anon.status == 0:
            raise _Unreachable(anon.error)
        if anon.ok:
            anon_ok.append(anon.status)

        # -- A: an unrelated question first (a separate generation, to compare ids),
        #    then the question that seeds the cache --
        other = ask(route, a, _fresh("Name one primary colour."))
        rc["a_first_status"] = other.status
        if not other.ok and other.status in _NOT_SERVED and named:
            return blanket(P_NOT_RUN, f"the server does not serve this route (HTTP {other.status})")
        if other.ok and stream and not other.streamed:
            return blanket(P_NOT_RUN, "the server did not answer with an event stream, so the "
                                      "streaming variant was not run")
        seed = ask(route, a, question) if other.ok else other
        if other.ok:
            rc["a_seed_status"] = seed.status
        if not seed.ok:
            if not named:
                return done(INCONCLUSIVE,
                            f"identity A could not get an answer (HTTP {seed.status}).")
            return blanket(P_NOT_EXERCISED, "identity A could not get an answer on this route "
                                            f"(HTTP {seed.status})")
        seed_id = seed.answer_id()
        run.served = tried_control = True

        # -- positive control: A repeats the request; it must be a cache hit --
        repeat = ask(route, a, question)
        for name in ([named_header] if named_header else list(CACHE_HIT_HEADERS)):
            cold, warm = seed.header(name), repeat.header(name)
            if warm is not None and warm != cold and warm not in _MISS_WORDS:
                run.header, run.cold_value, run.hit_value = name, cold, warm
                break
        if named_header and run.header is None:
            observations.append(f"the {named_header} header did not change between A's first "
                                "request and her repeat, so it was not used to recognise hits")
        ids_differ = bool(seed_id and other.answer_id() and seed_id != other.answer_id())
        ids_mark_hits = run.ids_mark_hits = ids_differ and repeat.ok and repeat.answer_id() == seed_id
        header, header_hit = run.header, run.header_hit
        rc["cache_hit_header"] = header
        rc["response_ids_mark_hits"] = ids_mark_hits
        rc["a_exact_hit"] = repeat.ok and (header is not None or ids_mark_hits)
        rc["hit_recognised_by"] = [n for n, used in (
            ("cache-hit header", header is not None), ("response id", ids_mark_hits)) if used]

        def marker_in_answer(resp: _Response, carried: bool) -> bool:
            return (not carried) and route_marker in resp.body

        def judge(resp: _Response, carried: bool, own_entry_possible: bool) -> Tuple[str, str]:
            """(outcome, note) for a response another identity received."""
            if not resp.ok:
                return P_OK, f"got HTTP {resp.status}"
            rid = resp.answer_id()
            if ids_mark_hits and rid == seed_id:
                return P_LEAK, "same response id as the answer A received"
            if marker_in_answer(resp, carried):
                return P_LEAK, "A's marker is in the answer to a question that did not carry it"
            if header_hit(resp):
                if ids_mark_hits and rid:
                    return P_OK, "a cache hit, but on a different entry than A's"
                if own_entry_possible:
                    return P_NOT_EXERCISED, ("the gateway reported a cache hit, but it may be this "
                                             "identity's own earlier entry and no response id tells")
                return P_LEAK, f"the {header} header reported a cache hit"
            return P_OK, f"got HTTP {resp.status}, not A's cached answer"

        # On a later route the same identities have already asked the caller's
        # one question on an earlier route, so a hit may be their own entry.
        asked_before = one_question and index > 0

        # -- reworded path first: B has sent nothing yet, so a hit can only be A's entry --
        a_reworded = ask(route, a, reworded_q)
        rc["a_reworded_hit"] = a_reworded.ok and (
            header_hit(a_reworded) or (ids_mark_hits and a_reworded.answer_id() == seed_id)
            or marker_in_answer(a_reworded, reworded_carries))
        b_may_own_entry = asked_before
        if rc["a_reworded_hit"]:
            outcome, note = judge(ask(route, b, reworded_q), reworded_carries, asked_before)
            b_may_own_entry = outcome != P_LEAK
            add(rows[0][0] + tag, rows[0][1], outcome, note)
        else:
            add(rows[0][0] + tag, rows[0][1], P_NOT_EXERCISED,
                "A's own reworded question was not a recognisable cache hit, so this path "
                "proves nothing")

        # -- exact path --
        no_control = "A repeated her own request and no cache hit could be recognised"
        if rc["a_exact_hit"]:
            outcome, note = judge(ask(route, b, question), True, b_may_own_entry)
            add(rows[1][0] + tag, rows[1][1], outcome, note)
        else:
            add(rows[1][0] + tag, rows[1][1], P_NOT_EXERCISED, no_control)

        # -- awkward ids: an extra identity asks A's question, then proves it can
        #    get an entry of its own back (its positive control) --
        #    An earlier extra identity may have cached the same question since; being
        #    served that entry is a leak between two identities just the same.
        answered: Dict[str, Any] = {}       # response id -> the identity it was made for

        def variant(v: _Variant) -> Tuple[str, Any, str]:
            attempt = ask(route, v.who, question)
            outcome, note = judge(attempt, True, asked_before or v.who.parts() == b.parts())
            rid = attempt.answer_id()
            if (outcome == P_OK and attempt.ok and ids_mark_hits
                    and answered.get(rid, v.who.parts()) != v.who.parts()):
                outcome, note = P_LEAK, ("same response id as the answer another of the "
                                         "extra identities received")
            if attempt.ok and rid:
                answered.setdefault(rid, v.who.parts())
            if outcome != P_OK:
                return outcome, attempt.status, note
            own_q = _fresh("Give one word for a calm sea.")
            first, again = ask(route, v.who, own_q), ask(route, v.who, own_q)
            own_hit = first.ok and again.ok and (header_hit(again) or (
                ids_mark_hits and again.answer_id() is not None
                and again.answer_id() == first.answer_id()))
            if own_hit:
                return P_OK, attempt.status, note
            return P_NOT_EXERCISED, None, ("the extra identity did not get its own repeated "
                                           f"request back from the cache (HTTP {again.status})")

        for plan in plans:
            if not plan.variants:
                add(plan.name + tag, plan.what, P_NOT_RUN, plan.reason)
            elif not rc["a_exact_hit"]:
                add(plan.name + tag, plan.what, P_NOT_EXERCISED, no_control)
            else:
                entry = _merge_variants(plan, [variant(v) for v in plan.variants])
                entry["name"] += tag
                entry.pop("b_status", None)
                rc.setdefault("edge_controls", {})[plan.name] = entry["outcome"] != P_NOT_EXERCISED
                paths.append(entry)
        return run

    def cross_route(first: _Route, run1: _RouteRun, route: _Route, run: _RouteRun) -> None:
        """A asks a new question on the first route; B asks it on ``route``."""
        name = f"cross_route@{route.name}"
        what = f"A asks on the {first.name} route, B asks the same question on this route"
        for r, state in ((first, run1), (route, run)):
            if not state.served:
                return add(name, what, P_NOT_RUN if state.not_run else P_NOT_EXERCISED,
                           f"the {r.name} route could not be used: {state.why}")
        question, _ = _question(base or _CROSS_QUERY, "stcache" + secrets.token_hex(8), append=True)
        seed = ask(first, a, question)
        own = ask(route, a, question) if seed.ok else seed
        seed_id = seed.answer_id()
        same_id = run1.ids_mark_hits and own.ok and seed_id is not None and own.answer_id() == seed_id
        rc = controls["routes"][route.name]
        rc["a_cross_route_hit"] = bool(own.ok and (same_id or run.header_hit(own)))
        if not rc["a_cross_route_hit"]:
            return add(name, what, P_NOT_EXERCISED,
                       "A's own question from the first route was not a recognisable cache hit "
                       "on this route, so this path proves nothing")
        got = ask(route, b, question)
        if not got.ok:
            return add(name, what, P_OK, f"got HTTP {got.status}")
        if same_id and got.answer_id() == seed_id:
            return add(name, what, P_LEAK, "same response id as the answer A received")
        if run.header_hit(got):
            if same_id and got.answer_id():
                return add(name, what, P_OK, "a cache hit, but on a different entry than A's")
            if one_question:
                return add(name, what, P_NOT_EXERCISED,
                           "the gateway reported a cache hit, but it may be this identity's own "
                           "earlier entry and no response id tells")
            return add(name, what, P_LEAK, f"the {run.header} header reported a cache hit")
        add(name, what, P_OK, f"got HTTP {got.status}, not A's cached answer")

    if named:
        controls["routes"] = {}
    runs: List[_RouteRun] = []
    try:
        for index, route in enumerate(routes):
            result = run_route(index, route)
            if isinstance(result, SemanticCacheReport):
                return result
            runs.append(result)
        for route, run in list(zip(routes, runs))[1:]:
            cross_route(routes[0], runs[0], route, run)
    except _Unreachable as exc:
        return done(INCONCLUSIVE, f"the gateway could not be reached ({exc}).")
    if named:
        per_route = list(controls["routes"].values())
        controls["no_identity_status"] = per_route[0].get("no_identity_status")
        for key in ("a_exact_hit", "a_reworded_hit"):
            controls[key] = any(rc.get(key) is True for rc in per_route)
        if one_question and len(routes) > 1:
            observations.append("the same question was used on every route; a cache that shares "
                                "entries across routes may answer a later route from an earlier "
                                "one's entry")

    skipped = [p["name"] for p in paths if p["outcome"] == P_NOT_EXERCISED]
    if skipped:
        observations.append("not exercised: " + ", ".join(skipped))
    observations.append("chat mode cannot ask the gateway who each caller is; that A and B "
                        "are two different users is taken from the identities you gave")

    controls["identity_required"] = not anon_ok
    if anon_ok:
        observations.append(f"a request with no identity got HTTP {anon_ok[0]}")
        if a.token is not None or a.header_id is not None:
            return done(OBSERVATION,
                        "the gateway answers callers who present no identity, so it does not "
                        "tell A and B apart; a shared hit here is not a cross-user leak.")
        observations.append("the identities differ only in the user field, which this "
                            "gateway does not require")
    if not tried_control:
        return _grade(report, done, "no path could be exercised: " + (runs[0].why or
                                                                      "see the note on each path") + ".")
    return _grade(report, done,
                  "no path could be exercised: A repeated her own request and no cache hit "
                  "could be recognised (no cache-hit header changed and the response id did "
                  "not stay the same).")
