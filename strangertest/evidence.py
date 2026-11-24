"""Evidence of a ``confirm`` result, for a reader who is not a tester.

``stranger-test confirm <test>`` acts as two identities, A and B, against a
system you run, and grades whether B can reach A's data. This module turns one
such result into a short document that an auditor or a customer can read: what
was tested, how, what came back, what it does not show, and a digest that ties
the page to the raw result file.

Two renderings of the same document are offered. The full page
(``render_markdown``) carries everything and prints to several pages. The
summary (``render_summary``) is the short version: the verdict, the tested
paths, the untested ones grouped by reason, the limits and the digest. It is
under half the length of the full page (one to two printed pages against
four) and always points back to the full page.

Usage::

    stranger-test confirm semantic-cache http://127.0.0.1:8080 \\
        --token-a <TOKEN_A> --token-b <TOKEN_B> --json > result.json
    python3 -m strangertest.evidence result.json --out evidence.md

Or in code::

    from strangertest.evidence import build_evidence, render_markdown
    page = render_markdown(build_evidence(report, system_name="Billing API"))

Input
-----
``build_evidence`` takes a report object from any ``confirm`` test (anything
with ``to_dict()``) or the plain dict that ``confirm --json`` prints. The dict
must have:

``probe``   which test produced it: ``agent-memory``, ``semantic-cache``,
            ``statehandle``, ``tasks_idor``, ``elicitation_takeover``,
            ``subscriptions_leak`` or ``confused_deputy``.
``grade``   ``LEAK`` (or ``FAIL``), ``OK``, ``INCONCLUSIVE`` or ``OBSERVATION``.

and may have ``target`` (a URL), ``controls`` (dict), ``fingerprints`` (dict of
``sha256:`` strings), and the per-path results in the form that test uses:
``paths`` (list of ``{name, outcome, b_status}``), ``methods`` / ``checks``
(dict of ``{grade}``), ``entropy`` (``{grade}``) or ``per_call`` (list of
``{grade, label}``).

Hygiene
-------
Nothing is copied from the result unless it is on an allow-list *and* has a safe
type: a known path name, a grade, a boolean, an HTTP status number, or a
``sha256:`` fingerprint. Free text in the result (``detail``, ``note``,
``reason``, ``observations``) is never copied, so a token or a raw marker that
ends up in such a field cannot reach the page. The target URL loses its
userinfo, query string and fragment. All wording on the page comes from this
module.

Standard library only. ``build_evidence`` and the renderers do no I/O.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

SCHEMA = "stranger-test/evidence/1"
TITLE = "Tenant isolation test — evidence of result"

LEAK, OK, INCONCLUSIVE, OBSERVATION, NOT_TESTED = (
    "LEAK", "OK", "INCONCLUSIVE", "OBSERVATION", "NOT_TESTED")

V_FAILURE = "isolation_failure_observed"
V_NONE_OBSERVED = "no_cross_identity_access_observed"
V_INCONCLUSIVE = "inconclusive"
V_OBSERVATION = "observation_only"

_HEADLINES = {
    V_FAILURE: "Isolation failure observed",
    V_NONE_OBSERVED: "No cross-identity access observed on the paths tested",
    V_INCONCLUSIVE: "Inconclusive — the test could not establish a valid baseline",
    V_OBSERVATION: "Observation only — neither a pass nor a failure",
}

PENTEST_LIMIT = ("This evidence supplements, does not replace, an independent "
                 "penetration test.")
MAPPING_DISCLAIMER = ("These mappings are the tool author's suggestion, not an auditor's "
                      "determination. Whether this evidence supports a control is for "
                      "your auditor to decide.")

__all__ = [
    "SCHEMA", "TITLE", "CONTROLS", "CONTROL_MAP", "build_evidence", "render_markdown",
    "render_summary", "render_json", "canonical_digest", "write_evidence", "main",
]


# --------------------------------------------------------------------------- #
# Control mapping. Identifier and a short title only; no text from the         #
# standards themselves.                                                        #
# --------------------------------------------------------------------------- #

CONTROLS: Dict[str, Dict[str, str]] = {
    "API1:2023": {
        "framework": "OWASP API Security Top 10 (2023)",
        "title": "Broken Object Level Authorization",
        "relevance": "The test checks whether one identity can reach an object that "
                     "belongs to another identity.",
    },
    "IVS-06": {
        "framework": "CSA Cloud Controls Matrix",
        "title": "Segmentation and Segregation",
        "relevance": "The test is a direct check that one tenant's data stays apart "
                     "from another tenant's on the paths listed.",
    },
    "LLM08:2025": {
        "framework": "OWASP Top 10 for LLM Applications (2025)",
        "title": "Vector and Embedding Weaknesses",
        "relevance": "Applies where the store under test is looked up by similarity "
                     "(embeddings): the test checks that such a lookup does not cross "
                     "from one identity to another.",
    },
    "CC6.1": {
        "framework": "AICPA Trust Services Criteria (used in SOC 2)",
        "title": "Logical access security (nearest criterion)",
        "relevance": "No Trust Services Criterion names tenant segregation. CC6.1 is the "
                     "nearest: it is about restricting logical access to data. A test that "
                     "one test account cannot reach another's data is one kind of evidence "
                     "about that; whether it counts is the auditor's judgement.",
    },
    "AIS-14": {
        "framework": "CSA AI Controls Matrix",
        "title": "AI Cache Protection",
        "relevance": "The test checks that a cached model answer stored for one "
                     "identity is not served to another.",
    },
}

_SEGREGATION = ("IVS-06", "CC6.1")
_OBJECT_ACCESS = ("API1:2023", "IVS-06", "CC6.1")

# confirm test id -> control identifiers. Deliberately narrow: a control is
# listed only where the test checks exactly what the control is about.
#  - API1 only where B addresses an object that belongs to A by its id.
#  - LLM08 only where the lookup under test is by similarity.
CONTROL_MAP: Dict[str, Tuple[str, ...]] = {
    "state-handle": _OBJECT_ACCESS,
    "confused-deputy": _SEGREGATION,
    "tasks-idor": _OBJECT_ACCESS,
    "elicitation": _SEGREGATION,
    "subscriptions": _SEGREGATION,
    "agent-memory": _OBJECT_ACCESS,
    "semantic-cache": _SEGREGATION + ("LLM08:2025", "AIS-14"),
}


# --------------------------------------------------------------------------- #
# What each test is, in plain words. Every word that reaches the page about a  #
# path comes from here, never from the result.                                 #
# --------------------------------------------------------------------------- #

_TESTS: Dict[str, Dict[str, Any]] = {
    "agent-memory": {
        "probe": "agent-memory",
        "title": "Agent memory isolation (threads and long-term store)",
        "what": "Identity A saved a unique marker in the agent server's memory. The "
                "test then checked whether identity B could read it back from A's "
                "conversation thread, from the memory store, or by asking the agent.",
        "paths": {
            "thread_get": "B reads A's thread by its id",
            "thread_state": "B reads A's saved conversation state",
            "thread_history": "B reads A's conversation history",
            "thread_search": "B lists threads and looks for A's",
            "store_get": "B reads A's memory item by namespace and key",
            "store_search_namespace": "B searches A's memory namespace",
            "store_search_all": "B searches all memory without naming a namespace",
            "store_search_own_prefix": "B searches B's own namespace (ids that share a prefix)",
            "agent_recall": "B asks the agent to recall A's memory",
            "store_edge_dot": "An identity whose id differs from A's by a dot-separated part searches its own namespace",
            "store_edge_separator": "An identity whose id differs from A's by a separator character searches its own namespace",
            "store_edge_wildcard": "An identity whose id contains a wildcard character searches its own namespace",
            "store_edge_case": "An identity whose id differs from A's only in letter case searches its own namespace",
            "store_edge_whitespace": "An identity whose id differs from A's only by whitespace searches its own namespace",
            "owner_in_body_thread_create": "B creates a thread claiming A's id in the body and A can then read it",
            "owner_in_body_store_put": "B writes to A's Store namespace and A reads it back (write path)",
            "thread_update": "B tries to change A's thread by its id (write)",
            "store_put_overwrite": "B tries to overwrite A's memory item (write)",
            "thread_delete": "B tries to delete A's thread by its id (write)",
            "store_delete": "B tries to delete A's memory item (write)",
        },
        "limits": [
            "Only the thread, store and agent-recall paths of the agent server's HTTP "
            "API were tested. Memory reached in other ways (tools, a database, a "
            "different API) was not.",
        ],
    },
    "semantic-cache": {
        "probe": "semantic-cache",
        "title": "Semantic cache cross-user isolation",
        "what": "Identity A stored an answer containing a unique marker in the cache. "
                "The test then checked whether identity B could get that answer back "
                "by asking the same question or a reworded one.",
        "paths": {
            "exact": "B asks A's exact question",
            "reworded": "B asks a reworded version of A's question",
            "prefix_sibling": "B, whose id is a prefix of A's, asks A's question",
            "edge_dot": "An identity whose id differs from A's by a dot-separated part asks A's question",
            "edge_separator": "An identity whose id differs from A's by a separator character asks A's question",
            "edge_wildcard": "An identity whose id contains a wildcard character asks A's question",
            "edge_case": "An identity whose id differs from A's only in letter case asks A's question",
            "edge_whitespace": "An identity whose id differs from A's only by whitespace asks A's question",
            "cross_route": "A asks on one API route; B asks the same question on another",
        },
        "limits": [
            "One question and one rewording were used, at one similarity setting. "
            "Other wordings, thresholds and cache keys were not tested.",
        ],
    },
    "state-handle": {
        "probe": "statehandle",
        "title": "State-handle replay",
        "what": "The server gave identity A a handle to A's state. The test then "
                "presented A's handle as identity B and checked whether B reached "
                "A's state.",
        "paths": {"handle_replay": "B presents A's state handle"},
        "limits": ["Only handle replay was tested, not how handles are generated "
                   "or how long they live."],
    },
    "tasks-idor": {
        "probe": "tasks_idor",
        "title": "Task access across identities",
        "what": "Identity A created a task. The test then checked whether identity B "
                "could read, update or cancel it by its id, and whether task ids can "
                "be guessed.",
        "paths": {
            "get": "B reads A's task by its id",
            "update": "B updates A's task",
            "cancel": "B cancels A's task",
            "enumerate": "B reaches a task by guessing its id",
            "id_entropy": "How guessable the task ids are",
        },
        "limits": ["Only the task get, update and cancel calls and id guessing "
                   "were tested."],
    },
    "elicitation": {
        "probe": "elicitation_takeover",
        "title": "Elicitation binding across identities",
        "what": "Identity A started an authorization request and identity B completed "
                "it. The test checked whose account the resulting grant was tied to.",
        "paths": {
            "binding": "B completes the request A started; whose grant is it",
            "form_secret": "Whether a form asks the user to type a secret",
        },
        "limits": ["Only the start-and-complete flow of one request was tested."],
    },
    "subscriptions": {
        "probe": "subscriptions_leak",
        "title": "Notification delivery across identities",
        "what": "Identity A's resource was changed. The test checked whether identity "
                "B's notification stream received a notice about it.",
        "paths": {"listen_stream": "B's stream receives a notice about A's resource"},
        "limits": ["One resource and one change were used. Other resource types and "
                   "long-lived streams were not tested."],
    },
    "confused-deputy": {
        "probe": "confused_deputy",
        "title": "Acting on behalf of a caller (confused deputy)",
        "what": "The server called an upstream service on behalf of each caller. The "
                "test recorded which credential and which identity reached the "
                "upstream.",
        "paths": {},
        "limits": ["This is a lab test against a recording upstream, not the real "
                   "upstream service."],
    },
}

_PROBE_TO_TEST = {spec["probe"]: test for test, spec in _TESTS.items()}

# confused-deputy per-call labels -> plain words.
_DEPUTY_LABELS = {
    "token_passthrough": "the caller's own token was forwarded to the upstream",
    "wrong_audience": "the upstream received a token meant for a different service",
    "own_authority": "the server acted with its own authority instead of the caller's",
    "exchanged": "a fresh token for this upstream carried the caller's identity",
    "refused": "the server refused the call",
    "inconclusive": "the call could not be judged",
}

# Positive-control and other check names -> plain words. Only these are copied.
_CHECK_LABELS = {
    # agent-memory
    "auth_enforced": "the server refuses callers with no token or a made-up token",
    "no_token_status": "HTTP status for a request with no token",
    "made_up_token_status": "HTTP status for a request with a made-up token",
    "a_create_thread_status": "HTTP status when A created a thread",
    "a_agent_save_status": "HTTP status when A saved through the agent",
    "a_store_put_status": "HTTP status when A wrote to the store",
    "a_agent_recall_sees_marker": "A's own recall through the agent returned her marker",
    "b_sees_a_namespace_name": "B can see that A's namespace exists",
    # semantic-cache
    "no_identity_status": "HTTP status for a query with no identity",
    "identity_required": "the cache refuses callers with no identity",
    "a_store_status": "HTTP status when A stored her answer",
    "a_exact_hit": "A got her own answer back with the exact question",
    "a_reworded_hit": "A got her own answer back with the reworded question",
    "b_store_status": "HTTP status when B stored an answer of his own",
    # state-handle
    "a_own_read": "A read her own state with her own handle",
    "b_own_read": "B read his own state with his own handle",
    "identities": "A and B are different principals",
    "forged_handle": "a made-up handle was refused",
    "canary": "a known-leaky fixture was caught in the same run",
    # tasks
    "own_read": "A read her own task and saw her marker",
    "b_own_update": "B could update his own task",
    "b_own_cancel": "B could cancel his own task",
    "forged_refused": "a made-up task id was refused",
    # subscriptions
    "a_own_stream_fires": "A's own stream received the notice about her resource",
    "b_own_stream_alive": "B's stream received B's own notices",
    # confused-deputy
    "control_reached_upstream": "a harmless call reached the recording upstream",
    "broken_fixture_failed": "a known-broken fixture was caught in the same run",
}

# Free-text control values are reduced to one of these words by their prefix.
_VALUE_PREFIXES = (
    ("passed", "passed"), ("refused", "refused"), ("distinct", "distinct"),
    ("fired", "fired"), ("did not fire", "did_not_fire"), ("collapsed", "collapsed"),
    ("unverified", "unverified"), ("failed", "failed"), ("accepted", "accepted"),
)

_GRADE_MEANING = {
    LEAK: "Identity B obtained identity A's data on this path.",
    OK: "Identity B did not obtain identity A's data on this path.",
    INCONCLUSIVE: "No valid baseline on this path. This is not a pass.",
    OBSERVATION: "Noted for review. Neither a pass nor a failure.",
    NOT_TESTED: "Not tested in this run.",
}
_NO_BASELINE = ("Not tested: identity A could not read her own data this way, so there "
                "was no baseline. Not counted as a pass.")
_NOT_RUN = "Not tested: this path was not run (an optional input was not given)."
_SAME_PRINCIPAL = ("The marker came back, but A and B were not shown to be different "
                   "principals. Neither a pass nor a failure.")

_FP_RE = re.compile(r"^sha256:[0-9a-f]{8,64}$")


# --------------------------------------------------------------------------- #
# Small sanitisers.                                                            #
# --------------------------------------------------------------------------- #

def _fingerprint(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and _FP_RE.match(value) else None


def _status(value: Any) -> Optional[int]:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value <= 599 else None


def _norm_grade(value: Any) -> str:
    text = str(value).strip().upper() if isinstance(value, str) else ""
    if text in ("LEAK", "FAIL"):
        return LEAK
    if text in (OK, OBSERVATION):
        return text
    return INCONCLUSIVE


def _check_value(value: Any) -> Any:
    """A control value reduced to a safe form, or None to drop it."""
    if isinstance(value, bool):
        return value
    if isinstance(value, dict):                       # tasks: {"passed": bool, "detail": "..."}
        return value.get("passed") if isinstance(value.get("passed"), bool) else None
    if _status(value) is not None:
        return value
    if isinstance(value, str):
        fp = _fingerprint(value)
        if fp:
            return fp
        low = value.strip().lower()
        for prefix, word in _VALUE_PREFIXES:
            if low.startswith(prefix):
                return word
    return None


def _clean_text(value: Any, limit: int = 300) -> Optional[str]:
    """Operator-supplied free text: one line, no control characters, capped."""
    if value is None:
        return None
    text = "".join(ch if ch.isprintable() else " " for ch in str(value))
    text = " ".join(text.split())
    return text[:limit] or None


def _clean_url(value: Any) -> Optional[str]:
    """scheme://host[:port]/path with userinfo, query string and fragment removed."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parts = urlsplit(value.strip())
        host, port = parts.hostname, parts.port
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not host:
        return None
    if ":" in host:
        host = "[" + host + "]"
    path = "".join(ch for ch in parts.path if ch.isprintable() and not ch.isspace())
    return f"{parts.scheme}://{host}{':' + str(port) if port else ''}{path}"


def _as_dict(result: Any) -> Dict[str, Any]:
    if isinstance(result, dict):
        return result
    to_dict = getattr(result, "to_dict", None)
    if callable(to_dict):
        data = to_dict()
        if isinstance(data, dict):
            return data
    raise TypeError("result must be a confirm report object (with to_dict()) or a dict")


def _canonical(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      default=str)


def canonical_digest(result: Any) -> str:
    """``sha256:<hex>`` of the result's canonical JSON (sorted keys, no spaces)."""
    return "sha256:" + hashlib.sha256(_canonical(_as_dict(result)).encode("ascii")).hexdigest()


# --------------------------------------------------------------------------- #
# Reading each test's result shape.                                            #
# --------------------------------------------------------------------------- #

def _path(name: str, what: str, grade: str, meaning: Optional[str] = None,
          b_status: Any = None, a_status: Any = None) -> Dict[str, Any]:
    entry: Dict[str, Any] = {"name": name, "what": what, "grade": grade,
                             "meaning": meaning or _GRADE_MEANING[grade]}
    status = _status(b_status)
    if status is not None:
        entry["b_http_status"] = status
    status = _status(a_status)
    if status is not None:
        entry["a_http_status"] = status
    return entry


_ROUTES = {"chat": "chat-completions route", "responses": "responses route",
           "messages": "messages route"}


def _named_paths(raw: Any, known: Dict[str, str]) -> List[Dict[str, Any]]:
    """``paths`` lists (agent-memory, semantic-cache): ``{name, outcome, b_status}``."""
    out: List[Dict[str, Any]] = []
    unknown = 0
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        base, _, route = name.partition("@") if isinstance(name, str) else ("", "", "")
        if isinstance(name, str) and name in known:
            what = known[name]
        elif base in known and route in _ROUTES:   # e.g. "exact@responses"
            what = f"{known[base]} ({_ROUTES[route]})"
        else:                                  # never echo a name we do not recognise
            unknown += 1
            name, what = f"unrecognised_{unknown}", "A path this version does not describe"
        outcome = item.get("outcome")
        if outcome == "LEAK":
            out.append(_path(name, what, LEAK, b_status=item.get("b_status"),
                             a_status=item.get("control_status")))
        elif outcome == "OK":
            out.append(_path(name, what, OK, b_status=item.get("b_status"),
                             a_status=item.get("control_status")))
        elif outcome == "NOT_EXERCISED":
            out.append(_path(name, what, NOT_TESTED, _NO_BASELINE))
        elif outcome == "NOT_RUN":
            out.append(_path(name, what, NOT_TESTED, _NOT_RUN))
        elif outcome == "OBSERVATION":
            out.append(_path(name, what, OBSERVATION))
        else:
            out.append(_path(name, what, INCONCLUSIVE))
    return out


def _graded_map(raw: Any, known: Dict[str, str]) -> List[Dict[str, Any]]:
    """``methods`` / ``checks`` dicts (tasks, elicitation): ``{name: {grade}}``."""
    out = []
    for name, what in known.items():
        item = raw.get(name) if isinstance(raw, dict) else None
        if isinstance(item, dict):
            out.append(_path(name, what, _norm_grade(item.get("grade"))))
    return out


def _extract_paths(test: str, data: Dict[str, Any]) -> List[Dict[str, Any]]:
    known = _TESTS[test]["paths"]
    if test in ("agent-memory", "semantic-cache"):
        return _named_paths(data.get("paths"), known)
    if test == "tasks-idor":
        paths = _graded_map(data.get("methods"), known)
        entropy = data.get("entropy")
        if isinstance(entropy, dict):
            paths.append(_path("id_entropy", known["id_entropy"],
                               _norm_grade(entropy.get("grade"))))
        return paths
    if test == "elicitation":
        return _graded_map(data.get("checks"), known)
    if test == "confused-deputy":
        paths = []
        calls = data.get("per_call")
        for index, call in enumerate(calls if isinstance(calls, list) else [], 1):
            if not isinstance(call, dict):
                continue
            grade = _norm_grade(call.get("grade"))
            label = call.get("label")
            seen = _DEPUTY_LABELS.get(label) if isinstance(label, str) else None
            meaning = _GRADE_MEANING[grade]
            if seen:
                meaning = f"Observed: {seen}."
            paths.append(_path(f"on_behalf_of_call_{index}",
                               "The server calls the upstream for a caller", grade, meaning))
        if not paths:
            paths.append(_path("on_behalf_of_call", "The server calls the upstream for a caller",
                               _norm_grade(data.get("grade"))))
        return paths
    # state-handle and subscriptions check a single path; its grade is the run's grade.
    name, what = next(iter(known.items()))
    return [_path(name, what, _norm_grade(data.get("grade")))]


# Which control decides "A could read her own data back", per test.
_BASELINE_KEY = {
    "state-handle": "a_own_read",
    "tasks-idor": "own_read",
    "subscriptions": "a_own_stream_fires",
    "confused-deputy": "control_reached_upstream",
}


def _positive_control(test: str, data: Dict[str, Any],
                      paths: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    raw = data.get("controls") if isinstance(data.get("controls"), dict) else {}
    checks = []
    for key, label in _CHECK_LABELS.items():
        if key in raw:
            value = _check_value(raw[key])
            if value is not None:
                checks.append({"name": key, "meaning": label, "value": value})
    by_name = {c["name"]: c["value"] for c in checks}

    if test == "agent-memory":
        passed = any(p["grade"] in (LEAK, OK) for p in paths)
    elif test == "semantic-cache":
        passed = by_name.get("a_exact_hit") is True or by_name.get("a_reworded_hit") is True
    elif test == "elicitation":
        passed = None
    else:
        passed = by_name.get(_BASELINE_KEY[test]) in (True, "passed")

    if passed is None:
        status = "not_recorded"
        statement = ("The result file does not record this test's baseline checks "
                     "separately. The test grades itself INCONCLUSIVE when they fail, so "
                     "the overall grade is the only signal here.")
    elif passed:
        status = "passed"
        statement = ("Passed: identity A could read her own data back on at least one "
                     "path, so a refusal to identity B means something.")
    else:
        status = "not_passed"
        statement = ("Not passed: identity A could not be shown to read her own data "
                     "back. Without that baseline a refusal to identity B proves nothing.")
    return {
        "description": "Before judging what B can reach, A must be able to read her own "
                       "data back. Without that, the result is INCONCLUSIVE rather than OK.",
        "status": status,
        "statement": statement,
        "checks": checks,
    }


def _identities(data: Dict[str, Any],
                described: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    fps = data.get("fingerprints") if isinstance(data.get("fingerprints"), dict) else {}
    controls = data.get("controls") if isinstance(data.get("controls"), dict) else {}
    roles = {"A": "Owner of the test data. Plants a unique marker and reads it back.",
             "B": "The other user. Tries to reach A's marker."}
    out = []
    for label in ("A", "B"):
        low = label.lower()
        credential = next((fp for fp in (_fingerprint(fps.get(k)) for k in
                                         (f"token_{low}", f"id_{low}", f"identity_{low}"))
                           if fp), None)
        out.append({
            "label": label,
            "role": roles[label],
            "credential_fingerprint": credential,
            "principal_fingerprint": _fingerprint(controls.get(f"whoami_{low}")),
            "described_as": _clean_text((described or {}).get(label)),
        })
    return out


def _verdict(grade: str, paths: Sequence[Dict[str, Any]], control_status: str) -> Dict[str, Any]:
    count = {g: sum(1 for p in paths if p["grade"] == g)
             for g in (LEAK, OK, INCONCLUSIVE, OBSERVATION, NOT_TESTED)}
    if grade == LEAK or count[LEAK]:
        code = V_FAILURE
        tested = max(len(paths) - count[NOT_TESTED], 1)
        statement = (f"{_HEADLINES[code]}: identity B reached identity A's data on "
                     f"{max(count[LEAK], 1)} of the {tested} path(s) tested.")
        if count[NOT_TESTED]:
            statement += f" {count[NOT_TESTED]} more listed path(s) were not tested."
    elif grade == INCONCLUSIVE or count[INCONCLUSIVE]:
        code = V_INCONCLUSIVE
    elif grade == OBSERVATION:
        code = V_OBSERVATION
        statement = (f"{_HEADLINES[code]}. This is NOT a pass: the run noted something "
                     "to review and does not show that identity B is kept out of "
                     "identity A's data.")
    elif control_status == "not_passed" or not count[OK]:
        code = V_INCONCLUSIVE                 # an OK grade with nothing to back it
    else:
        code = V_NONE_OBSERVED
    if code == V_INCONCLUSIVE:
        statement = (f"{_HEADLINES[code]}. This is NOT a pass: the run does not show "
                     "that identity B is kept out of identity A's data.")
        if count[NOT_TESTED]:
            statement += f" {count[NOT_TESTED]} listed path(s) were not tested."
    elif code == V_NONE_OBSERVED:
        statement = (f"{_HEADLINES[code]}: identity B did not reach identity A's data on "
                     f"any of the {count[OK]} path(s) tested, and the positive control "
                     + ("passed." if control_status == "passed" else "is covered by the "
                        "test's own grade."))
        extras = []
        if count[OBSERVATION]:
            extras.append(f"{count[OBSERVATION]} observation(s) are listed for review")
        if count[NOT_TESTED]:
            extras.append(f"{count[NOT_TESTED]} listed path(s) were not tested")
        if extras:
            statement += " " + "; ".join(extras).capitalize() + "."
    return {
        "code": code,
        "headline": _HEADLINES[code],
        "statement": statement,
        "not_a_pass": code != V_NONE_OBSERVED,
        "test_grade": grade,
        "path_counts": {g.lower(): n for g, n in count.items()},
    }


# Options whose value is a credential or names an identity; the value is
# replaced on the page. Anything else is shown as it was typed.
_SECRET_OPTIONS = {
    "--token-a": "<TOKEN_A>", "--token-b": "<TOKEN_B>", "--token-sibling": "<TOKEN_SIBLING>",
    "--api-key": "<API_KEY>", "--bearer": "<BEARER>", "--key": "<KEY>",
    "--user-a": "<USER_A>", "--user-b": "<USER_B>", "--user-sibling": "<USER_SIBLING>",
}
_KIND_VALUE_OPTIONS = {"--edge-identity": "<TOKEN>", "--edge-user": "<USER>"}
# Options that only shape this page; they are left out of the command.
_PAGE_OPTIONS = ("--evidence",)


def reproduce_command(argv: Sequence[str]) -> Optional[str]:
    """The ``stranger-test`` command line in ``argv`` (everything after the
    program name), with every credential value replaced by a placeholder.

    Returns None when ``argv`` is not a ``confirm`` command, so that a page is
    never given a command it cannot vouch for."""
    words = [str(word) for word in argv]
    if "confirm" not in words:
        return None
    out: List[str] = ["stranger-test"]
    index = 0
    while index < len(words):
        word = words[index]
        name, eq, _ = word.partition("=")
        if any(name == o or name.startswith(o + "-") for o in _PAGE_OPTIONS):
            index += 1 if eq else 2         # drop the option and its value
            continue
        if name in _SECRET_OPTIONS:
            out += [name, _SECRET_OPTIONS[name]]
            index += 1 if eq else 2
            continue
        if name in _KIND_VALUE_OPTIONS:
            value = word.partition("=")[2] if eq else (words[index + 1] if index + 1 < len(words) else "")
            kind = value.partition("=")[0] if "=" in value else "KIND"
            kind = kind if re.fullmatch(r"[a-z_-]{1,20}", kind) else "KIND"
            out += [name, f"{kind}={_KIND_VALUE_OPTIONS[name]}"]
            index += 1 if eq else 2
            continue
        if re.match(r"^https?://", word):
            cleaned = _clean_url(word) or "<TARGET_URL>"
            word = cleaned + ("?<QUERY>" if "?" in word and cleaned != "<TARGET_URL>" else "")
        out.append(word)
        index += 1
    plain = re.compile(r"<[A-Z_]+>|[a-zA-Z_-]{1,20}=<[A-Z_]+>|https?://[^\s'\"]*\?<QUERY>")
    quoted = [w if plain.fullmatch(w) else shlex.quote(w) for w in out]
    return " ".join(quoted)


def _reproduce(test: str, url: Optional[str], command: Optional[str] = None) -> Dict[str, Any]:
    if command:
        return {"commands": [command + " --evidence evidence.md"],
                "exact": True,
                "note": "This is the command that produced this page, with each credential "
                        "replaced by a placeholder in angle brackets. Credentials are never "
                        "written to this page. Run it with the same two test accounts."}
    target = url or "<TARGET_URL>"
    if test in ("confused-deputy", "subscriptions"):
        run = f"stranger-test confirm {test} --demo"
        note = ("This is a lab test: the command runs it against the bundled local "
                "fixtures, not against your system.")
    else:
        run = (f"stranger-test confirm {test} {target} --token-a <TOKEN_A> "
               f"--token-b <TOKEN_B> --json > result.json")
        note = ("<TOKEN_A> and <TOKEN_B> stand for the two test identities' credentials; "
                "they are never written to this page. Add any test-specific options "
                "used in the original run.")
    return {"commands": [run, "python3 -m strangertest.evidence result.json --out evidence.md"],
            "exact": False,
            "note": note + " This page was built from a saved result, so the options of "
                           "the original run are not known to it."}


def _tool_version() -> str:
    try:
        from . import __version__
        return str(__version__)
    except Exception:  # pragma: no cover - only when run outside the package
        return "unknown"


def _timestamp(now: Optional[datetime]) -> str:
    moment = now if now is not None else datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_evidence(result: Any, *, system_name: Optional[str] = None,
                   system_version: Optional[str] = None, environment: Optional[str] = None,
                   operator: Optional[str] = None, notes: Optional[str] = None,
                   now: Optional[datetime] = None,
                   run_started: Optional[datetime] = None,
                   run_finished: Optional[datetime] = None,
                   identity_a: Optional[str] = None, identity_b: Optional[str] = None,
                   command: Optional[Sequence[str]] = None,
                   result_file: Optional[str] = None) -> Dict[str, Any]:
    """Turn one ``confirm`` result into a JSON-serialisable evidence document.

    ``result`` is a report object or the dict ``confirm --json`` prints (see the
    module docstring for its shape). The keyword arguments are the operator's own
    words about the system and are copied as given (one line, capped). ``now``
    sets the timestamp; a naive datetime is read as UTC.
    """
    data = _as_dict(result)
    probe = data.get("probe")
    test = _PROBE_TO_TEST.get(probe) if isinstance(probe, str) else None
    if test is None:
        raise ValueError("not a confirm result: its 'probe' field is missing or unknown "
                         "(expected one of: " + ", ".join(sorted(_PROBE_TO_TEST)) + ")")
    spec = _TESTS[test]
    grade = _norm_grade(data.get("grade"))

    paths = _extract_paths(test, data)
    if grade == OBSERVATION:
        # The test itself judged that A and B are not two principals, so a marker
        # coming back is not a cross-identity result.
        for path in paths:
            if path["grade"] == LEAK:
                path["grade"], path["meaning"] = OBSERVATION, _SAME_PRINCIPAL
    control = _positive_control(test, data, paths)
    verdict = _verdict(grade, paths, control["status"])
    url = _clean_url(data.get("target"))

    untested = [p["name"] for p in paths if p["grade"] == NOT_TESTED]
    limits = [
        "This is one run, at one time, against one deployment and configuration. It "
        "says nothing about the system before or after that moment.",
        "Only the paths in the results table were checked. Other interfaces, data "
        "stores and features were not.",
        "Two test identities chosen by the operator were used. Other roles, tenants "
        "and administrator access were not tested.",
        "The test used a made-up marker, not real customer data.",
        ("The run was carried out by the operator named on this page" if _clean_text(operator)
         else "The run was carried out by whoever operated the tool (not named on this page)")
        + ", and was not witnessed by an independent party.",
        "The times on this page come from the clock of the machine that ran the tool. "
        "The page is not signed.",
    ] + list(spec["limits"])
    if untested:
        limits.append("Listed but not tested in this run: " + ", ".join(untested) + ".")
    limits.append(PENTEST_LIMIT)

    fps = data.get("fingerprints") if isinstance(data.get("fingerprints"), dict) else {}
    marker = _fingerprint(fps.get("marker")) or _fingerprint(data.get("marker_fingerprint"))

    return {
        "schema": SCHEMA,
        "title": TITLE,
        "tool": {"name": "stranger-test", "version": _tool_version()},
        "test": {"id": test, "title": spec["title"], "description": spec["what"]},
        "generated_at_utc": _timestamp(now),
        "run": {"started_at_utc": _timestamp(run_started) if run_started else None,
                "finished_at_utc": _timestamp(run_finished) if run_finished else None},
        "target": {"url": url},
        "system": {"name": _clean_text(system_name), "version": _clean_text(system_version),
                   "environment": _clean_text(environment)},
        "operator": _clean_text(operator),
        "notes": _clean_text(notes, 1000),
        "identities": _identities(data, {"A": identity_a, "B": identity_b}),
        "marker_fingerprint": marker,
        "positive_control": control,
        "paths": paths,
        "verdict": verdict,
        "control_mapping": {
            "disclaimer": MAPPING_DISCLAIMER,
            "controls": [dict(id=cid, **CONTROLS[cid]) for cid in CONTROL_MAP[test]],
        },
        "limits": limits,
        "reproduce": _reproduce(test, url, reproduce_command(command) if command else None),
        "source": {
            "result_file": os.path.basename(result_file) if result_file else None,
            "result_sha256": canonical_digest(data),
            "canonical_form": "JSON, UTF-8, keys sorted, separators ',' and ':', "
                              "non-ASCII escaped",
        },
    }


# --------------------------------------------------------------------------- #
# Renderers.                                                                   #
# --------------------------------------------------------------------------- #

def render_json(evidence: Dict[str, Any]) -> str:
    """Canonical JSON: sorted keys, fixed separators, one trailing newline."""
    return json.dumps(evidence, sort_keys=True, indent=2, separators=(",", ": "),
                      ensure_ascii=True) + "\n"


def _cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _show(value: Any) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return str(value).replace("_", " ")


def render_markdown(evidence: Dict[str, Any]) -> str:
    """The full page, in plain-language Markdown, for a reader who is not a tester."""
    ev = evidence
    verdict, control = ev["verdict"], ev["positive_control"]
    system = ev.get("system") or {}
    lines: List[str] = [f"# {TITLE}", ""]

    lines += ["## Summary", "", f"**{verdict['statement']}**", ""]

    lines += ["## What was tested", "", ev["test"]["description"], ""]
    facts = [
        ("Test", f"{ev['test']['title']} (`{ev['test']['id']}`)"),
        ("System", system.get("name") or "not stated by the operator"),
        ("System version", system.get("version") or "not stated by the operator"),
        ("Environment", system.get("environment") or "not stated by the operator"),
        ("Address tested", f"`{ev['target']['url']}`" if ev["target"].get("url") else "not recorded"),
        ("Run by", ev.get("operator") or "not stated by the operator"),
        ("Test run started (UTC)", (ev.get("run") or {}).get("started_at_utc")
         or "not recorded (page built from a saved result)"),
        ("Test run finished (UTC)", (ev.get("run") or {}).get("finished_at_utc")),
        ("Evidence generated (UTC)", ev["generated_at_utc"]),
        ("Tool", f"{ev['tool']['name']} {ev['tool']['version']}"),
        ("Notes", ev.get("notes")),
    ]
    lines += [f"- {name}: {value}" for name, value in facts if value]
    lines.append("")
    if not (ev.get("run") or {}).get("started_at_utc"):
        lines += ["The result file does not record when the test ran. The time above is "
                  "when this page was generated from it.", ""]

    lines += ["## How", "",
              "The test signs in as two separate test accounts, called identity A and "
              "identity B. A stores a unique made-up value (the marker). B then tries to "
              "get it. Credentials are never written here; a short `sha256` fingerprint "
              "stands in for each, so two pages can be compared without revealing them.", ""]
    for ident in ev["identities"]:
        extras = []
        if ident.get("credential_fingerprint"):
            extras.append(f"credential `{ident['credential_fingerprint']}`")
        if ident.get("principal_fingerprint"):
            extras.append(f"account the system reported for it `{ident['principal_fingerprint']}`")
        tail = f" ({'; '.join(extras)})" if extras else ""
        said = (f" Described by the operator as: {ident['described_as']}."
                if ident.get("described_as") else "")
        lines.append(f"- Identity {ident['label']}: {ident['role']}{said}{tail}")
    if ev.get("marker_fingerprint"):
        lines.append(f"- Marker fingerprint: `{ev['marker_fingerprint']}`")
    lines += ["", f"Baseline check (also called a positive control). {control['description']}", "",
              f"**{control['statement']}**", ""]
    lines += [f"- {c['meaning']}: {_show(c['value'])}" for c in control["checks"]]
    if control["checks"]:
        lines.append("")

    counts = verdict.get("path_counts") or {}
    tested = sum(1 for path in ev["paths"] if path["grade"] != NOT_TESTED)
    lines += ["## Results", "",
              f"A path is one way of getting at the data. {len(ev['paths'])} paths are "
              f"listed: {tested} tested, {counts.get(NOT_TESTED.lower(), 0)} not tested.", "",
              "- LEAK: identity B got identity A's data.",
              "- OK: identity B did not get it, and A could (so the refusal means something).",
              "- NOT TESTED: the path was not checked. It is not a pass.",
              "- INCONCLUSIVE: no clear answer. It is not a pass.",
              "- OBSERVATION: something to review. It is not a pass.", "",
              "| Path | What it checks | Grade | HTTP status seen | Meaning |",
              "| --- | --- | --- | --- | --- |"]
    for path in ev["paths"]:
        grade = path["grade"].replace("_", " ")
        seen = "; ".join(f"{who} {path[key]}" for who, key in
                         (("A", "a_http_status"), ("B", "b_http_status")) if key in path) or "-"
        lines.append(f"| `{_cell(path['name'])}` | {_cell(path['what'])} | {grade} | {seen} | "
                     f"{_cell(path['meaning'])} |")
    lines += ["", f"Overall: **{verdict['headline']}**.", ""]
    if verdict["code"] in (V_INCONCLUSIVE, V_OBSERVATION):
        lines += ["This result is NOT a pass. It must not be read as showing that the "
                  "two identities are isolated.", ""]

    lines += ["## Control mapping", "", "| Control | Short title | Why it may be relevant |",
              "| --- | --- | --- |"]
    for item in ev["control_mapping"]["controls"]:
        lines.append(f"| {_cell(item['id'])} ({_cell(item['framework'])}) | "
                     f"{_cell(item['title'])} | {_cell(item['relevance'])} |")
    lines += ["", ev["control_mapping"]["disclaimer"], ""]

    lines += ["## Limits", ""] + [f"- {limit}" for limit in ev["limits"]] + [""]

    lines += ["## Reproduce", "", "```bash"] + list(ev["reproduce"]["commands"]) + ["```", "",
              ev["reproduce"]["note"], ""]

    saved = ev["source"].get("result_file")
    lines += ["## Integrity", "",
              f"- Raw result file: `{saved}` (written next to this page)" if saved
              else "- Raw result file: the file this page was built from",
              f"- Digest of the raw result: `{ev['source']['result_sha256']}`",
              f"- Computed over: the raw result as {ev['source']['canonical_form']}.",
              f"- Evidence format: `{ev['schema']}`", "",
              "The digest ties this page to one raw result: run "
              f"`python3 -m strangertest.evidence {saved or 'RESULT.json'} --digest` and compare. "
              "It does not protect this page itself, and neither file is signed. The tool "
              "prints the `sha256` of this page when it writes it; record that value, the "
              "page and the raw result where your evidence is kept (a ticket or an audit "
              "folder) on the day of the run.", ""]
    return "\n".join(lines)


SUMMARY_TITLE = TITLE + " (summary)"
_SUMMARY_LEGEND = {
    LEAK: "LEAK: identity B got identity A's data.",
    OK: "OK: identity B did not get it, and A could.",
    INCONCLUSIVE: "INCONCLUSIVE: no clear answer. It is not a pass.",
    OBSERVATION: "OBSERVATION: something to review. It is not a pass.",
}


def render_summary(evidence: Dict[str, Any], full_page: Optional[str] = None) -> str:
    """The short version of the page, in Markdown: under half its length.

    Built from the same document as :func:`render_markdown` and adds nothing to
    it. It keeps the verdict, the facts of the run, every tested path with the
    HTTP statuses seen, the untested paths grouped by the reason they were not
    tested, the control identifiers, the limits and the digest. It leaves out
    the reproduce command, the list of baseline checks and the account
    fingerprints, and says so. ``full_page`` is the file name of the full page
    when one was written in the same run.
    """
    ev = evidence
    verdict, control = ev["verdict"], ev["positive_control"]
    system, run = ev.get("system") or {}, ev.get("run") or {}
    missing = "not stated by the operator"
    lines: List[str] = [f"# {SUMMARY_TITLE}", ""]
    lines += [f"**{verdict['statement']}**", ""]

    lines += ["## What was tested", "", ev["test"]["description"], ""]
    named = ", ".join(x for x in (system.get("name"), system.get("version")) if x) or missing
    where = system.get("environment") or missing
    if ev["target"].get("url"):
        where += f", `{ev['target']['url']}`"
    if run.get("started_at_utc"):
        when = f"{run['started_at_utc']} to {run.get('finished_at_utc') or 'not recorded'}"
    else:
        when = f"not recorded; this summary was generated {ev['generated_at_utc']}"
    lines += [f"- Test: {ev['test']['title']} (`{ev['test']['id']}`)",
              f"- System: {named}",
              f"- Environment: {where}",
              f"- Run (UTC): {when}",
              f"- Run by: {ev.get('operator') or missing}",
              f"- Tool: {ev['tool']['name']} {ev['tool']['version']}"]
    if ev.get("notes"):
        lines.append(f"- Notes: {ev['notes']}")
    lines.append("")

    lines += ["## How", "",
              "Two separate test accounts. Identity A stores a made-up value (the marker); "
              "identity B tries to get it. Credentials appear only as short `sha256` "
              "fingerprints.", ""]
    for ident in ev["identities"]:
        said = ident.get("described_as") or missing
        tail = (f" (credential `{ident['credential_fingerprint']}`)"
                if ident.get("credential_fingerprint") else "")
        lines.append(f"- Identity {ident['label']}: {said}{tail}")
    lines += [f"- Baseline check (positive control). {control['statement']}", ""]

    tested = [p for p in ev["paths"] if p["grade"] != NOT_TESTED]
    untested = [p for p in ev["paths"] if p["grade"] == NOT_TESTED]
    lines += ["## Results", "",
              f"{len(ev['paths'])} paths are listed: {len(tested)} tested, "
              f"{len(untested)} not tested.", ""]
    seen_grades = [g for g in (LEAK, OK, INCONCLUSIVE, OBSERVATION)
                   if any(p["grade"] == g for p in tested)]
    lines += [f"- {_SUMMARY_LEGEND[g]}" for g in seen_grades]
    if tested:
        lines += ["", "| Path | What it checks | Grade | HTTP status seen |",
                  "| --- | --- | --- | --- |"]
        for path in tested:
            seen = "; ".join(f"{who} {path[key]}" for who, key in
                             (("A", "a_http_status"), ("B", "b_http_status")) if key in path) or "-"
            lines.append(f"| `{_cell(path['name'])}` | {_cell(path['what'])} | "
                         f"{path['grade']} | {seen} |")
    lines.append("")
    if untested:
        lines += [f"Not tested ({len(untested)}). A path that was not tested is not a pass.", ""]
        reasons: Dict[str, List[str]] = {}
        for path in untested:
            reasons.setdefault(path["meaning"], []).append(path["name"])
        for reason, names in reasons.items():
            lines.append(f"- {reason} Paths: " + ", ".join(f"`{_cell(n)}`" for n in names) + ".")
        lines.append("")
    lines += [f"Overall: **{verdict['headline']}**.", ""]
    if verdict["code"] in (V_INCONCLUSIVE, V_OBSERVATION):
        lines += ["This result is NOT a pass. It must not be read as showing that the "
                  "two identities are isolated.", ""]

    lines += ["## Control mapping", ""]
    lines += [f"- {item['id']} ({item['framework']}): {item['title']}"
              for item in ev["control_mapping"]["controls"]]
    lines += ["", ev["control_mapping"]["disclaimer"], ""]

    # The untested paths are already named above, so that one limit is not repeated.
    limits = [limit for limit in ev["limits"] if not limit.startswith("Listed but not tested")]
    lines += ["## Limits", ""] + [f"- {limit}" for limit in limits] + [""]

    saved = ev["source"].get("result_file")
    lines += ["## Integrity", "",
              f"- Raw result file: `{saved}`" if saved
              else "- Raw result file: the file this summary was built from",
              f"- Digest of the raw result: `{ev['source']['result_sha256']}`",
              f"- Evidence format: `{ev['schema']}`. Neither file is signed.", ""]
    more = (f"the full page, `{os.path.basename(full_page)}`," if full_page
            else "the full page (`python3 -m strangertest.evidence RESULT.json`),")
    lines += ["This is a summary and adds nothing to the full page. The command to reproduce "
              "the run, each baseline check and the account fingerprints are in "
              f"{more} which is the page to keep as evidence.", ""]
    return "\n".join(lines)


def _result_path(path: str) -> str:
    stem, ext = os.path.splitext(str(path))
    return (stem if ext.lower() in (".md", ".json", ".markdown", ".txt") else str(path)) + ".result.json"


def write_evidence(path: Any, result: Any, *, fmt: Optional[str] = None,
                   save_result: bool = False, summary: Any = None,
                   **meta: Any) -> Dict[str, Any]:
    """Build the evidence for ``result`` and write it to ``path``.

    ``path`` is one file or a list of files; several files (say a ``.md`` and a
    ``.json``) are written from the same run and say the same thing. ``fmt`` is
    ``"md"`` or ``"json"``; by default a path ending in ``.json`` gets JSON and
    anything else gets Markdown. With ``save_result`` the raw result is written
    next to the first file as ``<name>.result.json``, so the digest on the page
    can be checked later. ``summary`` is one file or a list of files that get the
    short version (:func:`render_summary`) of the same run; ``path`` may then be
    empty. ``meta`` is passed to ``build_evidence``.

    The returned document has one extra key, ``"written"``: a list of
    ``{"path", "sha256"}`` for each file written (not part of the page).
    """
    paths = [str(p) for p in (path if isinstance(path, (list, tuple)) else [path]) if p]
    summaries = [str(p) for p in (summary if isinstance(summary, (list, tuple)) else [summary])
                 if p]
    if not paths and not summaries:
        raise ValueError("no evidence file name was given")
    clash = sorted(set(paths) & set(summaries))
    if clash:
        raise ValueError(f"{clash[0]} is named for both the full page and the summary")
    written: List[Dict[str, str]] = []
    if save_result:
        raw = _result_path((paths or summaries)[0])
        if raw in paths + summaries:
            raise ValueError(f"{raw} is where the raw result is saved; choose another evidence file name")
        text = json.dumps(_as_dict(result), sort_keys=True, indent=2, ensure_ascii=True) + "\n"
        with open(raw, "w", encoding="utf-8") as handle:
            handle.write(text)
        written.append({"path": raw, "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()})
        meta = dict(meta, result_file=raw)
    evidence = build_evidence(result, **meta)
    for one in paths:
        kind = fmt or ("json" if one.lower().endswith(".json") else "md")
        text = render_json(evidence) if kind == "json" else render_markdown(evidence)
        with open(one, "w", encoding="utf-8") as handle:
            handle.write(text)
        written.append({"path": one, "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()})
    full_page = next((one for one in paths if not one.lower().endswith(".json")), None)
    for one in summaries:
        text = render_summary(evidence, full_page=full_page)
        with open(one, "w", encoding="utf-8") as handle:
            handle.write(text)
        written.append({"path": one, "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()})
    return dict(evidence, written=written)


# --------------------------------------------------------------------------- #
# python3 -m strangertest.evidence                                             #
# --------------------------------------------------------------------------- #

def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m strangertest.evidence",
        description="Turn a `stranger-test confirm ... --json` result file into an "
                    "evidence page, or its short summary.")
    parser.add_argument("result", help="result JSON file written by `confirm --json` "
                                       "(use - for standard input)")
    parser.add_argument("--format", choices=("md", "json", "summary"), default=None,
                        help="output format: md is the full page, summary is the short "
                             "version (default: md, or json when --out ends in .json)")
    parser.add_argument("--out", default=None, help="write to this file instead of standard output")
    parser.add_argument("--system-name", default=None, help="name of the system tested")
    parser.add_argument("--system-version", default=None, help="its version or build")
    parser.add_argument("--environment", default=None, help="for example: staging")
    parser.add_argument("--operator", default=None, help="who ran the test")
    parser.add_argument("--notes", default=None, help="one line of context")
    parser.add_argument("--identity-a", default=None,
                        help="a few words describing test account A (never a credential)")
    parser.add_argument("--identity-b", default=None,
                        help="a few words describing test account B (never a credential)")
    parser.add_argument("--digest", action="store_true",
                        help="print only the result digest and exit")
    args = parser.parse_args(argv)

    try:
        if args.result == "-":
            raw = sys.stdin.read()
        else:
            with open(args.result, "r", encoding="utf-8") as handle:
                raw = handle.read()
        data = json.loads(raw)
    except (OSError, ValueError) as exc:
        print(f"error: could not read a JSON result from {args.result}: {exc}", file=sys.stderr)
        return 2
    if not isinstance(data, dict):
        print("error: the result file must hold one JSON object (run `confirm` against a "
              "target with --json; --demo output is not a single result)", file=sys.stderr)
        return 2

    if args.digest:
        print(canonical_digest(data))
        return 0
    try:
        evidence = build_evidence(
            data, system_name=args.system_name, system_version=args.system_version,
            environment=args.environment, operator=args.operator, notes=args.notes,
            identity_a=args.identity_a, identity_b=args.identity_b)
    except (TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    kind = args.format or ("json" if (args.out or "").lower().endswith(".json") else "md")
    text = (render_json(evidence) if kind == "json"
            else render_summary(evidence) if kind == "summary" else render_markdown(evidence))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
