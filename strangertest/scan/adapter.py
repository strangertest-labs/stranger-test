"""The universal adapter: connect to any MCP server/gateway by URL and profile it.

:func:`profile_target` is the scanner's connect layer. It performs ONLY safe,
read-only observation:

* connect and auto-detect the transport ("streamable-http" | "sse" | "unknown");
* run the MCP ``initialize`` handshake and capture the protocol version and
  server info;
* discover tools / resources / prompts **by name only** (``*/list`` calls — a
  tool is never called with arguments, nothing is written);
* fingerprint auth: is it required (401 + ``WWW-Authenticate``)? the scheme?
  OAuth protected-resource / authorization-server metadata if the server
  advertises it at a well-known path? an RFC 8693 token-exchange hint?
* observe the session channel for a *single identity only*: does the server
  issue an ``Mcp-Session-Id``? does it echo one the client sends in? does it
  accept a made-up one? (observed, never used to reach another identity);
* observe cache hygiene: does ``resources/read`` carry ``cacheScope`` / ``ttlMs``,
  and is a result forced to ``private``? (read only resources the server
  itself listed);
* record notable response headers, with every secret-shaped value redacted to a
  fingerprint.

It never calls a tool, never writes, never brute-forces auth, and never reaches
a second identity. It never raises on a bad or hostile target: it fills
``errors`` and returns a partial :class:`TargetProfile`. The one exception is the
loopback guard — a non-loopback host with ``allow_nonloopback=False`` raises
:class:`ValueError` before any network contact.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

from ..guard import extract_host, is_local_target
from ..mcp_client import (MCP_PROTOCOL_VERSION, MCP_PROTOCOL_VERSION_HEADER, build_request,
                          parse_result)
from ..transports import HANDSHAKE_VERSIONS, HTTPTransport, _HANDSHAKE_REFUSED
from .model import TargetProfile

__all__ = ["profile_target", "fingerprint_secret"]

# A forged session id the session probe sends in. It is obviously synthetic and
# tied to no real identity, so echoing or accepting it is observed, never used.
_FORGED_SESSION_ID = "stranger-test-probe-0000-0000"

# Header names whose value is always a secret/identifier and is replaced with a
# fingerprint when recorded.
_SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "mcp-session-id",
        "x-api-key",
        "api-key",
        "x-auth-token",
    }
)

# Response headers worth recording (lowercased). Anything beginning "mcp-" is
# also kept. Everything else is dropped to keep the profile small.
_NOTABLE_HEADERS = frozenset(
    {
        "content-type",
        "server",
        "www-authenticate",
        "cache-control",
        "x-powered-by",
        "date",
    }
)

# Looks-secret heuristics for values inside otherwise-ordinary headers: a JWT, or
# a long opaque run of token characters.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+")
_LONG_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_\-]{32,}\b")


def fingerprint_secret(value: str) -> str:
    """Return ``sha256:<first 12 hex>`` of ``value``.

    The adapter stores and prints only fingerprints of anything token-, key-, or
    secret-shaped; the raw value never leaves this process.
    """
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return "sha256:" + digest[:12]


def _redact_value(value: str) -> str:
    """Replace any secret-shaped substring of a header value with a fingerprint."""
    if not value:
        return value

    def _sub(match: "re.Match[str]") -> str:
        return fingerprint_secret(match.group(0))

    redacted = _JWT_RE.sub(_sub, value)
    redacted = _LONG_TOKEN_RE.sub(_sub, redacted)
    return redacted


def _redact_headers(raw: Dict[str, str]) -> Dict[str, str]:
    """Record only notable headers, with secret values fingerprinted."""
    out: Dict[str, str] = {}
    for name, value in raw.items():
        lname = name.lower()
        if lname not in _NOTABLE_HEADERS and not lname.startswith("mcp-"):
            continue
        if lname in _SENSITIVE_HEADERS:
            out[name] = fingerprint_secret(value)
        else:
            out[name] = _redact_value(value)
    return out


@dataclass
class _Resp:
    """A low-level HTTP result the adapter can inspect fully."""

    reachable: bool
    status: Optional[int] = None
    headers: Dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    messages: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None

    def result_for(self, request_id: Any) -> Optional[Dict[str, Any]]:
        """Return the JSON-RPC ``result`` for ``request_id`` if the call succeeded."""
        for msg in self.messages:
            if msg.get("id") == request_id and "result" in msg:
                return msg["result"]
        return None

    def rpc_error_for(self, request_id: Any) -> Optional[Dict[str, Any]]:
        for msg in self.messages:
            if msg.get("id") == request_id and "error" in msg:
                return msg["error"]
        return None

    def session_id(self) -> Optional[str]:
        for name, value in self.headers.items():
            if name.lower() == "mcp-session-id":
                return value
        return None


def _accept_headers(base: Dict[str, str]) -> Dict[str, str]:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    headers.update(base)
    return headers


def _request(
    url: str,
    method: str,
    headers: Dict[str, str],
    *,
    payload: Optional[Dict[str, Any]] = None,
    timeout: float = 10.0,
) -> _Resp:
    """One raw HTTP round trip. Never raises on a network or HTTP error."""
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw_headers = {k: v for k, v in resp.headers.items()}
            content_type = resp.headers.get("Content-Type", "") or ""
            body = resp.read().decode("utf-8", "replace")
            status = resp.status
    except urllib.error.HTTPError as exc:
        raw_headers = {k: v for k, v in exc.headers.items()} if exc.headers else {}
        content_type = (exc.headers.get("Content-Type", "") if exc.headers else "") or ""
        body = exc.read().decode("utf-8", "replace")
        status = exc.code
    except (urllib.error.URLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        return _Resp(reachable=False, error=str(reason))
    except Exception as exc:  # pragma: no cover - defensive; never raise to caller
        return _Resp(reachable=False, error=str(exc))

    messages: List[Dict[str, Any]] = []
    try:
        for parsed in HTTPTransport._iter_messages(content_type, body):
            if isinstance(parsed, dict):
                messages.append(parsed)
    except Exception:  # body was not JSON/SSE we could parse; leave messages empty
        pass
    return _Resp(
        reachable=True,
        status=status,
        headers=raw_headers,
        content_type=content_type,
        messages=messages,
    )


def _send(url: str, headers: Dict[str, str], payload: Dict[str, Any], timeout: float,
          modern: bool) -> _Resp:
    """POST one JSON-RPC message, in the per-request form when ``modern``.

    The per-request form (2026-07-28) is built by the same code the confirm
    tests use: the request carries its version and the client's capabilities
    in ``params._meta`` and is mirrored in the routing headers."""
    if modern:
        payload, extra = HTTPTransport(url, modern=True)._modern_envelope(payload)
        headers = dict(headers, **extra)
    return _request(url, "POST", _accept_headers(headers), payload=payload, timeout=timeout)


#: Start of the error recorded when no handshake version was accepted. The
#: report reads it to avoid calling an unexamined server clean.
HANDSHAKE_REFUSED_NOTE = "handshake refused"


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def _init_payload(request_id: Any) -> Dict[str, Any]:
    return build_request(
        request_id,
        "initialize",
        {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "stranger-test-scan", "version": "0.0.0"},
        },
    )


def profile_target(
    url: str,
    *,
    bearer: Optional[str] = None,
    timeout: float = 10.0,
    allow_nonloopback: bool = False,
) -> TargetProfile:
    """Connect to ``url`` and return a read-only :class:`TargetProfile`.

    ``bearer`` is sent as ``Authorization: Bearer <bearer>`` on the connecting
    requests (its fingerprint, never the value, is recorded). ``allow_nonloopback``
    must be set True to profile a non-loopback host; otherwise a non-loopback
    target raises :class:`ValueError` before any network contact.
    """
    host = extract_host(url)
    if host is None:
        raise ValueError(f"Could not read a hostname from target {url!r}.")
    if not is_local_target(host) and not allow_nonloopback:
        raise ValueError(
            f"Refusing to profile non-loopback host {host!r}. Pass "
            f"allow_nonloopback=True to profile a target you are authorized to test."
        )

    errors: List[str] = []
    fingerprints: Dict[str, Any] = {}
    if bearer:
        fingerprints["bearer"] = fingerprint_secret(bearer)

    auth_headers: Dict[str, str] = {}
    if bearer:
        auth_headers["Authorization"] = f"Bearer {bearer}"

    profile = TargetProfile(
        url=url,
        reachable=False,
        transport="unknown",
        protocol_version=None,
        server_info={},
        auth={
            "required": None,
            "scheme": None,
            "oauth_metadata": {},
            "token_exchange_hint": False,
            "www_authenticate": None,
        },
        capabilities={
            "tools": [],
            "resources": [],
            "prompts": [],
            "counts": {"tools": 0, "resources": 0, "prompts": 0},
        },
        session={
            "issues_session_id": False,
            "echoes_inbound_session_id": False,
            "accepts_forged_session_id": False,
        },
        cache={"advertises_cachescope": False, "forces_private": False, "ttl_ms": None},
        headers={},
        errors=errors,
        fingerprints=fingerprints,
    )

    # --- connect + transport detection + initialize --------------------------
    init_id = 1
    init_resp = _request(
        url, "POST", _accept_headers(auth_headers), payload=_init_payload(init_id), timeout=timeout
    )
    if not init_resp.reachable:
        errors.append(f"POST initialize: not reachable: {init_resp.error}")
    else:
        profile.reachable = True
        profile.headers = _redact_headers(init_resp.headers)

    session_headers = auth_headers   # replaced below when the server issues a session
    modern = False                   # True when the server speaks only the per-request form
    init_result = init_resp.result_for(init_id) if init_resp.reachable else None
    if (init_result is None and init_resp.reachable
            and init_resp.status not in (401, 403)
            and (init_resp.status in _HANDSHAKE_REFUSED
                 or init_resp.rpc_error_for(init_id) is not None)):
        # The server refused the handshake at the version we offered. Some
        # gateways take only an older handshake version, named in the
        # MCP-Protocol-Version header as well; offer those before giving up.
        first = init_resp
        for version in HANDSHAKE_VERSIONS:
            payload = _init_payload(init_id)
            payload["params"]["protocolVersion"] = version
            retry = _request(
                url, "POST",
                _accept_headers(dict(auth_headers, **{MCP_PROTOCOL_VERSION_HEADER: version})),
                payload=payload, timeout=timeout)
            retried = retry.result_for(init_id) if retry.reachable else None
            if retried is not None:
                init_resp, init_result = retry, retried
                agreed = retried.get("protocolVersion")
                # Later requests name the handshake version, as those versions require.
                auth_headers[MCP_PROTOCOL_VERSION_HEADER] = (
                    agreed if agreed in HANDSHAKE_VERSIONS else version)
                profile.headers = _redact_headers(retry.headers)
                break
        # No handshake version was accepted. A server that speaks only the
        # per-request form has no handshake at all: ask it for its tool list in
        # that form (read-only). The handshake is tried first because it is the
        # form that has session ids, which the scan also looks at.
        probe = (None if init_result is not None
                 else _send(url, auth_headers, build_request(2, "tools/list"), timeout, True))
        if probe is not None and probe.reachable and probe.result_for(2) is not None:
            modern = True
            init_result = {}        # no handshake result exists in this form
            profile.transport = "streamable-http"
            profile.protocol_version = MCP_PROTOCOL_VERSION
            profile.headers = _redact_headers(probe.headers)
            profile.session["per_request_form"] = True
        if init_result is None:
            errors.append(
                HANDSHAKE_REFUSED_NOTE + f" (HTTP {first.status}): the server accepted neither "
                "the per-request form nor any handshake version, so tools, sessions and "
                "caches were not examined")
    if modern:
        pass                         # recorded above; there is no handshake result to read
    elif init_result is not None:
        profile.transport = "streamable-http"
        profile.protocol_version = init_result.get("protocolVersion")
        server_info = init_result.get("serverInfo")
        profile.server_info = server_info if isinstance(server_info, dict) else {}
        sid = init_resp.session_id()
        if sid:
            profile.session["issues_session_id"] = True
            fingerprints["server_session_id"] = fingerprint_secret(sid)
            # A server that issues a session expects it back, and expects the
            # handshake to be completed, before it answers anything else.
            session_headers = dict(auth_headers, **{"Mcp-Session-Id": sid})
            _request(url, "POST", _accept_headers(session_headers),
                     payload={"jsonrpc": "2.0", "method": "notifications/initialized"},
                     timeout=timeout)
    else:
        # No usable initialize result over POST. Distinguish an auth wall from a
        # non-streamable endpoint, then try a legacy SSE GET.
        if init_resp.reachable and init_resp.status is not None:
            rpc_err = init_resp.rpc_error_for(init_id)
            if rpc_err is not None:
                errors.append(f"initialize JSON-RPC error: {rpc_err}")
            elif init_resp.status != 200:
                errors.append(f"initialize HTTP {init_resp.status}")
        sse = _detect_sse(url, auth_headers, timeout)
        if sse:
            profile.transport = "sse"
            profile.reachable = True
        elif init_resp.reachable and init_resp.status in (401, 403):
            # Reachable HTTP endpoint behind an auth wall; still streamable-http.
            profile.transport = "streamable-http"

    # --- auth fingerprint (unauthenticated probe) ----------------------------
    _profile_auth(profile, url, timeout, errors, modern=modern)

    # --- capabilities (names only) -------------------------------------------
    if init_result is not None:
        _profile_capabilities(profile, url, session_headers, timeout, errors, modern=modern)
        # --- session observation (single identity only) ----------------------
        # The per-request form has no session ids, so there is nothing to forge.
        if not modern:
            _profile_session(profile, url, auth_headers, timeout, errors)
        # --- cache observation ------------------------------------------------
        _profile_cache(profile, url, session_headers, timeout, errors, modern=modern)

    return profile


def _detect_sse(url: str, auth_headers: Dict[str, str], timeout: float) -> bool:
    """A legacy MCP SSE endpoint answers a GET with a ``text/event-stream``."""
    headers = {"Accept": "text/event-stream"}
    headers.update(auth_headers)
    resp = _request(url, "GET", headers, timeout=min(timeout, 3.0))
    return bool(
        resp.reachable
        and resp.status == 200
        and "text/event-stream" in resp.content_type.lower()
    )


def _profile_auth(
    profile: TargetProfile, url: str, timeout: float, errors: List[str], *, modern: bool = False
) -> None:
    """Probe with NO credentials to see whether auth is required, and discover
    any advertised OAuth metadata."""
    # In the per-request form there is no initialize to send; a tool listing
    # with no credential asks the same question.
    payload = build_request(99, "tools/list") if modern else _init_payload(99)
    unauth = _send(url, {}, payload, timeout, modern)
    www = None
    if unauth.reachable:
        for name, value in unauth.headers.items():
            if name.lower() == "www-authenticate":
                www = value
                break
        if unauth.status in (401, 403) or www is not None:
            profile.auth["required"] = True
        elif unauth.result_for(99) is not None:
            profile.auth["required"] = False
        else:
            profile.auth["required"] = None
        if www:
            profile.auth["www_authenticate"] = _redact_value(www)
            scheme = www.split(None, 1)[0] if www.split() else None
            profile.auth["scheme"] = scheme
    else:
        errors.append(f"unauthenticated auth probe: not reachable: {unauth.error}")

    _discover_oauth_metadata(profile, url, timeout, errors)


def _discover_oauth_metadata(
    profile: TargetProfile, url: str, timeout: float, errors: List[str]
) -> None:
    origin = _origin(url)
    wells = {
        "protected_resource": "/.well-known/oauth-protected-resource",
        "authorization_server": "/.well-known/oauth-authorization-server",
    }
    metadata: Dict[str, Any] = {}
    for key, path in wells.items():
        resp = _request(origin + path, "GET", {"Accept": "application/json"}, timeout=min(timeout, 3.0))
        if not resp.reachable or resp.status != 200:
            continue
        doc = None
        for msg in resp.messages:
            doc = msg
            break
        if doc is None:
            continue
        metadata[key] = _redact_json(doc)
    if metadata:
        profile.auth["oauth_metadata"] = metadata
        if profile.auth.get("scheme") is None:
            profile.auth["scheme"] = "OAuth"
        if profile.auth.get("required") is None:
            profile.auth["required"] = True
        # RFC 8693 token-exchange: advertised as a supported grant type.
        as_meta = metadata.get("authorization_server") or {}
        grants = as_meta.get("grant_types_supported")
        if isinstance(grants, list) and any(
            isinstance(g, str) and "token-exchange" in g for g in grants
        ):
            profile.auth["token_exchange_hint"] = True


def _redact_json(obj: Any) -> Any:
    """Deep-copy ``obj`` replacing any secret-shaped string with a fingerprint."""
    if isinstance(obj, dict):
        return {k: _redact_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_json(v) for v in obj]
    if isinstance(obj, str):
        return _redact_value(obj)
    return obj


def _call(
    url: str,
    method: str,
    auth_headers: Dict[str, str],
    request_id: Any,
    timeout: float,
    errors: List[str],
    *,
    extra_headers: Optional[Dict[str, str]] = None,
    modern: bool = False,
) -> _Resp:
    headers = dict(auth_headers)
    if extra_headers:
        headers.update(extra_headers)
    resp = _send(url, headers, build_request(request_id, method), timeout, modern)
    if resp.reachable:
        rpc_err = resp.rpc_error_for(request_id)
        if rpc_err is not None:
            errors.append(f"{method}: JSON-RPC error {rpc_err.get('code')}: {rpc_err.get('message')}")
        elif resp.status != 200 and resp.result_for(request_id) is None:
            errors.append(f"{method}: HTTP {resp.status}")
    else:
        errors.append(f"{method}: not reachable: {resp.error}")
    return resp


def _profile_capabilities(
    profile: TargetProfile,
    url: str,
    auth_headers: Dict[str, str],
    timeout: float,
    errors: List[str],
    *,
    modern: bool = False,
) -> None:
    tools_resp = _call(url, "tools/list", auth_headers, 10, timeout, errors, modern=modern)
    tools_result = tools_resp.result_for(10)
    tool_names: List[str] = []
    if isinstance(tools_result, dict):
        for tool in tools_result.get("tools", []) or []:
            name = tool.get("name") if isinstance(tool, dict) else None
            if isinstance(name, str):
                tool_names.append(name)

    res_resp = _call(url, "resources/list", auth_headers, 11, timeout, errors, modern=modern)
    res_result = res_resp.result_for(11)
    resource_uris: List[str] = []
    if isinstance(res_result, dict):
        for res in res_result.get("resources", []) or []:
            uri = res.get("uri") if isinstance(res, dict) else None
            if isinstance(uri, str):
                resource_uris.append(uri)

    prompts_resp = _call(url, "prompts/list", auth_headers, 12, timeout, errors, modern=modern)
    prompts_result = prompts_resp.result_for(12)
    prompt_names: List[str] = []
    if isinstance(prompts_result, dict):
        for prompt in prompts_result.get("prompts", []) or []:
            name = prompt.get("name") if isinstance(prompt, dict) else None
            if isinstance(name, str):
                prompt_names.append(name)

    profile.capabilities = {
        "tools": tool_names,
        "resources": resource_uris,
        "prompts": prompt_names,
        "counts": {
            "tools": len(tool_names),
            "resources": len(resource_uris),
            "prompts": len(prompt_names),
        },
    }


def _profile_session(
    profile: TargetProfile,
    url: str,
    auth_headers: Dict[str, str],
    timeout: float,
    errors: List[str],
) -> None:
    """Observe the single-identity session channel. No cross-identity action."""
    forged = {"Mcp-Session-Id": _FORGED_SESSION_ID}
    resp = _request(
        url,
        "POST",
        _accept_headers({**auth_headers, **forged}),
        payload=build_request(20, "tools/list"),
        timeout=timeout,
    )
    if not resp.reachable:
        errors.append(f"session probe: not reachable: {resp.error}")
        return
    echoed = resp.session_id()
    if echoed == _FORGED_SESSION_ID:
        profile.session["echoes_inbound_session_id"] = True
    # Accepts a made-up session id: the forged id was sent and the call still
    # succeeded rather than being rejected as an unknown/invalid session.
    if resp.status == 200 and resp.result_for(20) is not None:
        profile.session["accepts_forged_session_id"] = True


def _profile_cache(
    profile: TargetProfile,
    url: str,
    auth_headers: Dict[str, str],
    timeout: float,
    errors: List[str],
    *,
    modern: bool = False,
) -> None:
    """Read ONE server-listed resource and inspect its cache fields.

    Only a resource the server itself listed is read; no URI is invented and no
    tool is called.
    """
    uris = profile.capabilities.get("resources") or []
    if not uris:
        return
    uri = uris[0]
    resp = _send(url, auth_headers, build_request(30, "resources/read", {"uri": uri}),
                 timeout, modern)
    if not resp.reachable:
        errors.append(f"cache probe (resources/read): not reachable: {resp.error}")
        return
    result = resp.result_for(30)
    if not isinstance(result, dict):
        rpc_err = resp.rpc_error_for(30)
        if rpc_err is not None:
            errors.append(f"cache probe: resources/read error {rpc_err.get('code')}")
        return
    scope = result.get("cacheScope")
    ttl = result.get("ttlMs")
    profile.cache = {
        "advertises_cachescope": "cacheScope" in result,
        "forces_private": scope == "private",
        "ttl_ms": ttl if isinstance(ttl, int) and not isinstance(ttl, bool) else None,
    }
