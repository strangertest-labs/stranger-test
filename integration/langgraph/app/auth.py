"""Sample auth for a local LangGraph dev server. Three fixed test users.

``ali`` exists so that two ids are string-prefix siblings (``ali`` / ``alice``),
which the Store namespace-boundary check needs. ``EDGE_TOKENS`` are more test
users whose ids are awkward relatives of ``alice`` (a ``.`` or another separator
inside the id, a wildcard character, letter case, whitespace), for the probe's
awkward-id cases. They are ordinary users: each has its own token and may only
touch namespaces that start with its own id.

ST_SPIKE_MODE=leaky : authenticates callers but adds NO resource authorization
                      (the framework default when no @auth.on handler exists).
ST_SPIKE_MODE=safe  : owner filter on threads/runs, and Store access limited to
                      namespaces that start with the caller's own identity.
"""
import os
from langgraph_sdk import Auth

MODE = os.environ.get("ST_SPIKE_MODE", "leaky")
TOKENS = {"tok-alice": "alice", "tok-bob": "bob", "tok-ali": "ali"}
EDGE_TOKENS = {
    # dot: against alice's namespace ("alice", "notes"), and the pair acme / acme.alice
    "tok-dot": "alice.notes", "tok-dot-sibling": "alice.no",
    "tok-acme": "acme", "tok-acme-alice": "acme.alice",
    # separator: the same two shapes with ":", "/" and "|"
    "tok-sep-colon": "alice:notes", "tok-sep-slash": "alice/notes", "tok-sep-pipe": "alice|notes",
    "tok-team": "team", "tok-team-alice": "team:alice",
    # wildcard, case, whitespace
    "tok-wild-underscore": "al_ce", "tok-wild-percent": "al%", "tok-wild-star": "al*",
    "tok-case": "Alice",
    "tok-space-after": "alice ", "tok-space-before": " alice",
}
TOKENS.update(EDGE_TOKENS)

auth = Auth()


@auth.authenticate
async def authenticate(authorization: str | None) -> Auth.types.MinimalUserDict:
    token = (authorization or "").removeprefix("Bearer ").strip()
    user = TOKENS.get(token)
    if user is None:
        raise Auth.exceptions.HTTPException(status_code=401, detail="unknown token")
    return {"identity": user}


if MODE == "safe":

    @auth.on
    async def owner_only(ctx: Auth.types.AuthContext, value: dict):
        owner = {"owner": ctx.user.identity}
        value.setdefault("metadata", {}).update(owner)
        return owner

    @auth.on.store()
    async def own_namespace_only(ctx: Auth.types.AuthContext, value: dict):
        namespace = tuple(value.get("namespace") or ())
        if not namespace or namespace[0] != ctx.user.identity:
            raise Auth.exceptions.HTTPException(status_code=403, detail="not your namespace")
