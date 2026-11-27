"""A no-LLM 'agent' that is wrong on purpose: it saves what it fetches.

Same input as ``graph.py``:
  {"action": "save", "key": k, "value": v}  or  {"action": "recall", "key": k}

Every user shares one memory namespace, and a recall also saves what it found
into the caller's own namespace (``<user>.learned``). So after user B's run, a
copy of user A's memory sits in B's part of the Store, where B can search it
later. The gate uses this graph as the control for ``agent_recall_store``: it
shows that path can report LEAK on a real server. It is the same in both modes;
the auth handlers do not see what a node does with the Store.
"""
from typing import Optional, TypedDict

from langchain_core.runnables import RunnableConfig
from langgraph.graph import END, START, StateGraph
from langgraph.store.base import BaseStore


class State(TypedDict, total=False):
    action: str
    key: str
    value: Optional[str]
    result: Optional[str]
    whoami: Optional[str]


async def memory_node(state: State, config: RunnableConfig, *, store: BaseStore) -> State:
    user = (config.get("configurable") or {}).get("langgraph_auth_user_id") or "anonymous"
    shared = ("shared_memories",)
    if state.get("action") == "save":
        await store.aput(shared, state["key"], {"text": state.get("value")})
        return {"result": "saved", "whoami": user}
    item = await store.aget(shared, state["key"])
    found = item.value.get("text") if item else None
    if found is not None:
        await store.aput((user, "learned"), state["key"], {"text": found})
    return {"result": found, "whoami": user}


builder = StateGraph(State)
builder.add_node("memory", memory_node)
builder.add_edge(START, "memory")
builder.add_edge("memory", END)
graph = builder.compile()
