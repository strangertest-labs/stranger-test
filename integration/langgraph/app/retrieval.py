"""Two no-LLM 'agents' whose retrieval never reaches the final answer.

Both take the same input as ``graph.py``:
  {"action": "save", "key": k, "value": v}  or  {"action": "recall", "key": k}

``retrieve`` reads the saved item and writes it to ``docs``. What differs is why
the caller of ``runs/wait`` does not see it:

  graph          a later node clears ``docs`` (the final state is clean)
  hidden_graph   ``docs`` stays in the state, the output schema leaves it out

leaky: one shared namespace for every user.  safe: namespace starts with the user.
"""
import os
from typing import List, Optional, TypedDict

from langchain_core.runnables import RunnableConfig
from langgraph.graph import END, START, StateGraph
from langgraph.store.base import BaseStore

MODE = os.environ.get("ST_SPIKE_MODE", "leaky")


class State(TypedDict, total=False):
    action: str
    key: str
    value: Optional[str]
    docs: List[str]
    result: Optional[str]
    whoami: Optional[str]


class Output(TypedDict, total=False):
    result: Optional[str]
    whoami: Optional[str]


def _user(config: RunnableConfig) -> str:
    return (config.get("configurable") or {}).get("langgraph_auth_user_id") or "anonymous"


async def retrieve(state: State, config: RunnableConfig, *, store: BaseStore) -> State:
    user = _user(config)
    namespace = ("retrieval",) if MODE == "leaky" else (user, "retrieval")
    if state.get("action") == "save":
        await store.aput(namespace, state["key"], {"text": state.get("value")})
        return {"docs": [], "whoami": user}
    item = await store.aget(namespace, state["key"])
    return {"docs": [item.value.get("text")] if item else [], "whoami": user}


async def answer_and_clear(state: State) -> State:
    return {"docs": [], "value": None, "result": "answered from %d document(s)" % len(state.get("docs") or [])}


async def answer(state: State) -> State:
    return {"value": None, "result": "answered from %d document(s)" % len(state.get("docs") or [])}


_clearing = StateGraph(State)
_clearing.add_node("retrieve", retrieve)
_clearing.add_node("answer", answer_and_clear)
_clearing.add_edge(START, "retrieve")
_clearing.add_edge("retrieve", "answer")
_clearing.add_edge("answer", END)
graph = _clearing.compile()

_hidden = StateGraph(State, output_schema=Output)
_hidden.add_node("retrieve", retrieve)
_hidden.add_node("answer", answer)
_hidden.add_edge(START, "retrieve")
_hidden.add_edge("retrieve", "answer")
_hidden.add_edge("answer", END)
hidden_graph = _hidden.compile()
