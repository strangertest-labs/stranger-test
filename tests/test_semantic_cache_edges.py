"""The semantic-cache probe's awkward-id cases, extra routes and streaming.

Every target is the bundled practice cache on 127.0.0.1, ports 4600-4699,
started and stopped in-process. Nothing reaches the network."""

import io
import json
import threading
import unittest
import urllib.request
from contextlib import contextmanager, redirect_stderr, redirect_stdout

from strangertest import deep_tests as dt
from strangertest.cli import main
from strangertest.practice_semantic_cache_http import PRACTICE_TOKENS, build_server
from strangertest.semantic_cache import (
    EDGE_KINDS, INCONCLUSIVE, LEAK, OK, _read_event_stream, edge_path_name,
    run_semantic_cache_probe,
)

TA, TB = "tok-alice", "tok-bob"
EDGE_TOKENS = {"prefix": "tok-ali", "dot": "tok-dot", "separator": "tok-sep",
               "wildcard": "tok-wild", "case": "tok-case", "whitespace": "tok-space"}
EDGE_ARGS = [f"{kind}={token}" for kind, token in EDGE_TOKENS.items()]
BUGS = {"prefix": "prefixbug", "dot": "dotbug", "separator": "separatorbug",
        "wildcard": "wildcardbug", "case": "casebug", "whitespace": "whitespacebug"}
ALL_ROUTES = ["chat", "responses", "messages"]
# Nothing of these may reach a report: markers, response ids, practice tokens.
NEVER = ("stcache", "st-cache-", "st-own-", "chatcmpl-", "resp_", "msg_") + tuple(PRACTICE_TOKENS)


@contextmanager
def serving(cache, **options):
    server = build_server(cache, port=dt._free_port(), **options)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def probe(cache, id_a="alice", id_b="bob", server=None, **kw):
    with serving(cache, **(server or {})) as url:
        return run_semantic_cache_probe(url, id_a, id_b, authorized=True, **kw)


def tokens(cache, server=None, **kw):
    """Store shape, one bearer token per identity."""
    options = dict({"auth": "token"}, **(server or {}))
    return probe(cache, TA, TB, options, identity_as="bearer", **kw)


def chat(cache, server=None, **kw):
    options = dict({"auth": "token"}, **(server or {}))
    return probe(cache, TA, TB, options, mode="chat", **kw)


def outcomes(report):
    return {p["name"]: p["outcome"] for p in report.paths}


def notes(report):
    return {p["name"]: p.get("note", "") for p in report.paths}


def dumped(report):
    return json.dumps(report.to_dict()) + report.summary()


def _cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


EDGE_PATHS = [edge_path_name(kind) for kind in EDGE_KINDS]


# --------------------------------------------------------------------------- #
# awkward ids, store shape                                                     #
# --------------------------------------------------------------------------- #

class HeaderIds(unittest.TestCase):
    """Plain header ids: with edge_cases the related ids are made from A's."""

    def test_names(self):
        self.assertEqual(EDGE_PATHS, ["prefix_sibling", "edge_dot", "edge_separator",
                                      "edge_wildcard", "edge_case", "edge_whitespace"])

    def test_default_is_todays_behaviour(self):
        report = probe("safe")
        self.assertEqual(list(outcomes(report)), ["exact", "reworded", "prefix_sibling"])
        self.assertEqual(outcomes(report)["prefix_sibling"], "NOT_RUN")
        self.assertNotIn("edge_controls", report.controls)

    def test_safe_cache_is_ok_on_every_case(self):
        report = probe("safe", edge_cases="all")
        got = outcomes(report)
        self.assertEqual(report.grade, OK, report.summary())
        for name in EDGE_PATHS[:-1]:
            self.assertEqual(got[name], "OK", report.summary())
            self.assertTrue(report.controls["edge_controls"][name])
        # A header value cannot carry a leading or trailing space.
        self.assertEqual(got["edge_whitespace"], "NOT_RUN")
        self.assertIn("HTTP header", notes(report)["edge_whitespace"])

    def test_each_key_bug_leaks_on_its_own_case_only(self):
        for kind in ("prefix", "dot", "separator", "wildcard", "case"):
            report = probe(BUGS[kind], edge_cases="all")
            got = outcomes(report)
            self.assertEqual(report.grade, LEAK, report.summary())
            leaked = [name for name in got if got[name] == "LEAK"]
            self.assertEqual(leaked, [edge_path_name(kind)], report.summary())

    def test_a_list_of_cases_runs_only_those(self):
        report = probe("casebug", edge_cases="case,dot")
        self.assertEqual(list(outcomes(report)),
                         ["exact", "reworded", "prefix_sibling", "edge_dot", "edge_case"])
        self.assertEqual(outcomes(report)["prefix_sibling"], "NOT_RUN")
        self.assertEqual(outcomes(report)["edge_case"], "LEAK")
        self.assertEqual(probe("safe", edge_cases=["wildcard"]).grade, OK)

    def test_separator_reports_which_character_leaked(self):
        note = notes(probe("separatorbug", edge_cases="separator"))["edge_separator"]
        self.assertIn("':' LEAK", note)
        self.assertIn("'/' OK", note)
        self.assertIn("'|' OK", note)

    def test_a_dotted_id_is_also_tried_without_its_tail(self):
        report = probe("dotbug", id_a="acme.alice", edge_cases="dot")
        self.assertIn("shorter id LEAK", notes(report)["edge_dot"])
        self.assertEqual(outcomes(probe("safe", id_a="acme.alice", edge_cases="dot"))["edge_dot"], "OK")

    def test_shifted_question_lines_up_a_joined_key(self):
        # id "acme:alice" + ":" + q is the same string as "acme" + ":" + "alice:q".
        report = probe("separatorbug", id_a="acme:alice", edge_cases="separator")
        self.assertIn("':' shorter id LEAK", notes(report)["edge_separator"])
        report = probe("safe", id_a="acme:alice", edge_cases="separator")
        self.assertEqual(outcomes(report)["edge_separator"], "OK", report.summary())

    def test_ids_with_nothing_to_vary_are_not_run(self):
        report = probe("safe", id_a="7", id_b="8", edge_cases="prefix,case")
        got = outcomes(report)
        self.assertEqual((got["prefix_sibling"], got["edge_case"]), ("NOT_RUN", "NOT_RUN"))
        self.assertIn("single character", notes(report)["prefix_sibling"])
        self.assertIn("no letters", notes(report)["edge_case"])

    def test_broken_cache_stays_inconclusive(self):
        report = probe("broken", edge_cases="all")
        self.assertEqual(report.grade, INCONCLUSIVE, report.summary())
        self.assertEqual(set(outcomes(report).values()), {"NOT_EXERCISED", "NOT_RUN"})

    def test_a_given_header_id_wins_over_a_made_up_one(self):
        report = probe("casebug", edge_identity={"case": "ALICE"})
        self.assertEqual(outcomes(report)["edge_case"], "LEAK", report.summary())
        self.assertIn("given for this case", notes(report)["edge_case"])
        self.assertTrue(report.fingerprints["edge_ids"]["case"].startswith("sha256:"))

    def test_a_given_header_id_cannot_carry_whitespace(self):
        report = probe("whitespacebug", edge_identity=["whitespace=alice "])
        self.assertEqual(outcomes(report)["edge_whitespace"], "NOT_RUN", report.summary())

    def test_ids_are_not_made_up_next_to_a_user_field_or_token(self):
        report = probe("safe", TA, TB, {"auth": "token"}, mode="chat", edge_cases="all")
        for name in EDGE_PATHS:
            self.assertEqual(outcomes(report)[name], "NOT_RUN", report.summary())


class TokenIds(unittest.TestCase):
    """Credentials: nothing is made up, each case needs a given identity."""

    def test_cases_without_a_credential_are_not_run_never_ok(self):
        report = tokens("dotbug", edge_cases="all")
        got = outcomes(report)
        for kind in EDGE_KINDS:
            self.assertEqual(got[edge_path_name(kind)], "NOT_RUN", report.summary())
        self.assertIn("--edge-identity dot=", notes(report)["edge_dot"])
        self.assertIn("--token-sibling", notes(report)["prefix_sibling"])
        self.assertEqual(report.grade, OK)      # exact and reworded were clean

    def test_safe_cache_is_ok_with_every_credential(self):
        report = tokens("safe", edge_identity=EDGE_ARGS)
        self.assertEqual(report.grade, OK, report.summary())
        self.assertEqual({outcomes(report)[n] for n in EDGE_PATHS}, {"OK"})

    def test_each_key_bug_leaks_on_its_own_case(self):
        for kind in EDGE_KINDS:
            report = tokens(BUGS[kind], edge_identity=EDGE_ARGS)
            got = outcomes(report)
            self.assertEqual([n for n in got if got[n] == "LEAK"], [edge_path_name(kind)],
                             report.summary())

    def test_only_the_given_cases_are_listed(self):
        report = tokens("casebug", edge_identity=["case=tok-case"])
        self.assertEqual(list(outcomes(report)),
                         ["exact", "reworded", "prefix_sibling", "edge_case"])

    def test_failed_control_is_not_exercised(self):
        # A credential the cache refuses: the extra identity cannot get an entry
        # of its own back, so its clean answer proves nothing.
        report = tokens("safe", edge_identity=["dot=tok-nobody", "case=tok-case"])
        got = outcomes(report)
        self.assertEqual((got["edge_dot"], got["edge_case"]), ("NOT_EXERCISED", "OK"))
        self.assertIn("entry of its own", notes(report)["edge_dot"])
        self.assertFalse(report.controls["edge_controls"]["edge_dot"])
        self.assertTrue(any("edge_dot" in o for o in report.observations))

    def test_token_sibling_is_the_prefix_case(self):
        old = tokens("prefixbug", sibling="tok-ali")
        new = tokens("prefixbug", edge_identity=["prefix=tok-ali"])
        self.assertEqual(outcomes(old), outcomes(new))
        self.assertEqual(outcomes(new)["prefix_sibling"], "LEAK")
        self.assertEqual(old.fingerprints["id_sibling"], new.fingerprints["id_sibling"])
        both = tokens("prefixbug", sibling="tok-ali", edge_identity=["prefix=tok-ali"])
        self.assertEqual(outcomes(both)["prefix_sibling"], "LEAK")

    def test_namespace_after_the_token_is_ignored(self):
        report = tokens("casebug", edge_identity=["case=tok-case@alice.notes"])
        self.assertEqual(outcomes(report)["edge_case"], "LEAK", report.summary())

    def test_identity_equal_to_a_or_b_is_not_run(self):
        report = tokens("leaky", edge_identity=[f"case={TA}", f"dot={TB}"])
        got = outcomes(report)
        self.assertEqual((got["edge_case"], got["edge_dot"]), ("NOT_RUN", "NOT_RUN"))


# --------------------------------------------------------------------------- #
# awkward ids, chat shape                                                      #
# --------------------------------------------------------------------------- #

class ChatEdges(unittest.TestCase):
    def test_safe_gateway_is_ok_with_every_credential(self):
        report = chat("safe", edge_identity=EDGE_ARGS)
        self.assertEqual(report.grade, OK, report.summary())
        self.assertEqual({outcomes(report)[n] for n in EDGE_PATHS}, {"OK"})
        self.assertEqual(set(report.controls["edge_controls"].values()), {True})

    def test_each_key_bug_leaks_on_its_own_case(self):
        for kind in EDGE_KINDS:
            report = chat(BUGS[kind], edge_identity=EDGE_ARGS)
            got = outcomes(report)
            self.assertEqual([n for n in got if got[n] == "LEAK"], [edge_path_name(kind)],
                             report.summary())

    def test_missing_credentials_are_not_run(self):
        report = chat("casebug", edge_cases="case,whitespace")
        got = outcomes(report)
        self.assertEqual((got["edge_case"], got["edge_whitespace"]), ("NOT_RUN", "NOT_RUN"))
        self.assertEqual(report.grade, OK)

    def test_failed_control_is_not_exercised(self):
        report = chat("safe", edge_identity=["wildcard=tok-nobody"])
        self.assertEqual(outcomes(report)["edge_wildcard"], "NOT_EXERCISED", report.summary())
        self.assertIn("HTTP 401", notes(report)["edge_wildcard"])
        self.assertEqual(report.grade, OK)

    def test_broken_gateway_stays_inconclusive(self):
        report = chat("broken", edge_identity=EDGE_ARGS)
        self.assertEqual(report.grade, INCONCLUSIVE, report.summary())
        self.assertEqual(set(outcomes(report).values()), {"NOT_EXERCISED"})

    def test_header_ids_in_chat_mode_are_made_from_as(self):
        kw = dict(mode="chat", identity_as="header", edge_cases="all")
        report = probe("wildcardbug", **kw)
        got = outcomes(report)
        self.assertEqual([n for n in got if got[n] == "LEAK"], ["edge_wildcard"], report.summary())
        self.assertEqual(got["edge_whitespace"], "NOT_RUN")
        self.assertEqual(probe("safe", **kw).grade, OK)

    def test_user_field_cases_and_whitespace(self):
        server = {"auth": "user", "api_key": "shared-key-1"}
        kw = dict(id_a=None, id_b=None, server=server, mode="chat", api_key="shared-key-1",
                  user_a="alice", user_b="bob",
                  edge_user=["whitespace= alice ", "case=ALICE"])
        report = probe("whitespacebug", **kw)
        got = outcomes(report)
        self.assertEqual((got["edge_whitespace"], got["edge_case"]), ("LEAK", "OK"),
                         report.summary())
        report = probe("safe", **kw)
        self.assertEqual((outcomes(report)["edge_whitespace"], report.grade), ("OK", OK),
                         report.summary())
        # Asked for by name but not given: the user field is never made up.
        report = probe("safe", **dict(kw, edge_user=None, edge_cases="dot"))
        self.assertEqual(outcomes(report)["edge_dot"], "NOT_RUN")
        self.assertIn("--edge-user dot=", notes(report)["edge_dot"])

    def test_user_sibling_is_the_prefix_case(self):
        kw = dict(id_a=None, id_b=None, server={"auth": "user"}, mode="chat",
                  user_a="alice", user_b="bob")
        old = probe("prefixbug", user_sibling="ali", **kw)
        new = probe("prefixbug", edge_user={"prefix": "ali"}, **kw)
        self.assertEqual(outcomes(old)["prefix_sibling"], "LEAK")
        self.assertEqual(outcomes(old), outcomes(new))


# --------------------------------------------------------------------------- #
# more than one route                                                          #
# --------------------------------------------------------------------------- #

def route_paths(routes, extra=()):
    names = []
    for route in routes:
        names += [f"{p}@{route}" for p in ("reworded", "exact", "prefix_sibling") + tuple(extra)]
    return names + [f"cross_route@{route}" for route in routes[1:]]


class Routes(unittest.TestCase):
    def test_safe_gateway_is_ok_on_every_route(self):
        report = chat("safe", route=ALL_ROUTES)
        got = outcomes(report)
        self.assertEqual(report.grade, OK, report.summary())
        self.assertEqual(list(got), route_paths(ALL_ROUTES))
        for name in got:
            self.assertEqual(got[name], "NOT_RUN" if name.startswith("prefix_sibling") else "OK")
        self.assertEqual(list(report.controls["routes"]), ALL_ROUTES)
        for rc in report.controls["routes"].values():
            self.assertTrue(rc["a_exact_hit"])
        self.assertTrue(report.controls["routes"]["messages"]["a_cross_route_hit"])
        self.assertTrue(report.controls["a_exact_hit"])

    def test_identity_missing_on_other_routes_is_caught_per_route(self):
        report = chat("routebug", route=ALL_ROUTES)
        got = outcomes(report)
        self.assertEqual(report.grade, LEAK, report.summary())
        self.assertEqual((got["reworded@chat"], got["exact@chat"]), ("OK", "OK"))
        for route in ("responses", "messages"):
            for name in ("reworded", "exact", "cross_route"):
                self.assertEqual(got[f"{name}@{route}"], "LEAK", report.summary())
        # The chat route alone looks clean: this is what one route misses.
        self.assertEqual(chat("routebug").grade, OK)

    def test_leaky_gateway_leaks_everywhere(self):
        got = outcomes(chat("leaky", route=["chat", "responses"]))
        self.assertEqual({got[n] for n in got if not n.startswith("prefix_sibling")}, {"LEAK"})

    def test_edge_cases_run_on_every_route(self):
        report = chat("routebug", route=["chat", "messages"], edge_identity=["case=tok-case"])
        got = outcomes(report)
        self.assertEqual(list(got), route_paths(["chat", "messages"], ["edge_case"]))
        self.assertEqual((got["edge_case@chat"], got["edge_case@messages"]), ("OK", "LEAK"))

    def test_route_the_server_does_not_serve_is_not_run(self):
        report = chat("safe", {"routes": ["chat", "messages"]}, route=ALL_ROUTES)
        got = outcomes(report)
        for name in ("reworded", "exact", "prefix_sibling", "cross_route"):
            self.assertEqual(got[f"{name}@responses"], "NOT_RUN", report.summary())
        self.assertIn("HTTP 404", notes(report)["exact@responses"])
        self.assertEqual((got["exact@messages"], got["cross_route@messages"]), ("OK", "OK"))
        self.assertEqual(report.grade, OK)

    def test_no_route_served_is_inconclusive(self):
        report = chat("leaky", {"routes": ["chat"]}, route=["responses", "messages"])
        self.assertEqual(report.grade, INCONCLUSIVE, report.summary())
        self.assertEqual(set(outcomes(report).values()), {"NOT_RUN"})
        self.assertIn("does not serve this route", report.detail)

    def test_cross_route_needs_as_own_cross_route_hit(self):
        # A cache that keeps each route's entries apart: A's own question does
        # not come back on the other route, so nothing is proven there.
        report = chat("safe", {"per_route_cache": True}, route=["chat", "responses"])
        got = outcomes(report)
        self.assertEqual(got["cross_route@responses"], "NOT_EXERCISED", report.summary())
        self.assertFalse(report.controls["routes"]["responses"]["a_cross_route_hit"])
        self.assertEqual((got["exact@responses"], report.grade), ("OK", OK))

    def test_one_named_route_and_a_custom_path(self):
        report = chat("leaky", route=["responses=/responses"])
        self.assertEqual(list(outcomes(report)),
                         ["reworded@responses", "exact@responses", "prefix_sibling@responses"])
        self.assertEqual(report.grade, LEAK)
        report = chat("leaky", route=["chat"], chat_path="/chat/completions")
        self.assertEqual(outcomes(report)["exact@chat"], "LEAK", report.summary())

    def test_broken_gateway_stays_inconclusive(self):
        report = chat("broken", route=ALL_ROUTES)
        self.assertEqual(report.grade, INCONCLUSIVE, report.summary())
        self.assertNotIn("OK", set(outcomes(report).values()))

    def test_user_field_reaches_every_route(self):
        server = {"auth": "user"}
        kw = dict(id_a=None, id_b=None, server=server, mode="chat", user_a="u1", user_b="u2",
                  route=ALL_ROUTES)
        self.assertEqual(probe("safe", **kw).grade, OK)
        got = outcomes(probe("routebug", **kw))
        self.assertEqual((got["exact@chat"], got["exact@messages"]), ("OK", "LEAK"))

    def test_own_question_on_every_route_is_noted(self):
        report = chat("safe", route=["chat", "responses"], base_query="Falcon wire limit?",
                      reworded_query="wire limit of Falcon?")
        self.assertTrue(any("same question" in o for o in report.observations))
        self.assertNotEqual(report.grade, LEAK, report.summary())


# --------------------------------------------------------------------------- #
# streaming                                                                    #
# --------------------------------------------------------------------------- #

class Streaming(unittest.TestCase):
    def test_leaky_and_safe_on_every_route(self):
        report = chat("leaky", route=ALL_ROUTES, stream=True)
        got = outcomes(report)
        self.assertEqual({got[n] for n in got if not n.startswith("prefix_sibling")}, {"LEAK"},
                         report.summary())
        self.assertTrue(report.controls["stream"])
        report = chat("safe", route=ALL_ROUTES, stream=True)
        got = outcomes(report)
        self.assertEqual(report.grade, OK, report.summary())
        self.assertEqual({got[n] for n in got if not n.startswith("prefix_sibling")}, {"OK"})

    def test_single_route_keeps_the_plain_path_names(self):
        report = chat("leaky", stream=True)
        self.assertEqual(list(outcomes(report)), ["reworded", "exact", "prefix_sibling"])
        self.assertEqual(report.grade, LEAK)
        self.assertEqual(report.controls["hit_recognised_by"], ["response id"])

    def test_marker_is_found_across_stream_pieces(self):
        # Ids change on every answer and there is no header: only A's marker in
        # the reassembled text shows the hit.
        for route in ALL_ROUTES:
            report = chat("leaky", {"fresh_id_on_hit": True}, route=[route], stream=True)
            self.assertEqual(outcomes(report)[f"reworded@{route}"], "LEAK", report.summary())
            self.assertIn("marker", notes(report)[f"reworded@{route}"])

    def test_header_only_recognition_works_on_streams(self):
        server = {"hit_header": "x-cache", "fresh_id_on_hit": True}
        report = chat("leaky", server, stream=True)
        self.assertEqual(report.controls["hit_recognised_by"], ["cache-hit header"])
        self.assertIn("header", notes(report)["exact"])
        report = chat("safe", server, stream=True, edge_identity=["case=tok-case"])
        self.assertEqual((outcomes(report)["edge_case"], report.grade), ("OK", OK),
                         report.summary())

    def test_edge_cases_over_streams(self):
        self.assertEqual(outcomes(chat("casebug", stream=True, edge_identity=EDGE_ARGS))["edge_case"],
                         "LEAK")
        report = chat("safe", stream=True, edge_identity=["dot=tok-nobody"])
        self.assertEqual(outcomes(report)["edge_dot"], "NOT_EXERCISED", report.summary())

    def test_server_that_does_not_stream_is_not_run(self):
        report = chat("leaky", {"streaming": False}, stream=True)
        self.assertEqual(set(outcomes(report).values()), {"NOT_RUN"}, report.summary())
        self.assertEqual(report.grade, INCONCLUSIVE)
        self.assertIn("event stream", report.detail)
        report = chat("leaky", {"streaming": False}, stream=True, route=["chat", "responses"])
        self.assertEqual(set(outcomes(report).values()), {"NOT_RUN"}, report.summary())

    def test_broken_gateway_stays_inconclusive(self):
        report = chat("broken", stream=True)
        self.assertEqual(report.grade, INCONCLUSIVE, report.summary())
        self.assertFalse(report.controls["a_exact_hit"])

    def test_reader_understands_the_three_event_formats(self):
        def lines(*events):
            return [(e + "\n").encode() for e in events]
        text, rid = _read_event_stream(lines(
            'data: {"id":"c1","choices":[{"delta":{"role":"assistant","content":""}}]}', "",
            'data: {"id":"c1","choices":[{"delta":{"content":"mar"}}]}',
            'data: {"id":"c1","choices":[{"delta":{"content":"ker"}}]}',
            'data: {"id":"c1","choices":[{"delta":{},"finish_reason":"stop"}]}',
            "data: [DONE]", 'data: {"id":"c2","choices":[{"delta":{"content":"late"}}]}'))
        self.assertEqual((text, rid), ("marker", "c1"))
        text, rid = _read_event_stream(lines(
            "event: response.created",
            'data: {"type":"response.created","response":{"id":"r1"}}',
            ": a comment", "data: not json",
            'data: {"type":"response.output_text.delta","item_id":"i1","delta":"mar"}',
            'data: {"type":"response.output_text.delta","delta":"ker"}',
            'data: {"type":"response.function_call_arguments.delta","delta":"{}"}',
            'data: {"type":"response.completed","response":{"id":"r1"}}',
            'data: {"type":"response.output_text.delta","delta":"late"}'))
        self.assertEqual((text, rid), ("marker", "r1"))
        text, rid = _read_event_stream(lines(
            'data: {"type":"message_start","message":{"id":"m1","content":[]}}',
            'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"mar"}}',
            'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"ker"}}',
            'data: {"type":"message_stop"}'))
        self.assertEqual((text, rid), ("marker", "m1"))


# --------------------------------------------------------------------------- #
# hygiene and option errors                                                    #
# --------------------------------------------------------------------------- #

class ReportHygiene(unittest.TestCase):
    def _clean(self, report, *more):
        text = dumped(report)
        for secret in NEVER + more:
            self.assertNotIn(secret, text)

    def test_made_up_ids_and_as_id_stay_out(self):
        # Every made-up id starts with (most of) A's id; none may be echoed.
        for cache in ("safe", "separatorbug", "wildcardbug", "broken"):
            report = probe(cache, "cust-7F3a.1c:9", "tenant-9b2042", edge_cases="all")
            self._clean(report, "cust-7", "7F3a", "tenant-9b2042", "1c:9")

    def test_given_credentials_stay_out_in_both_shapes(self):
        for cache in ("safe", "casebug"):
            self._clean(tokens(cache, edge_identity=EDGE_ARGS + []), "alic%", "alice.st")
            report = chat(cache, {"hit_header": "x-cache"}, edge_identity=EDGE_ARGS,
                          route=ALL_ROUTES, stream=True)
            self._clean(report, "alic%", "alice.st")
            for fp in report.fingerprints["edge_ids"].values():
                self.assertTrue(fp.startswith("sha256:"))
            for fp in report.fingerprints["route_markers"].values():
                self.assertTrue(fp.startswith("sha256:"))

    def test_user_field_values_stay_out(self):
        report = probe("whitespacebug", None, None, {"auth": "user"}, mode="chat",
                       user_a="user-7f3a1c", user_b="user-9b2042",
                       edge_user=["whitespace=user-7f3a1c ", "case=USER-7F3A1C"])
        self.assertEqual(outcomes(report)["edge_whitespace"], "LEAK", report.summary())
        self._clean(report, "user-7f3a1c", "USER-7F3A1C", "user-9b2042")

    def test_command_line_output_text_and_json(self):
        table = {"sk-live-AAAA1111": "acct-alice-01", "sk-live-BBBB2222": "acct-bob-02",
                 "sk-live-CCCC3333": "ACCT-ALICE-01", "sk-live-DDDD4444": "acct-alice-01.x"}
        hidden = list(table) + list(table.values()) + ["acct-", "ACCT-"] + list(NEVER)
        edge = ["--edge-identity", "case=sk-live-CCCC3333@ns.one",
                "--edge-identity", "dot=sk-live-DDDD4444", "--edge-cases", "all"]
        shapes = (["--identity-as", "bearer"], ["--cache-mode", "chat"],
                  ["--cache-mode", "chat", "--stream", "--route", "chat",
                   "--route", "messages"])
        for shape in shapes:
            for fmt in ([], ["--json"]):
                with serving("casebug", auth="token", tokens=table, hit_header="x-cache") as url:
                    code, out, err = _cli(["confirm", "semantic-cache", url,
                                           "--token-a", "sk-live-AAAA1111",
                                           "--token-b", "sk-live-BBBB2222"] + edge + shape + fmt)
                self.assertEqual(code, 1, out + err)
                self.assertIn("edge_case", out)
                for secret in hidden:
                    self.assertNotIn(secret, out + err, (shape, fmt, secret))


class OptionErrors(unittest.TestCase):
    def bad(self, **kw):
        with self.assertRaises(ValueError) as caught:
            run_semantic_cache_probe("http://127.0.0.1:4699", TA, TB, **kw)
        return str(caught.exception)

    def test_edge_cases(self):
        for value in ("nonsense", "dot,nonsense", "", "all,dot", []):
            self.assertIn("--edge-cases", self.bad(edge_cases=value))

    def test_edge_identity(self):
        for value in (["sk-secret-value"], ["bogus=sk-secret-value"], ["case="],
                      ["case=a", "case=sk-secret-value"], {"nope": "sk-secret-value"}):
            message = self.bad(edge_identity=value)
            self.assertIn("--edge-identity", message)
            self.assertNotIn("sk-secret-value", message)      # may be a credential
            self.assertNotIn("bogus", message)

    def test_old_and_new_prefix_options_must_agree(self):
        self.assertIn("two different", self.bad(sibling="x", edge_identity=["prefix=y"]))
        self.assertIn("two different", self.bad(mode="chat", user_sibling="x",
                                                 edge_user=["prefix=y"]))

    def test_chat_only_options(self):
        for kw in ({"edge_user": ["case=U"]}, {"route": ["chat"]}, {"stream": True}):
            self.assertIn("--cache-mode chat", self.bad(**kw))

    def test_routes(self):
        for value in (["graphql"], ["chat", "chat=/x"], ["responses=v1/responses"],
                      ["=/v1/responses"]):
            self.assertIn("--route", self.bad(mode="chat", route=value))
        self.assertIn("two different paths",
                      self.bad(mode="chat", route=["chat=/a"], chat_path="/b"))


class CommandLine(unittest.TestCase):
    def test_edge_cases_with_header_ids(self):
        with serving("wildcardbug") as url:
            base = ["confirm", "semantic-cache", url, "--token-a", "alice", "--token-b", "bob"]
            code, out, _ = _cli(base)
            self.assertEqual(code, 0, out)
            self.assertNotIn("edge_", out)
            code, out, _ = _cli(base + ["--edge-cases", "all"])
            self.assertEqual(code, 1, out)
            self.assertIn("LEAK           edge_wildcard", out)
            self.assertIn("NOT_RUN        edge_whitespace", out)
            code, out, _ = _cli(base + ["--edge-cases", "case,dot"])
            self.assertEqual(code, 0, out)

    def test_edge_identity_with_api_keys(self):
        with serving("separatorbug", auth="token") as url:
            base = ["confirm", "semantic-cache", url, "--token-a", TA, "--token-b", TB,
                    "--identity-as", "bearer"]
            code, out, _ = _cli(base + ["--edge-cases", "separator"])
            self.assertEqual(code, 0, out)
            self.assertIn("NOT_RUN        edge_separator", out)
            code, out, _ = _cli(base + ["--edge-identity", "separator=tok-sep",
                                        "--edge-identity", "case=tok-case@ignored"])
            self.assertEqual(code, 1, out)
            self.assertIn("LEAK           edge_separator", out)
            self.assertIn("OK             edge_case", out)
            # --token-sibling still means the prefix case.
            code, out, _ = _cli(base + ["--token-sibling", "tok-ali"])
            self.assertIn("OK             prefix_sibling", out)

    def test_routes_stream_and_edge_user(self):
        with serving("routebug", auth="user", api_key="shared-key-1") as url:
            code, out, err = _cli(["confirm", "semantic-cache", url, "--cache-mode", "chat",
                                   "--api-key", "shared-key-1", "--user-a", "alice",
                                   "--user-b", "bob", "--edge-user", "case=ALICE",
                                   "--route", "chat", "--route", "responses=/responses",
                                   "--stream", "--json"])
        self.assertEqual(code, 1, out + err)
        report = json.loads(out)
        got = {p["name"]: p["outcome"] for p in report["paths"]}
        self.assertEqual((got["exact@chat"], got["exact@responses"],
                          got["edge_case@chat"], got["edge_case@responses"],
                          got["cross_route@responses"]), ("OK", "LEAK", "OK", "LEAK", "LEAK"))
        self.assertTrue(report["controls"]["stream"])

    def test_usage_errors_exit_3_and_do_not_echo_the_value(self):
        with serving("safe") as url:
            base = ["confirm", "semantic-cache", url, "--token-a", "alice", "--token-b", "bob"]
            for extra in (["--edge-cases", "nonsense"], ["--edge-identity", "sk-secret-value"],
                          ["--edge-identity", "bogus=sk-secret-value"],
                          ["--edge-user", "case=sk-secret-value"], ["--route", "responses"],
                          ["--stream"], ["--cache-mode", "chat", "--route", "graphql"]):
                code, out, err = _cli(base + extra)
                self.assertEqual(code, 3, err)
                self.assertIn("error:", err)
                self.assertNotIn("sk-secret-value", out + err)

    def test_demo_shows_the_new_cases(self):
        code, out, _ = _cli(["confirm", "semantic-cache", "--demo"])
        self.assertEqual(code, 0, out)
        self.assertIn("VERDICT: the test WORKS", out)
        for line in ("LEAK           edge_dot", "LEAK           edge_separator",
                     "LEAK           edge_wildcard", "LEAK           edge_case",
                     "LEAK           edge_whitespace", "LEAK           exact@responses",
                     "LEAK           cross_route@messages", "OK             cross_route@messages"):
            self.assertIn(line, out)
        for part in ("edges safe -> OK", "dotbug -> LEAK", "separatorbug -> LEAK",
                     "wildcardbug -> LEAK", "casebug -> LEAK", "whitespacebug -> LEAK",
                     "routes routebug -> LEAK", "routes safe -> OK",
                     "stream routebug -> LEAK", "stream safe -> OK"):
            self.assertIn(part, out)


class PracticeServer(unittest.TestCase):
    def _post(self, url, path, body, token=TA):
        req = urllib.request.Request(url + path, method="POST", data=json.dumps(body).encode(),
                                     headers={"Authorization": f"Bearer {token}",
                                              "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.headers.get("Content-Type"), r.read().decode()

    def test_route_answer_shapes_share_one_cache(self):
        with serving("safe", auth="token") as url:
            _, raw = self._post(url, "/v1/responses", {"model": "m", "input": "alpha beta gamma"})
            first = json.loads(raw)
            _, raw = self._post(url, "/v1/messages", {"model": "m", "max_tokens": 8, "messages": [
                {"role": "user", "content": [{"type": "text", "text": "alpha beta gamma"}]}]})
            again = json.loads(raw)
            _, raw = self._post(url, "/v1/messages", {"model": "m", "max_tokens": 8, "messages": [
                {"role": "user", "content": "alpha beta gamma"}]}, token=TB)
            other = json.loads(raw)
        self.assertEqual(first["object"], "response")
        self.assertIn("alpha beta gamma", first["output"][0]["content"][0]["text"])
        self.assertEqual((again["type"], again["id"]), ("message", first["id"]))
        self.assertEqual(again["content"][0]["text"], first["output"][0]["content"][0]["text"])
        self.assertNotEqual(other["id"], first["id"])

    def test_stream_carries_the_same_answer(self):
        with serving("safe", auth="token") as url:
            for path, body in (
                    ("/v1/chat/completions", {"messages": [{"role": "user", "content": "one two"}]}),
                    ("/v1/responses", {"input": "three four"}),
                    ("/v1/messages", {"messages": [{"role": "user", "content": "five six"}]})):
                body["model"] = "m"
                _, plain = self._post(url, path, body)
                kind, raw = self._post(url, path, dict(body, stream=True))
                self.assertEqual(kind, "text/event-stream")
                text, rid = _read_event_stream((line + "\n").encode() for line in raw.split("\n"))
                self.assertEqual(rid, json.loads(plain)["id"])
                self.assertIn(text, plain)
                self.assertIn("You asked:", text)

    def test_unknown_route_option_rejected(self):
        with self.assertRaises(ValueError):
            build_server("safe", routes=["chat", "graphql"])


if __name__ == "__main__":
    unittest.main()
