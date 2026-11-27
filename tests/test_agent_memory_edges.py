"""Awkward-id identity pairs and by-id write paths of the agent-memory probe.

Every target is a local practice server on 127.0.0.1, ports 4600-4699, started
and stopped in-process. Nothing reaches the network."""

import io
import json
import threading
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from urllib.parse import quote

from strangertest import deep_tests as dt
from strangertest.agent_memory import (
    EDGE_KINDS, EDGE_PATHS, INCONCLUSIVE, LEAK, OBSERVATION, OK, WRITE_PATHS,
    parse_edge_identity, parse_namespace, run_agent_memory_probe,
)
from strangertest.cli import main
from strangertest.practice_agent_memory_http import build_server

A, B = "tok-alice", "tok-bob"
BUG_MODE = dict(dt._PRACTICE_EDGE_BUGS)          # kind -> the mode with that bug
NEW_EDGE_PATHS = [EDGE_PATHS[k] for k in EDGE_KINDS if k != "prefix"]


@contextmanager
def serving(mode):
    server = build_server(mode, port=dt._free_port())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


def probe(mode, **overrides):
    options = dict(namespace_a=["alice", "notes"], authorized=True)
    options.update(overrides)
    with serving(mode) as server:
        report = run_agent_memory_probe(
            f"http://127.0.0.1:{server.server_address[1]}", A, B, **options)
        report.server_state = server.state
        return report


def outcomes(report):
    return {p["name"]: p["outcome"] for p in report.paths}


def edges(*kinds):
    return dt._practice_edge_identities(*kinds)


def _cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class EdgeCases(unittest.TestCase):
    def test_each_bug_mode_leaks_on_its_own_case_only(self):
        for kind in EDGE_KINDS:
            with self.subTest(kind=kind):
                report = probe(BUG_MODE[kind], edge_identities=edges(kind))
                got = outcomes(report)
                self.assertEqual(got[EDGE_PATHS[kind]], "LEAK", report.summary())
                self.assertEqual(report.grade, LEAK)
                # The app's own checks still hold: B's direct reads are refused.
                self.assertEqual(got["store_get"], "OK")
                self.assertEqual(got["store_search_namespace"], "OK")
                self.assertEqual([n for n, o in got.items() if o == "LEAK"], [EDGE_PATHS[kind]])

    def test_safe_server_is_ok_on_every_case(self):
        report = probe("safe", edge_identities=edges())
        got = outcomes(report)
        for kind in EDGE_KINDS:
            self.assertEqual(got[EDGE_PATHS[kind]], "OK", report.summary())
        self.assertEqual(report.grade, OK)

    def test_case_without_an_identity_is_not_run_never_ok(self):
        for mode in ("safe", "dotbug"):
            report = probe(mode, edge_identities=edges("case"))
            got = outcomes(report)
            for kind in EDGE_KINDS:
                expected = "OK" if kind == "case" else "NOT_RUN"
                self.assertEqual(got[EDGE_PATHS[kind]], expected, report.summary())

    def test_identity_the_server_rejects_is_not_exercised(self):
        # strictids refuses dotted and whitespace-edged labels, as a fixed store does.
        report = probe("strictids", edge_identities=edges("dot", "whitespace", "case"))
        got = outcomes(report)
        self.assertEqual(got["store_edge_dot"], "NOT_EXERCISED", report.summary())
        self.assertEqual(got["store_edge_whitespace"], "NOT_EXERCISED")
        self.assertEqual(got["store_edge_case"], "OK")
        self.assertEqual(report.grade, OK)
        note = next(p["note"] for p in report.paths if p["name"] == "store_edge_dot")
        self.assertIn("could not store and read back its own item", note)

    def test_nothing_to_reach_is_not_exercised(self):
        # A cannot write outside her own namespace on a safe server, so there is
        # no item of hers for the extra identity to reach.
        report = probe("safe", namespace_a=None, edge_identities=edges("case"))
        self.assertIn(outcomes(report)["store_edge_case"], ("NOT_RUN", "NOT_EXERCISED"))
        report = probe("broken", edge_identities=edges())
        self.assertEqual(report.grade, INCONCLUSIVE, report.summary())
        for name in EDGE_PATHS.values():
            self.assertEqual(outcomes(report)[name], "NOT_EXERCISED")

    def test_identity_of_the_wrong_shape_is_not_run(self):
        wrong = [{"kind": kind, "token": "tok-bob", "namespace": ["bob"]} for kind in EDGE_KINDS]
        report = probe("leaky", edge_identities=wrong)
        for name in EDGE_PATHS.values():
            self.assertEqual(outcomes(report)[name], "NOT_RUN", report.summary())
        inside = [{"kind": "dot", "token": "tok-bob", "namespace": ["alice"]},
                  {"kind": "case", "token": A, "namespace": ["Alice"]},
                  {"kind": "wildcard", "token": "tok-al_ce", "namespace": None}]
        report = probe("leaky", edge_identities=inside)
        for kind in ("dot", "case", "wildcard"):
            self.assertEqual(outcomes(report)[EDGE_PATHS[kind]], "NOT_RUN", report.summary())

    def test_parent_form_of_the_dot_and_separator_cases(self):
        # A's own id holds the dot / separator; the extra identity is the part before it.
        for kind, mode, a_id, other in (("dot", "dotbug", "acme.alice", "acme"),
                                        ("separator", "separatorbug", "team:alice", "team")):
            identity = [{"kind": kind, "token": "tok-" + other, "namespace": [other]}]
            for server_mode, expected in ((mode, "LEAK"), ("safe", "OK")):
                with serving(server_mode) as server:
                    report = run_agent_memory_probe(
                        f"http://127.0.0.1:{server.server_address[1]}", "tok-" + a_id, B,
                        namespace_a=[a_id], edge_identities=identity, authorized=True)
                self.assertEqual(outcomes(report)[EDGE_PATHS[kind]], expected, report.summary())

    def test_several_identities_of_one_kind_share_one_line(self):
        report = probe("dotbug", edge_identities=edges("dot"))
        entry = next(p for p in report.paths if p["name"] == "store_edge_dot")
        self.assertEqual(entry["identities"], 2)
        self.assertEqual(entry["outcome"], "LEAK")
        self.assertIn("1 LEAK, 1 OK", entry["note"])

    def test_prefix_identity_is_the_same_path_as_namespace_b(self):
        new = probe("prefixbug", edge_identities=edges("prefix"))
        with serving("prefixbug") as server:
            old = run_agent_memory_probe(
                f"http://127.0.0.1:{server.server_address[1]}", A, "tok-ali",
                namespace_a=["alice", "notes"], namespace_b=["ali"], authorized=True)
        self.assertEqual(outcomes(new)["store_search_own_prefix"], "LEAK", new.summary())
        self.assertEqual(outcomes(old)["store_search_own_prefix"], "LEAK", old.summary())
        self.assertEqual([p["name"] for p in new.paths], [p["name"] for p in old.paths])

    def test_unknown_kind_is_refused(self):
        with self.assertRaises(ValueError):
            probe("safe", edge_identities=[{"kind": "nonsense", "token": "t", "namespace": ["x"]}])


class WritePaths(unittest.TestCase):
    def test_off_by_default_and_nothing_is_written(self):
        report = probe("writeleak")
        got = outcomes(report)
        for name in WRITE_PATHS:
            self.assertEqual(got[name], "NOT_RUN", report.summary())
        self.assertEqual(report.grade, OK)
        state = report.server_state
        # Only the one thread and the one item of the read paths exist, untouched.
        self.assertEqual(len(state.threads), 1)
        self.assertEqual([key for _, key in state.items], ["st-item"])
        self.assertIn("--write-paths", report.hint())

    def test_unchecked_writes_are_leaks(self):
        for mode in ("writeleak", "leaky"):
            report = probe(mode, write_paths=True)
            got = outcomes(report)
            for name in WRITE_PATHS:
                self.assertEqual(got[name], "LEAK", report.summary())
            self.assertEqual(report.grade, LEAK)
            self.assertIn("A write crossed identities on", report.detail)
        self.assertEqual(outcomes(probe("writeleak", write_paths=True))["store_get"], "OK")

    def test_safe_server_refuses_every_write(self):
        report = probe("safe", write_paths=True)
        got = outcomes(report)
        for name in WRITE_PATHS:
            self.assertEqual(got[name], "OK", report.summary())
        self.assertEqual(report.grade, OK)
        # The object each attempt aimed at is still there.
        state = report.server_state
        self.assertIn("st-item-put", [key for _, key in state.items])
        self.assertIn("st-item-del", [key for _, key in state.items])

    def test_accepted_but_ignored_write_is_an_observation(self):
        report = probe("writeack", write_paths=True)
        got = outcomes(report)
        for name in WRITE_PATHS:
            self.assertEqual(got[name], "OBSERVATION", report.summary())
        self.assertEqual(report.grade, OBSERVATION)
        self.assertIn("accepted", report.detail)

    def test_write_a_cannot_do_herself_is_not_exercised(self):
        report = probe("nowrites", write_paths=True)
        got = outcomes(report)
        for name in ("thread_update", "thread_delete", "store_delete"):
            self.assertEqual(got[name], "NOT_EXERCISED", report.summary())
        self.assertEqual(got["store_put_overwrite"], "OK")      # PUT still works there
        report = probe("broken", write_paths=True)
        self.assertEqual(report.grade, INCONCLUSIVE)
        for name in WRITE_PATHS:
            self.assertEqual(outcomes(report)[name], "NOT_EXERCISED", report.summary())

    def test_no_write_is_sent_to_a_server_without_authentication(self):
        report = probe("open", write_paths=True)
        for name in WRITE_PATHS:
            self.assertEqual(outcomes(report)[name], "NOT_RUN", report.summary())
        self.assertEqual(report.grade, OBSERVATION)

    def test_writes_run_last_deletes_at_the_end(self):
        names = [p["name"] for p in probe("safe", write_paths=True).paths]
        self.assertEqual(tuple(names[-4:]), WRITE_PATHS)
        self.assertEqual(WRITE_PATHS[-2:], ("thread_delete", "store_delete"))


class AcrossTheBoard(unittest.TestCase):
    def test_safe_is_ok_with_everything_turned_on(self):
        report = probe("safe", edge_identities=edges(), write_paths=True, namespace_b=["bob"],
                       **dt._PRACTICE_AGENT)
        got = outcomes(report)
        self.assertEqual(got.pop("store_search_all"), "NOT_EXERCISED")   # refused even for A
        self.assertEqual(set(got.values()), {"OK"}, report.summary())
        self.assertEqual(report.grade, OK)
        self.assertEqual(report.hint(), "")

    def test_broken_stays_inconclusive(self):
        report = probe("broken", edge_identities=edges(), write_paths=True, **dt._PRACTICE_AGENT)
        self.assertEqual(report.grade, INCONCLUSIVE, report.summary())
        self.assertFalse({"OK", "LEAK"} & set(outcomes(report).values()))

    def test_demo_has_every_fixture(self):
        res = dt._demo_agent_memory()
        self.assertEqual(res["safe"].grade, OK)
        self.assertNotIn("NOT_RUN", outcomes(res["safe"]).values(), res["safe"].summary())
        for kind in EDGE_KINDS:
            self.assertEqual(outcomes(res[BUG_MODE[kind]])[EDGE_PATHS[kind]], "LEAK")
        for name in WRITE_PATHS:
            self.assertEqual(outcomes(res["writeleak"])[name], "LEAK")
            self.assertEqual(outcomes(res["leaky"])[name], "LEAK")
        code, out, _ = _cli(["confirm", "agent-memory", "--demo"])
        self.assertEqual(code, 0, out)
        for name in NEW_EDGE_PATHS + list(WRITE_PATHS):
            self.assertIn(name, out)


class Hygiene(unittest.TestCase):
    def test_no_raw_id_token_or_marker_anywhere(self):
        identities = edges()
        secrets_ = [A, B] + [i["token"] for i in identities]
        ids = [i["namespace"][0] for i in identities if i["namespace"][0] != "ali"] + ["tok-ali"]
        for mode in ("safe", "dotbug", "wildcardbug", "writeleak", "strictids"):
            report = probe(mode, edge_identities=identities, write_paths=True)
            dumped = json.dumps(report.to_dict()) + report.summary() + report.hint()
            for raw in secrets_ + ids + ["st-mem-", "st-own-", "st-touch-", "st-ctl-", "alice"]:
                self.assertNotIn(raw, dumped, mode)
            fps = report.fingerprints["edge_identities"]
            self.assertEqual(len(fps), len(identities))
            self.assertTrue(all(f["token"].startswith("sha256:") and f["kind"] in EDGE_KINDS
                                for f in fps))

    def test_cli_output_is_clean_too(self):
        flags = ["--token-a", A, "--token-b", B, "--namespace-a", "alice.notes", "--write-paths",
                 "--edge-identity", "dot=tok-alice.notes@alice.notes",
                 "--edge-identity", "case=tok-Alice@Alice",
                 "--edge-identity", 'wildcard=tok-al_ce@["al_ce"]']
        with serving("dotbug") as server:
            url = f"http://127.0.0.1:{server.server_address[1]}"
            code, out, _ = _cli(["confirm", "agent-memory", url] + flags)
            json_code, json_out, _ = _cli(["confirm", "agent-memory", url, "--json"] + flags)
        self.assertEqual((code, json_code), (1, 1), out)
        self.assertIn("store_edge_dot", out)
        data = json.loads(json_out)
        got = {p["name"]: p["outcome"] for p in data["paths"]}
        self.assertEqual(got["store_edge_dot"], "LEAK")
        self.assertEqual(got["store_edge_case"], "OK")
        self.assertEqual(got["store_edge_wildcard"], "OK")
        self.assertEqual(got["thread_delete"], "OK")
        for raw in ("tok-", "Alice", "al_ce", "alice", "st-mem-"):
            self.assertNotIn(raw, out + json_out)


class CommandLine(unittest.TestCase):
    def test_writes_need_the_flag(self):
        flags = ["--token-a", A, "--token-b", B, "--namespace-a", "alice.notes"]
        with serving("writeleak") as server:
            url = f"http://127.0.0.1:{server.server_address[1]}"
            code, out, _ = _cli(["confirm", "agent-memory", url] + flags)
            self.assertEqual(code, 0, out)
            self.assertEqual(len(server.state.threads), 1)
            code, out, _ = _cli(["confirm", "agent-memory", url, "--write-paths"] + flags)
            self.assertEqual(code, 1, out)
            self.assertIn("write crossed identities", out)

    def test_bad_edge_identity_is_a_usage_error(self):
        for spec in ("nonsense=tok-x@x", "dot", "dot=@x", 'dot=tok-x@["a", 1]'):
            with serving("safe") as server:
                code, _, err = _cli(["confirm", "agent-memory",
                                     f"http://127.0.0.1:{server.server_address[1]}",
                                     "--token-a", A, "--token-b", B, "--edge-identity", spec])
            self.assertEqual(code, 3, spec)
            self.assertTrue(err.startswith("error:"), err)

    def test_edge_identity_syntax(self):
        self.assertEqual(parse_edge_identity("dot=tok-x@acme.alice"),
                         {"kind": "dot", "token": "tok-x", "namespace": ["acme.alice"]})
        self.assertEqual(parse_edge_identity('SEPARATOR=t@["team:alice", "notes"]')["namespace"],
                         ["team:alice", "notes"])
        self.assertEqual(parse_edge_identity("case=t@user@example.com")["namespace"],
                         ["user@example.com"])
        self.assertIsNone(parse_edge_identity("wildcard=tok")["namespace"])
        self.assertEqual(parse_namespace("alice.notes"), ["alice", "notes"])
        self.assertEqual(parse_namespace('["acme.alice", "notes"]'), ["acme.alice", "notes"])

    def test_practice_ids_are_percent_decoded(self):
        with serving("safe") as server:
            self.assertEqual(server.state.identify("Bearer tok-" + quote("al% ", safe="")), "al% ")


if __name__ == "__main__":
    unittest.main()
