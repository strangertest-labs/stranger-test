"""The semantic-cache cross-user leak probe against the bundled practice cache.

Every target is a local practice cache on 127.0.0.1, ports 4600-4699, started
and stopped in-process. Nothing reaches the network."""

import io
import json
import threading
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout

from strangertest import deep_tests as dt
from strangertest.cli import main
from strangertest.guard import AuthorizationError
from strangertest.practice_semantic_cache_http import (
    MODES, build_server, similarity,
)
from strangertest.semantic_cache import (
    INCONCLUSIVE, LEAK, OBSERVATION, OK, run_semantic_cache_probe,
)

A, B = "alice", "bob"


@contextmanager
def serving(mode):
    server = build_server(mode, port=dt._free_port())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def probe(mode, id_a=A, id_b=B, **kw):
    with serving(mode) as url:
        return run_semantic_cache_probe(url, id_a, id_b, authorized=True, **kw)


def outcomes(report):
    return {p["name"]: p["outcome"] for p in report.paths}


class Similarity(unittest.TestCase):
    def test_identical_is_one(self):
        self.assertEqual(similarity("the Falcon wire limit", "the Falcon wire limit"), 1.0)

    def test_paraphrase_is_a_near_match(self):
        s = similarity("What is the wire transfer limit for the Falcon account?",
                       "How much can the Falcon account send by wire transfer?")
        self.assertGreater(s, 0.6)
        self.assertLess(s, 1.0)

    def test_unrelated_is_low(self):
        self.assertLess(similarity("Falcon wire transfer limit", "capital of France"), 0.3)


class Grades(unittest.TestCase):
    def test_leaky_cache_leaks_on_exact_and_reworded(self):
        report = probe("leaky")
        self.assertEqual(report.grade, LEAK, report.summary())
        got = outcomes(report)
        self.assertEqual(got["exact"], "LEAK")
        self.assertEqual(got["reworded"], "LEAK")

    def test_safe_cache_is_ok(self):
        report = probe("safe")
        self.assertEqual(report.grade, OK, report.summary())
        self.assertEqual(outcomes(report)["exact"], "OK")
        self.assertTrue(report.controls["identity_required"])

    def test_no_identity_cache_is_an_observation(self):
        report = probe("open")
        self.assertEqual(report.grade, OBSERVATION, report.summary())
        self.assertIn("does not identify callers", report.detail)

    def test_collapsed_principal_is_an_observation_not_a_leak(self):
        report = probe("collapse")
        self.assertEqual(report.grade, OBSERVATION, report.summary())
        self.assertIn("one principal", report.detail)

    def test_broken_cache_is_inconclusive_never_ok(self):
        report = probe("broken")
        self.assertEqual(report.grade, INCONCLUSIVE, report.summary())
        self.assertNotIn("OK", set(outcomes(report).values()))
        self.assertNotIn("LEAK", set(outcomes(report).values()))


class PrefixSibling(unittest.TestCase):
    def test_prefixbug_leaks_on_the_prefix_sibling_path(self):
        # ali is a string prefix of alice; A stores, B=ali reads in its own scope.
        report = probe("prefixbug", id_a="alice", id_b="ali")
        got = outcomes(report)
        self.assertEqual(got["prefix_sibling"], "LEAK", report.summary())
        self.assertEqual(report.grade, LEAK)

    def test_safe_cache_clears_the_prefix_sibling_path(self):
        report = probe("safe", id_a="alice", id_b="ali")
        self.assertEqual(outcomes(report)["prefix_sibling"], "OK", report.summary())
        self.assertEqual(report.grade, OK)

    def test_path_not_run_without_a_prefix_sibling_pair(self):
        report = probe("prefixbug", id_a="alice", id_b="bob")
        self.assertEqual(outcomes(report)["prefix_sibling"], "NOT_RUN")


class Controls(unittest.TestCase):
    def test_reworded_path_not_exercised_when_a_cannot_near_match(self):
        # A threshold of 1.0 makes only exact matches hit, so A's reworded query
        # never hits and that path cannot be exercised.
        report = probe("leaky", threshold=1.0)
        got = outcomes(report)
        self.assertEqual(got["exact"], "LEAK")
        self.assertEqual(got["reworded"], "NOT_EXERCISED")
        self.assertTrue(any("not exercised" in o for o in report.observations))

    def test_one_identity_for_both_is_inconclusive(self):
        with serving("leaky") as url:
            report = run_semantic_cache_probe(url, A, A, authorized=True)
        self.assertEqual(report.grade, INCONCLUSIVE)

    def test_unreachable_cache_is_inconclusive(self):
        url = f"http://127.0.0.1:{dt._free_port()}"
        report = run_semantic_cache_probe(url, A, B, timeout=2.0)
        self.assertEqual(report.grade, INCONCLUSIVE)
        self.assertIn("could not be reached", report.detail)

    def test_non_local_target_needs_authorization(self):
        with self.assertRaises(AuthorizationError):
            run_semantic_cache_probe("https://cache.example.com", A, B)

    def test_unknown_mode_rejected(self):
        self.assertIn("leaky", MODES)
        with self.assertRaises(ValueError):
            build_server("nonsense")


class ReportHygiene(unittest.TestCase):
    def test_no_identity_or_marker_in_the_report(self):
        report = probe("leaky", id_a="cust-7f3a1c", id_b="cust-9b2042")
        dumped = json.dumps(report.to_dict()) + report.summary()
        self.assertNotIn("st-cache-", dumped)
        self.assertNotIn("cust-7f3a1c", dumped)
        self.assertNotIn("cust-9b2042", dumped)
        self.assertTrue(report.fingerprints["marker"].startswith("sha256:"))
        self.assertNotEqual(report.fingerprints["id_a"], report.fingerprints["id_b"])


def _cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class CommandLine(unittest.TestCase):
    def test_listed(self):
        code, out, _ = _cli(["confirm", "--list"])
        self.assertEqual(code, 0)
        self.assertIn("semantic-cache", out)

    def test_demo_catches_leaky_and_clears_safe(self):
        code, out, _ = _cli(["confirm", "semantic-cache", "--demo"])
        self.assertEqual(code, 0, out)
        self.assertIn("VERDICT: the test WORKS", out)

    def test_demo_dict_includes_prefixbug_leak(self):
        res = dt._demo_semantic_cache()
        self.assertEqual(res["prefixbug"].grade, LEAK)
        self.assertEqual(outcomes(res["prefixbug"])["prefix_sibling"], "LEAK")

    def test_target_run_exit_codes(self):
        with serving("leaky") as url:
            code, out, _ = _cli(["confirm", "semantic-cache", url,
                                 "--token-a", A, "--token-b", B])
        self.assertEqual(code, 1, out)
        self.assertIn("LEAK", out)
        with serving("safe") as url:
            code, out, _ = _cli(["confirm", "semantic-cache", url,
                                 "--token-a", A, "--token-b", B])
        self.assertEqual(code, 0, out)
        with serving("open") as url:
            code, out, _ = _cli(["confirm", "semantic-cache", url,
                                 "--token-a", A, "--token-b", B])
        self.assertEqual(code, 2, out)


if __name__ == "__main__":
    unittest.main()
