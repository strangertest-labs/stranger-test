"""The semantic-cache probe's options for real caches and gateways: how each
identity is presented, custom paths, and the chat-completions shape.

Every target is the bundled practice cache on 127.0.0.1, ports 4600-4699,
started and stopped in-process. Nothing reaches the network."""

import io
import json
import threading
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from strangertest import deep_tests as dt
from strangertest.cli import main
from strangertest.practice_semantic_cache_http import build_server
from strangertest.semantic_cache import (
    INCONCLUSIVE, LEAK, OBSERVATION, OK, run_semantic_cache_probe,
)

TA, TB, TSIB = "tok-alice", "tok-bob", "tok-ali"


@contextmanager
def _run(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def serving(mode, **options):
    return _run(build_server(mode, port=dt._free_port(), **options))


def probe(cache, id_a=TA, id_b=TB, server=None, **kw):
    with serving(cache, **(server or {})) as url:
        return run_semantic_cache_probe(url, id_a, id_b, authorized=True, **kw)


def chat(cache, id_a=TA, id_b=TB, server=None, **kw):
    options = {"auth": "token"}
    options.update(server or {})
    return probe(cache, id_a, id_b, server=options, mode="chat", **kw)


def outcomes(report):
    return {p["name"]: p["outcome"] for p in report.paths}


def notes(report):
    return {p["name"]: p.get("note", "") for p in report.paths}


def _cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


# --------------------------------------------------------------------------- #
# store shape: identity options and paths                                      #
# --------------------------------------------------------------------------- #

class IdentityHeader(unittest.TestCase):
    def test_custom_header_name_reaches_the_cache(self):
        server = {"identity_header": "x-tenant-id"}
        self.assertEqual(probe("leaky", "t1", "t2", server, identity_header="x-tenant-id").grade, LEAK)
        report = probe("safe", "t1", "t2", server, identity_header="x-tenant-id")
        self.assertEqual(report.grade, OK, report.summary())
        self.assertEqual(report.controls["identity_carried_by"], ["x-tenant-id header"])

    def test_default_header_is_refused_by_a_cache_that_wants_another(self):
        report = probe("safe", "t1", "t2", {"identity_header": "x-tenant-id"})
        self.assertEqual(report.grade, INCONCLUSIVE, report.summary())
        self.assertIn("could not store", report.detail)

    def test_shared_api_key_plus_tenant_header(self):
        server = {"identity_header": "x-tenant-id", "api_key": "shared-key-1"}
        report = probe("safe", "t1", "t2", server, identity_header="x-tenant-id",
                       api_key="shared-key-1")
        self.assertEqual(report.grade, OK, report.summary())
        # Without the shared key nothing is accepted, so nothing can be told.
        report = probe("safe", "t1", "t2", server, identity_header="x-tenant-id")
        self.assertEqual(report.grade, INCONCLUSIVE, report.summary())

    def test_bad_header_name_is_a_usage_error(self):
        with self.assertRaises(ValueError):
            probe("safe", "t1", "t2", identity_header="bad header\r\nx: y")


class BearerTokens(unittest.TestCase):
    def test_tokens_as_authorization_bearer(self):
        server = {"auth": "token"}
        self.assertEqual(probe("leaky", server=server, identity_as="bearer").grade, LEAK)
        report = probe("safe", server=server, identity_as="bearer")
        self.assertEqual(report.grade, OK, report.summary())
        self.assertEqual(report.controls["identity_carried_by"], ["bearer token"])

    def test_api_key_in_a_custom_header_is_sent_raw(self):
        server = {"auth": "token", "token_header": "x-api-key"}
        report = probe("safe", server=server, token_header="x-api-key")
        self.assertEqual(report.grade, OK, report.summary())
        self.assertEqual(report.controls["identity_carried_by"], ["x-api-key header"])
        self.assertEqual(probe("leaky", server=server, token_header="x-api-key").grade, LEAK)

    def test_unknown_token_cannot_store(self):
        report = probe("safe", "tok-nobody", TB, {"auth": "token"}, identity_as="bearer")
        self.assertEqual(report.grade, INCONCLUSIVE, report.summary())

    def test_prefix_sibling_skipped_without_a_third_token(self):
        report = probe("prefixbug", server={"auth": "token"}, identity_as="bearer")
        self.assertEqual(outcomes(report)["prefix_sibling"], "NOT_RUN", report.summary())
        self.assertIn("--token-sibling", notes(report)["prefix_sibling"])
        self.assertEqual(report.grade, OK)      # the two paths that ran were clean

    def test_token_strings_that_are_prefixes_do_not_trigger_the_path(self):
        tokens = {"key-alice": "alice", "key": "bob"}
        report = probe("prefixbug", "key-alice", "key", {"auth": "token", "tokens": tokens},
                       identity_as="bearer")
        self.assertEqual(outcomes(report)["prefix_sibling"], "NOT_RUN", report.summary())

    def test_third_token_runs_the_prefix_sibling_path(self):
        report = probe("prefixbug", server={"auth": "token"}, identity_as="bearer", sibling=TSIB)
        self.assertEqual(outcomes(report)["prefix_sibling"], "LEAK", report.summary())
        self.assertEqual(report.grade, LEAK)
        report = probe("safe", server={"auth": "token"}, identity_as="bearer", sibling=TSIB)
        self.assertEqual(outcomes(report)["prefix_sibling"], "OK", report.summary())

    def test_sibling_equal_to_a_is_not_run(self):
        report = probe("leaky", server={"auth": "token"}, identity_as="bearer", sibling=TA)
        self.assertEqual(outcomes(report)["prefix_sibling"], "NOT_RUN", report.summary())

    def test_api_key_cannot_be_combined_with_per_identity_tokens(self):
        with self.assertRaises(ValueError):
            probe("safe", server={"auth": "token"}, identity_as="bearer", api_key="k")


class PrefixSiblingControl(unittest.TestCase):
    def test_broken_cache_with_a_prefix_pair_is_not_ok(self):
        report = probe("broken", "alice", "ali")
        self.assertEqual(outcomes(report)["prefix_sibling"], "NOT_EXERCISED", report.summary())
        self.assertEqual(report.grade, INCONCLUSIVE)


class _Remapped(BaseHTTPRequestHandler):
    """Forwards /cache/put and /cache/get to a practice cache's /store and /query."""
    protocol_version = "HTTP/1.1"
    upstream = ""
    routes = {"/cache/put": "/store", "/cache/get": "/query"}

    def log_message(self, *args):
        pass

    def do_POST(self):
        import urllib.error
        import urllib.request
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        target = self.routes.get(self.path)
        status, body = 404, b"{}"
        if target:
            req = urllib.request.Request(self.upstream + target, data=raw, method="POST",
                                         headers={"x-identity": self.headers.get("x-identity", ""),
                                                  "Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    status, body = r.status, r.read()
            except urllib.error.HTTPError as exc:
                status, body = exc.code, exc.read()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class CustomPaths(unittest.TestCase):
    @contextmanager
    def remapped(self, mode):
        with serving(mode) as upstream:
            handler = type("Handler", (_Remapped,), {"upstream": upstream})
            front = ThreadingHTTPServer(("127.0.0.1", dt._free_port()), handler)
            front.daemon_threads = True
            with _run(front) as url:
                yield url

    def test_store_and_query_paths(self):
        for mode, grade in (("leaky", LEAK), ("safe", OK)):
            with self.remapped(mode) as url:
                report = run_semantic_cache_probe(
                    url, "alice", "bob", store_path="/cache/put", query_path="/cache/get",
                    authorized=True)
            self.assertEqual(report.grade, grade, report.summary())

    def test_default_paths_do_not_exist_there(self):
        with self.remapped("leaky") as url:
            report = run_semantic_cache_probe(url, "alice", "bob", authorized=True)
        self.assertEqual(report.grade, INCONCLUSIVE, report.summary())

    def test_a_path_must_start_with_a_slash(self):
        with self.assertRaises(ValueError):
            probe("safe", "alice", "bob", store_path="store")


# --------------------------------------------------------------------------- #
# chat shape                                                                   #
# --------------------------------------------------------------------------- #

class ChatGrades(unittest.TestCase):
    def test_leaky_gateway_leaks_on_reworded_and_exact(self):
        report = chat("leaky")
        self.assertEqual(report.grade, LEAK, report.summary())
        got = outcomes(report)
        self.assertEqual((got["reworded"], got["exact"]), ("LEAK", "LEAK"))
        self.assertEqual(report.controls["hit_recognised_by"], ["response id"])

    def test_safe_gateway_is_ok(self):
        report = chat("safe")
        self.assertEqual(report.grade, OK, report.summary())
        got = outcomes(report)
        self.assertEqual((got["reworded"], got["exact"]), ("OK", "OK"))
        self.assertTrue(report.controls["a_exact_hit"])
        self.assertTrue(report.controls["identity_required"])

    def test_positive_control_fails_then_inconclusive_never_ok(self):
        report = chat("broken")
        self.assertEqual(report.grade, INCONCLUSIVE, report.summary())
        self.assertFalse(report.controls["a_exact_hit"])
        self.assertEqual(set(outcomes(report).values()), {"NOT_EXERCISED", "NOT_RUN"})

    def test_no_identity_gateway_is_an_observation(self):
        report = chat("open")
        self.assertEqual(report.grade, OBSERVATION, report.summary())
        self.assertIn("no identity", report.detail)

    def test_unknown_token_for_a_is_inconclusive(self):
        report = chat("leaky", id_a="tok-nobody")
        self.assertEqual(report.grade, INCONCLUSIVE, report.summary())
        self.assertIn("could not get an answer", report.detail)

    def test_refused_b_is_ok_not_a_leak(self):
        report = chat("leaky", id_b="tok-nobody")
        self.assertEqual(report.grade, OK, report.summary())
        self.assertIn("HTTP 401", notes(report)["exact"])

    def test_one_token_for_both_is_inconclusive(self):
        self.assertEqual(chat("leaky", id_b=TA).grade, INCONCLUSIVE)

    def test_unreachable_gateway_is_inconclusive(self):
        url = f"http://127.0.0.1:{dt._free_port()}"
        report = run_semantic_cache_probe(url, TA, TB, mode="chat", timeout=2.0)
        self.assertEqual(report.grade, INCONCLUSIVE)
        self.assertIn("could not be reached", report.detail)

    def test_exact_match_only_cache_exercises_the_exact_path_alone(self):
        # A reworded question that is nowhere near the base one: A's own reworded
        # request misses, so that path proves nothing.
        report = chat("leaky", reworded_query="Which planet is closest to the sun?")
        got = outcomes(report)
        self.assertEqual(got["reworded"], "NOT_EXERCISED", report.summary())
        self.assertEqual(got["exact"], "LEAK")
        self.assertEqual(report.grade, LEAK)

    def test_unknown_cache_mode_is_a_usage_error(self):
        with self.assertRaises(ValueError):
            probe("safe", mode="graphql")


class ChatPrefixSibling(unittest.TestCase):
    def test_skipped_without_a_third_token(self):
        report = chat("prefixbug")
        self.assertEqual(outcomes(report)["prefix_sibling"], "NOT_RUN", report.summary())
        self.assertIn("--token-sibling", notes(report)["prefix_sibling"])
        self.assertEqual(report.grade, OK)

    def test_third_token_catches_string_prefix_scoping(self):
        report = chat("prefixbug", sibling=TSIB)
        got = outcomes(report)
        self.assertEqual(got["prefix_sibling"], "LEAK", report.summary())
        self.assertEqual((got["reworded"], got["exact"]), ("OK", "OK"))
        self.assertEqual(report.grade, LEAK)

    def test_third_token_is_clean_on_a_safe_gateway(self):
        report = chat("safe", sibling=TSIB)
        self.assertEqual(outcomes(report)["prefix_sibling"], "OK", report.summary())


class ChatHitRecognition(unittest.TestCase):
    """Header first (calibrated), then the response body."""

    HEADER = {"hit_header": "x-cache"}
    HEADER_ONLY = {"hit_header": "x-cache", "fresh_id_on_hit": True}

    def test_header_is_found_without_being_named(self):
        report = chat("leaky", server=self.HEADER)
        self.assertEqual(report.controls["cache_hit_header"], "x-cache")
        self.assertEqual(report.controls["hit_recognised_by"], ["cache-hit header", "response id"])
        self.assertEqual(report.grade, LEAK)

    def test_named_header(self):
        server = {"hit_header": "x-gw-cache", "fresh_id_on_hit": True}
        report = chat("leaky", server=server, cache_hit_header="x-gw-cache")
        self.assertEqual(report.controls["cache_hit_header"], "x-gw-cache")
        self.assertEqual(report.grade, LEAK, report.summary())
        self.assertIn("x-gw-cache header reported a cache hit", notes(report)["exact"])

    def test_named_header_that_never_changes_falls_back_to_the_body(self):
        report = chat("leaky", cache_hit_header="content-type")
        self.assertIsNone(report.controls["cache_hit_header"])
        self.assertTrue(any("content-type" in o for o in report.observations))
        self.assertEqual(report.controls["hit_recognised_by"], ["response id"])
        self.assertEqual(report.grade, LEAK, report.summary())

    def test_header_only_leaky_gateway(self):
        # Ids are new on every response, so only the header (and, for the reworded
        # question, A's marker in the answer) can show the hit.
        report = chat("leaky", server=self.HEADER_ONLY)
        self.assertEqual(report.grade, LEAK, report.summary())
        self.assertFalse(report.controls["response_ids_mark_hits"])
        self.assertIn("marker", notes(report)["reworded"])
        self.assertIn("header", notes(report)["exact"])

    def test_header_hit_on_bs_own_entry_is_not_a_leak(self):
        # Safe gateway with a header: B's second question hits B's own first entry.
        report = chat("safe", server=self.HEADER)
        self.assertEqual(report.grade, OK, report.summary())
        self.assertIn("different entry", notes(report)["exact"])

    def test_header_hit_that_cannot_be_attributed_is_not_exercised(self):
        # Same, but with no stable ids there is no way to tell whose entry it was.
        report = chat("safe", server=self.HEADER_ONLY)
        got = outcomes(report)
        self.assertEqual(got["reworded"], "OK", report.summary())
        self.assertEqual(got["exact"], "NOT_EXERCISED")
        self.assertEqual(report.grade, OK)

    def test_body_only_marker_evidence_when_ids_change_and_no_header(self):
        report = chat("leaky", server={"fresh_id_on_hit": True})
        got = outcomes(report)
        self.assertEqual(got["reworded"], "LEAK", report.summary())
        self.assertEqual(got["exact"], "NOT_EXERCISED")
        self.assertEqual(report.grade, LEAK)

    def test_marker_placeholder_in_both_questions(self):
        report = chat("leaky", base_query="Falcon wire transfer limit {marker}?",
                      reworded_query="wire transfer limit of Falcon {marker}")
        self.assertEqual(report.grade, LEAK, report.summary())
        self.assertIn("same response id", notes(report)["reworded"])


class ChatUserField(unittest.TestCase):
    def test_user_field_with_a_shared_key(self):
        server = {"auth": "user", "api_key": "shared-key-1"}
        kw = dict(id_a=None, id_b=None, user_a="user-1", user_b="user-2", api_key="shared-key-1")
        report = chat("leaky", server=server, **kw)
        self.assertEqual(report.grade, LEAK, report.summary())
        self.assertEqual(report.controls["identity_carried_by"], ["user field"])
        self.assertEqual(chat("safe", server=server, **kw).grade, OK)

    def test_user_sibling(self):
        report = chat("prefixbug", None, None, {"auth": "user"},
                      user_a="alice", user_b="bob", user_sibling="ali")
        self.assertEqual(outcomes(report)["prefix_sibling"], "LEAK", report.summary())

    def test_user_field_the_gateway_does_not_require_is_noted(self):
        # A gateway that keys on tokens ignores the user field: both callers share
        # one token, so they are one principal to it and the "leak" stands only on
        # what the caller said. It is graded, and the report says so.
        tokens = {"shared": "one-principal"}
        report = chat("safe", None, None, {"auth": "token", "tokens": tokens},
                      user_a="u1", user_b="u2", api_key="shared")
        self.assertEqual(report.grade, LEAK, report.summary())
        self.assertTrue(any("user field" in o for o in report.observations))

    def test_user_options_need_chat_mode(self):
        with self.assertRaises(ValueError):
            probe("safe", "alice", "bob", user_a="u1", user_b="u2")

    def test_token_and_user_together(self):
        report = chat("safe", user_a="u1", user_b="u2")
        self.assertEqual(report.grade, OK, report.summary())
        self.assertEqual(report.controls["identity_carried_by"], ["bearer token", "user field"])


class ChatPathAndModel(unittest.TestCase):
    def test_custom_chat_path(self):
        report = chat("leaky", chat_path="/chat/completions")
        self.assertEqual(report.grade, LEAK, report.summary())
        report = chat("leaky", chat_path="/openai/v9/chat")
        self.assertEqual(report.grade, INCONCLUSIVE, report.summary())

    def test_model_name_is_sent(self):
        seen = []
        with serving("leaky", auth="token") as url:
            import strangertest.practice_semantic_cache_http as practice
            original = practice.SemanticCacheState.lookup

            def spy(self, identity, model, prompt, route="chat"):
                seen.append(model)
                return original(self, identity, model, prompt, route)

            practice.SemanticCacheState.lookup = spy
            try:
                run_semantic_cache_probe(url, TA, TB, mode="chat", model="my-model",
                                         authorized=True)
            finally:
                practice.SemanticCacheState.lookup = original
        self.assertTrue(seen)
        self.assertEqual(set(seen), {"my-model"})


class ReportHygiene(unittest.TestCase):
    SECRETS = ("tok-alice", "tok-bob", "tok-ali", "shared-key-1", "user-7f3a1c", "user-9b2042")

    def _clean(self, report):
        dumped = json.dumps(report.to_dict()) + report.summary()
        self.assertNotIn("stcache", dumped)
        self.assertNotIn("st-cache-", dumped)
        self.assertNotIn("chatcmpl-", dumped)
        for secret in self.SECRETS:
            self.assertNotIn(secret, dumped)
        self.assertTrue(report.fingerprints["marker"].startswith("sha256:"))
        self.assertNotEqual(report.fingerprints["id_a"], report.fingerprints["id_b"])

    def test_chat_report_has_no_marker_token_or_response_id(self):
        for mode in ("leaky", "safe", "broken", "prefixbug"):
            report = chat(mode, sibling=TSIB, server={"hit_header": "x-cache"})
            self._clean(report)
            self.assertTrue(report.fingerprints["id_sibling"].startswith("sha256:"))

    def test_user_field_and_shared_key_stay_out(self):
        report = chat("leaky", None, None, {"auth": "user", "api_key": "shared-key-1"},
                      user_a="user-7f3a1c", user_b="user-9b2042", api_key="shared-key-1")
        self._clean(report)

    def test_store_report_with_tokens_and_prefix_ids(self):
        self._clean(probe("prefixbug", server={"auth": "token"}, identity_as="bearer",
                          sibling=TSIB))
        # Header ids that are prefix siblings used to be echoed in a path note.
        report = probe("prefixbug", "cust-7f3a1c9", "cust-7f3a")
        dumped = json.dumps(report.to_dict()) + report.summary()
        self.assertEqual(outcomes(report)["prefix_sibling"], "LEAK")
        self.assertNotIn("cust-7f3a", dumped)


class CommandLine(unittest.TestCase):
    def test_identity_header_option(self):
        with serving("safe", identity_header="x-tenant-id") as url:
            code, out, _ = _cli(["confirm", "semantic-cache", url, "--token-a", "t1",
                                 "--token-b", "t2", "--identity-header", "x-tenant-id"])
            self.assertEqual(code, 0, out)
            # Without the option the ids go out as x-identity and the cache refuses them.
            code, out, _ = _cli(["confirm", "semantic-cache", url, "--token-a", "t1",
                                 "--token-b", "t2"])
            self.assertEqual(code, 2, out)

    def test_bearer_tokens_and_sibling_option(self):
        with serving("prefixbug", auth="token") as url:
            base = ["confirm", "semantic-cache", url, "--token-a", TA, "--token-b", TB,
                    "--identity-as", "bearer"]
            code, out, _ = _cli(base)
            self.assertEqual(code, 0, out)
            self.assertIn("NOT_RUN        prefix_sibling", out)
            code, out, _ = _cli(base + ["--token-sibling", TSIB])
            self.assertEqual(code, 1, out)
            self.assertIn("LEAK           prefix_sibling", out)
            self.assertNotIn("tok-", out)

    def test_token_header_option(self):
        with serving("leaky", auth="token", token_header="x-api-key") as url:
            code, out, _ = _cli(["confirm", "semantic-cache", url, "--token-a", TA,
                                 "--token-b", TB, "--token-header", "x-api-key"])
        self.assertEqual(code, 1, out)

    def test_chat_mode_exit_codes(self):
        for mode, expected in (("leaky", 1), ("safe", 0), ("broken", 2), ("open", 2)):
            with serving(mode, auth="token") as url:
                code, out, _ = _cli(["confirm", "semantic-cache", url, "--cache-mode", "chat",
                                     "--token-a", TA, "--token-b", TB, "--model", "m1"])
            self.assertEqual(code, expected, out)

    def test_chat_mode_user_field_api_key_and_header(self):
        with serving("leaky", auth="user", api_key="shared-key-1", hit_header="x-gw") as url:
            code, out, _ = _cli(["confirm", "semantic-cache", url, "--cache-mode", "chat",
                                 "--api-key", "shared-key-1", "--user-a", "u1", "--user-b", "u2",
                                 "--user-sibling", "u", "--cache-hit-header", "x-gw",
                                 "--chat-path", "/chat/completions", "--json"])
        self.assertEqual(code, 1, out)
        report = json.loads(out)
        self.assertEqual(report["controls"]["cache_hit_header"], "x-gw")
        self.assertEqual(report["controls"]["identity_carried_by"], ["user field"])
        self.assertNotIn("shared-key-1", out)

    def test_target_run_with_tokens_prints_no_token_or_raw_id(self):
        # Token identities in both shapes, text and JSON: only labels and
        # fingerprints may appear, on stdout and stderr alike.
        tokens = {"sk-live-AAAA1111": "acct-alice-01", "sk-live-BBBB2222": "acct-bob-02",
                  "sk-live-CCCC3333": "acct-ali"}
        secrets_ = list(tokens) + list(tokens.values()) + ["u-alice-77", "u-bob-88"]
        for cache in ("leaky", "prefixbug"):
            for shape in (["--identity-as", "bearer"], ["--cache-mode", "chat"],
                          ["--cache-mode", "chat", "--user-a", "u-alice-77",
                           "--user-b", "u-bob-88"]):
                for fmt in ([], ["--json"]):
                    with serving(cache, auth="token", tokens=tokens,
                                 hit_header="x-cache") as url:
                        code, out, err = _cli(
                            ["confirm", "semantic-cache", url,
                             "--token-a", "sk-live-AAAA1111", "--token-b", "sk-live-BBBB2222",
                             "--token-sibling", "sk-live-CCCC3333"] + shape + fmt)
                    self.assertIn(code, (0, 1, 2), err)
                    for secret in secrets_ + ["stcache", "st-cache-", "chatcmpl-"]:
                        self.assertNotIn(secret, out + err, (cache, shape, fmt))
                    self.assertIn("sha256:" if fmt else "prefix_sibling", out)

    def test_header_ids_that_are_prefix_siblings_are_not_printed(self):
        with serving("prefixbug") as url:
            for fmt in ([], ["--json"]):
                code, out, err = _cli(["confirm", "semantic-cache", url, "--token-a",
                                       "tenant-7f3a1c9", "--token-b", "tenant-7f3a"] + fmt)
                self.assertEqual(code, 1, out)
                self.assertNotIn("tenant-7f3a", out + err)

    def test_store_and_query_path_options_reach_the_probe(self):
        with serving("leaky") as url:
            code, out, _ = _cli(["confirm", "semantic-cache", url, "--token-a", "alice",
                                 "--token-b", "bob", "--store-path", "/nope",
                                 "--query-path", "/query"])
        self.assertEqual(code, 2, out)
        self.assertIn("could not store", out)

    def test_usage_errors_exit_3(self):
        with serving("safe") as url:
            for extra in (["--user-a", "u1"], ["--threshold", "high"],
                          ["--store-path", "store"], ["--identity-header", "a b"]):
                code, _, err = _cli(["confirm", "semantic-cache", url, "--token-a", "alice",
                                     "--token-b", "bob"] + extra)
                self.assertEqual(code, 3, err)
                self.assertIn("error:", err)

    def test_demo_shows_both_shapes(self):
        code, out, _ = _cli(["confirm", "semantic-cache", "--demo", "--full"])
        self.assertEqual(code, 0, out)
        self.assertIn("chat-completions shape", out)
        self.assertIn("chat leaky -> LEAK, chat safe -> OK, chat broken -> INCONCLUSIVE", out)

    def test_demo_dict_has_every_chat_grade(self):
        res = dt._demo_semantic_cache()
        self.assertEqual(res["chat_leaky"].grade, LEAK)
        self.assertEqual(res["chat_safe"].grade, OK)
        self.assertEqual(res["chat_broken"].grade, INCONCLUSIVE)


class PracticeServer(unittest.TestCase):
    def test_unknown_auth_rejected(self):
        with self.assertRaises(ValueError):
            build_server("safe", auth="kerberos")

    def test_chat_answer_shape_and_cache(self):
        import urllib.request
        with serving("safe", auth="token", hit_header="x-cache") as url:
            def ask(token, text):
                req = urllib.request.Request(
                    url + "/v1/chat/completions", method="POST",
                    data=json.dumps({"model": "m", "messages": [
                        {"role": "user", "content": text}]}).encode(),
                    headers={"Authorization": f"Bearer {token}",
                             "Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=10) as r:
                    return r.headers.get("x-cache"), json.loads(r.read())
            first = ask(TA, "alpha beta gamma")
            again = ask(TA, "alpha beta gamma")
            other = ask(TB, "alpha beta gamma")
        self.assertEqual((first[0], again[0], other[0]), ("MISS", "HIT", "MISS"))
        self.assertEqual(first[1], again[1])
        self.assertNotEqual(first[1]["id"], other[1]["id"])
        self.assertEqual(first[1]["object"], "chat.completion")
        self.assertIn("alpha beta gamma", first[1]["choices"][0]["message"]["content"])


if __name__ == "__main__":
    unittest.main()
