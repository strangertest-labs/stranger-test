"""The evidence page built from a ``confirm`` result.

Real result shapes come from running the agent-memory and semantic-cache probes
against the bundled practice servers on 127.0.0.1 (ports 4600-4699), started and
stopped in-process. Nothing reaches the network."""

import contextlib
import copy
import hashlib
import io
import json
import os
import re
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone

from strangertest import __version__, deep_tests as dt, evidence as ev
from strangertest import practice_agent_memory_http as memory_server
from strangertest import practice_semantic_cache_http as cache_server
from strangertest.agent_memory import run_agent_memory_probe
from strangertest.semantic_cache import run_semantic_cache_probe

NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
BANNED = re.compile(r"\b(secure|compliant|certified|passed audit)\b", re.IGNORECASE)
SECTIONS = ["## Summary", "## What was tested", "## How", "## Results",
            "## Control mapping", "## Limits", "## Reproduce", "## Integrity"]


@contextlib.contextmanager
def serving(module, mode):
    server = module.build_server(mode, port=dt._free_port())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def cache_run(mode, id_a="alice", id_b="bob"):
    with serving(cache_server, mode) as url:
        return run_semantic_cache_probe(url, id_a, id_b, authorized=True)


def memory_run(mode):
    with serving(memory_server, mode) as url:
        return run_agent_memory_probe(url, "tok-alice", "tok-bob", authorized=True,
                                      namespace_a=["alice", "notes"], **dt._PRACTICE_AGENT)


def cache_dict(grade="OK", outcomes=("OK", "OK"), a_hit=True):
    """A recorded semantic-cache result, for the rules that need an exact shape."""
    names = ("exact", "reworded")
    return {
        "probe": "semantic-cache", "target": "http://127.0.0.1:4650", "grade": grade,
        "detail": "x",
        "paths": [{"name": n, "what": "w", "outcome": o, "b_status": 200, "note": "n"}
                  for n, o in zip(names, outcomes)],
        "controls": {"no_identity_status": 401, "a_store_status": 200, "a_exact_hit": a_hit,
                     "a_reworded_hit": a_hit, "identity_required": True},
        "observations": [],
        "fingerprints": {"id_a": "sha256:aaaaaaaaaaaa", "id_b": "sha256:bbbbbbbbbbbb",
                         "marker": "sha256:cccccccccccc"},
    }


def both(result, **meta):
    doc = ev.build_evidence(result, now=NOW, **meta)
    return doc, ev.render_markdown(doc), ev.render_json(doc)


class VerdictRules(unittest.TestCase):
    def test_any_leak_is_an_isolation_failure(self):
        doc, md, _ = both(cache_dict("LEAK", ("OK", "LEAK")))
        self.assertEqual(doc["verdict"]["code"], ev.V_FAILURE)
        self.assertEqual(doc["verdict"]["headline"], "Isolation failure observed")
        self.assertIn("Isolation failure observed", md)
        self.assertTrue(doc["verdict"]["not_a_pass"])

    def test_a_leaked_path_wins_over_an_ok_grade(self):
        doc, _, _ = both(cache_dict("OK", ("OK", "LEAK")))
        self.assertEqual(doc["verdict"]["code"], ev.V_FAILURE)

    def test_all_ok_with_control_passed(self):
        doc, md, _ = both(cache_dict("OK"))
        self.assertEqual(doc["verdict"]["headline"],
                         "No cross-identity access observed on the paths tested")
        self.assertEqual(doc["positive_control"]["status"], "passed")
        self.assertFalse(doc["verdict"]["not_a_pass"])
        self.assertIn("No cross-identity access observed on the paths tested", md)
        self.assertNotIn("NOT a pass", md)

    def test_inconclusive_grade_is_never_a_pass(self):
        doc, md, js = both(cache_dict("INCONCLUSIVE", ("NOT_EXERCISED", "NOT_EXERCISED"), False))
        self.assertEqual(doc["verdict"]["headline"],
                         "Inconclusive — the test could not establish a valid baseline")
        self.assertTrue(doc["verdict"]["not_a_pass"])
        self.assertIn("NOT a pass", md)
        self.assertNotIn("No cross-identity access observed", md + js)
        self.assertEqual(doc["positive_control"]["status"], "not_passed")
        self.assertIn("Not passed", md)

    def test_ok_grade_without_the_positive_control_is_inconclusive(self):
        doc, md, _ = both(cache_dict("OK", ("OK", "OK"), a_hit=False))
        self.assertEqual(doc["verdict"]["code"], ev.V_INCONCLUSIVE)
        self.assertIn("NOT a pass", md)

    def test_ok_grade_with_no_ok_path_is_inconclusive(self):
        doc, _, _ = both(cache_dict("OK", ("NOT_RUN", "NOT_EXERCISED")))
        self.assertEqual(doc["verdict"]["code"], ev.V_INCONCLUSIVE)

    def test_unknown_grade_or_outcome_is_inconclusive(self):
        self.assertEqual(both(cache_dict("PASSED"))[0]["verdict"]["code"], ev.V_INCONCLUSIVE)
        doc, _, _ = both(cache_dict("OK", ("OK", "MAYBE")))
        self.assertEqual(doc["verdict"]["code"], ev.V_INCONCLUSIVE)
        self.assertEqual(doc["paths"][1]["grade"], "INCONCLUSIVE")

    def test_observation_is_neither_pass_nor_failure(self):
        doc, md, _ = both(cache_dict("OBSERVATION", ("LEAK", "LEAK")))
        self.assertEqual(doc["verdict"]["code"], ev.V_OBSERVATION)
        self.assertEqual({p["grade"] for p in doc["paths"]}, {"OBSERVATION"})
        self.assertIn("Observation only", md)
        self.assertIn("NOT a pass", md)
        self.assertNotIn("Isolation failure observed", md)
        self.assertNotIn("No cross-identity access observed", md)

    def test_untested_paths_are_listed_not_counted_as_ok(self):
        doc, md, _ = both(cache_dict("OK", ("OK", "NOT_EXERCISED")))
        self.assertEqual(doc["verdict"]["code"], ev.V_NONE_OBSERVED)
        self.assertEqual(doc["paths"][1]["grade"], "NOT_TESTED")
        self.assertIn("Not counted as a pass", doc["paths"][1]["meaning"])
        self.assertIn("any of the 1 path(s) tested", doc["verdict"]["statement"])
        self.assertTrue(any("not tested in this run: reworded" in limit
                            for limit in doc["limits"]))
        self.assertIn("| NOT TESTED |", md)

    def test_no_overclaiming_words_for_any_verdict(self):
        cases = [cache_dict("LEAK", ("LEAK", "OK")), cache_dict("OK"),
                 cache_dict("INCONCLUSIVE", ("NOT_EXERCISED",) * 2, False),
                 cache_dict("OBSERVATION")]
        for result in cases:
            _, md, js = both(result)
            self.assertIsNone(BANNED.search(md), BANNED.search(md))
            self.assertIsNone(BANNED.search(js), BANNED.search(js))


class RealProbeShapes(unittest.TestCase):
    """Reports produced by the probes themselves against the practice servers."""

    def test_semantic_cache_leak(self):
        report = cache_run("leaky")
        doc, md, _ = both(report)
        self.assertEqual(doc["test"]["id"], "semantic-cache")
        self.assertEqual(doc["verdict"]["code"], ev.V_FAILURE)
        grades = {p["name"]: p["grade"] for p in doc["paths"]}
        self.assertEqual(grades, {"exact": "LEAK", "reworded": "LEAK",
                                  "prefix_sibling": "NOT_TESTED"})
        self.assertEqual([c["id"] for c in doc["control_mapping"]["controls"]],
                         ["IVS-06", "CC6.1", "LLM08:2025", "AIS-14"])
        self.assertEqual(doc["identities"][0]["credential_fingerprint"],
                         report.fingerprints["id_a"])
        self.assertTrue(doc["target"]["url"].startswith("http://127.0.0.1:46"))
        for section in SECTIONS:
            self.assertIn(section, md)

    def test_semantic_cache_safe(self):
        doc, md, _ = both(cache_run("safe"))
        self.assertEqual(doc["verdict"]["code"], ev.V_NONE_OBSERVED)
        self.assertEqual(doc["positive_control"]["status"], "passed")
        self.assertIn("**Passed:", md)

    def test_semantic_cache_broken_is_inconclusive(self):
        doc, md, _ = both(cache_run("broken"))
        self.assertEqual(doc["verdict"]["code"], ev.V_INCONCLUSIVE)
        self.assertIn("NOT a pass", md)
        self.assertNotIn("| OK |", md)

    def test_semantic_cache_observations(self):
        for mode in ("open", "collapse"):
            doc, md, _ = both(cache_run(mode))
            self.assertEqual(doc["verdict"]["code"], ev.V_OBSERVATION, mode)
            self.assertNotIn("| LEAK |", md, mode)

    def test_semantic_cache_prefix_pair_leaves_no_raw_id(self):
        # Neither the probe's report nor the page may carry a raw id.
        report = cache_run("prefixbug", id_a="alicesecretid", id_b="alicesecret")
        self.assertNotIn("alicesecret", json.dumps(report.to_dict()))
        doc, md, js = both(report)
        self.assertEqual(doc["verdict"]["code"], ev.V_FAILURE)
        self.assertNotIn("alicesecret", md + js)

    def test_edge_cases_and_write_paths_are_named_on_the_page(self):
        with serving(memory_server, "safe") as url:
            report = run_agent_memory_probe(
                url, "tok-alice", "tok-bob", authorized=True, namespace_a=["alice", "notes"],
                edge_identities=dt._practice_edge_identities(), write_paths=True,
                **dt._PRACTICE_AGENT)
        doc, md, _ = both(report)
        names = [p["name"] for p in doc["paths"]]
        self.assertFalse([n for n in names if n.startswith("unrecognised")], names)
        for name in ("store_edge_case", "store_edge_wildcard", "thread_delete", "store_delete"):
            self.assertIn(name, names)
        with serving(cache_server, "safe") as url:
            report = run_semantic_cache_probe(url, "alice", "bob", authorized=True,
                                              edge_cases="all")
        doc, md, _ = both(report)
        names = [p["name"] for p in doc["paths"]]
        self.assertFalse([n for n in names if n.startswith("unrecognised")], names)
        self.assertIn("edge_case", names)

    def test_route_suffixed_paths_are_named_on_the_page(self):
        result = cache_dict()
        result["paths"] = [{"name": n, "what": "w", "outcome": "OK", "b_status": 200, "note": "n"}
                           for n in ("exact@chat", "exact@responses", "cross_route@messages",
                                     "exact@elsewhere")]
        doc = ev.build_evidence(result)
        names = [p["name"] for p in doc["paths"]]
        self.assertEqual(names[:3], ["exact@chat", "exact@responses", "cross_route@messages"])
        self.assertTrue(names[3].startswith("unrecognised"))

    def test_agent_memory_leak(self):
        report = memory_run("leaky")
        doc, md, js = both(report)
        self.assertEqual(doc["test"]["id"], "agent-memory")
        self.assertEqual(doc["verdict"]["code"], ev.V_FAILURE)
        self.assertEqual([c["id"] for c in doc["control_mapping"]["controls"]],
                         ["API1:2023", "IVS-06", "CC6.1"])
        self.assertEqual(doc["identities"][1]["credential_fingerprint"],
                         report.fingerprints["token_b"])
        self.assertEqual(doc["marker_fingerprint"], report.fingerprints["marker"])
        self.assertNotIn("tok-alice", md + js)
        self.assertNotIn("tok-bob", md + js)
        for section in SECTIONS:
            self.assertIn(section, md)

    def test_agent_memory_safe(self):
        doc, _, _ = both(memory_run("safe"))
        self.assertEqual(doc["verdict"]["code"], ev.V_NONE_OBSERVED)
        grades = {p["name"]: p["grade"] for p in doc["paths"]}
        self.assertEqual(grades["store_search_all"], "NOT_TESTED")
        self.assertEqual(grades["thread_get"], "OK")

    def test_agent_memory_broken_and_open(self):
        doc, md, _ = both(memory_run("broken"))
        self.assertEqual(doc["verdict"]["code"], ev.V_INCONCLUSIVE)
        self.assertIn("NOT a pass", md)
        self.assertEqual(both(memory_run("open"))[0]["verdict"]["code"], ev.V_OBSERVATION)

    def test_report_object_and_its_dict_give_the_same_page(self):
        report = cache_run("safe")
        self.assertEqual(both(report)[1], both(report.to_dict())[1])
        self.assertEqual(both(report)[1], both(json.loads(json.dumps(report.to_dict())))[1])


class EveryConfirmTest(unittest.TestCase):
    def test_every_bundled_demo_result_renders(self):
        for test_id, test in dt.DEEP_TESTS.items():
            results = test.demo()
            for mode, expected in (("leaky", ev.V_FAILURE), ("safe", ev.V_NONE_OBSERVED)):
                doc, md, js = both(results[mode])
                self.assertEqual(doc["test"]["id"], test_id)
                self.assertEqual(doc["verdict"]["code"], expected, (test_id, mode))
                self.assertTrue(doc["paths"], test_id)
                for section in SECTIONS:
                    self.assertIn(section, md, test_id)
                self.assertIsNone(BANNED.search(md + js), (test_id, mode))
                json.loads(js)

    def test_control_mapping_is_conservative(self):
        self.assertEqual(set(ev.CONTROL_MAP), set(dt.DEEP_TESTS))
        self.assertEqual(set(ev.CONTROLS),
                         {"API1:2023", "IVS-06", "CC6.1", "LLM08:2025", "AIS-14"})
        for test_id, ids in ev.CONTROL_MAP.items():
            self.assertEqual("API1:2023" in ids,
                             test_id in ("state-handle", "tasks-idor", "agent-memory"))
            self.assertIn("IVS-06", ids)
            self.assertIn("CC6.1", ids)
            self.assertEqual("AIS-14" in ids, test_id == "semantic-cache")
            self.assertEqual("LLM08:2025" in ids, test_id == "semantic-cache")
        # SOC 2 has no criterion that names tenant segregation; the page must say so.
        self.assertIn("nearest", ev.CONTROLS["CC6.1"]["title"])
        self.assertIn("No Trust Services Criterion names tenant segregation",
                      ev.CONTROLS["CC6.1"]["relevance"])

    def test_mapping_is_marked_as_a_suggestion(self):
        doc, md, _ = both(cache_dict())
        self.assertIn("tool author's suggestion, not an auditor's determination",
                      doc["control_mapping"]["disclaimer"])
        self.assertIn("not an auditor's determination", md)
        for control in doc["control_mapping"]["controls"]:
            self.assertTrue(control["id"] and control["title"] and control["relevance"])

    def test_limits_say_it_does_not_replace_a_pentest(self):
        doc, md, _ = both(cache_dict())
        self.assertIn(ev.PENTEST_LIMIT, doc["limits"])
        self.assertIn("supplements, does not replace, an independent penetration test", md)
        self.assertIn("one run, at one time", " ".join(doc["limits"]))

    def test_unknown_result_is_refused(self):
        with self.assertRaises(ValueError):
            ev.build_evidence({"probe": "something-else", "grade": "OK"})
        with self.assertRaises(ValueError):
            ev.build_evidence({"grade": "OK"})
        with self.assertRaises(TypeError):
            ev.build_evidence("OK")


SECRET = "tok-SUPERSECRET-9f8e7d"
MARKER = "st-cache-0123456789abcdef"


def dirty_result():
    result = cache_dict("LEAK", ("LEAK", "OK"))
    result["target"] = f"https://admin:{SECRET}@cache.internal.test:8443/v1/cache?key={SECRET}#{SECRET}"
    result["detail"] = f"B read {MARKER} with {SECRET}"
    result["observations"] = [f"token {SECRET}", MARKER]
    result["token_a"] = SECRET
    result["authorization"] = f"Bearer {SECRET}"
    result["identity_a"] = SECRET
    result["paths"][0]["note"] = f"ids are prefix siblings ({SECRET!r})"
    result["paths"][0]["what"] = f"B asks with {SECRET}"
    result["paths"][0]["b_status"] = SECRET
    result["paths"][0]["body"] = MARKER
    result["paths"].append({"name": SECRET, "what": MARKER, "outcome": "OK", "note": SECRET})
    result["controls"]["whoami_a"] = SECRET                 # not a fingerprint
    result["controls"]["a_store_status"] = SECRET           # not a status
    result["controls"][SECRET] = True                       # unknown key
    result["controls"]["raw_marker"] = MARKER
    result["controls"]["identity_required"] = f"passed {SECRET}"
    result["fingerprints"] = {"id_a": SECRET, "id_b": "sha256:bbbbbbbbbbbb", "marker": MARKER,
                              SECRET: "sha256:dddddddddddd"}
    return result


class Hygiene(unittest.TestCase):
    def test_nothing_off_the_allow_list_reaches_the_page(self):
        doc, md, js = both(dirty_result())
        for text in (md, js):
            self.assertNotIn(SECRET, text)
            self.assertNotIn("SUPERSECRET", text)
            self.assertNotIn(MARKER, text)
            self.assertNotIn("admin:", text)
            self.assertNotIn("@cache", text)
            self.assertNotIn("key=", text)
            self.assertNotIn("Bearer", text)
        self.assertEqual(doc["target"]["url"], "https://cache.internal.test:8443/v1/cache")
        self.assertIsNone(doc["identities"][0]["credential_fingerprint"])
        self.assertIsNone(doc["identities"][0]["principal_fingerprint"])
        self.assertEqual(doc["identities"][1]["credential_fingerprint"], "sha256:bbbbbbbbbbbb")
        self.assertIsNone(doc["marker_fingerprint"])
        self.assertEqual(doc["paths"][2]["name"], "unrecognised_1")
        self.assertNotIn("b_http_status", doc["paths"][0])
        checks = {c["name"]: c["value"] for c in doc["positive_control"]["checks"]}
        self.assertNotIn("a_store_status", checks)
        self.assertEqual(checks["identity_required"], "passed")

    def test_urls(self):
        clean = ev._clean_url
        self.assertEqual(clean("http://u:p@127.0.0.1:2024/a/b?x=1#f"), "http://127.0.0.1:2024/a/b")
        self.assertEqual(clean("https://example.test?token=abc"), "https://example.test")
        self.assertEqual(clean("http://[::1]:8080/x"), "http://[::1]:8080/x")
        for bad in (None, "", 42, "not a url", "file:///etc/passwd", "http://", "http://h:port/"):
            self.assertIsNone(clean(bad), bad)

    def test_reproduce_uses_placeholders(self):
        doc, md, _ = both(dirty_result())
        command = doc["reproduce"]["commands"][0]
        self.assertIn("--token-a <TOKEN_A> --token-b <TOKEN_B>", command)
        self.assertIn("https://cache.internal.test:8443/v1/cache", command)
        self.assertIn(command, md)
        doc, _, _ = both({"probe": "semantic-cache", "grade": "INCONCLUSIVE"})
        self.assertIn("<TARGET_URL>", doc["reproduce"]["commands"][0])
        self.assertIsNone(doc["target"]["url"])

    def test_operator_text_is_one_line_and_capped(self):
        doc, md, _ = both(cache_dict(), system_name="Billing\nAPI | v2", notes="x" * 5000,
                          operator="  QA   team\t", environment="staging", system_version="1.4")
        self.assertEqual(doc["system"]["name"], "Billing API | v2")
        self.assertEqual(doc["operator"], "QA team")
        self.assertEqual(len(doc["notes"]), 1000)
        self.assertIn("- System: Billing API | v2", md)
        self.assertIn("- Environment: staging", md)

    def test_the_input_is_not_modified(self):
        result = dirty_result()
        before = copy.deepcopy(result)
        ev.build_evidence(result, now=NOW)
        self.assertEqual(result, before)


class Determinism(unittest.TestCase):
    def test_same_input_and_time_give_identical_output(self):
        report = memory_run("safe").to_dict()
        first, second = both(report, operator="QA"), both(copy.deepcopy(report), operator="QA")
        self.assertEqual(first[1], second[1])
        self.assertEqual(first[2], second[2])

    def test_timestamp_is_utc_iso_8601(self):
        self.assertEqual(both(cache_dict())[0]["generated_at_utc"], "2026-01-02T03:04:05Z")
        naive = ev.build_evidence(cache_dict(), now=datetime(2026, 1, 2, 3, 4, 5))
        self.assertEqual(naive["generated_at_utc"], "2026-01-02T03:04:05Z")
        east = datetime(2026, 1, 2, 8, 34, 5, tzinfo=timezone(timedelta(hours=5, minutes=30)))
        self.assertEqual(ev.build_evidence(cache_dict(), now=east)["generated_at_utc"],
                         "2026-01-02T03:04:05Z")
        self.assertRegex(ev.build_evidence(cache_dict())["generated_at_utc"],
                         r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

    def test_schema_and_tool(self):
        doc, _, js = both(cache_dict())
        self.assertEqual(doc["schema"], "stranger-test/evidence/1")
        self.assertEqual(doc["tool"], {"name": "stranger-test", "version": __version__})
        self.assertEqual(json.loads(js), doc)
        self.assertEqual(js, json.dumps(doc, sort_keys=True, indent=2, separators=(",", ": "),
                                        ensure_ascii=True) + "\n")

    def test_digest_is_stable_and_tied_to_the_result(self):
        result = cache_dict()
        digest = ev.canonical_digest(result)
        self.assertRegex(digest, r"^sha256:[0-9a-f]{64}$")
        reordered = dict(reversed(list(result.items())))
        self.assertEqual(ev.canonical_digest(reordered), digest)
        self.assertEqual(ev.canonical_digest(json.loads(json.dumps(result, indent=2))), digest)
        doc, md, _ = both(result)
        self.assertEqual(doc["source"]["result_sha256"], digest)
        self.assertIn(digest, md)
        changed = cache_dict()
        changed["paths"][0]["b_status"] = 403
        self.assertNotEqual(ev.canonical_digest(changed), digest)

    def test_markdown_layout(self):
        _, md, _ = both(cache_dict())
        self.assertTrue(md.startswith("# Tenant isolation test — evidence of result\n"))
        positions = [md.index(section) for section in SECTIONS]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(md.count("\n## "), len(SECTIONS))
        self.assertIn("| `exact` | B asks A's exact question | OK |", md)


class AuditorReadability(unittest.TestCase):
    """The points a reviewer raised on real pages (2026-11-22)."""

    def test_the_command_that_ran_is_shown_without_its_credentials(self):
        argv = ["confirm", "agent-memory", "http://user:pw@127.0.0.1:4671/api?bundle_key=SECRETKEY",
                "--token-a", "tok-alice", "--token-b=tok-ali", "--token-sibling", "tok-al",
                "--api-key", "sk-live-1", "--user-a", "alice", "--namespace-a", "alice",
                "--namespace-b", "ali", "--assistant", "memory", "--save-input",
                '{"marker": "{marker}"}', "--edge-identity", "dot=tok-a.b@a.b",
                "--edge-user=case=Alice", "--write-paths",
                "--evidence", "out/page.md", "--evidence=out/page.json",
                "--evidence-operator", "Platform QA", "--evidence-system=Billing"]
        command = ev.reproduce_command(argv)
        for secret in ("tok-alice", "tok-ali", "tok-al ", "sk-live-1", "SECRETKEY", "user:pw",
                       "tok-a.b", "Alice", "Platform QA", "Billing", "out/page"):
            self.assertNotIn(secret, command + " ", secret)
        for kept in ("stranger-test confirm agent-memory http://127.0.0.1:4671/api?<QUERY>",
                     "--token-a <TOKEN_A>", "--token-b <TOKEN_B>", "--token-sibling <TOKEN_SIBLING>",
                     "--api-key <API_KEY>", "--user-a <USER_A>", "--namespace-a alice",
                     "--namespace-b ali", "--assistant memory", "--edge-identity dot=<TOKEN>",
                     "--edge-user case=<USER>", "--write-paths",
                     """--save-input '{"marker": "{marker}"}'"""):
            self.assertIn(kept, command, kept)

    def test_only_a_confirm_command_is_vouched_for(self):
        self.assertIsNone(ev.reproduce_command(["scan", "http://127.0.0.1:1/mcp"]))
        self.assertIsNone(ev.reproduce_command([]))

    def test_a_page_from_a_live_run_carries_its_full_command(self):
        report = memory_run("leaky")
        doc, page, _ = both(report, command=["confirm", "agent-memory", "http://127.0.0.1:9/x",
                                             "--token-a", "tok-alice", "--token-b", "tok-bob",
                                             "--namespace-a", "alice", "--namespace-b", "bob"])
        self.assertTrue(doc["reproduce"]["exact"])
        self.assertEqual(len(doc["reproduce"]["commands"]), 1)
        self.assertIn("--namespace-a alice --namespace-b bob --evidence evidence.md", page)
        self.assertNotIn("tok-alice", page)
        self.assertNotIn("Add any test-specific options", page)

    def test_a_page_from_a_saved_result_says_the_options_are_not_known(self):
        doc, page, _ = both(memory_run("leaky"))
        self.assertFalse(doc["reproduce"]["exact"])
        self.assertIn("the options of the original run are not known", page)

    def test_run_times_and_the_not_recorded_sentence_never_appear_together(self):
        sentence = "The result file does not record when the test ran."
        report = cache_run("safe")
        _, live, _ = both(report, run_started=NOW, run_finished=NOW + timedelta(seconds=3))
        self.assertIn("- Test run started (UTC): ", live)
        self.assertNotIn(sentence, live)
        _, saved, _ = both(report)
        self.assertIn(sentence, saved)
        self.assertIn("not recorded (page built from a saved result)", saved)

    def test_a_failure_summary_also_counts_what_was_not_tested(self):
        doc, page, _ = both(memory_run("leaky"))
        untested = doc["verdict"]["path_counts"]["not_tested"]
        self.assertGreater(untested, 0)
        self.assertIn(f"{untested} more listed path(s) were not tested.", doc["verdict"]["statement"])
        tested = len(doc["paths"]) - untested
        self.assertIn(f"{len(doc['paths'])} paths are listed: {tested} tested, {untested} not tested.",
                      page)

    def test_who_and_what_are_stated_or_said_to_be_missing(self):
        report = cache_run("safe")
        _, bare, _ = both(report)
        for line in ("- System: not stated by the operator", "- Run by: not stated by the operator",
                     "- Environment: not stated by the operator"):
            self.assertIn(line, bare)
        self.assertIn("whoever operated the tool (not named on this page)", bare)
        self.assertNotIn("the operator named", bare)
        doc, full, _ = both(report, operator="Platform QA", system_name="Answer cache",
                            identity_a="test account alice (tenant 1)",
                            identity_b="test account ali (tenant 2, id is a prefix of A's)")
        self.assertIn("- Run by: Platform QA", full)
        self.assertIn("carried out by the operator named on this page", full)
        self.assertIn("Described by the operator as: test account alice (tenant 1).", full)
        self.assertEqual(doc["identities"][1]["described_as"],
                         "test account ali (tenant 2, id is a prefix of A's)")

    def test_each_tested_path_shows_the_statuses_seen(self):
        doc, page, _ = both(memory_run("safe"))
        with_status = [p for p in doc["paths"] if "b_http_status" in p and "a_http_status" in p]
        self.assertTrue(with_status)
        self.assertIn("| HTTP status seen |", page)
        one = with_status[0]
        self.assertIn(f"A {one['a_http_status']}; B {one['b_http_status']}", page)

    def test_grades_are_explained_on_the_page(self):
        _, page, _ = both(cache_run("safe"))
        for line in ("- NOT TESTED: the path was not checked. It is not a pass.",
                     "Baseline check (also called a positive control)."):
            self.assertIn(line, page)
        self.assertIn("neither file is signed", page)

    def test_one_run_writes_both_formats_and_the_raw_result(self):
        report = memory_run("leaky")
        with tempfile.TemporaryDirectory() as tmp:
            md, js = os.path.join(tmp, "page.md"), os.path.join(tmp, "page.json")
            doc = ev.write_evidence([md, js], report, save_result=True, now=NOW,
                                    run_started=NOW, run_finished=NOW)
            raw = os.path.join(tmp, "page.result.json")
            self.assertEqual([item["path"] for item in doc["written"]], [raw, md, js])
            for item in doc["written"]:
                with open(item["path"], "rb") as handle:
                    self.assertEqual(hashlib.sha256(handle.read()).hexdigest(), item["sha256"])
            with open(raw) as handle:
                self.assertEqual(ev.canonical_digest(json.load(handle)),
                                 doc["source"]["result_sha256"])
            with open(js) as handle:
                saved = json.load(handle)
            self.assertEqual(saved["source"]["result_file"], "page.result.json")
            self.assertNotIn("written", saved)
            with open(md, encoding="utf-8") as handle:
                page = handle.read()
            self.assertIn("- Raw result file: `page.result.json`", page)
            self.assertIn(saved["source"]["result_sha256"], page)
            self.assertEqual(saved["verdict"]["statement"] in page, True)

    def test_the_raw_result_never_overwrites_an_evidence_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                ev.write_evidence([os.path.join(tmp, "page.md"),
                                   os.path.join(tmp, "page.result.json")],
                                  cache_run("safe"), save_result=True)

    def test_confirm_writes_the_page_with_the_operator_s_words(self):
        from strangertest import cli
        with serving(memory_server, "leaky") as url, tempfile.TemporaryDirectory() as tmp:
            md, js = os.path.join(tmp, "e.md"), os.path.join(tmp, "e.json")
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main(["confirm", "agent-memory", url, "--token-a", "tok-alice",
                                 "--token-b", "tok-bob", "--namespace-a", "alice",
                                 "--namespace-b", "bob", "--evidence", md, "--evidence", js,
                                 "--evidence-system", "Practice agent server",
                                 "--evidence-operator", "QA", "--evidence-environment", "local",
                                 "--evidence-identity-a", "test account alice"])
            self.assertEqual(code, 1)                      # a leak is a failing exit
            with open(md, encoding="utf-8") as handle:
                page = handle.read()
            for line in ("- System: Practice agent server", "- Run by: QA", "- Environment: local",
                         "Described by the operator as: test account alice.",
                         "--namespace-a alice --namespace-b bob --evidence evidence.md",
                         "- Raw result file: `e.result.json`"):
                self.assertIn(line, page)
            self.assertNotIn("tok-alice", page)
            self.assertNotIn("does not record when the test ran", page)
            self.assertEqual(err.getvalue().count("evidence written: "), 3)
            self.assertRegex(err.getvalue(), r"e\.md  sha256:[0-9a-f]{64}")
            with open(js) as handle:
                self.assertEqual(json.load(handle)["operator"], "QA")
            self.assertTrue(os.path.exists(os.path.join(tmp, "e.result.json")))


class ShortSummary(unittest.TestCase):
    """The summary is a shorter rendering of the same document, never a second opinion."""

    def pages(self, result, **meta):
        doc = ev.build_evidence(result, now=NOW, **meta)
        return doc, ev.render_markdown(doc), ev.render_summary(doc)

    def test_it_says_what_the_full_page_says(self):
        doc, page, summary = self.pages(memory_run("safe"), operator="QA")
        self.assertIn(f"**{doc['verdict']['statement']}**", summary)
        self.assertIn(f"Overall: **{doc['verdict']['headline']}**.", summary)
        self.assertIn(doc["source"]["result_sha256"], summary)
        self.assertIn(ev.PENTEST_LIMIT, summary)
        self.assertIn(ev.MAPPING_DISCLAIMER, summary)
        self.assertIn("- Run by: QA", summary)
        for limit in doc["limits"]:
            if not limit.startswith("Listed but not tested"):
                self.assertIn(f"- {limit}", summary)
        for item in doc["control_mapping"]["controls"]:
            self.assertIn(f"- {item['id']} (", summary)
        self.assertTrue(summary.startswith("# " + ev.SUMMARY_TITLE))
        self.assertIsNone(BANNED.search(summary))

    def test_every_path_is_accounted_for(self):
        doc, _, summary = self.pages(memory_run("safe"))
        tested = [p for p in doc["paths"] if p["grade"] != ev.NOT_TESTED]
        untested = [p for p in doc["paths"] if p["grade"] == ev.NOT_TESTED]
        self.assertTrue(tested and untested)
        self.assertIn(f"{len(doc['paths'])} paths are listed: {len(tested)} tested, "
                      f"{len(untested)} not tested.", summary)
        for path in tested:
            row = next(line for line in summary.splitlines()
                       if line.startswith(f"| `{path['name']}` |"))
            self.assertIn(f"| {path['grade']} |", row)
            if "b_http_status" in path:
                self.assertIn(f"B {path['b_http_status']}", row)
        self.assertIn(f"Not tested ({len(untested)}). A path that was not tested is not a pass.",
                      summary)
        listed = "\n".join(line for line in summary.splitlines() if " Paths: " in line)
        for path in untested:
            self.assertIn(f"`{path['name']}`", listed)
            self.assertNotIn(f"| `{path['name']}` |", summary)   # never in the tested table
        self.assertLessEqual(listed.count("\n") + 1, len({p["meaning"] for p in untested}))

    def test_a_leak_is_a_leak_in_the_summary_too(self):
        doc, _, summary = self.pages(memory_run("leaky"))
        self.assertEqual(doc["verdict"]["code"], ev.V_FAILURE)
        self.assertIn("Isolation failure observed", summary)
        self.assertIn("| LEAK |", summary)
        self.assertIn("- LEAK: identity B got identity A's data.", summary)

    def test_a_run_that_is_not_a_pass_says_so(self):
        for mode in ("broken", "open"):
            doc, _, summary = self.pages(memory_run(mode))
            self.assertTrue(doc["verdict"]["not_a_pass"])
            self.assertIn("This result is NOT a pass.", summary)

    def test_it_is_under_half_the_length_and_names_what_it_leaves_out(self):
        _, page, summary = self.pages(memory_run("safe"))
        self.assertLess(len(summary.split()), len(page.split()) / 2)
        self.assertNotIn("## Reproduce", summary)
        self.assertNotIn("stranger-test confirm", summary)
        self.assertIn("This is a summary and adds nothing to the full page.", summary)
        self.assertIn("The command to reproduce the run, each baseline check and the account "
                      "fingerprints are in the full page", summary)

    def test_nothing_reaches_the_summary_that_is_not_on_the_full_page(self):
        result = cache_dict()
        result["detail"] = "token tok-secret-123 leaked"
        result["paths"][0]["note"] = "raw marker st-marker-999"
        result["observations"] = ["tok-secret-123"]
        _, _, summary = self.pages(result, notes="one line\nof context")
        for secret in ("tok-secret-123", "st-marker-999"):
            self.assertNotIn(secret, summary)
        self.assertIn("- Notes: one line of context", summary)

    def test_every_bundled_test_renders_a_summary(self):
        for test, spec in ev._TESTS.items():
            doc = ev.build_evidence({"probe": spec["probe"], "grade": "OK"}, now=NOW)
            summary = ev.render_summary(doc)
            self.assertIn(spec["title"], summary, test)
            self.assertIn(ev.PENTEST_LIMIT, summary, test)

    def test_one_run_writes_the_page_the_summary_and_the_raw_result(self):
        report = memory_run("safe")
        with tempfile.TemporaryDirectory() as tmp:
            md, short = os.path.join(tmp, "page.md"), os.path.join(tmp, "page-summary.md")
            doc = ev.write_evidence(md, report, save_result=True, summary=short, now=NOW)
            raw = os.path.join(tmp, "page.result.json")
            self.assertEqual([item["path"] for item in doc["written"]], [raw, md, short])
            with open(short, "rb") as handle:
                body = handle.read()
            self.assertEqual(hashlib.sha256(body).hexdigest(), doc["written"][2]["sha256"])
            text = body.decode("utf-8")
            self.assertIn("are in the full page, `page.md`, which is the page to keep", text)
            self.assertIn("- Raw result file: `page.result.json`", text)

    def test_the_summary_can_be_written_on_its_own(self):
        with tempfile.TemporaryDirectory() as tmp:
            short = os.path.join(tmp, "s.md")
            doc = ev.write_evidence([], cache_run("safe"), save_result=True, summary=short, now=NOW)
            self.assertEqual([os.path.basename(item["path"]) for item in doc["written"]],
                             ["s.result.json", "s.md"])
            with open(short, encoding="utf-8") as handle:
                self.assertIn("python3 -m strangertest.evidence RESULT.json", handle.read())

    def test_bad_file_names_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            same = os.path.join(tmp, "page.md")
            with self.assertRaises(ValueError):
                ev.write_evidence(same, cache_run("safe"), summary=same)
            with self.assertRaises(ValueError):
                ev.write_evidence([], cache_run("safe"))
            with self.assertRaises(ValueError):
                ev.write_evidence(same, cache_run("safe"), save_result=True,
                                  summary=os.path.join(tmp, "page.result.json"))

    def test_confirm_writes_a_summary_and_keeps_it_out_of_the_command(self):
        from strangertest import cli
        with serving(memory_server, "safe") as url, tempfile.TemporaryDirectory() as tmp:
            md, short = os.path.join(tmp, "e.md"), os.path.join(tmp, "e-summary.md")
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main(["confirm", "agent-memory", url, "--token-a", "tok-alice",
                                 "--token-b", "tok-bob", "--namespace-a", "alice",
                                 "--evidence", md, "--evidence-summary", short,
                                 "--evidence-operator", "QA"])
            self.assertEqual(code, 0)
            self.assertEqual(err.getvalue().count("evidence written: "), 3)
            with open(md, encoding="utf-8") as handle:
                page = handle.read()
            with open(short, encoding="utf-8") as handle:
                summary = handle.read()
            self.assertIn("--namespace-a alice --evidence evidence.md", page)
            self.assertNotIn("e-summary.md", page)
            self.assertIn("- Run by: QA", summary)
            self.assertNotIn("tok-alice", summary)
            self.assertRegex(summary, r"- Run \(UTC\): \d{4}-\d\d-\d\dT[\d:]+Z to \d{4}")

            only = os.path.join(tmp, "only.md")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = cli.main(["confirm", "agent-memory", url, "--token-a", "tok-alice",
                                 "--token-b", "tok-bob", "--evidence-summary", only])
            self.assertEqual(code, 0)
            self.assertTrue(os.path.exists(os.path.join(tmp, "only.result.json")))
            self.assertFalse(os.path.exists(os.path.join(tmp, "only.json")))


class CommandLine(unittest.TestCase):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ev.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_reads_a_result_file_and_writes_both_formats(self):
        report = cache_run("leaky").to_dict()
        with tempfile.TemporaryDirectory() as tmp:
            source = os.path.join(tmp, "result.json")
            with open(source, "w") as handle:       # as `confirm --json` prints it
                handle.write(json.dumps(report, indent=2, default=str))
            code, out, _ = self.run_cli(source, "--system-name", "Answer cache")
            self.assertEqual(code, 0)
            self.assertIn("# Tenant isolation test — evidence of result", out)
            self.assertIn("- System: Answer cache", out)

            code, out, _ = self.run_cli(source, "--format", "json")
            self.assertEqual(json.loads(out)["verdict"]["code"], ev.V_FAILURE)

            target = os.path.join(tmp, "evidence.json")
            code, out, _ = self.run_cli(source, "--out", target, "--operator", "QA")
            self.assertEqual((code, out), (0, ""))
            with open(target) as handle:
                saved = json.load(handle)
            self.assertEqual(saved["operator"], "QA")
            self.assertEqual(saved["source"]["result_sha256"], ev.canonical_digest(report))

            code, out, _ = self.run_cli(source, "--digest")
            self.assertEqual(out.strip(), ev.canonical_digest(report))

            code, out, _ = self.run_cli(source, "--format", "summary")
            self.assertEqual(code, 0)
            self.assertTrue(out.startswith("# " + ev.SUMMARY_TITLE))
            self.assertIn(ev.canonical_digest(report), out)

            page = os.path.join(tmp, "evidence.md")
            ev.write_evidence(page, report, now=NOW, environment="staging")
            with open(page, encoding="utf-8") as handle:
                self.assertIn("- Environment: staging", handle.read())

    def test_bad_input_is_an_error_not_a_page(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name, body in (("a.json", "not json"), ("b.json", "[1, 2]"),
                               ("c.json", '{"probe": "nope", "grade": "OK"}')):
                path = os.path.join(tmp, name)
                with open(path, "w") as handle:
                    handle.write(body)
                code, out, err = self.run_cli(path)
                self.assertEqual((code, out), (2, ""), name)
                self.assertIn("error:", err)
            code, _, _ = self.run_cli(os.path.join(tmp, "missing.json"))
            self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
