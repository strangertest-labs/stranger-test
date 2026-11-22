"""The evidence page built from a ``confirm`` result.

Real result shapes come from running the agent-memory and semantic-cache probes
against the bundled practice servers on 127.0.0.1 (ports 4600-4699), started and
stopped in-process. Nothing reaches the network."""

import contextlib
import copy
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
                         ["IVS-06", "LLM08:2025", "AIS-14"])
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
                         ["API1:2023", "IVS-06"])
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
                         {"API1:2023", "IVS-06", "LLM08:2025", "AIS-14"})
        for test_id, ids in ev.CONTROL_MAP.items():
            self.assertEqual("API1:2023" in ids,
                             test_id in ("state-handle", "tasks-idor", "agent-memory"))
            self.assertIn("IVS-06", ids)
            self.assertEqual("AIS-14" in ids, test_id == "semantic-cache")
            self.assertEqual("LLM08:2025" in ids, test_id == "semantic-cache")

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
