"""The LiteLLM gates' version pin and its one opt-in (ST_ALLOW_ANY_VERSION=1).

The pin helper is pure and tested directly. Both gates are then driven up to the
pin check with everything around it replaced (no LiteLLM, no network, no
process): by default a release other than the pinned one is refused; with the
opt-in the gate goes on. The gates import pyjwt at module level, which the unit
test environment may not have, so stand-in modules are used for the import only.
"""

import importlib
import os
import pathlib
import sys
import unittest
from unittest import mock

_INTEGRATION = pathlib.Path(__file__).resolve().parent.parent / "integration"
_STUBBED = ("jwt", "jwt.algorithms", "cryptography", "cryptography.hazmat",
            "cryptography.hazmat.primitives",
            "cryptography.hazmat.primitives.serialization",
            "cryptography.hazmat.primitives.asymmetric",
            "cryptography.hazmat.primitives.asymmetric.rsa",
            "cryptography.hazmat.primitives.hashes",
            "cryptography.hazmat.backends")
_GATE_MODULES = ("version_pin", "local_as", "xid10_litellm_gate",
                 "xid10_litellm_cve59822_gate")


class _Reached(Exception):
    """Raised by the stand-in for the first step AFTER the pin check."""


def _load_gates():
    """Import both gates with stand-ins for pyjwt/cryptography; undo afterwards."""
    saved_modules = {name: sys.modules.get(name)
                     for name in _STUBBED + _GATE_MODULES}
    saved_path = list(sys.path)
    try:
        for name in _STUBBED:
            sys.modules[name] = mock.MagicMock(name=name)
        for name in _GATE_MODULES:
            sys.modules.pop(name, None)
        sys.path.insert(0, str(_INTEGRATION))
        return {name: importlib.import_module(name) for name in _GATE_MODULES}
    finally:
        sys.path[:] = saved_path
        for name, module in saved_modules.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


class VersionPinHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vp = _load_gates()["version_pin"]

    def test_pinned_version_passes_and_records_no_override(self):
        record = self.vp.check_version_pin("1.109.1", ("1.109.1",), "refused", {})
        self.assertEqual(record["installed"], "1.109.1")
        self.assertTrue(record["matches_pin"])
        self.assertIsNone(record["override"])

    def test_other_version_is_refused_by_default(self):
        with self.assertRaises(SystemExit) as caught:
            self.vp.check_version_pin("1.111.0", ("1.109.1",), "refused: pinned", {})
        self.assertEqual(str(caught.exception), "refused: pinned")

    def test_opt_in_records_the_installed_version_and_runs(self):
        record = self.vp.check_version_pin(
            "1.111.0", ("1.109.1",), "refused", {"ST_ALLOW_ANY_VERSION": "1"})
        self.assertEqual(record["installed"], "1.111.0")
        self.assertFalse(record["matches_pin"])
        self.assertEqual(record["override"], "ST_ALLOW_ANY_VERSION=1")
        self.assertEqual(record["validated_versions"], ["1.109.1"])

    def test_opt_in_must_be_an_explicit_yes(self):
        for value in ("", "0", "false", "no", "maybe"):
            with self.assertRaises(SystemExit):
                self.vp.check_version_pin(
                    "1.111.0", ("1.109.1",), "refused",
                    {"ST_ALLOW_ANY_VERSION": value})

    def test_opt_in_on_the_pinned_version_is_not_an_override(self):
        record = self.vp.check_version_pin(
            "1.109.1", ("1.109.1",), "refused", {"ST_ALLOW_ANY_VERSION": "1"})
        self.assertIsNone(record["override"])


class GatePinTests(unittest.TestCase):
    """Both gates, run up to (and just past) the pin check."""

    @classmethod
    def setUpClass(cls):
        modules = _load_gates()
        cls.delegation = modules["xid10_litellm_gate"]
        cls.cve = modules["xid10_litellm_cve59822_gate"]

    def _env(self, **extra):
        env = {key: value for key, value in os.environ.items()
               if key != "ST_ALLOW_ANY_VERSION"}
        env.update({"LL_BIN": "/nonexistent/bin/litellm", "LL_PORT": "4610",
                    "UPSTREAM_PORT": "4611", "FIXTURE_PORT": "4620",
                    "FIXTURE_BASE": "4620", "AS_BASE": "http://127.0.0.1:4612",
                    "LL_MODE": "delegation"})
        env.update(extra)
        return env

    def _run_delegation(self, version, **extra):
        gate = self.delegation
        with mock.patch.dict(os.environ, self._env(**extra), clear=True), \
                mock.patch.object(gate, "litellm_versions",
                                  return_value={"litellm": version, "mcp": "2.3.0"}), \
                mock.patch.object(gate, "login_facts", side_effect=_Reached):
            gate.main()

    def _run_cve(self, version, **extra):
        gate = self.cve
        with mock.patch.dict(os.environ, self._env(**extra), clear=True), \
                mock.patch.object(gate, "litellm_versions",
                                  return_value={"litellm": version, "mcp": "2.3.0"}), \
                mock.patch.object(gate, "MinimalUpstream", side_effect=_Reached):
            gate.main()

    def test_delegation_gate_refuses_other_versions_by_default(self):
        with self.assertRaises(SystemExit) as caught:
            self._run_delegation("1.111.0")
        self.assertIn("pinned to 1.109.1", str(caught.exception))

    def test_delegation_gate_runs_the_pinned_version(self):
        with self.assertRaises(_Reached):
            self._run_delegation("1.109.1")

    def test_delegation_gate_opt_in_runs_another_version(self):
        with self.assertRaises(_Reached):
            self._run_delegation("1.111.0", ST_ALLOW_ANY_VERSION="1")

    def test_cve_gate_refuses_unvalidated_versions_by_default(self):
        with self.assertRaises(SystemExit) as caught:
            self._run_cve("1.111.0")
        self.assertIn("validated for fixed versions", str(caught.exception))

    def test_cve_gate_runs_a_validated_version(self):
        with self.assertRaises(_Reached):
            self._run_cve("1.109.1")

    def test_cve_gate_opt_in_runs_another_fixed_version(self):
        with self.assertRaises(_Reached):
            self._run_cve("1.111.0", ST_ALLOW_ANY_VERSION="1")

    def test_cve_gate_never_runs_an_affected_version_even_with_opt_in(self):
        with self.assertRaises(SystemExit) as caught:
            self._run_cve("1.83.9", ST_ALLOW_ANY_VERSION="1")
        self.assertIn("AFFECTED", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
