"""How the HTTP client and the scan open a connection to servers that refuse
the first ``initialize``.

Each fake server below copies one behaviour seen on a real gateway on loopback
(2026-11-22): agentgateway 1.7.0 refuses an ``initialize`` that offers
2026-07-28 with HTTP 400 and accepts older handshake versions and the modern
per-request form; microsoft/mcp-gateway 1.0.1 accepts the modern form only.
"""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from strangertest.mcp_client import MCPClient
from strangertest.scan import checks as scan_checks
from strangertest.scan import report as scan_report
from strangertest.scan.adapter import profile_target
from strangertest.transports import HANDSHAKE_VERSIONS, HTTPTransport, HTTPTransportError

MODERN = "2026-07-28"
TOOLS = {"tools": [{"name": "whoami", "inputSchema": {"type": "object"}}]}


class _Fake:
    """A loopback MCP endpoint whose handshake rules are set per test."""

    def __init__(self, *, modern=False, handshake=(), answer_version=None,
                 need_header=False, need_auth=False, session=None, resource=None):
        self.modern = modern                    # answers the per-request form
        self.handshake = tuple(handshake)       # initialize versions it accepts
        self.answer_version = answer_version    # version named in the initialize result
        self.need_header = need_header          # follow-ups must name the handshake version
        self.need_auth = need_auth
        self.session = session
        self.resource = resource                # one listed resource: (uri, read result)
        self.names = []                         # Mcp-Name header of each modern request
        self.seen = []                          # (method, MCP-Protocol-Version, Mcp-Session-Id)
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, body, headers=None):
                data = json.dumps(body).encode() if not isinstance(body, bytes) else body
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                for name, value in (headers or {}).items():
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._send(405, {"error": "POST only"})

            def do_POST(self):
                message = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                method, ident = message.get("method"), message.get("id")
                version = self.headers.get("MCP-Protocol-Version")
                fake.seen.append((method, version, self.headers.get("Mcp-Session-Id")))
                if fake.need_auth and not self.headers.get("Authorization"):
                    return self._send(401, {"error": "unauthorized"})
                ok = lambda result, **h: self._send(  # noqa: E731
                    200, {"jsonrpc": "2.0", "id": ident, "result": result}, h)
                if version == MODERN and self.headers.get("Mcp-Method"):
                    if not fake.modern or method == "initialize":
                        return self._send(404, {"jsonrpc": "2.0", "id": ident, "error": {
                            "code": -32601, "message": "method not found"}})
                    fake.names.append(self.headers.get("Mcp-Name"))
                    return ok(fake.answer(method, message))
                if method == "initialize":
                    offered = message["params"]["protocolVersion"]
                    if offered not in fake.handshake:
                        return self._send(400, b"invalid MCP protocol version header")
                    headers = {"Mcp-Session-Id": fake.session} if fake.session else {}
                    return ok({"protocolVersion": fake.answer_version or offered,
                               "capabilities": {}, "serverInfo": {"name": "fake", "version": "1"}},
                              **headers)
                if not fake.handshake:
                    return self._send(400, b"A single MCP-Protocol-Version header is required.")
                if fake.need_header and version not in fake.handshake:
                    return self._send(400, b"unsupported MCP protocol version")
                if fake.session and self.headers.get("Mcp-Session-Id") != fake.session:
                    return self._send(400, b"session required")
                if ident is None:
                    return self._send(202, b"")
                return ok(fake.answer(method, message))

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = "http://127.0.0.1:%d/mcp" % self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def answer(self, method, message):
        if method == "tools/list":
            return TOOLS
        if self.resource and method == "resources/list":
            return {"resources": [{"uri": self.resource[0]}]}
        if self.resource and method == "resources/read":
            return self.resource[1]
        return {}

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def methods(self):
        return [entry[0] for entry in self.seen]


class _Base(unittest.TestCase):
    def fake(self, **options):
        fake = _Fake(**options)
        self.addCleanup(fake.close)
        return fake

    def connect(self, fake, **headers):
        transport = HTTPTransport(fake.url, headers=headers, timeout=5)
        client = MCPClient(transport)
        client.initialize()
        return transport, client


class TransportNegotiationTests(_Base):
    def test_a_modern_only_server_is_used_in_the_modern_form(self):
        fake = self.fake(modern=True)
        transport, client = self.connect(fake)
        self.assertEqual(transport.negotiation, "modern-after-refusal")
        self.assertEqual(client.protocol_version, MODERN)
        self.assertEqual([t["name"] for t in client.list_tools()], ["whoami"])
        # No notifications/initialized is sent in the modern form.
        self.assertNotIn("notifications/initialized", fake.methods())
        self.assertEqual(fake.seen[-1][1], MODERN)

    def test_a_server_that_speaks_both_is_used_in_the_modern_form(self):
        # agentgateway 1.7.0: refuses initialize at 2026-07-28, answers the rest.
        fake = self.fake(modern=True, handshake=HANDSHAKE_VERSIONS)
        transport, client = self.connect(fake)
        self.assertEqual(transport.negotiation, "modern-after-refusal")
        self.assertEqual(len(client.list_tools()), 1)

    def test_an_older_handshake_is_offered_when_the_modern_form_is_refused(self):
        fake = self.fake(handshake=("2025-06-18",), need_header=True)
        transport, client = self.connect(fake)
        self.assertEqual(transport.negotiation, "handshake-2025-06-18-after-refusal")
        self.assertEqual(client.protocol_version, "2025-06-18")
        self.assertEqual(len(client.list_tools()), 1)
        follow_ups = [entry for entry in fake.seen if entry[0] in ("notifications/initialized",
                                                                   "tools/list")][-2:]
        self.assertEqual([entry[1] for entry in follow_ups], ["2025-06-18", "2025-06-18"])

    def test_the_newest_older_version_is_offered_first(self):
        fake = self.fake(handshake=HANDSHAKE_VERSIONS, need_header=True)
        transport, _ = self.connect(fake)
        self.assertEqual(transport.negotiation, "handshake-%s-after-refusal" % HANDSHAKE_VERSIONS[0])

    def test_a_server_that_names_the_modern_version_in_an_older_handshake(self):
        # Seen through agentgateway: an upstream answered 2026-07-28 to an older
        # initialize. The follow-ups must carry the handshake's version, because
        # the gateway reads a 2026-07-28 header as the modern form.
        fake = self.fake(handshake=("2025-11-25",), answer_version=MODERN, need_header=True)
        transport, client = self.connect(fake)
        self.assertEqual(client.protocol_version, MODERN)
        self.assertEqual(len(client.list_tools()), 1)
        self.assertEqual(fake.seen[-1][1], "2025-11-25")

    def test_an_accepted_first_handshake_is_left_alone(self):
        # The practice servers: they accept initialize at 2026-07-28 as before.
        fake = self.fake(handshake=(MODERN,))
        transport, client = self.connect(fake)
        self.assertEqual(transport.negotiation, "handshake")
        self.assertEqual(fake.methods(), ["initialize", "notifications/initialized"])
        client.list_tools()
        self.assertIsNone(fake.seen[-1][1])     # no header is added

    def test_a_first_handshake_that_settles_on_an_older_version_gets_the_header(self):
        fake = self.fake(handshake=(MODERN,), answer_version="2025-06-18", need_header=False)
        _, client = self.connect(fake)
        client.list_tools()
        self.assertEqual(fake.seen[-1][1], "2025-06-18")

    def test_the_session_is_carried_after_an_older_handshake(self):
        fake = self.fake(handshake=("2025-11-25",), need_header=True, session="s-1")
        _, client = self.connect(fake)
        self.assertEqual(len(client.list_tools()), 1)
        self.assertEqual(fake.seen[-1][2], "s-1")

    def test_a_refused_caller_is_not_retried(self):
        fake = self.fake(modern=True, handshake=HANDSHAKE_VERSIONS, need_auth=True)
        with self.assertRaises(HTTPTransportError) as caught:
            self.connect(fake)
        self.assertEqual(caught.exception.status, 401)
        self.assertEqual(fake.methods(), ["initialize"])

    def test_the_first_refusal_is_reported_when_nothing_is_accepted(self):
        fake = self.fake()
        with self.assertRaises(HTTPTransportError) as caught:
            self.connect(fake)
        self.assertEqual(caught.exception.status, 400)
        self.assertIn("invalid MCP protocol version header", str(caught.exception))
        # one first try, one modern probe, one try per older version
        self.assertEqual(len(fake.seen), 2 + len(HANDSHAKE_VERSIONS))

    def test_a_transport_asked_to_be_modern_does_not_negotiate(self):
        fake = self.fake(modern=True)
        transport = HTTPTransport(fake.url, modern=True, timeout=5)
        client = MCPClient(transport)
        client.initialize()
        self.assertEqual(transport.negotiation, "modern")
        self.assertEqual(fake.seen, [])


class ScanHandshakeTests(_Base):
    def test_the_scan_offers_an_older_handshake_and_carries_the_session(self):
        fake = self.fake(handshake=("2025-11-25",), need_header=True, session="s-9")
        profile = profile_target(fake.url, timeout=5)
        self.assertEqual(profile.transport, "streamable-http")
        self.assertEqual(profile.protocol_version, "2025-11-25")
        self.assertEqual(profile.capabilities["tools"], ["whoami"])
        self.assertFalse([e for e in profile.errors if e.startswith("handshake refused")])
        listed = [entry for entry in fake.seen if entry[0] == "tools/list" and entry[2] == "s-9"]
        self.assertTrue(listed)
        self.assertEqual(listed[0][1], "2025-11-25")

    def test_a_per_request_only_server_is_examined(self):
        # microsoft/mcp-gateway 1.0.1 shape: no handshake of any version.
        fake = self.fake(modern=True, resource=("note://a", {
            "contents": [{"uri": "note://a", "text": "x"}], "cacheScope": "private", "ttlMs": 5}))
        profile = profile_target(fake.url, timeout=5)
        self.assertEqual(profile.transport, "streamable-http")
        self.assertEqual(profile.protocol_version, MODERN)
        self.assertEqual(profile.capabilities["tools"], ["whoami"])
        self.assertEqual(profile.capabilities["resources"], ["note://a"])
        self.assertEqual(profile.cache, {"advertises_cachescope": True, "forces_private": True,
                                         "ttl_ms": 5})
        self.assertFalse([e for e in profile.errors if e.startswith("handshake refused")])
        self.assertIs(profile.auth["required"], False)
        # The read named its resource in the routing header, as the form requires.
        self.assertIn("note://a", fake.names)
        self.assertIn("no risk signals", scan_report._verdict_line(profile, []))

    def test_no_session_id_is_sent_to_a_per_request_server(self):
        fake = self.fake(modern=True)
        profile = profile_target(fake.url, timeout=5)
        self.assertTrue(profile.session["per_request_form"])
        self.assertFalse(profile.session["accepts_forged_session_id"])
        self.assertEqual({entry[2] for entry in fake.seen}, {None})
        finding = scan_checks.check_session_id_as_bearer(profile, None)
        self.assertEqual(finding.grade, "OK")
        self.assertIn("Not applicable", finding.rationale)

    def test_a_per_request_server_that_wants_a_credential(self):
        fake = self.fake(modern=True, need_auth=True)
        profile = profile_target(fake.url, bearer="tok-test", timeout=5)
        self.assertEqual(profile.capabilities["tools"], ["whoami"])
        self.assertIs(profile.auth["required"], True)

    def test_a_server_that_speaks_both_is_scanned_with_the_handshake(self):
        # agentgateway 1.7.0 shape. The handshake is preferred by the scan
        # because only that form has session ids for it to look at.
        fake = self.fake(modern=True, handshake=HANDSHAKE_VERSIONS, need_header=True,
                         session="s-2")
        profile = profile_target(fake.url, timeout=5)
        self.assertEqual(profile.protocol_version, HANDSHAKE_VERSIONS[0])
        self.assertEqual(profile.capabilities["tools"], ["whoami"])
        self.assertTrue(profile.session["issues_session_id"])
        self.assertIs(profile.session["accepts_forged_session_id"], False)
        self.assertNotIn("per_request_form", profile.session)

    def test_a_refused_handshake_is_not_reported_as_clean(self):
        fake = self.fake()                  # accepts no form and no version
        profile = profile_target(fake.url, timeout=5)
        self.assertIsNone(profile.protocol_version)
        self.assertTrue([e for e in profile.errors if e.startswith("handshake refused")])
        verdict = scan_report._verdict_line(profile, [])
        self.assertIn("not examined", verdict)
        self.assertIn("not a clean result", verdict)
        self.assertNotIn("no risk signals", verdict)

    def test_an_accepted_handshake_keeps_the_usual_verdict(self):
        fake = self.fake(handshake=(MODERN,))
        profile = profile_target(fake.url, timeout=5)
        self.assertEqual(profile.capabilities["tools"], ["whoami"])
        self.assertIn("no risk signals", scan_report._verdict_line(profile, []))


if __name__ == "__main__":
    unittest.main()
