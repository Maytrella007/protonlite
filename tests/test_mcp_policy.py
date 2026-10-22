import os
import tempfile
import types
import unittest

from protonlite_mcp import policy, tools


class _FakeClient:
    def send(self, *, to, subject, body, mime_type, attachments=None):
        self.sent = {"to": to, "subject": subject}
        return types.SimpleNamespace(id="SENT1")


class PolicyTests(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.remove(self.path)  # start with no file
        self._saved = {k: os.environ.get(k) for k in (
            "PROTONLITE_MCP_POLICY", "PROTON_ALLOWED_RECIPIENTS",
            "PROTON_REQUIRE_SEND_CONFIRMATION")}
        os.environ["PROTONLITE_MCP_POLICY"] = self.path
        for k in ("PROTON_ALLOWED_RECIPIENTS", "PROTON_REQUIRE_SEND_CONFIRMATION"):
            os.environ.pop(k, None)

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        if os.path.exists(self.path):
            os.remove(self.path)

    def test_default_is_open_and_no_confirmation(self):
        out = tools.email_policy_status()
        self.assertIn("OPEN", out)
        self.assertIn("Confirm before sending: no", out)

    def test_allowlist_refuses_outsiders(self):
        tools.email_allow(["allowed@example.com"])
        c = _FakeClient()
        out = tools.send(c, to=["stranger@evil.com"], subject="s", body="b")
        self.assertIn("Refused", out)
        self.assertFalse(hasattr(c, "sent"))  # never reached the client

    def test_allowlist_permits_listed(self):
        tools.email_allow(["allowed@example.com"])
        c = _FakeClient()
        out = tools.send(c, to=["allowed@example.com"], subject="s", body="b")
        self.assertIn("Sent", out)

    def test_glob_allow(self):
        tools.email_allow(["*@example.com"])
        c = _FakeClient()
        self.assertIn("Sent", tools.send(c, to=["anyone@example.com"], subject="s", body="b"))
        self.assertIn("Refused", tools.send(c, to=["x@other.com"], subject="s", body="b"))

    def test_confirmation_two_step(self):
        tools.set_send_confirmation(True)
        c = _FakeClient()
        first = tools.send(c, to=["a@b.com"], subject="s", body="b")
        self.assertIn("Confirmation required", first)
        self.assertFalse(hasattr(c, "sent"))
        second = tools.send(c, to=["a@b.com"], subject="s", body="b", confirm=True)
        self.assertIn("Sent", second)

    def test_env_ceiling_cannot_be_loosened(self):
        os.environ["PROTON_ALLOWED_RECIPIENTS"] = "*@company.com"
        tools.email_allow(["*"])  # tool tries to open fully
        c = _FakeClient()
        # inside the ceiling: allowed
        self.assertIn("Sent", tools.send(c, to=["bob@company.com"], subject="s", body="b"))
        # outside the ceiling: refused despite the open allowlist
        self.assertIn("Refused", tools.send(c, to=["bob@evil.com"], subject="s", body="b"))

    def test_env_forces_confirmation_cannot_be_disabled(self):
        os.environ["PROTON_REQUIRE_SEND_CONFIRMATION"] = "1"
        out = tools.set_send_confirmation(False)
        self.assertIn("Refused", out)
        c = _FakeClient()
        # Hard confirmation: even confirm=true is ignored and nothing is sent.
        blocked = tools.send(c, to=["a@b.com"], subject="s", body="b", confirm=True)
        self.assertIn("turned off by policy", blocked)
        self.assertFalse(hasattr(c, "sent"))

    def test_locked_ceiling_is_hard(self):
        policy.set_locked(ceiling=["*@company.com"])
        tools.email_allow(["*"])  # open the soft list
        c = _FakeClient()
        self.assertIn("Sent", tools.send(c, to=["bob@company.com"], subject="s", body="b"))
        self.assertIn("Refused", tools.send(c, to=["bob@evil.com"], subject="s", body="b"))

    def test_locked_confirmation_ignores_confirm_flag(self):
        policy.set_locked(require_confirmation=True)
        c = _FakeClient()
        out = tools.send(c, to=["a@b.com"], subject="s", body="b", confirm=True)
        self.assertIn("turned off by policy", out)
        self.assertFalse(hasattr(c, "sent"))
        # a tool cannot turn a CLI-locked rule off
        self.assertIn("Refused", tools.set_send_confirmation(False))

    def test_refusal_distinguishes_ceiling_from_allowlist(self):
        c = _FakeClient()
        tools.email_allow(["allowed@example.com"])
        soft = tools.send(c, to=["stranger@x.com"], subject="s", body="b")
        self.assertIn("not on the allowlist", soft)
        self.assertNotIn("hard ceiling", soft)
        policy.set_locked(ceiling=["*@company.com"])
        tools.email_allow(["*"])  # open the soft list; ceiling still blocks
        hard = tools.send(c, to=["stranger@x.com"], subject="s", body="b")
        self.assertIn("hard ceiling", hard)
        self.assertIn("protonlite policy ceiling", hard)

    def test_cli_locked_is_separate_from_soft(self):
        policy.set_locked(require_confirmation=True)
        d = policy.load()
        self.assertTrue(policy.hard_confirmation(d))
        self.assertFalse(policy.soft_confirmation(d))  # soft untouched
        policy.set_locked(require_confirmation=False)
        self.assertFalse(policy.hard_confirmation(policy.load()))


if __name__ == "__main__":
    unittest.main()
