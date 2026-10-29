import unittest

import authz_radar as ar


class FakeAgent:
    def __init__(self):
        self.attrs, self.errors, self.user = {}, 0, None

    def add_custom_attribute(self, k, v):
        self.attrs[k] = v

    def notice_error(self, expected=None):
        self.errors += 1 if expected else 0

    def set_user_id(self, v):
        self.user = v


class AuthzRadarTest(unittest.TestCase):
    def setUp(self):
        self.nr, self.state = FakeAgent(), ar.RequestState()

    def test_owner_is_allowed(self):
        self.assertTrue(ar.check_ownership("alice", "alice", self.state, agent=self.nr))
        self.assertEqual(self.nr.attrs, {"resource.owner_match": True, "authz.decision": "allow"})

    def test_mismatch_is_denied_in_enforce_mode(self):
        with self.assertRaises(ar.OwnershipError):
            ar.check_ownership("bob", "alice", self.state, agent=self.nr)
        self.assertEqual(self.nr.attrs, {"resource.owner_match": False, "authz.decision": "deny"})
        self.assertEqual(self.nr.errors, 1)

    def test_observe_mode_records_d01_shape(self):
        ar.check_ownership("bob", "alice", self.state, enforce=False, agent=self.nr)
        self.assertEqual(self.nr.attrs, {"resource.owner_match": False, "authz.decision": "allow"})

    def test_owner_match_is_sticky(self):
        ar.check_ownership("bob", "alice", self.state, enforce=False, agent=self.nr)
        ar.check_ownership("alice", "alice", self.state, enforce=False, agent=self.nr)
        self.assertFalse(self.nr.attrs["resource.owner_match"])

    def test_bypass_is_labelled(self):
        ar.check_ownership("bob", "ops", self.state, bypass_scope="admin:read", agent=self.nr)
        self.assertEqual(self.nr.attrs["authz.required_scope"], "admin:read")
        self.assertEqual(self.nr.attrs["authz.decision"], "allow")

    def test_user_is_pseudonymized_and_needs_a_key(self):
        ar.set_user("alice", b"k", agent=self.nr)
        self.assertTrue(self.nr.user.startswith("u_") and "alice" not in self.nr.user)
        self.assertIsNone(ar.pseudonym("alice", b""))


if __name__ == "__main__":
    unittest.main()
