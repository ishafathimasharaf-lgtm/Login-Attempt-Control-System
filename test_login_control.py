
import unittest
from unittest.mock import patch

from login_control import LoginAttemptControl


class TestLoginSecurity(unittest.TestCase):

    def setUp(self):
        self.security = LoginAttemptControl()
        self.username = "alice"
        self.ip = "192.0.2.10"

    def test_first_failed_attempt(self):
        with patch("login_control.time.sleep"):
            result = self.security.authenticate(
                self.username,
                "wrong",
                self.ip,
                lambda u, p: False
            )

        self.assertEqual(result, "Invalid credentials.")
        self.assertEqual(
            self.security.failed_attempts[self.username], 1
        )

    def test_account_locks_after_five_failures(self):
        with patch("login_control.time.sleep"):
            for _ in range(5):
                result = self.security.authenticate(
                    self.username,
                    "wrong",
                    self.ip,
                    lambda u, p: False
                )

        self.assertEqual(result, "Account locked for 15 minutes.")
        self.assertTrue(
            self.security.is_locked(self.username, self.ip)
        )

    def test_locked_account_rejects_login(self):
        with patch("login_control.time.sleep"):
            for _ in range(5):
                self.security.authenticate(
                    self.username,
                    "wrong",
                    self.ip,
                    lambda u, p: False
                )

        result = self.security.authenticate(
            self.username,
            "CorrectPassword123!",
            self.ip,
            lambda u, p: True
        )

        self.assertEqual(result, "Access temporarily restricted.")

    def test_successful_login_resets_counter(self):
        with patch("login_control.time.sleep"):
            for _ in range(2):
                self.security.authenticate(
                    self.username,
                    "wrong",
                    self.ip,
                    lambda u, p: False
                )

        result = self.security.authenticate(
            self.username,
            "correct",
            self.ip,
            lambda u, p: True
        )

        self.assertEqual(result, "Login successful.")
        self.assertNotIn(
            self.username,
            self.security.failed_attempts
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
