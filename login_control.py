
import time
import logging
import threading
from collections import defaultdict


# Security configuration
MAX_ATTEMPTS = 5
LOCKOUT_DURATION = 15 * 60  # 15 minutes
BASE_DELAY = 1
MAX_DELAY = 8

# Audit logging
logging.basicConfig(
    filename="security_audit.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


class LoginAttemptControl:

    def __init__(self):
        self.failed_attempts = defaultdict(int)
        self.ip_attempts = defaultdict(int)
        self.locked_accounts = {}
        self.locked_ips = {}
        self.lock = threading.RLock()

    def is_locked(self, username, ip):
        now = time.time()

        with self.lock:
            account_expiry = self.locked_accounts.get(username, 0)
            ip_expiry = self.locked_ips.get(ip, 0)

            if account_expiry > now or ip_expiry > now:
                return True

            if account_expiry:
                self.locked_accounts.pop(username, None)

            if ip_expiry:
                self.locked_ips.pop(ip, None)

            return False

    def record_failure(self, username, ip):
        with self.lock:
            self.failed_attempts[username] += 1
            self.ip_attempts[ip] += 1

            attempts = self.failed_attempts[username]

            logging.warning(
                "Failed login: username=%s IP=%s attempts=%d",
                username, ip, attempts
            )

            if attempts >= MAX_ATTEMPTS:
                self.locked_accounts[username] = (
                    time.time() + LOCKOUT_DURATION
                )

                logging.critical(
                    "ACCOUNT LOCKED: username=%s IP=%s duration=15 minutes",
                    username, ip
                )

                return "Account locked for 15 minutes."

            # Progressive delay
            delay = min(
                BASE_DELAY * (2 ** (attempts - 1)),
                MAX_DELAY
            )

        time.sleep(delay)
        return "Invalid credentials."

    def record_success(self, username, ip):
        with self.lock:
            self.failed_attempts.pop(username, None)
            self.ip_attempts[ip] = 0

            logging.info(
                "Successful login: username=%s IP=%s",
                username, ip
            )

            return "Login successful."

    def authenticate(self, username, password, ip, verify_password):
        """
        verify_password must be a secure password-verification
        function supplied by the application's authentication layer.
        """

        if self.is_locked(username, ip):
            logging.warning(
                "Blocked login attempt: username=%s IP=%s",
                username, ip
            )
            return "Access temporarily restricted."

        if verify_password(username, password):
            return self.record_success(username, ip)

        return self.record_failure(username, ip)


# Demonstration password verifier.
# Replace this with secure password-hash verification in production.
def demo_verify(username, password):
    credentials = {
        "alice": "CorrectPassword123!"
    }
    return credentials.get(username) == password


if __name__ == "__main__":
    security = LoginAttemptControl()

    username = "alice"
    ip = "192.0.2.10"

    print("LOGIN ATTEMPT CONTROL SYSTEM")
    print("-----------------------------")

    for attempt in range(1, 7):
        result = security.authenticate(
            username,
            "WrongPassword",
            ip,
            demo_verify
        )

        print(f"Attempt {attempt}: {result}")

    print("\nAudit log: security_audit.log")
