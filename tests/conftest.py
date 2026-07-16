import os

# Disable the /chat rate limit for the suite — many tests hammer the
# endpoint from one client IP. The rate-limit tests re-enable it by
# monkeypatching backend.main.RATE_LIMIT_PER_MINUTE directly.
# (conftest runs before test modules import backend.main, so the env
# var is in place when the module-level constant is read.)
os.environ.setdefault("SENTINEL_RATE_LIMIT_PER_MIN", "0")
