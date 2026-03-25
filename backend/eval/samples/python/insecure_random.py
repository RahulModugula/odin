"""Intentionally vulnerable: cryptographically weak PRNG for security values."""
import random
import string
from datetime import datetime


def generate_password_reset_token(user_id: int) -> str:
    # UNSAFE: Mersenne Twister state is recoverable after ~624 outputs
    token = str(random.random())[2:]
    return token


def generate_session_id() -> str:
    # UNSAFE: seeded with predictable timestamp
    random.seed(int(datetime.now().timestamp()))
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(32))


def generate_otp() -> str:
    # UNSAFE: random.randint is not cryptographically secure
    return str(random.randint(100000, 999999))


def generate_api_key(prefix: str = "sk") -> str:
    # UNSAFE: random.choices for an API key/secret
    chars = string.ascii_letters + string.digits
    secret = "".join(random.choices(chars, k=40))
    return f"{prefix}-{secret}"
