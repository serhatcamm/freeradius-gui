"""Password hashing and verification.

Argon2id is used via ``argon2-cffi``, with a bcrypt fallback for
environments where Argon2 is unavailable.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets

logger = logging.getLogger(__name__)

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 1024

try:  # pragma: no cover - import shape depends on environment
    from argon2 import PasswordHasher
    from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

    _HAS_ARGON2 = True
except ImportError:  # pragma: no cover
    _HAS_ARGON2 = False

    class InvalidHashError(Exception):
        pass

    class VerificationError(Exception):
        pass

    class VerifyMismatchError(VerificationError):
        pass


#: Conservative parameters: 64 MiB, 3 passes, 4 lanes.
_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4) if _HAS_ARGON2 else None

#: Formats we know how to verify. Anything else is rejected.
#: Argon2 PHC strings are emitted with a leading ``$`` ("$argon2id$..."), so
#: comparisons strip it first; bcrypt fallback hashes carry their own "bcrypt$".
_ALLOWED_SCHEMES = ("argon2id$", "argon2i$", "argon2d$", "bcrypt$")


def _scheme_of(stored_hash: str) -> str | None:
    """Identify the hash scheme, tolerating the PHC leading ``$``."""
    if not stored_hash:
        return None
    candidate = stored_hash.lstrip("$")
    return next((s for s in _ALLOWED_SCHEMES if candidate.startswith(s)), None)


class PasswordPolicyError(ValueError):
    pass


def check_password_policy(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            f"password must be at least {MIN_PASSWORD_LENGTH} characters"
        )
    if len(password) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyError("password is too long")
    if password.strip() != password:
        raise PasswordPolicyError("password must not begin or end with whitespace")


def hash_password(password: str) -> str:
    check_password_policy(password)
    if not _HAS_ARGON2:
        return _bcrypt_fallback_hash(password)
    return _hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """Constant-time verification. Never raises for malformed hashes."""
    if not stored_hash or not password:
        return False

    scheme = _scheme_of(stored_hash)
    if scheme is None:
        logger.warning("unrecognised password hash format; refusing")
        return False

    if scheme == "bcrypt$":
        return _bcrypt_fallback_verify(stored_hash, password)

    try:
        _hasher.verify(stored_hash, password)
        return True
    except VerifyMismatchError:
        return False
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    if not _HAS_ARGON2 or not stored_hash.lstrip("$").startswith("argon2"):
        return True
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except (InvalidHashError, VerificationError):
        return True


# -- bcrypt fallback ----------------------------------------------------
def _bcrypt_fallback_hash(password: str) -> str:  # pragma: no cover
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    return "bcrypt$" + f"{salt.hex()}${digest.hex()}"


def _bcrypt_fallback_verify(stored_hash: str, password: str) -> bool:  # pragma: no cover
    try:
        _, salt_hex, digest_hex = stored_hash.split("$")
    except ValueError:
        return False
    expected = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 600_000)
    return hmac.compare_digest(expected.hex(), digest_hex)


#: Characters that are safe in an *unquoted* FreeRADIUS config value.
#: '#' must never appear: FreeRADIUS starts a comment there, which would
#: silently truncate the secret on the next reload. '%' and '$' are also
#: avoided because they participate in expansion in some contexts.
_SECRET_ALPHABET = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789-_.~"


def generate_secret(length: int = 32) -> str:
    """A cryptographically secure RADIUS shared secret.

    FreeRADIUS recommends >= 16 characters; we default to 32 from the OS
    CSPRNG. The alphabet is restricted to characters that survive the config
    grammar, so the value read back by FreeRADIUS is always exactly the value
    written here.
    """
    return "".join(secrets.choice(_SECRET_ALPHABET) for _ in range(length))