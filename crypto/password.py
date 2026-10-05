"""
crypto/password.py
------------------
Password hashing with Argon2id.

WHY ARGON2ID
------------
Argon2id is the OWASP-recommended password hash (2024). It is:
- Memory-hard — expensive to parallelise on GPUs/ASICs
- Time-cost adjustable
- Resistant to side-channel attacks (the "id" variant mixes data-dependent
  and data-independent memory access)

PARAMETERS
----------
Defaults match OWASP's recommended minimum for interactive login:
- time_cost    = 3 iterations
- memory_cost  = 64 MiB
- parallelism  = 4 lanes
- hash_len     = 32 bytes
- salt_len     = 16 bytes

NEVER STORE PLAINTEXT PASSWORDS. NEVER LOG PASSWORDS. NEVER SEND PASSWORDS
TO EXTERNAL APIS (except via HIBP's k-anonymity range API, which only sees
a 5-character SHA-1 prefix).
"""

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALGORITHM_LABEL = "Argon2id"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class PasswordError(ValueError):
    """Raised for malformed password inputs."""


# ---------------------------------------------------------------------------
# Module-level hasher
# ---------------------------------------------------------------------------

_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=64 * 1024,  # 64 MiB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 1024  # Argon2 has no hard limit; we cap to bound memory


def validate_policy(password: str) -> None:
    """
    Enforce minimum length. Composition rules (upper/lower/digit/symbol)
    are NOT enforced here — modern guidance discourages them in favour of
    length and a breached-password check (implemented in Phase 9 via HIBP).
    """
    if not isinstance(password, str):
        raise PasswordError("Password must be a string.")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
        )
    if len(password) > MAX_PASSWORD_LENGTH:
        raise PasswordError("Password is too long.")


def hash_password(password: str) -> str:
    """
    Hash a plaintext password. Returns an Argon2id encoded string suitable
    for storage. The encoded string contains the salt and parameters.
    """
    validate_policy(password)
    return _hasher.hash(password)


def verify_password(stored_hash: str, candidate: str) -> bool:
    """
    Constant-time verification. Returns True if the password matches.
    Never raises on mismatch — only on malformed stored hashes.
    """
    try:
        _hasher.verify(stored_hash, candidate)
        return True
    except (VerifyMismatchError, VerificationError):
        return False
    except InvalidHashError as exc:
        raise PasswordError("Stored hash is malformed.") from exc


def needs_rehash(stored_hash: str) -> bool:
    """
    Return True if the stored hash was produced with weaker parameters
    than the current policy. Call after successful login and rehash.
    """
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return True
