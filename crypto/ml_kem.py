"""
crypto/ml_kem.py
----------------
ML-KEM-768 (FIPS 203) post-quantum key encapsulation.

PURPOSE
-------
Establish a shared secret between two parties over an insecure channel,
resistant to future quantum computers.

WHAT THIS IS NOT
----------------
- ML-KEM is NOT an encryption algorithm. It cannot directly encrypt an
  arbitrary message. It establishes a fixed-length shared secret; you then
  use that secret with a symmetric cipher (AES-GCM) to protect messages.
  This is the standard "KEM + DEM" pattern (Key Encapsulation Mechanism +
  Data Encapsulation Mechanism).

WORKFLOW
--------
    Recipient                      Sender
    ---------                      ------
    (pk, sk) = keygen()
                  -- pk -->
                                   (ct, ss) = encaps(pk)
                  <-- ct --
    ss = decaps(sk, ct)

    Both sides now share `ss`, which is then fed into HKDF (see kdf.py)
    to derive an AES-256-GCM session key.

BACKEND
-------
This wrapper targets the vendored `kyber_py` package in the project root.
The library is a pure-Python ML-KEM implementation — the API mirrors the
NIST reference. Public API of kyber_py:

    pk, sk = ML_KEM_768.keygen()
    ss, ct = ML_KEM_768.encaps(pk)      # NOTE: returns (ss, ct), not (ct, ss)
    ss     = ML_KEM_768.decaps(sk, ct)

We deliberately hide the vendor API behind our own so that we can swap in
liboqs or another backend later without touching call sites.
"""

import sys
import os

# Ensure the vendored kyber_py in the project root is importable
sys.path.append(os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from kyber_py.ml_kem.default_parameters import ML_KEM_768


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALGORITHM_LABEL = "ML-KEM-768"

# Sizes from FIPS 203 (and matching kyber_py)
PUBLIC_KEY_BYTES = 1184
SECRET_KEY_BYTES = 2400
CIPHERTEXT_BYTES = 1088
SHARED_SECRET_BYTES = 32


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class KEMError(ValueError):
    """Raised when KEM inputs are malformed or a mismatch is detected."""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def keygen() -> tuple[bytes, bytes]:
    """
    Generate an ML-KEM-768 keypair.

    Returns
    -------
    (public_key, secret_key) : tuple[bytes, bytes]
        public_key is 1184 bytes, secret_key is 2400 bytes.
    """
    public_key, secret_key = ML_KEM_768.keygen()

    # Sanity checks catch a bad vendored library immediately.
    if len(public_key) != PUBLIC_KEY_BYTES:
        raise KEMError(
            f"Unexpected public key length: {len(public_key)} "
            f"(expected {PUBLIC_KEY_BYTES})."
        )
    if len(secret_key) != SECRET_KEY_BYTES:
        raise KEMError(
            f"Unexpected secret key length: {len(secret_key)} "
            f"(expected {SECRET_KEY_BYTES})."
        )
    return public_key, secret_key


def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """
    Encapsulate: produce a shared secret and a ciphertext.

    Returns
    -------
    (shared_secret, ciphertext) : tuple[bytes, bytes]
        shared_secret is 32 bytes; ciphertext is 1088 bytes.

    Notes
    -----
    kyber_py's `encaps` returns (ss, ct). We return them in that same order,
    but name them clearly so callers cannot accidentally swap them.
    """
    if len(public_key) != PUBLIC_KEY_BYTES:
        raise KEMError(f"Public key must be {PUBLIC_KEY_BYTES} bytes.")

    shared_secret, ciphertext = ML_KEM_768.encaps(public_key)

    if len(shared_secret) != SHARED_SECRET_BYTES:
        raise KEMError("Shared secret has unexpected length.")
    if len(ciphertext) != CIPHERTEXT_BYTES:
        raise KEMError("Ciphertext has unexpected length.")

    return shared_secret, ciphertext


def decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """
    Decapsulate: recover the shared secret from a ciphertext.

    Returns
    -------
    shared_secret : bytes (32)

    Notes
    -----
    ML-KEM is designed so that decapsulation NEVER fails loudly. If the
    ciphertext is invalid or was produced by a different keypair, decaps
    returns a *different* random secret (implicit rejection). It is the
    caller's responsibility to verify the secret via the KEM + HKDF + AEAD
    flow — if the resulting AEAD tag does not verify, the whole handshake
    is aborted.
    """
    if len(secret_key) != SECRET_KEY_BYTES:
        raise KEMError(f"Secret key must be {SECRET_KEY_BYTES} bytes.")
    if len(ciphertext) != CIPHERTEXT_BYTES:
        raise KEMError(f"Ciphertext must be {CIPHERTEXT_BYTES} bytes.")

    shared_secret = ML_KEM_768.decaps(secret_key, ciphertext)

    if len(shared_secret) != SHARED_SECRET_BYTES:
        raise KEMError("Recovered shared secret has unexpected length.")

    return shared_secret


def selftest() -> dict:
    """
    Run a full keygen/encaps/decaps cycle and return statistics.

    Useful as a smoke test in /health and in the crypto lab UI.
    """
    import time

    t0 = time.perf_counter()
    pk, sk = keygen()
    t1 = time.perf_counter()
    ss_bob, ct = encapsulate(pk)
    t2 = time.perf_counter()
    ss_alice = decapsulate(sk, ct)
    t3 = time.perf_counter()

    return {
        "algorithm": ALGORITHM_LABEL,
        "shared_secrets_match": ss_alice == ss_bob,
        "public_key_bytes": len(pk),
        "secret_key_bytes": len(sk),
        "ciphertext_bytes": len(ct),
        "shared_secret_bytes": len(ss_bob),
        "timings_ms": {
            "keygen": round((t1 - t0) * 1000, 3),
            "encaps": round((t2 - t1) * 1000, 3),
            "decaps": round((t3 - t2) * 1000, 3),
        },
    }
