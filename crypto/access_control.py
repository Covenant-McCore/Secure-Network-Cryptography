"""
crypto/access_control.py
------------------------
Policy-Based Cryptographic Access Control (PBAC).

PURPOSE
-------
Gate the decryption of an AES-256-GCM ciphertext behind a set of
policy attributes. The AES key is wrapped by XORing it with a
policy-derived seed, and the wrapped key is stored alongside the
ciphertext.

IMPORTANT — WHAT THIS IS NOT
----------------------------
This is NOT Attribute-Based Encryption (ABE). Real CP-ABE (e.g.
Bethencourt-Sahai-Waters) uses bilinear pairings over elliptic curves
and enforces the policy cryptographically. Here the policy check is
performed in application code before the key is unwrapped, and the
wrap is a symmetric XOR against a PBKDF2-derived seed. Anyone who
holds the master secret and knows the policy string can unwrap the
AES key.

This construction is appropriate as a *demonstration* of policy-gated
access control in a final-year prototype. It must NOT be described as
ABE in the thesis or in the UI.

SECURITY NOTES
--------------
- The master secret MUST come from the environment (PBAC_MASTER_SECRET),
  never from source code.
- The PBKDF2 iteration count used here (1000) is low by modern standards
  and is kept for demonstration speed. Production would use >= 600_000.
- Rotating the master secret invalidates all previously wrapped keys.
  That is intentional and is exercised in the Key Management module.
"""

import base64
import hmac
from typing import Iterable

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

from config import Config

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PBKDF2_ITERATIONS = 1000  # Demonstration only; low by modern standards.
KEY_LENGTH_BYTES = 32     # AES-256


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class PolicyNotSatisfiedError(PermissionError):
    """Raised when the caller's attributes do not satisfy the policy."""


# ---------------------------------------------------------------------------
# PolicyBasedAccessControl
# ---------------------------------------------------------------------------

class PolicyBasedAccessControl:
    """
    Policy-gated encryption using AES-256-GCM.

    The AES key is wrapped by XORing it with a deterministic seed derived
    from the sorted policy attributes and the master secret. Unwrapping
    requires the same policy string and master secret.
    """

    def __init__(self, master_secret: bytes | None = None):
        """
        Parameters
        ----------
        master_secret : bytes, optional
            Master secret used to derive the policy seed.
            Defaults to Config.PBAC_MASTER_SECRET.
        """
        self._master_secret = master_secret or Config.PBAC_MASTER_SECRET
        if len(self._master_secret) < 16:
            raise ValueError(
                "PBAC master secret must be at least 16 bytes. "
                "Rotate PBAC_MASTER_SECRET and restart."
            )

    # ---------- internal helpers ----------

    @staticmethod
    def _canonical(attributes: Iterable[str]) -> str:
        """
        Normalise an attribute set into a canonical, deterministic string.

        This makes the wrapped key independent of input order.
        """
        cleaned = sorted({a.strip().lower() for a in attributes if a and a.strip()})
        return ",".join(cleaned)

    def _derive_policy_seed(self, policy_string: str) -> bytes:
        """Derive the deterministic key-wrap seed from a policy string."""
        return PBKDF2(
            self._master_secret,
            policy_string.encode("utf-8"),
            dkLen=KEY_LENGTH_BYTES,
            count=PBKDF2_ITERATIONS,
        )

    # ---------- public API ----------

    def encrypt(self, plaintext: str, required_policy: Iterable[str]) -> dict:
        """
        Encrypt plaintext under a policy.

        Returns a dict with base64-encoded fields suitable for Firestore.
        """
        policy_string = self._canonical(required_policy)
        if not policy_string:
            raise ValueError("Policy cannot be empty.")

        # 1. Fresh AES-256 key and GCM nonce
        aes_key = get_random_bytes(KEY_LENGTH_BYTES)
        cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))

        # 2. Wrap the AES key under the policy seed
        policy_seed = self._derive_policy_seed(policy_string)
        wrapped_key = bytes(a ^ b for a, b in zip(aes_key, policy_seed))

        # 3. Zero the plaintext key from local scope as early as we can
        del aes_key

        return {
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "nonce": base64.b64encode(cipher.nonce).decode("ascii"),
            "tag": base64.b64encode(tag).decode("ascii"),
            "wrapped_key": base64.b64encode(wrapped_key).decode("ascii"),
            "required_policy": policy_string.split(","),
            "algorithm": "AES-256-GCM + PBAC-key-wrap",
        }

    def decrypt(self, payload: dict, user_attributes: Iterable[str]) -> str:
        """
        Attempt to decrypt a payload produced by encrypt().

        The caller's attributes must be a superset of the required policy.

        Raises
        ------
        PolicyNotSatisfiedError
            If the caller's attributes do not satisfy the policy.
        ValueError
            If the AES-GCM tag does not verify (tampered payload).
        """
        # ---- 1. Policy check ----
        required = set(payload["required_policy"])
        provided = {a.strip().lower() for a in user_attributes if a and a.strip()}

        if not required.issubset(provided):
            missing = required - provided
            raise PolicyNotSatisfiedError(
                f"Access denied. Missing attributes: {sorted(missing)}"
            )

        # ---- 2. Unwrap the AES key ----
        policy_string = ",".join(payload["required_policy"])
        policy_seed = self._derive_policy_seed(policy_string)
        wrapped_key = base64.b64decode(payload["wrapped_key"])

        if len(wrapped_key) != KEY_LENGTH_BYTES:
            raise ValueError("Wrapped key has unexpected length.")

        aes_key = bytes(a ^ b for a, b in zip(wrapped_key, policy_seed))

        # ---- 3. AES-GCM authenticated decryption ----
        nonce = base64.b64decode(payload["nonce"])
        tag = base64.b64decode(payload["tag"])
        ciphertext = base64.b64decode(payload["ciphertext"])

        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        finally:
            del aes_key

        return plaintext.decode("utf-8")

