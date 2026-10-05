"""
crypto/cpabe.py
---------------
Ciphertext-Policy Attribute-Based Encryption (CP-ABE) using Charm-Crypto.

Scheme:
    Bethencourt-Sahai-Waters (BSW07) with Charm's HybridABEnc adapter.

This module is LOCAL-ONLY for the CRYPTO-NET demonstration environment.
It is intentionally kept separate from the PBAC implementation used by
the deployable application.
"""

import base64

from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.adapters.abenc_adapt_hybrid import HybridABEnc

import re


def _charm_attribute(attribute: str) -> str:
    """
    Convert CRYPTO-NET application attributes into Charm-safe identifiers.

    Example:
        ROLE:DOCTOR -> ROLE_DOCTOR
        DEPT:Clinical -> DEPT_CLINICAL
        ORG:org-lagos-general -> ORG_ORG_LAGOS_GENERAL
    """
    value = attribute.strip().upper()
    value = re.sub(r"[^A-Z0-9_]+", "_", value)
    value = re.sub(r"_+", "_", value).strip("_")

    if not value:
        raise ValueError("CP-ABE attribute cannot be empty.")

    return value


def _charm_attributes(attributes: list[str]) -> list[str]:
    """Convert a list of CRYPTO-NET attributes for Charm."""
    return [_charm_attribute(attribute) for attribute in attributes]


def _charm_policy(policy: str) -> str:
    """
    Convert CRYPTO-NET attribute names inside a boolean CP-ABE policy
    into Charm-safe attribute identifiers.

    Example:
        ROLE:DOCTOR and DEPT:Clinical
        ->
        ROLE_DOCTOR and DEPT_CLINICAL
    """
    if not policy or not policy.strip():
        raise ValueError("CP-ABE policy cannot be empty.")

    # Convert attribute tokens while preserving boolean operators and
    # parentheses.
    tokens = re.split(r"(\s+|\(|\))", policy.strip())

    converted = []

    for token in tokens:
        stripped = token.strip()

        if not stripped:
            converted.append(token)
            continue

        if stripped.upper() in {"AND", "OR"}:
            converted.append(stripped.lower())
        elif stripped in {"(", ")"}:
            converted.append(stripped)
        else:
            converted.append(_charm_attribute(stripped))

    return "".join(converted)

# ---------------------------------------------------------------------------
# Pairing group configuration
# ---------------------------------------------------------------------------

PAIRING_GROUP = "SS512"


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def _serialize(group, obj) -> str:
    """
    Recursively serialize Charm cryptographic objects.

    Charm keys and ciphertexts are usually dictionaries containing pairing
    elements rather than a single pairing element. Each Charm element is
    serialized with Charm's native serializer, while dictionaries, lists,
    tuples, and primitive values are handled recursively.

    The resulting structure is converted to JSON and then Base64 encoded,
    making it safe for Firestore storage.
    """
    import json

    def encode(value):
        if type(value).__name__ == "Element":
            return {
                "__charm_element__": base64.b64encode(
                    group.serialize(value)
                ).decode("ascii")
            }

        if isinstance(value, dict):
            return {
                "__dict__": {
                    str(key): encode(item)
                    for key, item in value.items()
                }
            }

        if isinstance(value, list):
            return {
                "__list__": [encode(item) for item in value]
            }

        if isinstance(value, tuple):
            return {
                "__tuple__": [encode(item) for item in value]
            }

        if isinstance(value, (str, int, float, bool)) or value is None:
            return value

        raise TypeError(
            f"Unsupported Charm serialization type: {type(value)!r}"
        )

    encoded = encode(obj)

    return base64.b64encode(
        json.dumps(encoded, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")


def _deserialize(group, blob: str):
    """
    Reverse the recursive Charm serialization format.
    """
    import json

    raw = base64.b64decode(blob.encode("ascii"))
    encoded = json.loads(raw.decode("utf-8"))

    def decode(value):
        if isinstance(value, dict):
            if "__charm_element__" in value:
                element_bytes = base64.b64decode(
                    value["__charm_element__"]
                )
                return group.deserialize(element_bytes)

            if "__dict__" in value:
                return {
                    key: decode(item)
                    for key, item in value["__dict__"].items()
                }

            if "__list__" in value:
                return [
                    decode(item)
                    for item in value["__list__"]
                ]

            if "__tuple__" in value:
                return tuple(
                    decode(item)
                    for item in value["__tuple__"]
                )

        return value

    return decode(encoded)



# ---------------------------------------------------------------------------
# CP-ABE system
# ---------------------------------------------------------------------------

class CPABESystem:
    """
    Thin wrapper around Charm's BSW07 CP-ABE + HybridABEnc.

    The wrapper is stateless. Key persistence is intentionally handled by
    the service layer rather than this cryptographic module.
    """

    def __init__(self, group_name: str = PAIRING_GROUP):
        self.group = PairingGroup(group_name)

        base_cpabe = CPabe_BSW07(self.group)
        self.hybrid = HybridABEnc(base_cpabe, self.group)

    # -----------------------------------------------------------------------
    # Setup
    # -----------------------------------------------------------------------

    def setup(self) -> tuple[str, str]:
        """
        Generate the CP-ABE public and master secret keys.

        Returns:
            (public_key_blob, master_secret_key_blob)
        """
        pk, mk = self.hybrid.setup()

        return (
            _serialize(self.group, pk),
            _serialize(self.group, mk),
        )

    # -----------------------------------------------------------------------
    # User key generation
    # -----------------------------------------------------------------------

    def keygen(
        self,
        master_public_key_blob: str,
        master_secret_key_blob: str,
        attributes: list[str],
    ) -> str:
        """
        Generate a CP-ABE secret key for the supplied attributes.
        """

        pk = _deserialize(self.group, master_public_key_blob)
        mk = _deserialize(self.group, master_secret_key_blob)

        charm_attributes = _charm_attributes(attributes)
        sk = self.hybrid.keygen(pk, mk, charm_attributes)

        return _serialize(self.group, sk)

    # -----------------------------------------------------------------------
    # Encryption
    # -----------------------------------------------------------------------

    def encrypt(
        self,
        master_public_key_blob: str,
        plaintext: str,
        policy: str,
    ) -> str:
        """
        Encrypt plaintext under a boolean access policy.

        Examples:

            ADMIN and LAGOS

            (DOCTOR or NURSE) and LAGOS

            ((HR and MANAGER) or (ADMIN and LAGOS))
        """

        if not plaintext:
            raise ValueError("Plaintext cannot be empty.")

        if not policy or not policy.strip():
            raise ValueError("CP-ABE policy cannot be empty.")

        pk = _deserialize(self.group, master_public_key_blob)

        charm_policy = _charm_policy(policy)

        ciphertext = self.hybrid.encrypt(
            pk,
            plaintext.encode("utf-8"),
            charm_policy,
        )

        return _serialize(self.group, ciphertext)

    # -----------------------------------------------------------------------
    # Decryption
    # -----------------------------------------------------------------------

    def decrypt(
        self,
        master_public_key_blob: str,
        user_secret_key_blob: str,
        ciphertext_blob: str,
    ) -> str:
        """
        Attempt to decrypt a CP-ABE ciphertext.

        Raises:
            PermissionError:
                When the user's attributes cannot satisfy the policy.

            ValueError:
                When Charm returns an unexpected plaintext type.
        """

        pk = _deserialize(self.group, master_public_key_blob)
        sk = _deserialize(self.group, user_secret_key_blob)
        ciphertext = _deserialize(self.group, ciphertext_blob)

        try:
            plaintext_bytes = self.hybrid.decrypt(
                pk,
                sk,
                ciphertext,
            )
        except Exception as exc:
            raise PermissionError(
                "CP-ABE decryption failed: attributes do not satisfy policy."
            ) from exc

        # Charm may return None when the policy is not satisfied.
        if plaintext_bytes is None:
            raise PermissionError(
                "CP-ABE decryption failed: attributes do not satisfy policy."
            )

        if not isinstance(plaintext_bytes, (bytes, bytearray)):
            raise ValueError(
                "CP-ABE returned an unexpected plaintext type."
            )

        return bytes(plaintext_bytes).decode("utf-8")

    # -----------------------------------------------------------------------
    # Utility
    # -----------------------------------------------------------------------

    @staticmethod
    def policy_preview(policy: str) -> str:
        """Return a cleaned policy string for display."""
        return policy.strip()

