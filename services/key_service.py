"""
services/key_service.py
-----------------------
Per-user cryptographic key management.

RESPONSIBILITIES
----------------
1. On first startup, generate and persist the CP-ABE master keypair.
2. On user creation, issue:
     - an Ed25519 signing keypair (public + private)
     - a CP-ABE secret key bound to the user's attributes
     - an ML-KEM-768 keypair (public + private)
3. Provide lookup of the public components for encryption routes.
4. Provide retrieval of private components for decryption routes,
   with the caller responsible for never sending them over the wire.

STORAGE
-------
Everything lives in Firestore. Public components are stored in the user
document and in `cryptographic_keys`. Private components are stored ONLY
in `cryptographic_keys` with a `privateMaterial` field. This is documented
in the thesis as a deliberate prototype simplification; production would
use an HSM or KMS.

NEVER EXPOSE privateMaterial VIA ANY API ROUTE.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

import extensions
from config import Config
from crypto import ml_kem, signatures

# CP-ABE is an optional local backend.
# The real BSW07 implementation requires Charm-Crypto/PBC and is kept
# available in the local development environment. Deployment environments
# without Charm must still be able to start the Flask application.
try:
    from crypto.cpabe import CPABESystem, _serialize, _deserialize
    CPABE_AVAILABLE = True
except ModuleNotFoundError as exc:
    if exc.name != "charm":
        raise
    CPABESystem = None
    _serialize = None
    _deserialize = None
    CPABE_AVAILABLE = False
    logging.getLogger(__name__).warning(
        "Charm/PBC CP-ABE backend unavailable; "
        "deployment will use the PBAC fallback."
    )


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class KeyServiceError(RuntimeError):
    """Raised when the key service cannot fulfil a request."""


# ---------------------------------------------------------------------------
# CP-ABE master key — lazily created, cached in-process
# ---------------------------------------------------------------------------

_abe_system: Optional[CPABESystem] = None  # type: ignore[type-arg]
_abe_master_pk_blob: Optional[str] = None
_abe_master_sk_blob: Optional[str] = None


def _load_or_create_abe_master() -> None:
    """
    Ensure the CP-ABE master keypair exists. On first call, generate it
    and persist it under `abe_master_keys/cpabe`.

    Raises KeyServiceError when the optional local Charm/PBC backend is
    unavailable.
    """
    global _abe_system, _abe_master_pk_blob, _abe_master_sk_blob

    if not CPABE_AVAILABLE:
        raise KeyServiceError(
            "CP-ABE backend unavailable. Charm-Crypto/PBC is not installed "
            "in this deployment environment."
        )

    if _abe_master_pk_blob is not None:
        return

    if extensions.db is None:
        raise KeyServiceError("Firestore is not initialised.")

    doc_ref = (
        extensions.db.collection(Config.COLLECTION_ABE_MASTER).document("cpabe")
    )
    doc = doc_ref.get()

    if doc.exists:
        data = doc.to_dict() or {}
        _abe_master_pk_blob = data.get("masterPublicKey")
        _abe_master_sk_blob = data.get("masterSecretKey")
        if not (_abe_master_pk_blob and _abe_master_sk_blob):
            raise KeyServiceError("Corrupt CP-ABE master key document.")
    else:
        logger.info("No CP-ABE master key found; generating a new one.")
        system = CPABESystem()
        pk_blob, sk_blob = system.setup()
        doc_ref.set({
            "masterPublicKey": pk_blob,
            "masterSecretKey": sk_blob,
            "createdAt": datetime.now(timezone.utc),
        })
        _abe_master_pk_blob = pk_blob
        _abe_master_sk_blob = sk_blob

    _abe_system = CPABESystem()


def get_abe_system() -> CPABESystem:
    """Return the singleton CP-ABE system. Initialises on first call."""
    if _abe_system is None:
        _load_or_create_abe_master()
    assert _abe_system is not None
    return _abe_system


def get_abe_master_public_key() -> str:
    """Return the serialized CP-ABE master public key."""
    _load_or_create_abe_master()
    assert _abe_master_pk_blob is not None
    return _abe_master_pk_blob


def get_abe_master_secret_key() -> str:
    """
    Return the serialized CP-ABE master secret key.

    INTERNAL USE ONLY. The key service passes this to `keygen` when issuing
    a user secret key. It must never reach a route, a template, or the
    browser.
    """
    _load_or_create_abe_master()
    assert _abe_master_sk_blob is not None
    return _abe_master_sk_blob


# ---------------------------------------------------------------------------
# Per-user key issuance
# ---------------------------------------------------------------------------

def issue_user_keys(user_id: str, attributes: list[str]) -> dict:
    """
    Generate all key material for a user and persist it.

    Returns a summary dict WITHOUT any private material. Callers may safely
    log or return this.

    Parameters
    ----------
    user_id : str
    attributes : list[str]
        CP-ABE attributes for the user, e.g.
        ["DOCTOR", "LAGOS", "CLEARANCE-3"].
    """
    if extensions.db is None:
        raise KeyServiceError("Firestore is not initialised.")

    # ---- 1. Ed25519 signature keypair ----
    ed_priv, ed_pub = signatures.generate_keypair()

    # ---- 2. ML-KEM-768 keypair ----
    kem_pub, kem_priv = ml_kem.keygen()

    # ---- 3. CP-ABE user secret key ----
    # Real CP-ABE is available in the local Charm/PBC environment.
    # Deployment environments without Charm use the PBAC fallback and
    # therefore do not generate/store a CP-ABE secret key.
    if CPABE_AVAILABLE:
        system = get_abe_system()
        cpabe_sk_blob = system.keygen(
            get_abe_master_public_key(),
            get_abe_master_secret_key(),
            attributes,
        )
        cpabe_algorithm = "CP-ABE (BSW07)"
    else:
        cpabe_sk_blob = None
        cpabe_algorithm = "CP-ABE unavailable; PBAC fallback"

    # ---- 4. Persist ----
    now = datetime.now(timezone.utc)

    keys_doc = {
        "userId": user_id,
        "createdAt": now,
        "updatedAt": now,
        "attributes": attributes,
        "ed25519": {
            "publicKey": ed_pub,             # bytes; Firestore stores as Blob
            "algorithm": signatures.ALGORITHM_LABEL,
        },
        "mlKem768": {
            "publicKey": kem_pub,            # bytes
            "algorithm": ml_kem.ALGORITHM_LABEL,
        },
        "cpabe": {
            "secretKeyBlob": cpabe_sk_blob,  # base64 string when CP-ABE is available
            "algorithm": cpabe_algorithm,
        },
        # PRIVATE MATERIAL — never exposed by any API route
        "privateMaterial": {
            "ed25519PrivateKey": ed_priv,    # bytes
            "mlKem768PrivateKey": kem_priv,  # bytes
        },
        "status": "active",
    }

    ref = (
        extensions.db.collection(Config.COLLECTION_KEYS).document(user_id)
    )
    ref.set(keys_doc)

    # ---- 5. Update user doc with public identifiers only ----
    extensions.db.collection(Config.COLLECTION_USERS).document(user_id).update({
        "publicKeyId": user_id,
    })

    logger.info("Issued keys for user %s with attributes %s", user_id, attributes)

    return {
        "userId": user_id,
        "ed25519PublicKeyLength": len(ed_pub),
        "mlKem768PublicKeyLength": len(kem_pub),
        "cpabeAttributes": attributes,
        "algorithm": {
            "signature": signatures.ALGORITHM_LABEL,
            "kem": ml_kem.ALGORITHM_LABEL,
            "abe": cpabe_algorithm,
        },
    }


# ---------------------------------------------------------------------------
# Retrieval — PUBLIC components (safe for encryption routes)
# ---------------------------------------------------------------------------

def get_user_public_keys(user_id: str) -> Optional[dict]:
    """
    Fetch a user's public key material.

    Returns a dict with `ed25519PublicKey`, `mlKem768PublicKey`, and
    `cpabeAttributes` (the latter is not strictly "public" but is needed by
    the encryption route to know which attributes to encode into the
    policy).
    """
    if extensions.db is None:
        raise KeyServiceError("Firestore is not initialised.")

    doc = (
        extensions.db.collection(Config.COLLECTION_KEYS)
        .document(user_id)
        .get()
    )
    if not doc.exists:
        return None
    data = doc.to_dict() or {}
    return {
        "userId": user_id,
        "ed25519PublicKey": data.get("ed25519", {}).get("publicKey"),
        "mlKem768PublicKey": data.get("mlKem768", {}).get("publicKey"),
        "cpabeAttributes": data.get("attributes", []),
        "status": data.get("status"),
    }


# ---------------------------------------------------------------------------
# Retrieval — PRIVATE components (used ONLY by decryption routes)
# ---------------------------------------------------------------------------

def get_user_private_material(user_id: str) -> Optional[dict]:
    """
    Fetch a user's private key material.

    Any caller must enforce that `user_id == current_user.id` before
    invoking this. The audit service should log every call.
    """
    if extensions.db is None:
        raise KeyServiceError("Firestore is not initialised.")

    doc = (
        extensions.db.collection(Config.COLLECTION_KEYS)
        .document(user_id)
        .get()
    )
    if not doc.exists:
        return None
    data = doc.to_dict() or {}
    return {
        "userId": user_id,
        "ed25519PrivateKey": data.get("privateMaterial", {}).get("ed25519PrivateKey"),
        "mlKem768PrivateKey": data.get("privateMaterial", {}).get("mlKem768PrivateKey"),
        "cpabeSecretKeyBlob": data.get("cpabe", {}).get("secretKeyBlob"),
        "cpabeAttributes": data.get("attributes", []),
    }


# ---------------------------------------------------------------------------
# Key lifecycle (rotation / revocation placeholders used in Phase 6)
# ---------------------------------------------------------------------------

def revoke_user_keys(user_id: str) -> None:
    """
    Mark a user's keys as revoked. Decryption routes must refuse to use
    revoked keys.
    """
    if extensions.db is None:
        raise KeyServiceError("Firestore is not initialised.")
    extensions.db.collection(Config.COLLECTION_KEYS).document(user_id).update({
        "status": "revoked",
        "updatedAt": datetime.now(timezone.utc),
    })
    logger.warning("Revoked keys for user %s", user_id)


def rotate_user_keys(user_id: str, attributes: list[str]) -> dict:
    """
    Issue a fresh set of keys for a user, overwriting the previous
    key material.

    This function is intended for key rotation workflows. Existing
    private material is replaced and the key status is restored to
    active.
    """
    if extensions.db is None:
        raise KeyServiceError("Firestore is not initialised.")

    # Generate fresh key material using the same key-generation
    # mechanism as initial provisioning.
    key_material = issue_user_keys(user_id, attributes)

    (
        extensions.db
        .collection(Config.COLLECTION_KEYS)
        .document(user_id)
        .set(
            key_material,
            merge=True,
        )
    )

    logger.info("Rotated keys for user %s", user_id)

    return get_user_public_keys(user_id)
