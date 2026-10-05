"""
routes/crypto_lab.py
--------------------
Cryptographic laboratories:

  /crypto/pqc          Post-quantum key establishment (ML-KEM-768)
  /crypto/signatures   Digital signatures (Ed25519)
  /crypto/integrity    Integrity verification (SHA-256)

Each lab has an HTML page and one or more JSON endpoints.
"""

import logging
import time

from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user, login_required

from crypto import hashing, ml_kem, signatures
from services import audit_service


logger = logging.getLogger(__name__)

crypto_lab_bp = Blueprint("crypto_lab", __name__, url_prefix="/crypto")


# ---------------------------------------------------------------------------
# PQC Lab
# ---------------------------------------------------------------------------

@crypto_lab_bp.route("/pqc")
@login_required
def pqc_page():
    return render_template("lab_pqc.html")


@crypto_lab_bp.route("/pqc/run", methods=["POST"])
@login_required
def pqc_run():
    """
    Alice generates a keypair, Bob encapsulates to Alice's public key,
    Alice decapsulates, and we compare shared secrets.

    Also derives an AES-256 session key from the shared secret via HKDF
    and demonstrates a round-trip with a fixed message, so the lab ties
    KEM to symmetric encryption properly.
    """
    from crypto import aes_gcm, kdf

    try:
        t0 = time.perf_counter()
        alice_pk, alice_sk = ml_kem.keygen()
        t1 = time.perf_counter()

        bob_ss, kem_ct = ml_kem.encapsulate(alice_pk)
        t2 = time.perf_counter()

        alice_ss = ml_kem.decapsulate(alice_sk, kem_ct)
        t3 = time.perf_counter()

        secrets_match = (bob_ss == alice_ss)

        # -------- Ties KEM to AES-GCM via HKDF --------
        salt = kdf.new_salt(32)
        session_key = kdf.derive_key(bob_ss, 32, salt, b"crypto-net/lab/pqc/v1")

        demo_message = b"Encrypted organizational payload."
        env = aes_gcm.encrypt(demo_message, session_key)
        recovered = aes_gcm.decrypt(env, session_key)
        aes_roundtrip_ok = (recovered == demo_message)

        audit_service.log_event(
            "LAB_PQC_RUN",
            user_id=current_user.id,
            resource="lab/pqc",
            result="SUCCESS",
            details={"secrets_match": secrets_match},
        )

        return jsonify({
            "status": "ok",
            "algorithm": ml_kem.ALGORITHM_LABEL,
            "shared_secrets_match": secrets_match,
            "derived_session_key_roundtrip_ok": aes_roundtrip_ok,
            "sizes": {
                "public_key_bytes": len(alice_pk),
                "secret_key_bytes": len(alice_sk),
                "kem_ciphertext_bytes": len(kem_ct),
                "shared_secret_bytes": len(bob_ss),
            },
            "timings_ms": {
                "keygen": round((t1 - t0) * 1000, 3),
                "encapsulate": round((t2 - t1) * 1000, 3),
                "decapsulate": round((t3 - t2) * 1000, 3),
            },
        }), 200
    except Exception as exc:
        logger.exception("PQC lab failed: %s", exc)
        return jsonify({"status": "error", "message": "PQC lab error."}), 500


# ---------------------------------------------------------------------------
# Signature Lab
# ---------------------------------------------------------------------------

@crypto_lab_bp.route("/signatures")
@login_required
def signatures_page():
    return render_template("lab_signatures.html")


@crypto_lab_bp.route("/signatures/run", methods=["POST"])
@login_required
def signatures_run():
    """
    Run four test cases:
      1. Sign + verify original message        -> VALID
      2. Sign original, verify modified message-> INVALID
      3. Verify with wrong public key          -> INVALID
      4. Verify with modified signature        -> INVALID
    """
    payload = request.get_json(silent=True) or {}
    message = (payload.get("message") or "Transfer NGN 100,000 to Account 00112233.").encode("utf-8")
    modified = (payload.get("modified") or message.decode("utf-8") + " (ALTERED)").encode("utf-8")

    try:
        priv, pub = signatures.generate_keypair()
        sig = signatures.sign(message, priv)

        wrong_priv, wrong_pub = signatures.generate_keypair()

        results = {
            "original_message": {
                "label": "Original message + correct public key",
                "result": "VALID" if signatures.verify(message, sig, pub) else "INVALID",
            },
            "modified_message": {
                "label": "Modified message + original signature",
                "result": "VALID" if signatures.verify(modified, sig, pub) else "INVALID",
            },
            "wrong_public_key": {
                "label": "Original message + wrong public key",
                "result": "VALID" if signatures.verify(message, sig, wrong_pub) else "INVALID",
            },
            "modified_signature": {
                "label": "Original message + modified signature",
                "result": "VALID" if signatures.verify(
                    message,
                    bytes([sig[0] ^ 1]) + sig[1:],
                    pub,
                ) else "INVALID",
            },
        }

        audit_service.log_event(
            "LAB_SIGNATURE_RUN",
            user_id=current_user.id,
            resource="lab/signatures",
            result="SUCCESS",
            details={"algorithm": signatures.ALGORITHM_LABEL},
        )

        return jsonify({
            "status": "ok",
            "algorithm": signatures.ALGORITHM_LABEL,
            "post_quantum": signatures.POST_QUANTUM,
            "signature_bytes": len(sig),
            "public_key_bytes": len(pub),
            "test_cases": results,
            "note": (
                "Ed25519 is used as a reliable classical signature. ML-DSA "
                "(FIPS 204) is documented as future work because a "
                "standards-compliant implementation is not currently "
                "packaged for the deployment environment."
            ),
        }), 200
    except Exception as exc:
        logger.exception("Signature lab failed: %s", exc)
        return jsonify({"status": "error", "message": "Signature lab error."}), 500


# ---------------------------------------------------------------------------
# Integrity Lab
# ---------------------------------------------------------------------------

@crypto_lab_bp.route("/integrity")
@login_required
def integrity_page():
    return render_template("lab_integrity.html")


@crypto_lab_bp.route("/integrity/run", methods=["POST"])
@login_required
def integrity_run():
    """
    Compute SHA-256 of the original message, modify the message,
    compute SHA-256 again, and report whether they match.
    """
    payload = request.get_json(silent=True) or {}
    original = (payload.get("original") or "Balance: NGN 500,000.").encode("utf-8")
    modified = (payload.get("modified") or "Balance: NGN 900,000.").encode("utf-8")

    try:
        h1 = hashing.sha256_hex(original)
        h2 = hashing.sha256_hex(modified)
        match = hashing.verify_sha256(modified, h1)

        audit_service.log_event(
            "LAB_INTEGRITY_RUN",
            user_id=current_user.id,
            resource="lab/integrity",
            result="SUCCESS",
            details={"integrity_preserved": match},
        )

        return jsonify({
            "status": "ok",
            "algorithm": "SHA-256",
            "original": {
                "text": original.decode("utf-8", errors="replace"),
                "hash": h1,
            },
            "modified": {
                "text": modified.decode("utf-8", errors="replace"),
                "hash": h2,
            },
            "hashes_match": match,
            "integrity_status": "INTEGRITY VERIFIED" if match else "INTEGRITY VIOLATION DETECTED",
        }), 200
    except Exception as exc:
        logger.exception("Integrity lab failed: %s", exc)
        return jsonify({"status": "error", "message": "Integrity lab error."}), 500
