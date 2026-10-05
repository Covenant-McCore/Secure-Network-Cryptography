"""
routes/analytics.py
-------------------
Privacy-preserving analytics using TenSEAL BFV.

The server encrypts two integer vectors, performs addition on the
ciphertexts, then decrypts to confirm the result. In a real deployment
the "server" that computes would not hold the secret key; here we hold
it locally to demonstrate the round-trip.
"""

import logging
import time

from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user, login_required

import extensions
from crypto import homomorphic
from services import audit_service


logger = logging.getLogger(__name__)

analytics_bp = Blueprint("analytics", __name__, url_prefix="/analytics")


@analytics_bp.route("/privacy")
@login_required
def page():
    return render_template("lab_analytics.html")


@analytics_bp.route("/privacy/run", methods=["POST"])
@login_required
def run():
    if extensions.he_context is None:
        return jsonify({"status": "error", "message": "HE context unavailable."}), 500

    payload = request.get_json(silent=True) or {}
    try:
        a = int(payload.get("a", 135))
        b = int(payload.get("b", 105))
    except (TypeError, ValueError):
        return jsonify({"status": "error", "message": "a and b must be integers."}), 400

    try:
        ctx = extensions.he_context

        t0 = time.perf_counter()
        enc_a = homomorphic.encrypt_vector(ctx, [a])
        enc_b = homomorphic.encrypt_vector(ctx, [b])
        t1 = time.perf_counter()

        enc_sum = homomorphic.add_encrypted(ctx, enc_a, enc_b)
        t2 = time.perf_counter()

        decrypted = homomorphic.decrypt_vector(ctx, enc_sum)
        t3 = time.perf_counter()

        audit_service.log_event(
            "LAB_ANALYTICS_RUN",
            user_id=current_user.id,
            resource="lab/analytics",
            result="SUCCESS",
            details={"a": a, "b": b, "sum": decrypted[0]},
        )

        return jsonify({
            "status": "ok",
            "scheme": homomorphic.ALGORITHM_LABEL,
            "plaintext_inputs": {"a": a, "b": b},
            "encrypted_output_preview": homomorphic.serialize_for_storage(enc_sum)[:80] + "…",
            "computed_sum": decrypted[0],
            "matches_expected": (decrypted[0] == a + b),
            "timings_ms": {
                "encrypt": round((t1 - t0) * 1000, 3),
                "compute": round((t2 - t1) * 1000, 3),
                "decrypt": round((t3 - t2) * 1000, 3),
            },
            "note": (
                "The addition is performed on ciphertext. The server performs "
                "the arithmetic without seeing the plaintext inputs."
            ),
        }), 200
    except Exception as exc:
        logger.exception("Analytics lab failed: %s", exc)
        return jsonify({"status": "error", "message": "Analytics lab error."}), 500
