"""
routes/evaluation.py
--------------------
/evaluation — performance benchmarks and cryptographic test results.

Benchmarks are run on demand. Results are persisted to
`performance_tests` so they survive restarts and can be exported.
"""

import logging
import statistics
import time
from datetime import datetime, timezone

from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user, login_required

import extensions
from config import Config
from crypto import aes_gcm, homomorphic, kdf, ml_kem, signatures
from services import aggregation_service, audit_service


logger = logging.getLogger(__name__)

evaluation_bp = Blueprint("evaluation", __name__, url_prefix="/evaluation")


# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------

@evaluation_bp.route("/")
@login_required
def index():
    return render_template("evaluation.html")


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------

@evaluation_bp.route("/run", methods=["POST"])
@login_required
def run():
    """
    Run N trials of each primitive and persist results.

    Request body:
        {"trials": 20, "message_size": 1024}
    """
    payload = request.get_json(silent=True) or {}
    trials = max(1, min(int(payload.get("trials", 20)), 100))
    msg_size = max(64, min(int(payload.get("message_size", 1024)), 16384))

    results = {
        "aes": _bench_aes(trials, msg_size),
        "ml_kem": _bench_ml_kem(trials),
        "signatures": _bench_signatures(trials),
        "hkdf": _bench_hkdf(trials),
        "homomorphic": _bench_homomorphic(trials),
    }

    # Persist summary rows
    _persist_results(results, trials)

    audit_service.log_event(
        "LAB_PERFORMANCE_RUN",
        user_id=current_user.id,
        resource="evaluation",
        result="SUCCESS",
        details={"trials": trials, "message_size": msg_size},
    )

    return jsonify({
        "status": "ok",
        "trials": trials,
        "message_size_bytes": msg_size,
        "results": results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }), 200


@evaluation_bp.route("/results")
@login_required
def results():
    """Return the most recent persisted benchmark summary."""
    if extensions.db is None:
        return jsonify({"status": "unavailable"}), 200
    query = (
        extensions.db.collection(Config.COLLECTION_PERFORMANCE_TESTS)
        .order_by("timestamp", direction="DESCENDING")
        .limit(200)
    )
    rows = [doc.to_dict() for doc in query.stream()]
    return jsonify({"status": "ok", "rows": rows}), 200


# ---------------------------------------------------------------------------
# Individual benchmarks
# ---------------------------------------------------------------------------

def _bench_aes(trials: int, msg_size: int) -> dict:
    plaintext = b"A" * msg_size
    enc_times, dec_times, ct_sizes = [], [], []

    for _ in range(trials):
        key = aes_gcm.generate_key()
        t0 = time.perf_counter()
        env = aes_gcm.encrypt(plaintext, key)
        t1 = time.perf_counter()
        aes_gcm.decrypt(env, key)
        t2 = time.perf_counter()
        enc_times.append((t1 - t0) * 1000)
        dec_times.append((t2 - t1) * 1000)
        ct_sizes.append(len(env["ciphertext"]))

    return {
        "algorithm": "AES-256-GCM",
        "operation": f"encrypt+decrypt {msg_size}B",
        "trials": trials,
        "encrypt_ms": _stats(enc_times),
        "decrypt_ms": _stats(dec_times),
        "ciphertext_bytes": ct_sizes[0] if ct_sizes else 0,
        "input_bytes": msg_size,
    }


def _bench_ml_kem(trials: int) -> dict:
    kg, en, de = [], [], []
    for _ in range(trials):
        t0 = time.perf_counter()
        pk, sk = ml_kem.keygen()
        t1 = time.perf_counter()
        ss, ct = ml_kem.encapsulate(pk)
        t2 = time.perf_counter()
        ml_kem.decapsulate(sk, ct)
        t3 = time.perf_counter()
        kg.append((t1 - t0) * 1000)
        en.append((t2 - t1) * 1000)
        de.append((t3 - t2) * 1000)
    return {
        "algorithm": "ML-KEM-768",
        "operation": "keygen / encaps / decaps",
        "trials": trials,
        "keygen_ms": _stats(kg),
        "encaps_ms": _stats(en),
        "decaps_ms": _stats(de),
        "public_key_bytes": ml_kem.PUBLIC_KEY_BYTES,
        "ciphertext_bytes": ml_kem.CIPHERTEXT_BYTES,
    }


def _bench_signatures(trials: int) -> dict:
    kg, sg, vr = [], [], []
    for _ in range(trials):
        t0 = time.perf_counter()
        priv, pub = signatures.generate_keypair()
        t1 = time.perf_counter()
        sig = signatures.sign(b"benchmark message", priv)
        t2 = time.perf_counter()
        signatures.verify(b"benchmark message", sig, pub)
        t3 = time.perf_counter()
        kg.append((t1 - t0) * 1000)
        sg.append((t2 - t1) * 1000)
        vr.append((t3 - t2) * 1000)
    return {
        "algorithm": signatures.ALGORITHM_LABEL,
        "operation": "keygen / sign / verify",
        "trials": trials,
        "keygen_ms": _stats(kg),
        "sign_ms": _stats(sg),
        "verify_ms": _stats(vr),
        "signature_bytes": signatures.SIGNATURE_BYTES,
        "post_quantum": signatures.POST_QUANTUM,
    }


def _bench_hkdf(trials: int) -> dict:
    times = []
    for _ in range(trials):
        secret = kdf.new_salt(32)
        t0 = time.perf_counter()
        kdf.derive_key(secret, 32, kdf.new_salt(32), b"bench")
        t1 = time.perf_counter()
        times.append((t1 - t0) * 1000)
    return {
        "algorithm": "HKDF-SHA-256",
        "operation": "derive 32-byte key",
        "trials": trials,
        "derive_ms": _stats(times),
    }


def _bench_homomorphic(trials: int) -> dict:
    if extensions.he_context is None:
        return {"algorithm": "BFV (TenSEAL)", "status": "unavailable"}
    en, cmp_, de = [], [], []
    for _ in range(trials):
        t0 = time.perf_counter()
        a = homomorphic.encrypt_vector(extensions.he_context, [150])
        b = homomorphic.encrypt_vector(extensions.he_context, [95])
        t1 = time.perf_counter()
        c = homomorphic.add_encrypted(extensions.he_context, a, b)
        t2 = time.perf_counter()
        homomorphic.decrypt_vector(extensions.he_context, c)
        t3 = time.perf_counter()
        en.append((t1 - t0) * 1000)
        cmp_.append((t2 - t1) * 1000)
        de.append((t3 - t2) * 1000)
    return {
        "algorithm": homomorphic.ALGORITHM_LABEL,
        "operation": "encrypt / add / decrypt",
        "trials": trials,
        "encrypt_ms": _stats(en),
        "compute_ms": _stats(cmp_),
        "decrypt_ms": _stats(de),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _stats(values: list[float]) -> dict:
    if not values:
        return {}
    return {
        "min": round(min(values), 4),
        "max": round(max(values), 4),
        "avg": round(statistics.mean(values), 4),
        "stddev": round(statistics.stdev(values), 4) if len(values) > 1 else 0.0,
    }


def _persist_results(results: dict, trials: int) -> None:
    if extensions.db is None:
        return
    now = datetime.now(timezone.utc)
    for algo, payload in results.items():
        try:
            doc = {
                "algorithm": payload.get("algorithm", algo),
                "operation": payload.get("operation", ""),
                "trials": trials,
                "payload": payload,
                "timestamp": now,
            }
            extensions.db.collection(Config.COLLECTION_PERFORMANCE_TESTS).document().set(doc)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not persist benchmark for %s: %s", algo, exc)
