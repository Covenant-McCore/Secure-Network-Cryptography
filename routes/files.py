"""
routes/files.py
---------------
Secure file transfer UI and actions.
"""

import io
import logging

from flask import (
    Blueprint, abort, flash, redirect, render_template, request, send_file,
    url_for,
)
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from config import Config
from crypto.file_envelope import (
    FileDecryptionError,
    FileEnvelopeError,
    FileSignatureError,
    FileTooLargeError,
)
from services import audit_service, file_service


logger = logging.getLogger(__name__)

files_bp = Blueprint("files", __name__, url_prefix="/files")


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------

@files_bp.route("/")
@login_required
def index():
    tab = request.args.get("tab", "inbox")
    if tab == "sent":
        items = file_service.list_sent(current_user.id)
    else:
        tab = "inbox"
        items = file_service.list_inbox(current_user.id)
    return render_template("files_list.html", tab=tab, items=items)


# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------

@files_bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    recipients = file_service.list_eligible_recipients(current_user.id)

    if request.method == "POST":
        recipient_id = (request.form.get("recipient_id") or "").strip()
        classification = (request.form.get("classification") or "INTERNAL").strip()

        if not recipient_id:
            flash("Please select a recipient.", "warning")
            return render_template("files_upload.html",
                                   recipients=recipients), 400

        uploaded = request.files.get("file")
        if not uploaded or not uploaded.filename:
            flash("Please choose a file to upload.", "warning")
            return render_template("files_upload.html",
                                   recipients=recipients), 400

        # Basic sanity check on the client-declared size.
        uploaded.stream.seek(0, io.SEEK_END)
        size = uploaded.stream.tell()
        uploaded.stream.seek(0)
        if size > Config.MAX_FILE_BYTES:
            flash(
                f"File exceeds the {Config.MAX_FILE_BYTES // 1024} KiB limit.",
                "danger",
            )
            return render_template("files_upload.html",
                                   recipients=recipients), 413

        content = uploaded.stream.read()
        filename = secure_filename(uploaded.filename) or "upload.bin"
        mimetype = uploaded.mimetype or "application/octet-stream"

        if mimetype not in Config.ALLOWED_FILE_MIME_TYPES:
            flash(f"File type not permitted: {mimetype}", "danger")
            return render_template("files_upload.html",
                                   recipients=recipients), 415

        try:
            file_id = file_service.upload_file(
                sender_id=current_user.id,
                recipient_id=recipient_id,
                organization_id=current_user.organization_id,
                filename=filename,
                mimetype=mimetype,
                content=content,
                classification=classification,
            )
        except FileTooLargeError as exc:
            flash(str(exc), "danger")
            return render_template("files_upload.html",
                                   recipients=recipients), 413
        except file_service.FileServiceError as exc:
            logger.exception("upload_file failed: %s", exc)
            flash("Could not upload the file.", "danger")
            return render_template("files_upload.html",
                                   recipients=recipients), 500

        flash(
            "File sealed: ML-KEM-768 key established, AES-256-GCM ciphertext "
            "created, SHA-256 fingerprint recorded, Ed25519 signature applied.",
            "success",
        )
        return redirect(url_for("files.detail_sent", file_id=file_id))

    return render_template("files_upload.html", recipients=recipients)


# ---------------------------------------------------------------------------
# Recipient detail
# ---------------------------------------------------------------------------

@files_bp.route("/<file_id>")
@login_required
def detail(file_id: str):
    doc = file_service.get_file(file_id)
    if doc is None:
        abort(404)
    if doc["recipientId"] != current_user.id:
        audit_service.access_denied(
            user_id=current_user.id,
            resource=f"file/{file_id}",
            reason="not the recipient",
        )
        abort(403)

    from services import auth_service
    sender = auth_service.get_user(doc["senderId"]) or {}
    sender_display = sender.get("fullName") or doc["senderId"]

    return render_template(
        "files_detail.html",
        file=doc,
        sender_display=sender_display,
        is_sender=False,
    )


@files_bp.route("/<file_id>/sent")
@login_required
def detail_sent(file_id: str):
    doc = file_service.get_file(file_id)
    if doc is None:
        abort(404)
    if doc["senderId"] != current_user.id:
        audit_service.access_denied(
            user_id=current_user.id,
            resource=f"file/{file_id}",
            reason="not the sender",
        )
        abort(403)

    from services import auth_service
    recipient = auth_service.get_user(doc["recipientId"]) or {}
    recipient_display = recipient.get("fullName") or doc["recipientId"]

    return render_template(
        "files_detail.html",
        file=doc,
        sender_display=recipient_display,
        is_sender=True,
    )


# ---------------------------------------------------------------------------
# Download (decrypt + stream)
# ---------------------------------------------------------------------------

@files_bp.route("/<file_id>/download", methods=["POST"])
@login_required
def download(file_id: str):
    user_dict = {"userId": current_user.id}
    try:
        result = file_service.download_file(file_id, user_dict)
    except file_service.FileNotAuthorized:
        abort(403)
    except file_service.FileNotFoundInStore:
        abort(404)
    except FileSignatureError:
        flash(
            "Signature verification FAILED. The file was not decrypted. "
            "This event has been logged.",
            "danger",
        )
        return redirect(url_for("files.detail", file_id=file_id))
    except (FileDecryptionError, FileEnvelopeError):
        flash(
            "Decryption FAILED. The ciphertext failed integrity checks. "
            "This event has been logged.",
            "danger",
        )
        return redirect(url_for("files.detail", file_id=file_id))
    except file_service.FileServiceError as exc:
        logger.exception("download_file failed: %s", exc)
        flash("Could not decrypt the file.", "danger")
        return redirect(url_for("files.detail", file_id=file_id))

    buffer = io.BytesIO(result["content"])
    buffer.seek(0)
    return send_file(
        buffer,
        mimetype=result["mimetype"] or "application/octet-stream",
        as_attachment=True,
        download_name=result["filename"] or "download.bin",
    )
