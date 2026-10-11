"""Google Drive upload / download / delete / list."""
from flask import Blueprint, jsonify, request, Response

import drive_service as drive
from auth_manager import active_email
from config_manager import load_cfg, get_key_for_agent
from crypto_utils import aes_encrypt_bytes, aes_decrypt_bytes

bp = Blueprint("drive", __name__)


@bp.route("/api/drive/files")
def drive_files():
    cfg = load_cfg()
    if not cfg.get("drive_id"):
        return jsonify({"error": "Drive ID not configured"}), 400
    try:
        return jsonify(drive.drive_list(cfg["drive_id"], active_email()))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.route("/api/drive/download/<file_id>")
def drive_dl(file_id):
    cfg = load_cfg()
    email = active_email()
    filename = request.args.get("name", file_id)
    gid_str = request.args.get("gid", "")
    if not gid_str.isdigit():
        return jsonify({"error": "No agent selected — select an agent before downloading"}), 400
    key = get_key_for_agent(cfg, int(gid_str))
    try:
        raw = drive.drive_download(file_id, email)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    out = raw
    decrypted = False
    if key:
        dec = aes_decrypt_bytes(raw, key)
        if dec is not None:
            out = dec
            decrypted = True
    return Response(out, headers={
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Content-Type":        "application/octet-stream",
        "X-Decrypted":         str(decrypted).lower(),
    })


@bp.route("/api/drive/upload", methods=["POST"])
def drive_ul():
    cfg = load_cfg()
    email = active_email()
    if not cfg.get("drive_id"):
        return jsonify({"error": "Drive ID not configured"}), 400
    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400
    gid_str = request.form.get("gid", "")
    if not gid_str.isdigit():
        return jsonify({"error": "No agent selected — select an agent before uploading"}), 400
    key = get_key_for_agent(cfg, int(gid_str))
    f = request.files["file"]
    raw = f.read()
    if key:
        data = aes_encrypt_bytes(raw, key)
        name = f.filename + ".enc"
    else:
        data = raw
        name = f.filename
    try:
        fid = drive.drive_upload(cfg["drive_id"], data, name, email)
        return jsonify({"ok": True, "file_id": fid, "name": name,
                        "encrypted": key is not None})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.route("/api/drive/delete/<file_id>", methods=["POST"])
def drive_del(file_id):
    try:
        drive.drive_delete(file_id, active_email())
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
