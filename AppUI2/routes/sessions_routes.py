"""Local DB session management: list, rename, delete.

Used to view data from agents whose Sheet tabs were deleted, and to
permanently wipe DB records."""
from flask import Blueprint, jsonify, request

import database as db
from auth_manager import active_email

bp = Blueprint("sessions", __name__)


@bp.route("/api/db-sessions")
def db_sessions_list():
    """Return every session present in the local DB for the active account.
    Does not touch the Sheet — safe to call on page load."""
    email = active_email()
    return jsonify({"sessions": db.list_sessions(email), "account": email})


@bp.route("/api/db-sessions/<int:gid>", methods=["GET"])
def db_session_detail(gid):
    """History + metadata for one session, from DB only."""
    email = active_email()
    meta = db.get_agent_meta(email, gid) or {}
    return jsonify({
        "gid":        gid,
        "name":       meta.get("name", f"gid_{gid}"),
        "history":    db.get_commands(email, gid),
        "watermark":  db.get_watermark(email, gid),
        "logs":       db.get_logs(email, gid, 300),
    })


@bp.route("/api/db-sessions/<int:gid>/rename", methods=["POST"])
def db_session_rename(gid):
    email = active_email()
    name = (request.json or {}).get("name", "").strip()
    if not name:
        return jsonify({"error": "Empty name"}), 400
    db.rename_session(email, gid, name)
    db.add_log(email, gid, "info", f"Session renamed to '{name}'", source="app")
    return jsonify({"ok": True})


@bp.route("/api/db-sessions/<int:gid>/delete", methods=["POST"])
def db_session_delete(gid):
    """Permanently remove all DB records for a gid."""
    email = active_email()
    try:
        db.delete_session(email, gid)
        db.add_log(email, None, "warn",
                   f"Session gid={gid} removed from local DB", source="app")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
