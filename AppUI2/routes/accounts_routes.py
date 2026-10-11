"""Multi-account management."""
from flask import Blueprint, jsonify, request

import database as db
from auth_manager import (add_account_record, load_accounts, remove_account,
                          set_active, start_interactive_flow)

bp = Blueprint("accounts", __name__)


@bp.route("/api/accounts")
def accounts_list():
    st = load_accounts()
    return jsonify({"accounts": st["accounts"], "active": st["active"]})


@bp.route("/api/accounts/add", methods=["POST"])
def accounts_add():
    try:
        email, creds = start_interactive_flow()
        add_account_record(email, creds)
        db.add_log(email, None, "info", f"Account {email} added", source="auth")
        return jsonify({"ok": True, "email": email})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.route("/api/accounts/active", methods=["POST"])
def accounts_set_active():
    email = (request.json or {}).get("email", "")
    try:
        set_active(email)
        return jsonify({"ok": True, "active": email})
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 404


@bp.route("/api/accounts/remove", methods=["POST"])
def accounts_remove():
    email = (request.json or {}).get("email", "")
    remove_account(email)
    db.add_log(email, None, "warn", f"Account {email} removed", source="auth")
    return jsonify({"ok": True})
