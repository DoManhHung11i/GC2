"""OAuth2 status / login endpoints."""
from flask import Blueprint, jsonify
from auth_manager import (creds_for, get_creds, load_accounts)

bp = Blueprint("auth", __name__)


@bp.route("/api/auth/status")
def auth_status():
    st = load_accounts()
    accounts = []
    for a in st["accounts"]:
        try:
            creds = creds_for(a["email"])
            valid = bool(creds and creds.valid)
        except Exception:
            valid = False
        accounts.append({
            "email":  a["email"],
            "valid":  valid,
            "active": a["email"] == st["active"],
        })
    if accounts:
        authenticated = any(a["valid"] and a["active"] for a in accounts)
        return jsonify({"authenticated": authenticated,
                        "accounts": accounts, "active": st["active"]})
    try:
        get_creds()
        return jsonify({"authenticated": True, "accounts": [], "active": ""})
    except Exception as e:
        return jsonify({"authenticated": False, "accounts": [], "active": "",
                        "error": str(e)})


@bp.route("/api/auth/login")
def auth_login():
    try:
        get_creds()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
