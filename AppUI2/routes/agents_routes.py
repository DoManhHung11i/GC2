"""Live Sheet agent operations (list, history, command, ticker, clear,
delete tab, clear-to-here, logs)."""
from flask import Blueprint, jsonify, request

import database as db
import sheets_service as sheets
from auth_manager import active_email
from config_manager import load_cfg, get_key_for_agent

bp = Blueprint("agents", __name__)


@bp.route("/api/agents")
def agents_list():
    """Fetch the agent list from the Sheet (called only on manual ⟳ click)."""
    cfg = load_cfg()
    if not cfg.get("sheet_id"):
        return jsonify({"error": "Sheet ID not configured"}), 400
    email = active_email()
    try:
        agents = sheets.list_agents(cfg["sheet_id"], email)
        for a in agents:
            db.upsert_agent(email, a["id"], a["name"])
        return jsonify(agents)
    except Exception as e:
        db.add_log(email, None, "error", f"list_agents: {e}", source="agents")
        return jsonify({"error": str(e)}), 500


@bp.route("/api/agents/<int:gid>/history")
def agents_history(gid):
    """source=sheet (default): fetch from Sheet + sync DB.
       source=db: read local SQLite only (no Google request)."""
    source = (request.args.get("source") or "sheet").lower()
    email  = active_email()
    cfg    = load_cfg()
    key    = get_key_for_agent(cfg, gid)

    if source == "db":
        return jsonify({
            "history":    db.get_commands(email, gid),
            "source":     "db",
            "watermark":  db.get_watermark(email, gid),
            "ticker":     None,
            "encryption": key is not None,
            "gid":        gid,
        })

    try:
        tab = sheets.resolve_name(cfg["sheet_id"], gid, email)
        hist, tk = sheets.get_history(cfg["sheet_id"], tab, key, email)
    except Exception as e:
        db.add_log(email, gid, "error", f"history fetch: {e}", source="history")
        return jsonify({"error": str(e)}), 500

    try:
        db.upsert_history(email, gid, hist)
        db.upsert_agent(email, gid, tab)
        db.add_log(email, gid, "info",
                   f"Fetched {len(hist)} rows from Sheet", source="history")
    except Exception as e:
        db.add_log(email, gid, "error", f"db sync: {e}", source="db")

    return jsonify({
        "history":    db.get_commands(email, gid),
        "ticker":     tk,
        "encryption": key is not None,
        "name":       tab,
        "gid":        gid,
        "source":     "sheet",
        "watermark":  db.get_watermark(email, gid),
    })


@bp.route("/api/agents/<int:gid>/command", methods=["POST"])
def agents_command(gid):
    cfg = load_cfg()
    email = active_email()
    key = get_key_for_agent(cfg, gid)
    cmd = (request.json or {}).get("command", "").strip()
    if not cmd:
        return jsonify({"error": "Empty command"}), 400
    try:
        tab = sheets.resolve_name(cfg["sheet_id"], gid, email)
        row = sheets.next_empty_row(cfg["sheet_id"], tab, email)
        sheets.send_cmd(cfg["sheet_id"], tab, cmd, row, key, email)
        db.insert_local_command(email, gid, row, cmd,
                                encrypted=key is not None, pending=True)
        db.add_log(email, gid, "info",
                   f"Sent command to row {row}: {cmd[:80]}", source="command")
        return jsonify({"ok": True, "row": row, "encrypted": key is not None})
    except Exception as e:
        db.add_log(email, gid, "error", f"send: {e}", source="command")
        return jsonify({"error": str(e)}), 500


@bp.route("/api/agents/<int:gid>/ticker", methods=["POST"])
def agents_ticker(gid):
    """Writes Sheet cell E2 — controls the Go agent poll interval only.
    The Web UI poll interval is separate (frontend localStorage)."""
    cfg = load_cfg()
    email = active_email()
    secs = int((request.json or {}).get("seconds", 10))
    try:
        tab = sheets.resolve_name(cfg["sheet_id"], gid, email)
        sheets.set_ticker(cfg["sheet_id"], tab, secs, email)
        db.add_log(email, gid, "info",
                   f"Agent ticker set to {secs}s (Sheet E2)", source="app")
        return jsonify({"ok": True, "seconds": secs})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.route("/api/agents/<int:gid>/clear", methods=["POST"])
def agents_clear(gid):
    """Clear session on Sheet (preserves row-count for agent pointer)."""
    cfg = load_cfg()
    email = active_email()
    try:
        tab = sheets.resolve_name(cfg["sheet_id"], gid, email)
        sheets.clear_session(cfg["sheet_id"], tab, email)
        db.add_log(email, gid, "warn", "Session cleared on Sheet", source="app")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.route("/api/agents/<int:gid>/delete", methods=["POST"])
def agents_delete(gid):
    """Delete the Sheet tab ONLY. Local DB records are preserved.
       To wipe DB, call POST /api/db-sessions/<gid>/delete separately."""
    cfg = load_cfg()
    email = active_email()
    try:
        cfg.get("agent_keys", {}).pop(str(gid), None)
        from config_manager import save_cfg
        save_cfg(cfg)
        sheets.delete_tab(cfg["sheet_id"], gid, email)
        db.add_log(email, gid, "warn",
                   "Sheet tab deleted (local DB preserved)", source="app")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.route("/api/agents/<int:gid>/clear-to-here", methods=["POST"])
def agents_clear_to_here(gid):
    """Set per-agent view watermark. Rows <= watermark are visually faded."""
    email = active_email()
    wm = int((request.json or {}).get("watermark", 0))
    db.set_watermark(email, gid, wm)
    db.add_log(email, gid, "info", f"View cleared to row {wm}", source="app")
    return jsonify({"ok": True, "watermark": wm})


@bp.route("/api/agents/<int:gid>/logs")
def agents_logs(gid):
    email = active_email()
    limit = int(request.args.get("limit", 300))
    return jsonify({"logs": db.get_logs(email, gid, limit)})
