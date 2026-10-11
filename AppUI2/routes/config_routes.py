"""Config file + encryption key management."""
from flask import Blueprint, jsonify, request

from config_manager import load_cfg, save_cfg
from crypto_utils import gen_key_hex
from constants import DEFAULT_WEB_POLL_MS

bp = Blueprint("config", __name__)


@bp.route("/api/config", methods=["GET"])
def cfg_get():
    cfg = load_cfg()
    masked_global = ""
    if cfg.get("aes_key_hex"):
        k = cfg["aes_key_hex"]
        masked_global = k[:8] + "…" + k[-4:]
    masked_agents = {
        gid: (k[:8] + "…" + k[-4:]) if k else ""
        for gid, k in cfg.get("agent_keys", {}).items()
    }
    return jsonify({
        "sheet_id":            cfg.get("sheet_id", ""),
        "drive_id":            cfg.get("drive_id", ""),
        "aes_key_hex":         masked_global,
        "aes_key_set":         bool(cfg.get("aes_key_hex")),
        "agent_keys":          masked_agents,
        "default_web_poll_ms": DEFAULT_WEB_POLL_MS,
    })


@bp.route("/api/config", methods=["POST"])
def cfg_save():
    data = request.json or {}
    cfg = load_cfg()
    for k in ("sheet_id", "drive_id"):
        if k in data and data[k] is not None:
            cfg[k] = data[k]
    if data.get("aes_key_hex") and "…" not in data["aes_key_hex"]:
        cfg["aes_key_hex"] = data["aes_key_hex"].strip().lower()
    save_cfg(cfg)
    return jsonify({"ok": True})


@bp.route("/api/config/generate-key", methods=["POST"])
def cfg_gen_key():
    cfg = load_cfg()
    k = gen_key_hex()
    cfg["aes_key_hex"] = k
    save_cfg(cfg)
    return jsonify({"ok": True, "aes_key_hex": k})


@bp.route("/api/config/agent-key/<int:gid>", methods=["GET"])
def cfg_get_agent_key(gid):
    cfg = load_cfg()
    raw = cfg.get("agent_keys", {}).get(str(gid), "")
    if raw:
        return jsonify({"key_set": True, "key_hex": raw[:8] + "…" + raw[-4:]})
    return jsonify({"key_set": False, "key_hex": ""})


@bp.route("/api/config/agent-key/<int:gid>", methods=["POST"])
def cfg_set_agent_key(gid):
    data = request.json or {}
    cfg = load_cfg()
    cfg.setdefault("agent_keys", {})
    raw = (data.get("key_hex") or "").strip().lower()
    if raw and "…" not in raw:
        if len(raw) != 64:
            return jsonify({"error": "Key must be 64 hex chars (256 bits)"}), 400
        cfg["agent_keys"][str(gid)] = raw
    else:
        cfg["agent_keys"].pop(str(gid), None)
    save_cfg(cfg)
    return jsonify({"ok": True})


@bp.route("/api/config/agent-key/<int:gid>/generate", methods=["POST"])
def cfg_gen_agent_key(gid):
    cfg = load_cfg()
    cfg.setdefault("agent_keys", {})
    k = gen_key_hex()
    cfg["agent_keys"][str(gid)] = k
    save_cfg(cfg)
    return jsonify({"ok": True, "key_hex": k})
