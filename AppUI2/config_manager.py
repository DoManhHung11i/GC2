"""Read/write config.json."""
import json
import os
import threading

from constants import CONFIG_FILE, legacy_fallback
from crypto_utils import parse_key

_lock = threading.RLock()
_cache = {"path": None, "mtime": 0, "data": None}


def _path():
    return legacy_fallback("config.json") if not os.path.exists(CONFIG_FILE) else CONFIG_FILE


def load_cfg() -> dict:
    """Return config; uses mtime-based cache to avoid disk IO on every call."""
    path = _path()
    with _lock:
        try:
            mtime = os.path.getmtime(path) if os.path.exists(path) else 0
        except OSError:
            mtime = 0
        if _cache["data"] is not None and _cache["path"] == path and _cache["mtime"] == mtime:
            return dict(_cache["data"])
        if os.path.exists(path):
            with open(path) as fh:
                cfg = json.load(fh)
        else:
            cfg = {}
        cfg.setdefault("sheet_id", "")
        cfg.setdefault("drive_id", "")
        cfg.setdefault("aes_key_hex", "")
        cfg.setdefault("agent_keys", {})
        _cache.update({"path": path, "mtime": mtime, "data": dict(cfg)})
        return cfg


def save_cfg(cfg: dict):
    cfg.setdefault("agent_keys", {})
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, "w") as fh:
        json.dump(cfg, fh, indent=2)
    with _lock:
        _cache["data"] = None  # invalidate


def get_key_for_agent(cfg: dict, gid: int):
    """Per-agent key takes priority over global key."""
    per = cfg.get("agent_keys", {}).get(str(gid), "")
    if per:
        k = parse_key(per)
        if k:
            return k
    return parse_key(cfg.get("aes_key_hex", ""))
