"""Local SQLite storage for commands, outputs, metadata, and logs.

Scoped by (account_email, gid). Survives Sheet deletion — rows removed
from Sheet are marked deleted_from_sheet=1, never erased."""
import sqlite3
import threading
from datetime import datetime

from constants import DB_PATH, ensure_dirs

ensure_dirs()
_lock = threading.RLock()


def _conn():
    c = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30.0)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA synchronous=NORMAL")
    c.execute("PRAGMA foreign_keys=ON")
    return c


def _now():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def init_db():
    with _lock:
        c = _conn()
        try:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account TEXT NOT NULL DEFAULT '',
                gid INTEGER NOT NULL,
                row INTEGER NOT NULL,
                command TEXT DEFAULT '',
                output TEXT DEFAULT '',
                timestamp TEXT DEFAULT '',
                encrypted_cmd INTEGER NOT NULL DEFAULT 0,
                pending INTEGER NOT NULL DEFAULT 0,
                deleted_from_sheet INTEGER NOT NULL DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now')),
                UNIQUE(account, gid, row)
            );
            CREATE INDEX IF NOT EXISTS idx_cmd_lookup ON commands(account, gid, row);

            CREATE TABLE IF NOT EXISTS agent_meta (
                account TEXT NOT NULL DEFAULT '',
                gid INTEGER NOT NULL,
                name TEXT NOT NULL DEFAULT '',
                view_watermark INTEGER NOT NULL DEFAULT 0,
                last_seen TEXT,
                updated_at TEXT DEFAULT (datetime('now')),
                PRIMARY KEY (account, gid)
            );

            CREATE TABLE IF NOT EXISTS agent_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account TEXT NOT NULL DEFAULT '',
                gid INTEGER,
                level TEXT NOT NULL DEFAULT 'info',
                source TEXT NOT NULL DEFAULT 'app',
                message TEXT NOT NULL DEFAULT '',
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_logs_lookup ON agent_logs(account, gid, id DESC);
            """)
            c.commit()
        finally:
            c.close()


# ---------- agent metadata ----------
def upsert_agent(account, gid, name):
    with _lock:
        c = _conn()
        try:
            c.execute("""
                INSERT INTO agent_meta(account, gid, name, last_seen)
                VALUES (?,?,?,?)
                ON CONFLICT(account, gid) DO UPDATE SET
                    name = CASE WHEN excluded.name<>'' THEN excluded.name ELSE agent_meta.name END,
                    last_seen = excluded.last_seen,
                    updated_at = datetime('now')
            """, (account, gid, name, _now()))
            c.commit()
        finally:
            c.close()


def get_agent_meta(account, gid):
    with _lock:
        c = _conn()
        try:
            r = c.execute("SELECT * FROM agent_meta WHERE account=? AND gid=?",
                          (account, gid)).fetchone()
            return dict(r) if r else None
        finally:
            c.close()


def set_watermark(account, gid, watermark):
    with _lock:
        c = _conn()
        try:
            c.execute("""
                INSERT INTO agent_meta(account, gid, view_watermark)
                VALUES (?,?,?)
                ON CONFLICT(account, gid) DO UPDATE SET
                    view_watermark=excluded.view_watermark,
                    updated_at=datetime('now')
            """, (account, gid, int(watermark)))
            c.commit()
        finally:
            c.close()


def get_watermark(account, gid):
    with _lock:
        c = _conn()
        try:
            r = c.execute("SELECT view_watermark FROM agent_meta WHERE account=? AND gid=?",
                          (account, gid)).fetchone()
            return int(r["view_watermark"]) if r else 0
        finally:
            c.close()


# ---------- commands ----------
def upsert_history(account, gid, rows):
    """Idempotent sync of Sheet history into local DB.
    Rows absent from the Sheet are marked deleted_from_sheet=1."""
    if not rows:
        return
    with _lock:
        c = _conn()
        try:
            existing = {r["row"] for r in c.execute(
                "SELECT row FROM commands WHERE account=? AND gid=?", (account, gid))}
            sheet_rows = set()
            for item in rows:
                row = int(item["row"])
                sheet_rows.add(row)
                c.execute("""
                    INSERT INTO commands
                      (account, gid, row, command, output, timestamp,
                       encrypted_cmd, pending, deleted_from_sheet, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,0, datetime('now'))
                    ON CONFLICT(account, gid, row) DO UPDATE SET
                        command=excluded.command,
                        output=excluded.output,
                        timestamp=excluded.timestamp,
                        encrypted_cmd=excluded.encrypted_cmd,
                        pending=excluded.pending,
                        deleted_from_sheet=0,
                        updated_at=datetime('now')
                """, (account, gid, row,
                      item.get("command", "") or "",
                      item.get("output", "") or "",
                      item.get("timestamp", "") or "",
                      1 if item.get("encrypted_cmd") else 0,
                      1 if item.get("pending") else 0))
            for row in existing - sheet_rows:
                c.execute("""UPDATE commands SET deleted_from_sheet=1,
                             updated_at=datetime('now')
                             WHERE account=? AND gid=? AND row=?""",
                          (account, gid, row))
            c.commit()
        finally:
            c.close()


def insert_local_command(account, gid, row, command, encrypted=False, pending=True):
    """Record a command locally as soon as it is sent (before agent output)."""
    with _lock:
        c = _conn()
        try:
            c.execute("""
                INSERT INTO commands
                  (account, gid, row, command, output, timestamp,
                   encrypted_cmd, pending, updated_at)
                VALUES (?,?,?,?,'',?,?,?, datetime('now'))
                ON CONFLICT(account, gid, row) DO UPDATE SET
                    command=excluded.command,
                    encrypted_cmd=excluded.encrypted_cmd,
                    pending=excluded.pending,
                    updated_at=datetime('now')
            """, (account, gid, row, command, _now(),
                  1 if encrypted else 0, 1 if pending else 0))
            c.commit()
        finally:
            c.close()


def get_commands(account, gid, after_row=0):
    with _lock:
        c = _conn()
        try:
            return [dict(r) for r in c.execute("""
                SELECT row, command, output, timestamp, encrypted_cmd,
                       pending, deleted_from_sheet
                FROM commands
                WHERE account=? AND gid=? AND row>?
                ORDER BY row ASC
            """, (account, gid, int(after_row)))]
        finally:
            c.close()


# ---------- sessions (DB-level listing) ----------
def list_sessions(account):
    """Return every gid present in DB for the account, with stats.
    Includes entries that only exist in commands (no meta row yet)."""
    with _lock:
        c = _conn()
        try:
            meta_rows = [dict(r) for r in c.execute("""
                SELECT gid, name, last_seen FROM agent_meta WHERE account=?
            """, (account,))]
            meta_by_gid = {r["gid"]: r for r in meta_rows}

            # Counts per gid
            count_rows = [dict(r) for r in c.execute("""
                SELECT gid,
                       COUNT(*) AS row_count,
                       SUM(CASE WHEN pending=1 THEN 1 ELSE 0 END) AS pending_count,
                       MAX(updated_at) AS last_activity
                FROM commands WHERE account=?
                GROUP BY gid
            """, (account,))]
            count_by_gid = {r["gid"]: r for r in count_rows}

            all_gids = set(meta_by_gid) | set(count_by_gid)
            out = []
            for gid in sorted(all_gids):
                m = meta_by_gid.get(gid, {})
                n = count_by_gid.get(gid, {})
                out.append({
                    "gid":           gid,
                    "name":          m.get("name") or f"gid_{gid}",
                    "last_seen":     m.get("last_seen"),
                    "row_count":     int(n.get("row_count") or 0),
                    "pending_count": int(n.get("pending_count") or 0),
                    "last_activity": n.get("last_activity"),
                })
            return out
        finally:
            c.close()


def delete_session(account, gid):
    """Permanently remove a session from the DB (commands + meta + logs)."""
    with _lock:
        c = _conn()
        try:
            c.execute("DELETE FROM commands    WHERE account=? AND gid=?", (account, gid))
            c.execute("DELETE FROM agent_meta  WHERE account=? AND gid=?", (account, gid))
            c.execute("DELETE FROM agent_logs  WHERE account=? AND gid=?", (account, gid))
            c.commit()
        finally:
            c.close()


def rename_session(account, gid, name):
    """Update the stored name (used when the Sheet tab is renamed)."""
    with _lock:
        c = _conn()
        try:
            c.execute("""
                INSERT INTO agent_meta(account, gid, name) VALUES (?,?,?)
                ON CONFLICT(account, gid) DO UPDATE SET
                    name=excluded.name, updated_at=datetime('now')
            """, (account, gid, name))
            c.commit()
        finally:
            c.close()


# ---------- logs ----------
def add_log(account, gid, level, message, source="app"):
    with _lock:
        c = _conn()
        try:
            c.execute("""
                INSERT INTO agent_logs(account, gid, level, source, message)
                VALUES (?,?,?,?,?)
            """, (account or "", gid, level, source, (message or "")[:8000]))
            c.commit()
        finally:
            c.close()


def get_logs(account, gid, limit=300):
    with _lock:
        c = _conn()
        try:
            rows = c.execute("""
                SELECT id, level, source, message, created_at
                FROM agent_logs
                WHERE account=? AND (gid=? OR gid IS NULL)
                ORDER BY id DESC LIMIT ?
            """, (account or "", gid, int(limit))).fetchall()
            return [dict(r) for r in reversed(rows)]
        finally:
            c.close()


init_db()
