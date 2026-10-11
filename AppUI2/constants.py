"""Global paths, constants, and one-time directory setup."""
import os

BASE_DIR         = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR       = os.path.join(BASE_DIR, "config")
TOKENS_DIR       = os.path.join(CONFIG_DIR, "tokens")
DATA_DIR         = os.path.join(BASE_DIR, "data")
DOWNLOAD_FOLDER  = os.path.join(BASE_DIR, "downloads")
UPLOAD_FOLDER    = os.path.join(BASE_DIR, "uploads")

CREDENTIALS_FILE = os.path.join(CONFIG_DIR, "credentials.json")
CONFIG_FILE      = os.path.join(CONFIG_DIR, "config.json")
ACCOUNTS_FILE    = os.path.join(CONFIG_DIR, "accounts.json")
DB_PATH          = os.path.join(DATA_DIR, "gc2_history.db")

SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/userinfo.email",
    "openid",
]

# Google Sheet column layout (must match the Go agent)
COL_CMD        = "A"
COL_OUT        = "B"
COL_TS         = "C"
TICKER_CELL    = "E2"
COL_WATERMARK  = "F"

# Web UI default poll interval (frontend also allows override via localStorage)
DEFAULT_WEB_POLL_MS = 60_000


def ensure_dirs():
    for d in (CONFIG_DIR, TOKENS_DIR, DATA_DIR, DOWNLOAD_FOLDER, UPLOAD_FOLDER):
        os.makedirs(d, exist_ok=True)


def legacy_fallback(name: str) -> str:
    """Return the new path in CONFIG_DIR; fall back to BASE_DIR if a legacy
    copy exists there (helps when upgrading from the old flat layout)."""
    new_path = os.path.join(CONFIG_DIR, name)
    if os.path.exists(new_path):
        return new_path
    legacy = os.path.join(BASE_DIR, name)
    if os.path.exists(legacy):
        return legacy
    return new_path
