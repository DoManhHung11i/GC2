"""Multi-account Google OAuth2 manager.

Each account has its own token file under config/tokens/.
The accounts.json file tracks the list and which one is active.
"""
import json
import os
import threading

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request as GoogleAuthRequest
from googleapiclient.discovery import build

from constants import (ACCOUNTS_FILE, CREDENTIALS_FILE, TOKENS_DIR,
                       SCOPES, legacy_fallback)

_lock = threading.RLock()
_creds_cache = {}  # email -> Credentials


def load_accounts() -> dict:
    with _lock:
        if os.path.exists(ACCOUNTS_FILE):
            with open(ACCOUNTS_FILE) as fh:
                st = json.load(fh)
        else:
            st = {}
        st.setdefault("active", "")
        st.setdefault("accounts", [])
        return st


def save_accounts(st: dict):
    os.makedirs(os.path.dirname(ACCOUNTS_FILE), exist_ok=True)
    with _lock:
        with open(ACCOUNTS_FILE, "w") as fh:
            json.dump(st, fh, indent=2)


def token_path(email: str) -> str:
    return os.path.join(TOKENS_DIR, f"token_{email}.json")


def fetch_email(creds) -> str:
    try:
        svc = build("oauth2", "v2", credentials=creds, cache_discovery=False)
        return svc.userinfo().get().execute().get("email", "")
    except Exception:
        return ""


def creds_for(email: str):
    """Return valid credentials for a specific account, refreshing if needed."""
    with _lock:
        cached = _creds_cache.get(email)
        if cached and cached.valid:
            return cached
    tp = token_path(email)
    if not os.path.exists(tp):
        # legacy fallback: token.json at project root
        legacy = os.path.join(os.path.dirname(ACCOUNTS_FILE), "..", "token.json")
        legacy = os.path.normpath(legacy)
        if os.path.exists(legacy):
            tp = legacy
        else:
            raise FileNotFoundError(f"No token for account {email}")
    creds = Credentials.from_authorized_user_file(tp, SCOPES)
    if not creds.valid:
        if creds.expired and creds.refresh_token:
            creds.refresh(GoogleAuthRequest())
            if tp.endswith(".json") and os.path.basename(tp).startswith("token_"):
                with open(tp, "w") as fh:
                    fh.write(creds.to_json())
        else:
            raise RuntimeError(f"Credentials invalid for {email} — re-login required")
    with _lock:
        _creds_cache[email] = creds
    return creds


def active_email() -> str:
    return load_accounts().get("active", "")


def get_creds():
    """Backward-compat: return creds for the active account, or start
    an interactive OAuth flow if no account exists yet."""
    st = load_accounts()
    if not st["accounts"]:
        if not os.path.exists(CREDENTIALS_FILE):
            raise FileNotFoundError(f"credentials.json not found at {CREDENTIALS_FILE}")
        flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
        creds = flow.run_local_server(port=0)
        email = fetch_email(creds)
        add_account_record(email, creds)
        return creds
    if not st["active"]:
        st["active"] = st["accounts"][0]["email"]
        save_accounts(st)
    return creds_for(st["active"])


def add_account_record(email: str, creds):
    """Persist a new account's token and register it in accounts.json."""
    st = load_accounts()
    if not any(a["email"] == email for a in st["accounts"]):
        st["accounts"].append({"email": email, "token_file": f"token_{email}.json"})
    st["active"] = email
    save_accounts(st)
    with open(token_path(email), "w") as fh:
        fh.write(creds.to_json())
    with _lock:
        _creds_cache[email] = creds


def start_interactive_flow() -> tuple:
    """Run the OAuth flow forcing account selection. Returns (email, creds)."""
    if not os.path.exists(CREDENTIALS_FILE):
        raise FileNotFoundError(f"credentials.json not found at {CREDENTIALS_FILE}")
    flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
    creds = flow.run_local_server(port=0, prompt="select_account")
    email = fetch_email(creds)
    if not email:
        raise RuntimeError("Could not determine email from Google response")
    return email, creds


def remove_account(email: str):
    st = load_accounts()
    st["accounts"] = [a for a in st["accounts"] if a["email"] != email]
    if st["active"] == email:
        st["active"] = st["accounts"][0]["email"] if st["accounts"] else ""
    save_accounts(st)
    tp = token_path(email)
    if os.path.exists(tp):
        os.remove(tp)
    with _lock:
        _creds_cache.pop(email, None)


def set_active(email: str):
    st = load_accounts()
    if not any(a["email"] == email for a in st["accounts"]):
        raise ValueError("Account not found")
    st["active"] = email
    save_accounts(st)
