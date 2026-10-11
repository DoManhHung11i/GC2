"""AES-256-GCM helpers. Wire format: base64(nonce[12] || ciphertext || tag[16])."""
import base64
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def parse_key(hex_str):
    """Return 32-byte key from a 64-char hex string, or None if invalid."""
    h = (hex_str or "").strip().lower()
    if len(h) != 64:
        return None
    try:
        return bytes.fromhex(h)
    except ValueError:
        return None


def gen_key_hex() -> str:
    return secrets.token_hex(32)


def aes_encrypt(plaintext: str, key: bytes) -> str:
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).decode()


def aes_decrypt(b64: str, key: bytes):
    try:
        raw = base64.b64decode(b64)
        return AESGCM(key).decrypt(raw[:12], raw[12:], None).decode()
    except Exception:
        return None


def aes_encrypt_bytes(data: bytes, key: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(key).encrypt(nonce, data, None)


def aes_decrypt_bytes(data: bytes, key: bytes):
    try:
        return AESGCM(key).decrypt(data[:12], data[12:], None)
    except Exception:
        return None
