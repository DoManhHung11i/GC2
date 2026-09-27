import argparse
import base64
import hashlib
import os
import platform
import re
import secrets
import subprocess
import sys
from pathlib import Path

SUPPORTED_TARGETS = {
    "linux/amd64",
    "linux/arm64",
    "windows/amd64",
    "darwin/amd64",
    "darwin/arm64",
}

DEFAULT_OUTPUT = "GC2-sheet"
ROOT_DIR = Path(__file__).resolve().parent
OPTIONS_YML = ROOT_DIR / "cmd" / "options.yml"
OPTIONS_ENC = ROOT_DIR / "cmd" / "options.enc"
ROOT_GO = ROOT_DIR / "cmd" / "root.go"
CRYPTO_GO = ROOT_DIR / "internal" / "crypto" / "crypto.go"

CONFIG_KEY_PATTERN = re.compile(
    r'const EncryptConfigKey = ".*?"'
)
DATA_KEY_PATTERN = re.compile(
    r'(EncryptDataKey = mustDecodeHex\(")([0-9a-fA-F]{64})("\))'
)

VERBOSE_PATTERN = re.compile(
    r'^(Verbose\s*:\s*)(true|false)(\s*(?:#.*)?)?$',
    re.MULTILINE | re.IGNORECASE,
)

def log(msg: str, level: str = "INFO"):
    colors = {
        "INFO": "\033[36m",
        "OK": "\033[32m",
        "WARN": "\033[33m",
        "ERR": "\033[31m",
        "RESET": "\033[0m",
    }
    c = colors.get(level, colors["INFO"])
    print(f"{c}[{level}]{colors['RESET']} {msg}")


def fail(msg: str, code: int = 1):
    log(msg, "ERR")
    sys.exit(code)


def gen_config_key(length: int = 48) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def gen_data_key() -> str:
    return secrets.token_hex(32)


def encrypt_config(yml_path: Path, enc_path: Path, passphrase: str):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        fail("Missing dependency: pip install cryptography")

    plaintext = yml_path.read_bytes()
    key = hashlib.sha256(passphrase.encode()).digest()
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ciphertext = nonce + aesgcm.encrypt(nonce, plaintext, None)
    encoded = base64.b64encode(ciphertext)

    enc_path.write_bytes(encoded)
    log(f"Encrypted config → {enc_path}", "OK")


def patch_file(path: Path, pattern: re.Pattern, replacement: str, label: str):
    if not path.exists():
        fail(f"File not found: {path}")

    original = path.read_text(encoding="utf-8")
    new_content, count = pattern.subn(replacement, original, count=1)

    if count == 0:
        fail(f"Could not find {label} pattern in {path}")

    path.write_text(new_content, encoding="utf-8")
    log(f"Patched {label} in {path.name}", "OK")


def patch_verbose(yml_path: Path, verbose: bool):
    if not yml_path.exists():
        fail(f"Missing {yml_path}")

    content = yml_path.read_text(encoding="utf-8")
    new_val = "true" if verbose else "false"
    new_content, count = VERBOSE_PATTERN.subn(
        rf'\g<1>{new_val}\g<3>',
        content,
        count=1,
    )

    if count == 0:
        if not new_content.endswith("\n"):
            new_content += "\n"
        new_content += f"Verbose: {new_val}\n"
        log("Verbose line not found – appended", "WARN")
    else:
        log(f"Set Verbose: {new_val} in options.yml", "OK")

    yml_path.write_text(new_content, encoding="utf-8")

def validate_target(goos: str, goarch: str):
    target = f"{goos}/{goarch}"
    if target not in SUPPORTED_TARGETS:
        fail(
            f"Unsupported target '{target}'.\n"
            f"Supported: {', '.join(sorted(SUPPORTED_TARGETS))}"
        )


def build_binary(goos: str, goarch: str, output: str) -> Path:
    env = os.environ.copy()
    env["GOOS"] = goos
    env["GOARCH"] = goarch
    env["CGO_ENABLED"] = "0"

    ldflags = "-s -w"
    if goos == "windows":
        ldflags += " -H windowsgui"
        if not output.lower().endswith(".exe"):
            output += ".exe"

    out_path = ROOT_DIR / output

    cmd = [
        "go", "build",
        "-ldflags", ldflags,
        "-o", str(out_path),
        ".",
    ]

    log(f"Building → GOOS={goos} GOARCH={goarch}  output={out_path.name}")
    try:
        result = subprocess.run(
            cmd,
            cwd=ROOT_DIR,
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        if result.stdout.strip():
            print(result.stdout)
        log(f"Build successful: {out_path}", "OK")
        return out_path
    except subprocess.CalledProcessError as e:
        log("go build failed:", "ERR")
        print(e.stderr or e.stdout)
        fail("Build aborted")


def parse_args():
    parser = argparse.ArgumentParser(
        description="GC2-sheet automated builder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  # Random keys + Windows amd64
  python builder.py --os windows --arch amd64

  # Custom keys + Linux arm64
  python builder.py -o myagent --os linux --arch arm64 \\
      --config-key "MySecretPass!" --data-key fc7a1199...4453c1

  # Preview only (no build)
  python builder.py --os linux --arch amd64 --dry-run

Supported targets:
{chr(10).join('  ' + t for t in sorted(SUPPORTED_TARGETS))}
""",
    )

    parser.add_argument("--os", dest="goos", default=None,
                        help="Target GOOS (linux / windows / darwin)")
    parser.add_argument("--arch", dest="goarch", default=None,
                        help="Target GOARCH (amd64 / arm64)")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT,
                        help=f"Output binary name (default: {DEFAULT_OUTPUT})")
    parser.add_argument("--config-key", default=None,
                        help="Passphrase for EncryptConfigKey (random if omitted)")
    parser.add_argument("--data-key", default=None,
                        help="64-char hex for EncryptDataKey (random if omitted)")
    parser.add_argument(
        "--build",
        choices=["Debug", "Release"],
        default="Release",
        help="Build mode: Debug → Verbose=true, Release → Verbose=false (default: Release)",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    # Target
    goos = args.goos or ("windows" if platform.system() == "Windows" else "linux")
    goarch = args.goarch or "amd64"
    validate_target(goos, goarch)

    # Keys
    config_key = args.config_key or gen_config_key()
    data_key = args.data_key or gen_data_key()

    if args.data_key and (len(data_key) != 64 or not re.fullmatch(r"[0-9a-fA-F]+", data_key)):
        fail("--data-key must be exactly 64 hexadecimal characters")

    data_key = data_key.lower()

    # Summary
    print()
    log("=== GC2-sheet Builder ===")
    log(f"Target        : {goos}/{goarch}")
    log(f"Output        : {args.output}" + (".exe" if goos == "windows" else ""))
    log(f"Config key    : {config_key}")
    log(f"Data key      : {data_key}")
    print()

    # Preconditions
    if not OPTIONS_YML.exists():
        fail(f"Missing {OPTIONS_YML}")
    if not ROOT_GO.exists():
        fail(f"Missing {ROOT_GO}")
    if not CRYPTO_GO.exists():
        fail(f"Missing {CRYPTO_GO}")

    verbose = args.build == "Debug"
    log(f"Build mode    : {args.build} (Verbose={str(verbose).lower()})")
    patch_verbose(OPTIONS_YML, verbose)

    try:
        # Step 1: Encrypt config
        log("Step 1/4 – Encrypting options.yml …")
        encrypt_config(OPTIONS_YML, OPTIONS_ENC, config_key)

        # Step 2: Patch EncryptConfigKey
        log("Step 2/4 – Patching EncryptConfigKey in root.go …")
        patch_file(
            ROOT_GO,
            CONFIG_KEY_PATTERN,
            f'const EncryptConfigKey = "{config_key}"',
            "EncryptConfigKey",
        )

        # Step 3: Patch EncryptDataKey
        log("Step 3/4 – Patching EncryptDataKey in crypto.go …")
        patch_file(
            CRYPTO_GO,
            DATA_KEY_PATTERN,
            rf'\g<1>{data_key}\g<3>',
            "EncryptDataKey",
        )

        # Step 4: Build
        log("Step 4/4 – Compiling …")
        out_path = build_binary(goos, goarch, args.output)

        # Success
        print()
        log("========== BUILD SUCCESS ==========", "OK")
        log(f"Binary        : {out_path}")
        log(f"Size          : {out_path.stat().st_size / 1024:.1f} KB")
        log(f"Target        : {goos}/{goarch}")
        log(f"Config key    : {config_key}")
        log(f"Data key      : {data_key}")
        log(f"Build mode    : {args.build}")
        print()

    except Exception as e:
        fail(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()