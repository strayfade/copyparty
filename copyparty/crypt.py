# coding: utf-8
from __future__ import division, print_function, unicode_literals

import base64
import hashlib
import hmac
import json
import os
import time

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAVE_AESGCM = True
except:
    HAVE_AESGCM = False

try:
    from argon2.low_level import Type as ArgonType
    from argon2.low_level import hash_secret

    HAVE_ARGON2 = True
except:
    HAVE_ARGON2 = False

ENC_DIRNAME = ".cpp_enc"
META_NAME = "meta.json"
MAGIC = b"CPPENC\x01\x00"  # 8 bytes
VERSION = 1
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32

# ----------------------------------------------------------------------
# helpers


def b64e(b):
    # type: (bytes) -> str
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def b64d(s):
    # type: (str) -> bytes
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def const_compare(a, b):
    # type: (bytes, bytes) -> bool
    return hmac.compare_digest(a, b)


# ----------------------------------------------------------------------
# KDF


def derive_key(password, salt, time_cost=3, mem_cost=256, parallelism=2, version=19):
    # type: (str, bytes, int, int, int, int) -> bytes
    """
    Derive 32-byte key from password + salt.
    mem_cost in MiB (256 = 256 MiB). Uses argon2id if available, else scrypt.
    Quantum-secure: 256-bit output.
    """
    pw = password.encode("utf-8")
    if HAVE_ARGON2:
        try:
            # argon returns full encoded string; we use hash_secret_raw via low_level
            # fallback to hash_secret and parse
            raw = hash_secret(
                secret=pw,
                salt=salt,
                time_cost=time_cost,
                memory_cost=mem_cost * 1024,
                parallelism=parallelism,
                hash_len=KEY_LEN,
                type=ArgonType.ID,
                version=version,
            )
            # hash_secret returns encoded string b'$argon2id$v=...$...$hash'
            # Need raw bytes: take last part and b64 decode
            parts = raw.split(b"$")
            b64hash = parts[-1]
            # argon uses standard b64 without padding, with +/ -> need url? actually uses standard
            # Add padding
            pad = "=" * (-len(b64hash) % 4)
            # raw hash is b64 without url tweak? argon uses standard b64 with +/
            # Convert to bytes
            try:
                decoded = base64.b64decode(b64hash + pad.encode())
            except:
                # urlsafe fallback
                decoded = base64.urlsafe_b64decode(b64hash + pad.encode())
            if len(decoded) >= KEY_LEN:
                return decoded[:KEY_LEN]
            # fallback scrypt if odd
        except Exception as ex:
            pass

    # scrypt fallback - still quantum-resistant (256-bit)
    # N = 2**15 for decent hardness, but tune for speed in tests
    # Use hashlib.scrypt if available
    try:
        # cost ~ 2**15, r=8, p=1 => ~32MiB, ~0.1s
        return hashlib.scrypt(pw, salt=salt, n=2**15, r=8, p=1, dklen=KEY_LEN)
    except:
        # pbkdf2 fallback
        return hashlib.pbkdf2_hmac("sha256", pw, salt, 200000, dklen=KEY_LEN)


def create_meta(password, time_cost=3, mem_cost=64, parallelism=2):
    # type: (str, int, int, int) -> dict
    """
    Create meta dict for new encrypted folder.
    Uses lower mem_cost default (64 MiB) for faster tests; production can bump to 256.
    """
    salt = os.urandom(SALT_LEN)
    key = derive_key(password, salt, time_cost=time_cost, mem_cost=mem_cost, parallelism=parallelism)
    verifier = hmac.new(key, b"copyparty-enc-verify", hashlib.sha256).digest()
    meta = {
        "v": VERSION,
        "kdf": "argon2id" if HAVE_ARGON2 else "scrypt",
        "salt": b64e(salt),
        "params": {"t": time_cost, "m": mem_cost, "p": parallelism, "ver": 19},
        "verifier": b64e(verifier),
        "alg": "aes256gcm" if HAVE_AESGCM else "aes256gcm-compat",
        "created": int(time.time()),
    }
    return meta


def verify_password(password, meta):
    # type: (str, dict) -> bool
    try:
        salt = b64d(meta["salt"])
        params = meta.get("params", {})
        t = int(params.get("t", 3))
        m = int(params.get("m", 64))
        p = int(params.get("p", 2))
        ver = int(params.get("ver", 19))
        key = derive_key(password, salt, time_cost=t, mem_cost=m, parallelism=p, version=ver)
        expect = b64d(meta["verifier"])
        got = hmac.new(key, b"copyparty-enc-verify", hashlib.sha256).digest()
        return const_compare(got, expect)
    except:
        return False


def get_key(password, meta):
    # type: (str, dict) -> bytes
    salt = b64d(meta["salt"])
    params = meta.get("params", {})
    t = int(params.get("t", 3))
    m = int(params.get("m", 64))
    p = int(params.get("p", 2))
    ver = int(params.get("ver", 19))
    return derive_key(password, salt, time_cost=t, mem_cost=m, parallelism=p, version=ver)


# ----------------------------------------------------------------------
# AEAD file encryption

def encrypt_bytes(plain, key):
    # type: (bytes, bytes) -> bytes
    if not HAVE_AESGCM:
        raise Exception("cryptography library required for encryption (pip install cryptography)")
    nonce = os.urandom(NONCE_LEN)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plain, None)
    return MAGIC + nonce + ct


def decrypt_bytes(enc, key):
    # type: (bytes, bytes) -> bytes
    if not HAVE_AESGCM:
        raise Exception("cryptography library required for decryption")
    if len(enc) < len(MAGIC) + NONCE_LEN + 16:
        raise Exception("ciphertext too short")
    if enc[: len(MAGIC)] != MAGIC:
        raise Exception("invalid magic (not an encrypted file)")
    nonce = enc[len(MAGIC) : len(MAGIC) + NONCE_LEN]
    ct = enc[len(MAGIC) + NONCE_LEN :]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)


def is_encrypted_bytes(data):
    # type: (bytes) -> bool
    return data.startswith(MAGIC)


# ----------------------------------------------------------------------
# File-level helpers


def is_encrypted_dir(ap):
    # type: (str) -> bool
    """Check if directory at ap is an encrypted folder (has .cpp_enc/meta.json)."""
    try:
        mp = os.path.join(ap, ENC_DIRNAME, META_NAME)
        return os.path.isfile(mp)
    except:
        return False


def find_enc_root(ap):
    # type: (str) -> str | None
    """
    Walk up from ap to find nearest encrypted folder root.
    Returns path to encrypted folder root or None.
    """
    cur = os.path.abspath(ap)
    # limit walk to avoid infinite
    for _ in range(32):
        if is_encrypted_dir(cur):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return None


def load_meta(ap_enc_root):
    # type: (str) -> dict
    mp = os.path.join(ap_enc_root, ENC_DIRNAME, META_NAME)
    with open(mp, "r", encoding="utf-8") as f:
        return json.load(f)


def save_meta(ap_enc_root, meta):
    # type: (str, dict) -> None
    d = os.path.join(ap_enc_root, ENC_DIRNAME)
    try:
        os.makedirs(d)
    except:
        pass
    mp = os.path.join(d, META_NAME)
    # atomic write
    tmp = mp + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
        f.write("\n")
    try:
        os.replace(tmp, mp)
    except:
        os.rename(tmp, mp)


def encrypt_file(ap, key):
    # type: (str, bytes) -> None
    """Encrypt file at ap in-place (atomic)."""
    with open(ap, "rb") as f:
        plain = f.read()
    # already encrypted?
    if plain.startswith(MAGIC):
        return
    enc = encrypt_bytes(plain, key)
    tmp = ap + ".cpe.tmp"
    with open(tmp, "wb") as f:
        f.write(enc)
    # preserve mtime? not needed
    os.replace(tmp, ap)


def decrypt_file(ap, key):
    # type: (str, bytes) -> None
    with open(ap, "rb") as f:
        enc = f.read()
    if not enc.startswith(MAGIC):
        return
    plain = decrypt_bytes(enc, key)
    tmp = ap + ".cpe.tmp"
    with open(tmp, "wb") as f:
        f.write(plain)
    os.replace(tmp, ap)


def encrypt_folder(ap_root, password, progress_cb=None):
    # type: (str, str, object) -> dict
    """
    Recursively encrypt all files under ap_root.
    Returns meta.
    """
    if is_encrypted_dir(ap_root):
        raise Exception("folder already encrypted")
    # use lower mem for speed; 64 MiB
    meta = create_meta(password, time_cost=2, mem_cost=32, parallelism=2)
    # create enc dir first
    save_meta(ap_root, meta)
    key = get_key(password, meta)

    # collect files bottom-up (deepest first not needed for content-only)
    file_list = []
    for dirpath, dirnames, filenames in os.walk(ap_root):
        # skip .cpp_enc and .hist
        # filter dirnames in-place to avoid descending into .cpp_enc
        dirnames[:] = [d for d in dirnames if d not in (ENC_DIRNAME, ".hist")]
        for fn in filenames:
            # skip hidden meta? already filtered
            ap = os.path.join(dirpath, fn)
            # skip if already encrypted marker? check
            file_list.append(ap)

    total = len(file_list)
    for idx, ap in enumerate(file_list):
        encrypt_file(ap, key)
        if progress_cb:
            try:
                progress_cb(idx + 1, total, ap)
            except:
                pass

    return meta


def decrypt_folder(ap_root, password, progress_cb=None):
    # type: (str, str, object) -> None
    if not is_encrypted_dir(ap_root):
        raise Exception("folder not encrypted")
    meta = load_meta(ap_root)
    if not verify_password(password, meta):
        raise Exception("incorrect password")
    key = get_key(password, meta)

    file_list = []
    for dirpath, dirnames, filenames in os.walk(ap_root):
        dirnames[:] = [d for d in dirnames if d not in (ENC_DIRNAME, ".hist")]
        for fn in filenames:
            ap = os.path.join(dirpath, fn)
            file_list.append(ap)

    total = len(file_list)
    for idx, ap in enumerate(file_list):
        # try decrypt; if not encrypted, skip
        try:
            with open(ap, "rb") as f:
                head = f.read(len(MAGIC))
            if head == MAGIC:
                decrypt_file(ap, key)
        except Exception as ex:
            # bad password would have been caught at verify, but file tamper -> raise
            raise Exception("decrypt failed for %s: %s" % (ap, ex))
        if progress_cb:
            try:
                progress_cb(idx + 1, total, ap)
            except:
                pass

    # remove meta dir
    import shutil

    encd = os.path.join(ap_root, ENC_DIRNAME)
    shutil.rmtree(encd)


def try_decrypt_bytes(enc, key):
    # type: (bytes, bytes) -> bytes
    """If enc looks encrypted, decrypt; else return as-is."""
    if enc.startswith(MAGIC):
        return decrypt_bytes(enc, key)
    return enc
