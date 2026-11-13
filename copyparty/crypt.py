# coding: utf-8
"""
Password-protected (encrypted) folders for copyparty.

Design
------
Everything about a folder's contents is hidden on disk:

  folder/
    .cpp_enc/
      meta.json      password-wrapped vault key + KDF params (the only plaintext)
      index.enc      AES-256-GCM encrypted tree: names, sizes, mtimes, parents
      d/<id>         one AES-256-GCM blob per file, opaque name, padded size
      tmp/           in-flight job data, cleared on startup

The vault key (VK) is random per folder and wrapped with an Argon2id-derived
key-encryption-key, so changing the password later only rewraps 32 bytes.
Files are split into 1 MiB chunks, each authenticated (AAD binds the header,
the chunk index and the per-file key) which makes truncation, reordering and
chunk-swapping detectable. Plaintext sizes are padded to coarse buckets and
only stored inside the encrypted index, so on-disk blob sizes are approximate.

Nothing here ever writes plaintext to disk; the server decrypts per request.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import shutil
import stat as statmod
import struct
import threading
import time

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    HAVE_AESGCM = True
except Exception:
    HAVE_AESGCM = False

try:
    from argon2.low_level import Type as ArgonType
    from argon2.low_level import hash_secret_raw

    HAVE_ARGON2 = True
except Exception:
    HAVE_ARGON2 = False


DIRNAME = ".cpp_enc"
META_NAME = "meta.json"
INDEX_NAME = "index.enc"
DATA_DIR = "d"
TMP_DIR = "tmp"
CLEANUP_NAME = "cleanup.json"

VERSION = 2
MAGIC = b"CPPENC2\n"
INDEX_MAGIC = b"CPPIDX2\n"
CHUNK = 1 << 20
KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
HEADER_LEN = len(MAGIC) + 2 + 4 + 4 + 8 + 16  # 42

AAD_WRAP = b"cppenc-v2-wrap"
AAD_INDEX = b"cppenc-v2-index"
AAD_VERIFY = b"cppenc-v2-verify"
AAD_FILE = b"cppenc-v2-file"

DEFAULT_T = 3
DEFAULT_M = 262144  # KiB == 256 MiB
DEFAULT_P = 4
DEFAULT_IDLE = 300

# sanity limits for values read back from meta.json (untrusted input)
MAX_M = 1 << 20  # 1 GiB in KiB
MAX_T = 16
MAX_P = 32


class CryptError(Exception):
    pass


class BadPassword(CryptError):
    pass


class NotVault(CryptError):
    pass


class VaultBusy(CryptError):
    pass


class VaultBroken(CryptError):
    pass


# ----------------------------------------------------------------------
# small helpers


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def have_crypto() -> bool:
    return HAVE_AESGCM and HAVE_ARGON2


def const_compare(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def _hkdf(key: bytes, info: bytes, n: int = KEY_LEN) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(algorithm=hashes.SHA256(), length=n, salt=None, info=info).derive(key)


def file_key(vk: bytes, fid: str) -> bytes:
    return _hkdf(vk, AAD_FILE + fid.encode("ascii"))


def index_key(vk: bytes) -> bytes:
    return _hkdf(vk, AAD_INDEX)


def _aead(key: bytes):
    return AESGCM(key)


def new_id() -> str:
    return secrets.token_hex(16)


def pad_len(n: int) -> int:
    """size bucket + random jitter; hides the exact plaintext size"""
    if n <= 0:
        step = 4096
        base = 4096
    else:
        nxt = 1 << (n - 1).bit_length()
        step = max(4096, min(nxt >> 5, 64 << 20))
        base = ((n + step - 1) // step) * step
        if base == n:
            base += step
    jitter = int.from_bytes(os.urandom(2), "big") % (step // 4 + 1)
    return base + jitter


def blob_path(root: str, fid: str) -> str:
    return os.path.join(root, DIRNAME, DATA_DIR, fid)


def _fsync_dir(path: str) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except Exception:
        return
    try:
        os.fsync(fd)
    except Exception:
        pass
    finally:
        os.close(fd)


def _atomic_write(path: str, data: bytes, mode: int = 0o600) -> None:
    tmp = path + ".tmp" + secrets.token_hex(4)
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        try:
            os.fsync(f.fileno())
        except Exception:
            pass
    try:
        os.chmod(tmp, mode)
    except Exception:
        pass
    os.replace(tmp, path)
    _fsync_dir(os.path.dirname(path))


# ----------------------------------------------------------------------
# meta.json / key wrapping


def _clean_int(v, default: int, hi: int) -> int:
    try:
        v = int(v)
    except Exception:
        return default
    return max(1, min(hi, v))


def derive_kek(password: str, salt: bytes, t: int, m: int, p: int) -> bytes:
    if not HAVE_ARGON2:
        raise CryptError("argon2-cffi is required for folder encryption")
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=_clean_int(t, DEFAULT_T, MAX_T),
        memory_cost=_clean_int(m, DEFAULT_M, MAX_M),
        parallelism=_clean_int(p, DEFAULT_P, MAX_P),
        hash_len=KEY_LEN,
        type=ArgonType.ID,
        version=19,
    )


def is_vault(root: str) -> bool:
    try:
        return os.path.isfile(os.path.join(root, DIRNAME, META_NAME))
    except Exception:
        return False


def find_vault_root(path: str, max_up: int = 64) -> str | None:
    """walk up from path to the nearest folder with .cpp_enc/meta.json"""
    try:
        cur = os.path.abspath(path)
        if not os.path.isdir(cur):
            cur = os.path.dirname(cur)
        for _ in range(max_up):
            if is_vault(cur):
                return cur
            parent = os.path.dirname(cur)
            if parent == cur:
                break
            cur = parent
    except Exception:
        pass
    return None


def load_meta(root: str) -> dict:
    try:
        with open(os.path.join(root, DIRNAME, META_NAME), "r", encoding="utf-8") as f:
            meta = json.load(f)
    except Exception as ex:
        raise VaultBroken("cannot read vault metadata: %s" % (ex,))
    if int(meta.get("v", 0)) != VERSION:
        raise VaultBroken("unsupported vault version %r" % (meta.get("v"),))
    return meta


def save_meta(root: str, meta: dict) -> None:
    d = os.path.join(root, DIRNAME)
    os.makedirs(d, exist_ok=True)
    data = json.dumps(meta, indent=1, sort_keys=True).encode("utf-8")
    _atomic_write(os.path.join(d, META_NAME), data, 0o600)


def new_meta(password: str, t: int, m: int, p: int) -> tuple[dict, bytes]:
    if not HAVE_AESGCM:
        raise CryptError("the cryptography module is required for folder encryption")
    salt = os.urandom(SALT_LEN)
    vk = os.urandom(KEY_LEN)
    kek = derive_kek(password, salt, t, m, p)
    nonce = os.urandom(NONCE_LEN)
    wrapped = _aead(kek).encrypt(nonce, vk, AAD_WRAP)
    meta = {
        "v": VERSION,
        "kdf": "argon2id",
        "t": t,
        "m": m,
        "p": p,
        "salt": b64e(salt),
        "wrap": b64e(nonce + wrapped),
        "verifier": b64e(hmac.new(vk, AAD_VERIFY, hashlib.sha256).digest()),
        "state": "locked",
        "created": int(time.time()),
    }
    return meta, vk


def unwrap_vk(password: str, meta: dict) -> bytes:
    if not HAVE_AESGCM:
        raise CryptError("the cryptography module is required for folder encryption")
    try:
        salt = b64d(meta["salt"])
        blob = b64d(meta["wrap"])
        kek = derive_kek(password, salt, meta.get("t"), meta.get("m"), meta.get("p"))
        vk = _aead(kek).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], AAD_WRAP)
    except BadPassword:
        raise
    except Exception:
        raise BadPassword("incorrect password")
    want = b64d(meta.get("verifier", ""))
    got = hmac.new(vk, AAD_VERIFY, hashlib.sha256).digest()
    if not const_compare(got, want):
        raise BadPassword("incorrect password")
    return vk


def unlock(root: str, password: str, allow: tuple = ("locked", None)) -> tuple[bytes, dict]:
    meta = load_meta(root)
    if meta.get("state") not in allow:
        raise VaultBroken("vault is busy (%s)" % (meta.get("state"),))
    return unwrap_vk(password, meta), meta

def verify_password(root: str, password: str) -> bool:
    try:
        unlock(root, password)
        return True
    except Exception:
        return False


# ----------------------------------------------------------------------
# encrypted index


def _check_name(name) -> None:
    if not isinstance(name, str) or not name or name in (".", ".."):
        raise CryptError("invalid file name in vault")
    if "/" in name or "\\" in name or "\x00" in name:
        raise CryptError("invalid file name in vault")


class Index:
    """the folder tree; every id maps to a file or dir entry"""

    def __init__(self) -> None:
        self.e: dict[str, dict] = {}
    # -- lookups
    def get(self, fid: str) -> dict | None:
        return self.e.get(fid)

    def children(self, pid: str) -> tuple[list[str], list[str]]:
        dirs = []
        files = []
        for fid, ent in self.e.items():
            if ent.get("p", "") != pid:
                continue
            if ent.get("t") == "d":
                dirs.append(fid)
            else:
                files.append(fid)
        dirs.sort(key=lambda x: self.e[x]["n"].lower())
        files.sort(key=lambda x: self.e[x]["n"].lower())
        return dirs, files

    def lookup(self, pid: str, name: str) -> str | None:
        for fid, ent in self.e.items():
            if ent.get("p", "") == pid and ent.get("n") == name:
                return fid
        return None

    def trail(self, fid: str) -> list[tuple[str, str]]:
        """[(fid,name), ...] from root down to fid (exclusive of root)"""
        out = []
        seen = set()
        for _ in range(4096):
            if not fid or fid in seen:
                break
            seen.add(fid)
            ent = self.e.get(fid)
            if not ent:
                break
            out.append((fid, ent["n"]))
            fid = ent.get("p", "")
        out.reverse()
        return out

    # -- mutations
    def add(self, pid: str, name: str, typ: str, sz: int = 0, mt: int = 0) -> str:
        _check_name(name)
        fid = new_id()
        while fid in self.e:
            fid = new_id()
        self.e[fid] = {"n": name, "t": typ, "p": pid, "sz": int(sz), "mt": int(mt)}
        return fid

    def rename(self, fid: str, name: str) -> None:
        _check_name(name)
        ent = self.e.get(fid)
        if not ent:
            raise CryptError("no such entry")
        ent["n"] = name

    def remove(self, fid: str) -> list[str]:
        """delete entry and all children (for dirs); returns all removed ids"""
        out = []
        stack = [fid]
        while stack:
            cur = stack.pop()
            if cur not in self.e:
                continue
            out.append(cur)
            stack.extend(
                x for x, ent in self.e.items() if ent.get("p", "") == cur
            )
        for x in out:
            self.e.pop(x, None)
        return out

    def all_ids(self, fid: str) -> list[str]:
        out = []
        stack = [fid]
        while stack:
            cur = stack.pop()
            ent = self.e.get(cur)
            if not ent:
                continue
            out.append(cur)
            if ent.get("t") == "d":
                stack.extend(x for x, e2 in self.e.items() if e2.get("p", "") == cur)
        return out

    # -- serialization
    def dumps(self) -> bytes:
        return json.dumps({"v": VERSION, "e": self.e}, separators=(",", ":")).encode(
            "utf-8"
        )

    @classmethod
    def loads(cls, data: bytes) -> "Index":
        obj = json.loads(data.decode("utf-8"))
        if int(obj.get("v", 0)) != VERSION:
            raise VaultBroken("unsupported index version")
        idx = cls()
        idx.e = obj["e"]
        for fid, ent in idx.e.items():
            _check_name(ent.get("n"))
            if ent.get("t") not in ("f", "d"):
                raise VaultBroken("invalid vault index entry")
        return idx


def index_path(root: str) -> str:
    return os.path.join(root, DIRNAME, INDEX_NAME)


def save_index(root: str, vk: bytes, idx: Index) -> None:
    nonce = os.urandom(NONCE_LEN)
    ct = _aead(index_key(vk)).encrypt(nonce, idx.dumps(), AAD_INDEX)
    _atomic_write(index_path(root), INDEX_MAGIC + nonce + ct, 0o600)


def load_index(root: str, vk: bytes) -> Index:
    try:
        with open(index_path(root), "rb") as f:
            blob = f.read()
    except FileNotFoundError:
        raise VaultBroken("vault index is missing")
    if not blob.startswith(INDEX_MAGIC):
        raise VaultBroken("vault index is damaged")
    blob = blob[len(INDEX_MAGIC) :]
    try:
        pt = _aead(index_key(vk)).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], AAD_INDEX)
    except Exception:
        raise VaultBroken("vault index failed authentication")
    return Index.loads(pt)


# ----------------------------------------------------------------------
# file blobs


def _header(fid: str, chunk: int, nchunks: int, padded: int) -> bytes:
    return MAGIC + struct.pack(">HIIQ", VERSION, chunk, nchunks, padded) + bytes.fromhex(
        fid
    )


def _parse_header(head: bytes) -> tuple[int, int, int, str]:
    if len(head) != HEADER_LEN or not head.startswith(MAGIC):
        raise CryptError("not an encrypted file")
    ver, chunk, nchunks, padded, fidb = struct.unpack(">HIIQ16s", head[len(MAGIC) :])
    if ver != VERSION or chunk < 4096 or chunk > (64 << 20) or nchunks < 1:
        raise CryptError("unsupported encrypted file")
    return chunk, nchunks, padded, fidb.hex()


def encrypt_stream(src, dst, vk: bytes, fid: str, real_sz: int, prog=None) -> int:
    """encrypt exactly real_sz bytes from src into dst; returns padded size"""
    padded = pad_len(real_sz)
    nchunks = (padded + CHUNK - 1) // CHUNK
    head = _header(fid, CHUNK, nchunks, padded)
    dst.write(head)
    aead = _aead(file_key(vk, fid))
    done = 0
    read = 0
    for i in range(nchunks):
        n = min(CHUNK, padded - i * CHUNK)
        real = max(0, min(n, real_sz - read))
        buf = src.read(real)
        if len(buf) != real:
            raise CryptError("input ended early (wanted %d, got %d)" % (real, len(buf)))
        read += real
        if real < n:
            buf += os.urandom(n - real)
        nonce = struct.pack(">I", 0) + struct.pack(">Q", i)
        ct = aead.encrypt(nonce, buf, head + struct.pack(">Q", i))
        dst.write(ct)
        done += n
        if prog:
            prog(real)
    if read != real_sz:
        raise CryptError("input longer than expected")
    return padded


def encrypt_file(src: str, dst: str, vk: bytes, fid: str, real_sz: int, prog=None) -> int:
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        padded = encrypt_stream(fi, fo, vk, fid, real_sz, prog)
        fo.flush()
        try:
            os.fsync(fo.fileno())
        except Exception:
            pass
    os.chmod(dst, 0o600)
    return padded


def _read_header(path: str) -> tuple[int, int, int, str, int]:
    with open(path, "rb") as f:
        head = f.read(HEADER_LEN)
    chunk, nchunks, padded, fid = _parse_header(head)
    return chunk, nchunks, padded, fid, os.path.getsize(path)


def file_size(root: str, fid: str) -> int:
    """padded plaintext size (content length of the blob)"""
    _, _, padded, _, _ = _read_header(blob_path(root, fid))
    return padded


def iter_decrypt(
    root: str, fid: str, vk: bytes, real_sz: int, off: int = 0, length: int | None = None
):
    """yield plaintext bytes [off, off+length) of an encrypted file"""
    path = blob_path(root, fid)
    chunk, nchunks, padded, fid2, fsz = _read_header(path)
    if fid2 != fid:
        raise CryptError("vault index and blob disagree about file id")
    if real_sz > padded:
        raise CryptError("index size exceeds encrypted size")
    if length is None:
        length = max(0, real_sz - off)
    if off < 0 or length < 0 or off + length > real_sz:
        raise CryptError("range outside file")
    if not length:
        return
    aead = _aead(file_key(vk, fid))
    head = _header(fid, chunk, nchunks, padded)
    first = off // chunk
    last = (off + length - 1) // chunk
    pos = HEADER_LEN + first * (chunk + TAG_LEN)
    with open(path, "rb") as f:
        f.seek(pos)
        for i in range(first, last + 1):
            clen = min(chunk, padded - i * chunk)
            blob = f.read(clen + TAG_LEN)
            if len(blob) != clen + TAG_LEN:
                raise CryptError("encrypted file is truncated")
            nonce = struct.pack(">I", 0) + struct.pack(">Q", i)
            try:
                pt = aead.decrypt(nonce, blob, head + struct.pack(">Q", i))
            except Exception:
                raise CryptError("encrypted file failed authentication")
            base = i * chunk
            lo = max(off, base)
            hi = min(off + length, base + clen, real_sz)
            if hi > lo:
                yield pt[lo - base : hi - base]


def decrypt_file(
    root: str, fid: str, vk: bytes, real_sz: int, dst_path: str, prog=None
) -> None:
    tmp = dst_path + ".cppdec.tmp"
    with open(tmp, "wb") as f:
        for buf in iter_decrypt(root, fid, vk, real_sz):
            f.write(buf)
            if prog:
                prog(len(buf))
        f.flush()
        try:
            os.fsync(f.fileno())
        except Exception:
            pass
    os.replace(tmp, dst_path)


# ----------------------------------------------------------------------
# vault lifecycle


def _walk_files(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(x for x in dirnames if x not in (DIRNAME, ".hist"))
        for fn in sorted(filenames):
            ap = os.path.join(dirpath, fn)
            try:
                st = os.lstat(ap)
            except Exception:
                continue
            if statmod.S_ISLNK(st.st_mode):
                raise CryptError("folders containing symlinks cannot be encrypted")
            if statmod.S_ISREG(st.st_mode):
                yield ap, st
            # sockets/fifos are left alone


def _nested_vaults(root: str) -> list[str]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        if os.path.abspath(dirpath) != os.path.abspath(root) and DIRNAME in dirnames:
            out.append(dirpath)
        dirnames[:] = [x for x in dirnames if x not in (".hist",) and x != DIRNAME]
    return out


def encrypt_folder(
    root: str,
    password: str,
    prog=None,
    cancel=None,
    t=DEFAULT_T,
    m=DEFAULT_M,
    p=DEFAULT_P,
    purge_cb=None,
) -> dict:
    """turn a normal folder into a vault; safe to interrupt before index commit"""
    if not have_crypto():
        raise CryptError("server is missing cryptography/argon2 support")
    root = os.path.abspath(root)
    if is_vault(root):
        raise CryptError("folder is already encrypted")
    if find_vault_root(os.path.dirname(root)):
        raise CryptError("cannot encrypt a folder inside an encrypted folder")
    if _nested_vaults(root):
        raise CryptError("cannot encrypt a folder containing an encrypted folder")

    meta, vk = new_meta(password, t, m, p)
    meta["state"] = "encrypting"
    ed = os.path.join(root, DIRNAME)
    os.makedirs(os.path.join(ed, DATA_DIR), exist_ok=True)
    os.makedirs(os.path.join(ed, TMP_DIR), exist_ok=True)
    save_meta(root, meta)

    idx = Index()
    dir_ids = {"": ""}
    files = list(_walk_files(root))
    total = sum(st.st_size for _, st in files)
    if prog:
        prog(0, total, 0, len(files))

    done_b = 0
    done_f = 0
    cleanup: list[str] = []
    try:
        # create dir entries first so the tree is preserved
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(x for x in dirnames if x not in (DIRNAME, ".hist"))
            rel = os.path.relpath(dirpath, root)
            rel = "" if rel == "." else rel.replace(os.sep, "/")
            pid = dir_ids.get(rel, "")
            for dn in dirnames:
                r2 = dn if not rel else rel + "/" + dn
                try:
                    dmt = int(os.stat(os.path.join(dirpath, dn)).st_mtime)
                except Exception:
                    dmt = int(time.time())
                dir_ids[r2] = idx.add(pid, dn, "d", 0, dmt)

        for ap, st in files:
            if cancel and cancel.is_set():
                raise CryptError("cancelled")
            rel = os.path.relpath(ap, root).replace(os.sep, "/")
            rd, fn = rel.rsplit("/", 1) if "/" in rel else ("", rel)
            pid = dir_ids.get(rd, "")
            fid = new_id()
            while fid in idx.e:
                fid = new_id()
            tmp = os.path.join(ed, TMP_DIR, fid)
            _check_name(fn)
            idx.e[fid] = {"n": fn, "t": "f", "p": pid, "sz": int(st.st_size), "mt": int(st.st_mtime)}
            encrypt_file(ap, tmp, vk, fid, int(st.st_size), None)
            os.replace(tmp, blob_path(root, fid))
            if purge_cb:
                try:
                    purge_cb(rel, int(st.st_mtime))
                except Exception:
                    pass
            cleanup.append(rel)
            done_b += st.st_size
            done_f += 1
            if prog:
                prog(done_b, total, done_f, len(files))

        save_index(root, vk, idx)
        _fsync_dir(os.path.join(ed, DATA_DIR))
        # originals are only removed once the index above is durable
        _atomic_write(
            os.path.join(ed, TMP_DIR, CLEANUP_NAME),
            json.dumps(cleanup).encode("utf-8"),
            0o600,
        )
        for rel in cleanup:
            try:
                os.unlink(os.path.join(root, rel))
            except Exception:
                pass
        _rmdirs(root)
        try:
            os.unlink(os.path.join(ed, TMP_DIR, CLEANUP_NAME))
        except Exception:
            pass
        meta["state"] = "locked"
        save_meta(root, meta)
    except Exception:
        # only roll back while the plaintext originals are intact
        if not os.path.isfile(index_path(root)):
            shutil.rmtree(ed, ignore_errors=True)
        raise
    return meta


def _rmdirs(root: str) -> None:
    for dirpath, dirnames, filenames in os.walk(root, topdown=False):
        if os.path.abspath(dirpath) == os.path.abspath(root):
            continue
        if DIRNAME in dirpath.split(os.sep):
            continue
        try:
            os.rmdir(dirpath)
        except Exception:
            pass


def remove_vault(root: str, password: str, prog=None, cancel=None) -> None:
    """permanently decrypt a vault back to a normal folder (needs the password)"""
    root = os.path.abspath(root)
    meta = load_meta(root)
    resume = meta.get("state") == "removing"
    vk = unwrap_vk(password, meta)
    idx = load_index(root, vk)
    meta["state"] = "removing"
    save_meta(root, meta)

    files = [x for x, e in idx.e.items() if e.get("t") == "f"]
    total = sum(int(idx.e[x].get("sz", 0)) for x in files)
    if prog:
        prog(0, total, 0, len(files))

    done_b = 0
    done_f = 0
    for fid in files:
        if cancel and cancel.is_set():
            raise CryptError("cancelled")
        ent = idx.e[fid]
        parts = [name for _, name in idx.trail(fid)]
        dst = os.path.join(root, *parts)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if os.path.exists(dst):
            if not resume:
                raise VaultBroken("refusing to overwrite %r" % (dst,))
            try:
                os.unlink(dst)
            except Exception:
                raise VaultBroken("cannot overwrite %r" % (dst,))
        decrypt_file(root, fid, vk, int(ent.get("sz", 0)), dst)
        try:
            os.utime(dst, (int(ent.get("mt", 0)), int(ent.get("mt", 0))))
        except Exception:
            pass
        done_b += int(ent.get("sz", 0))
        done_f += 1
        if prog:
            prog(done_b, total, done_f, len(files))

    # every plaintext file is safely on disk; dropping .cpp_enc completes the job
    shutil.rmtree(os.path.join(root, DIRNAME))
    _fsync_dir(root)


def recover(root: str) -> str:
    """finish/rollback an interrupted job without needing the password"""
    try:
        meta = load_meta(root)
    except Exception:
        return "broken"
    state = meta.get("state", "locked")
    ed = os.path.join(root, DIRNAME)
    if state == "encrypting":
        cp = os.path.join(ed, TMP_DIR, CLEANUP_NAME)
        if os.path.isfile(index_path(root)):
            # the index was committed, so every remaining file outside
            # .cpp_enc is an original that is now safely vaulted
            try:
                if os.path.isfile(cp):
                    with open(cp, "r", encoding="utf-8") as f:
                        for rel in json.load(f):
                            try:
                                os.unlink(os.path.join(root, rel))
                            except Exception:
                                pass
                    os.unlink(cp)
                else:
                    for dirpath, dirnames, filenames in os.walk(root):
                        dirnames[:] = [
                            x for x in dirnames if x not in (DIRNAME, ".hist")
                        ]
                        for fn in filenames:
                            try:
                                os.unlink(os.path.join(dirpath, fn))
                            except Exception:
                                pass
                _rmdirs(root)
                meta["state"] = "locked"
                save_meta(root, meta)
                return "recovered"
            except Exception:
                return "broken"
        shutil.rmtree(ed, ignore_errors=True)
        return "rolledback"
    if state == "removing":
        return "resume-remove"
    return "ok"


def vault_stats(root: str) -> dict:
    """cheap metadata for listings (no key needed)"""
    meta = load_meta(root)
    return {
        "state": meta.get("state", "locked"),
        "created": int(meta.get("created", 0)),
    }


# ----------------------------------------------------------------------
# in-memory unlocked sessions


class Vault:
    def __init__(self, root: str, vk: bytes, meta: dict, idx: Index) -> None:
        self.root = root
        self.vk = vk
        self.meta = meta
        self.idx = idx
        self.sig = _index_sig(root)
        self.last = time.time()

    def refresh(self) -> bool:
        sig = _index_sig(self.root)
        if sig != self.sig:
            self.idx = load_index(self.root, self.vk)
            self.sig = sig
            return True
        return False

    def drop(self) -> None:
        self.idx = Index()
        _wipe(self.vk)


def _index_sig(root: str) -> tuple:
    try:
        st = os.stat(index_path(root))
        return (st.st_mtime_ns, st.st_size)
    except Exception:
        return (0, 0)


def _wipe(buf) -> None:
    try:
        for i in range(len(buf)):
            buf[i] = 0
    except Exception:
        pass


class Sessions:
    """sid -> {uname, vaults: {root: Vault}}; all state is per-process RAM"""

    def __init__(self, idle: int = DEFAULT_IDLE) -> None:
        self.idle = max(15, int(idle))
        self.lock = threading.RLock()
        self.s: dict[str, dict] = {}

    @staticmethod
    def _key(root: str) -> str:
        return os.path.normcase(os.path.abspath(root))

    def new_sid(self, uname: str) -> str:
        sid = secrets.token_urlsafe(32)
        with self.lock:
            self.s[sid] = {"uname": uname, "vaults": {}}
        return sid

    def sid_ok(self, sid: str, uname: str) -> bool:
        with self.lock:
            s = self.s.get(sid)
            return bool(s and s["uname"] == uname)

    def put(
        self, sid: str, uname: str, vk: bytes, meta: dict, idx: Index, root: str
    ) -> tuple[str, Vault]:
        root = os.path.abspath(root)
        with self.lock:
            s = self.s.get(sid)
            if not s or s["uname"] != uname:
                sid = self.new_sid(uname)
                s = self.s[sid]
            v = Vault(root, vk, meta, idx)
            s["vaults"][self._key(root)] = v
            return sid, v

    def get(self, sid: str, uname: str, root: str) -> Vault | None:
        key = self._key(root)
        with self.lock:
            s = self.s.get(sid)
            if not s or s["uname"] != uname:
                return None
            v = s["vaults"].get(key)
            if not v:
                return None
            if time.time() - v.last > self.idle:
                s["vaults"].pop(key, None)
                v.drop()
                return None
            v.last = time.time()
            return v

    def drop(self, sid: str, root: str | None = None) -> None:
        with self.lock:
            s = self.s.get(sid)
            if not s:
                return
            if root:
                v = s["vaults"].pop(self._key(root), None)
                if v:
                    v.drop()
            else:
                for v in s["vaults"].values():
                    v.drop()
                self.s.pop(sid, None)

    def sweep(self) -> None:
        now = time.time()
        with self.lock:
            for sid in list(self.s):
                s = self.s[sid]
                for root in list(s["vaults"]):
                    v = s["vaults"][root]
                    if now - v.last > self.idle:
                        s["vaults"].pop(root, None)
                        v.drop()
                if not s["vaults"]:
                    self.s.pop(sid, None)


# one lock per vault path, so jobs and requests cannot interleave
_locks: dict[str, threading.RLock] = {}
_locks_guard = threading.Lock()


def vault_lock(root: str) -> threading.RLock:
    root = os.path.abspath(root)
    with _locks_guard:
        lock = _locks.get(root)
        if not lock:
            lock = _locks[root] = threading.RLock()
        return lock


# ----------------------------------------------------------------------
# background jobs


class Job:
    def __init__(self, kind: str, root: str) -> None:
        self.id = secrets.token_urlsafe(12)
        self.kind = kind
        self.root = root
        self.phase = "starting"
        self.done_b = 0
        self.total_b = 0
        self.done_f = 0
        self.total_f = 0
        self.error = ""
        self.started = time.time()
        self.done = False
        self.cancel = threading.Event()
        self.thread: threading.Thread | None = None

    def progress(self, db: int, tb: int, df: int, tf: int) -> None:
        self.done_b, self.total_b, self.done_f, self.total_f = db, tb, df, tf

    def json(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "phase": self.phase,
            "done_b": self.done_b,
            "total_b": self.total_b,
            "done_f": self.done_f,
            "total_f": self.total_f,
            "error": self.error,
            "done": self.done,
            "started": int(self.started),
        }


class Jobs:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.j: dict[str, Job] = {}

    def get(self, jid: str) -> Job | None:
        with self.lock:
            return self.j.get(jid)

    def for_root(self, root: str) -> Job | None:
        with self.lock:
            for job in self.j.values():
                if job.root == root and not job.done:
                    return job
            return None

    def start(
        self, kind: str, root: str, password: str, kdf_m: int = DEFAULT_M, purge_cb=None
    ) -> Job:
        root = os.path.abspath(root)
        with self.lock:
            for job in self.j.values():
                if job.root == root and not job.done:
                    raise VaultBusy("another job is already running for this folder")
            job = Job(kind, root)
            self.j[job.id] = job
            # keep the table small
            if len(self.j) > 64:
                for k in sorted(self.j, key=lambda x: self.j[x].started)[:16]:
                    if self.j[k].done:
                        self.j.pop(k, None)

        def run() -> None:
            lock = vault_lock(root)
            with lock:
                if kind == "encrypt":
                    job.phase = "encrypting"
                    try:
                        encrypt_folder(
                            root, password, job.progress, job.cancel, m=kdf_m, purge_cb=purge_cb
                        )
                        job.phase = "done"
                    except Exception as ex:
                        job.error = str(ex)
                        job.phase = "failed"
                elif kind == "remove":
                    job.phase = "decrypting"
                    try:
                        remove_vault(root, password, job.progress, job.cancel)
                        job.phase = "done"
                    except Exception as ex:
                        job.error = str(ex)
                        job.phase = "failed"
                else:
                    job.error = "unknown job"
                    job.phase = "failed"
                job.done = True

        th = threading.Thread(target=run, name="cpp-enc-" + kind)
        th.daemon = True
        job.thread = th
        th.start()
        return job


def clear_tmp(root: str) -> None:
    try:
        shutil.rmtree(os.path.join(root, DIRNAME, TMP_DIR))
    except Exception:
        pass
