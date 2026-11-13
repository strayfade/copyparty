# Encrypted folders

Password-protected folders ("vaults") encrypt a folder's entire contents at
rest: file data, file names, extensions, the directory tree, timestamps and
sizes. Entering the folder requires its password.

Enable the feature with `--enc` (it is off by default):

```sh
copyparty -v /mnt/Storage2::A --enc
```

Optional tuning:

| flag | default | meaning |
|---|---|---|
| `--enc-idle SEC` | `300` | auto-lock a folder after this much inactivity |
| `--enc-kdf MIB` | `256` | Argon2id memory cost when a folder is created |

The `cryptography` and `argon2-cffi` Python modules are required; the `-ac`
docker image already provides them.

## Using it

Right-click a folder:

* **Encrypt Folder…** – choose a password (min 8 chars). All files are moved
  into the vault; the plaintext originals are removed after the encrypted
  index is safely written. A progress dialog tracks the job.
* **Unlock Folder…** – asks for the password and opens the folder.
* **Lock Folder Now** – drops the key immediately.
* **Remove Password…** – asks for the password and decrypts everything back to
  normal files. This is the only operation that writes plaintext to disk.

While unlocked, files stream out decrypted on the fly (including HTTP range
requests, so audio/video seeking works), uploads are encrypted as they arrive,
and new folders can be created. The lock badge in the toolbar shows the state;
the folder locks itself after `--enc-idle` seconds without access.

There is **no password recovery**. Losing the password loses the folder.

## How it works

```
photos/
  .cpp_enc/
    meta.json     Argon2id parameters, salt, password-wrapped vault key
    index.enc     AES-256-GCM encrypted tree: names, sizes, mtimes
    d/<id>        one encrypted blob per file, opaque name, padded size
```

- A random 32-byte **vault key** is generated per folder. The password never
  encrypts files directly; Argon2id (memory-hard, 256 MiB by default) derives a
  key-encryption-key that wraps the vault key. Changing the password would only
  re-wrap 32 bytes.
- Every file gets its own key via HKDF from the vault key and a random file id.
  Content is split into 1 MiB chunks, each sealed with AES-256-GCM using the
  chunk index as nonce. The authenticated data binds the blob header, the chunk
  index and the file id, so tampering, truncation, reordering and chunk-swapping
  are all detected.
- Plaintext is padded to coarse size buckets (plus random jitter) before
  encryption; the real size lives only in the encrypted index. On-disk blob
  sizes are therefore approximate, not exact.
- The directory tree, including original names, extensions and mtimes, exists
  only inside `index.enc`. On disk every file is an extensionless id.
- The password and the keys are never written to disk. Unlocking keeps the key
  in server memory for the idle window, bound to the logged-in user and a
  cookie (`cppwenc`, HttpOnly). A server restart locks every folder.
- Unlock attempts are rate-limited, and passwords are redacted from the request
  log.

This is at-rest encryption: a stolen disk, a copied backup or a snapshot only
contains ciphertext. While a folder is unlocked, the server process holds the
key in RAM, so someone with root on the *running* machine can read what is
being served (as with any server-side encryption). Only the web UI can browse a
vault; WebDAV/FTP/SFTP/SMB see the folder as empty, and search/thumbnails inside
vaults are limited to what the web UI generates on the fly.

Encryption requires a single-process server (`--workers 1`); the feature is
disabled with a warning otherwise.

## Operations

- Back up the whole folder as usual; `.cpp_enc` is self-contained. Restoring
  the folder restores the vault.
- `meta.json` is the only readable file and reveals only that the folder is a
  vault (salt, KDF parameters, wrapped key).
- If the server dies during encryption, the plaintext originals are still
  intact until the encrypted index has been committed; a partial vault is
  detected and rolled back on next access. If it dies during **Remove
  Password**, some plaintext files may already exist next to the vault; run
  Remove Password again with the same password to finish.
- Deleting a vault folder through the normal UI deletes its ciphertext.
