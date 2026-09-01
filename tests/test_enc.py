#!/usr/bin/env python3
# coding: utf-8
import json
import os
import pathlib
import shutil
import tempfile

from copyparty import crypt
from tests.util import Cfg, VHttpConn
from copyparty.util import Garda


def mk_conn(td, buf):
    args = Cfg(v=[td + "::A"])
    from copyparty.authsrv import AuthSrv

    asrv = AuthSrv(args, lambda *a, **kw: None)
    log = lambda s, m, c=0: None
    conn = VHttpConn(args, asrv, log, buf)
    conn.hsrv.genc = Garda("")
    return conn


def http_req(conn, method, path, headers=None, body=b""):
    headers = headers or {}
    hdr_lines = [f"{method} {path} HTTP/1.1", "Host: localhost", "Connection: close"]
    if body:
        hdr_lines.append(f"Content-Length: {len(body)}")
    for k, v in headers.items():
        hdr_lines.append(f"{k}: {v}")
    hdr_lines.append("")
    hdr_lines.append("")
    raw = "\r\n".join(hdr_lines).encode() + body
    conn.setbuf(raw)
    from copyparty.httpcli import HttpCli

    cli = HttpCli(conn)
    try:
        cli.run()
    except Exception:
        pass
    reply = conn.s._reply
    try:
        header, body2 = reply.split(b"\r\n\r\n", 1)
    except:
        header, body2 = reply, b""
    status_line = header.split(b"\r\n")[0].decode(errors="ignore")
    return status_line, header, body2


def test_crypt_basic(tmp_path=None):
    td = tempfile.mkdtemp()
    try:
        sub = os.path.join(td, "secret")
        os.makedirs(sub)
        pathlib.Path(os.path.join(sub, "a.txt")).write_text("hello", encoding="utf-8")
        meta = crypt.encrypt_folder(sub, "pw123")
        assert crypt.is_encrypted_dir(sub)
        assert crypt.verify_password("pw123", meta)
        assert not crypt.verify_password("wrong", meta)
        # file is ciphertext
        data = open(os.path.join(sub, "a.txt"), "rb").read()
        assert data.startswith(crypt.MAGIC)
        # cannot decrypt with wrong password
        try:
            crypt.decrypt_folder(sub, "wrong")
            assert False, "should have failed with wrong pw"
        except Exception as e:
            assert "incorrect" in str(e).lower()
        # correct decrypt
        crypt.decrypt_folder(sub, "pw123")
        assert not crypt.is_encrypted_dir(sub)
        assert open(os.path.join(sub, "a.txt")).read() == "hello"
        print("test_crypt_basic ok")
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_http_encrypt_flow():
    td = tempfile.mkdtemp()
    sub = os.path.join(td, "secret")
    os.makedirs(sub)
    pathlib.Path(os.path.join(sub, "hello.txt")).write_text("hello world", encoding="utf-8")
    try:
        # encrypt
        body = json.dumps({"password": "s3cret!", "confirm": "s3cret!"}).encode()
        conn = mk_conn(td, b"")
        status, _, body2 = http_req(conn, "POST", "/secret/?encrypt", {"Content-Type": "application/json"}, body)
        assert "200" in status, body2
        assert crypt.is_encrypted_dir(sub)

        # ls without pw -> 403 locked
        conn = mk_conn(td, b"")
        status, _, body2 = http_req(conn, "GET", "/secret/?ls=json", {}, b"")
        assert "403" in status
        assert b"locked" in body2

        # ls with pw -> 200
        conn = mk_conn(td, b"")
        status, _, body2 = http_req(conn, "GET", "/secret/?ls=json", {"X-Enc-PW": "s3cret!"}, b"")
        assert "200" in status
        j = json.loads(body2.decode())
        # should have file (json ls has href, not name)
        assert any("hello.txt" in f.get("href", "") or f.get("name") == "hello.txt" for f in j["files"])

        # get file without pw -> 403
        conn = mk_conn(td, b"")
        status, _, body2 = http_req(conn, "GET", "/secret/hello.txt", {}, b"")
        assert "403" in status

        # get file with pw -> 200 and plaintext
        conn = mk_conn(td, b"")
        status, _, body2 = http_req(conn, "GET", "/secret/hello.txt", {"X-Enc-PW": "s3cret!"}, b"")
        assert "200" in status
        # body2 is file content plus headers? http_req splits, so body2 is file content
        # For file download, body2 is file content (11 bytes)
        assert b"hello world" in body2

        # decrypt with wrong pw -> 403
        conn = mk_conn(td, b"")
        body = json.dumps({"password": "wrong"}).encode()
        status, _, body2 = http_req(conn, "POST", "/secret/?decrypt", {"Content-Type": "application/json"}, body)
        assert "403" in status

        # decrypt with correct pw -> 200
        conn = mk_conn(td, b"")
        body = json.dumps({"password": "s3cret!"}).encode()
        status, _, body2 = http_req(conn, "POST", "/secret/?decrypt", {"Content-Type": "application/json"}, body)
        assert "200" in status
        assert not crypt.is_encrypted_dir(sub)
        assert open(os.path.join(sub, "hello.txt")).read() == "hello world"
        print("test_http_encrypt_flow ok")
    finally:
        shutil.rmtree(td, ignore_errors=True)


if __name__ == "__main__":
    test_crypt_basic()
    test_http_encrypt_flow()
    print("all enc tests passed")
