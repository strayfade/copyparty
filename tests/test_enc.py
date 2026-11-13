#!/usr/bin/env python3
# coding: utf-8
import json
import os
import pathlib
import shutil
import tempfile
import threading
import time

from copyparty import crypt
from copyparty.util import Garda
from tests.util import Cfg, VHttpConn


def mk_conn(td):
    from copyparty.authsrv import AuthSrv

    args = Cfg(v=[td + "::A"])
    asrv = AuthSrv(args, lambda *a, **kw: None)
    conn = VHttpConn(args, asrv, lambda *a, **kw: None, b"")
    conn.hsrv.genc = Garda("")
    return conn


def http_req(conn, method, path, headers=None, body=b""):
    headers = headers or {}
    hdr_lines = ["%s %s HTTP/1.1" % (method, path), "Host: localhost", "Connection: close"]
    if body or method in ("POST", "PUT"):
        hdr_lines.append("Content-Length: %d" % (len(body),))
    for k, v in headers.items():
        hdr_lines.append("%s: %s" % (k, v))
    hdr_lines += ["", ""]
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
    except Exception:
        header, body2 = reply, b""
    status_line = header.split(b"\r\n")[0].decode(errors="ignore")
    return status_line, header, body2


def get_cookie(header):
    for line in header.decode("utf-8", "replace").split("\r\n"):
        if line.lower().startswith("set-cookie:") and "cppwenc=" in line:
            return line.split(";", 1)[0].split(":", 1)[1].strip()
    return ""


def wait_job(conn, jid, timeout=30):
    t0 = time.time()
    while time.time() - t0 < timeout:
        job = conn.hsrv.enc_jobs.get(jid)
        if job and job.done:
            assert not job.error, job.error
            return
        time.sleep(0.02)
    raise AssertionError("job did not finish")


def test_nested_reject():
    td = tempfile.mkdtemp()
    try:
        outer = os.path.join(td, "outer")
        inner = os.path.join(outer, "inner")
        os.makedirs(inner)
        pathlib.Path(os.path.join(inner, "x.txt")).write_text("x")
        crypt.encrypt_folder(inner, "pw123456")
        try:
            crypt.encrypt_folder(outer, "pw123456")
            raise AssertionError("nested vault was allowed")
        except crypt.CryptError:
            pass
        try:
            crypt.Index().add("", "../escape", "f")
            raise AssertionError("path traversal was allowed")
        except crypt.CryptError:
            pass
        print("test_nested_reject ok")
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_recover():
    td = tempfile.mkdtemp()
    try:
        # rollback: no index committed, originals must survive
        a = os.path.join(td, "a")
        os.makedirs(os.path.join(a, enc_crypt_dir()))
        pathlib.Path(os.path.join(a, "keep.txt")).write_text("keep")
        meta = {"v": 2, "state": "encrypting"}
        pathlib.Path(os.path.join(a, enc_crypt_dir(), "meta.json")).write_text(
            json.dumps(meta)
        )
        assert crypt.recover(a) == "rolledback"
        assert not os.path.isdir(os.path.join(a, enc_crypt_dir()))
        assert os.path.isfile(os.path.join(a, "keep.txt"))

        # finish: index committed, leftover plaintext must be removed
        b = os.path.join(td, "b")
        os.makedirs(b)
        pathlib.Path(os.path.join(b, "orig.txt")).write_text("orig")
        crypt.encrypt_folder(b, "pw123456")
        m = crypt.load_meta(b)
        m["state"] = "encrypting"
        crypt.save_meta(b, m)
        pathlib.Path(os.path.join(b, "leftover.txt")).write_text("leak")
        assert crypt.recover(b) == "recovered"
        assert crypt.load_meta(b)["state"] == "locked"
        assert not os.path.exists(os.path.join(b, "leftover.txt"))
        vk, _ = crypt.unlock(b, "pw123456")
        idx = crypt.load_index(b, vk)
        names = [e["n"] for e in idx.e.values() if e["t"] == "f"]
        assert names == ["orig.txt"], names
        print("test_recover ok")
    finally:
        shutil.rmtree(td, ignore_errors=True)


def enc_crypt_dir():
    return crypt.DIRNAME


def test_crypt_roundtrip():
    td = tempfile.mkdtemp()
    try:
        sub = os.path.join(td, "secret")
        os.makedirs(os.path.join(sub, "deep"))
        data = {
            "a.txt": b"hello world",
            "empty.bin": b"",
            "big.bin": os.urandom((3 << 20) + 12345),
            "deep/y.jpg": os.urandom(9999),
        }
        for rel, blob in data.items():
            p = os.path.join(sub, *rel.split("/"))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "wb").write(blob)

        crypt.encrypt_folder(sub, "pw123456")
        assert crypt.is_vault(sub)
        assert crypt.verify_password(sub, "pw123456")
        assert not crypt.verify_password(sub, "wrong")
        for rel in data:
            assert not os.path.exists(os.path.join(sub, *rel.split("/"))), rel
            assert not os.path.exists(os.path.join(sub, rel)), rel
            dirn = os.path.dirname(rel)
            if dirn:
                assert not os.path.exists(os.path.join(sub, dirn))

        vk, meta = crypt.unlock(sub, "pw123456")
        idx = crypt.load_index(sub, vk)
        for fid, ent in idx.e.items():
            if ent["t"] != "f":
                continue
            rel = "/".join(x[1] for x in idx.trail(fid))
            assert b"".join(crypt.iter_decrypt(sub, fid, vk, ent["sz"])) == data[rel]
            if ent["sz"] > 3 << 20:
                # range + tamper
                assert (
                    b"".join(
                        crypt.iter_decrypt(sub, fid, vk, ent["sz"], 1000, 5000)
                    )
                    == data[rel][1000:6000]
                )
                p = crypt.blob_path(sub, fid)
                b = bytearray(open(p, "rb").read())
                orig = b[100]
                b[100] ^= 1
                open(p, "wb").write(b)
                try:
                    b"".join(crypt.iter_decrypt(sub, fid, vk, ent["sz"]))
                    raise AssertionError("tamper was not detected")
                except crypt.CryptError:
                    pass
                b[100] = orig
                open(p, "wb").write(b)

        crypt.remove_vault(sub, "pw123456")
        assert not crypt.is_vault(sub)
        for rel, blob in data.items():
            assert open(os.path.join(sub, *rel.split("/")), "rb").read() == blob
        print("test_crypt_roundtrip ok")
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_http_flow():
    td = tempfile.mkdtemp()
    sub = os.path.join(td, "secret")
    os.makedirs(sub)
    pathlib.Path(os.path.join(sub, "hello.txt")).write_text("hello world", encoding="utf-8")
    conn = mk_conn(td)
    try:
        body = json.dumps({"password": "s3cret-pw", "confirm": "s3cret-pw"}).encode()
        st, hd, b = http_req(
            conn, "POST", "/secret/?enc_new", {"Content-Type": "application/json"}, body
        )
        assert "200" in st, b
        job = json.loads(b)["job"]
        wait_job(conn, job["id"])
        assert crypt.is_vault(sub)

        st, hd, b = http_req(conn, "GET", "/secret/?ls=json")
        assert "200" in st, b
        ls = json.loads(b)
        assert ls["enc"]["locked"] is True, ls
        assert not any("hello" in str(x) for x in ls["files"] + ls["dirs"]), ls
        st, hd, b = http_req(conn, "GET", "/?ls=json")
        par = [x for x in json.loads(b)["dirs"] if x["href"].startswith("secret/")][0]
        assert par["encv"] == 1 and par["encl"] == 1, par

        st, hd, b = http_req(conn, "GET", "/secret/")
        assert "200" in st

        st, hd, b = http_req(
            conn,
            "POST",
            "/secret/?enc_unlock",
            {"Content-Type": "application/json"},
            json.dumps({"password": "wrong-pw"}).encode(),
        )
        assert "403" in st, b

        st, hd, b = http_req(
            conn,
            "POST",
            "/secret/?enc_unlock",
            {"Content-Type": "application/json"},
            json.dumps({"password": "s3cret-pw"}).encode(),
        )
        assert "200" in st, b
        ck = get_cookie(hd)
        assert ck
        st, hd, b = http_req(conn, "GET", "/?ls=json", {"Cookie": ck})
        par = [x for x in json.loads(b)["dirs"] if x["href"].startswith("secret/")][0]
        assert par["encl"] == 0, par

        st, hd, b = http_req(conn, "GET", "/secret/?ls=json", {"Cookie": ck})
        assert "200" in st, b
        ls = json.loads(b)
        assert ls["enc"]["locked"] is False
        names = [x["name"] for x in ls["files"]]
        assert "hello.txt" in names, names
        fid = [x["href"] for x in ls["files"] if x["name"] == "hello.txt"][0]
        assert ".cpp_enc/d/" in fid
        if fid.startswith("."):
            fid = "/secret/" + fid

        st, hd, b = http_req(conn, "GET", fid, {"Cookie": ck})
        assert "200" in st, b
        assert b == b"hello world", b

        st, hd, b = http_req(conn, "GET", fid, {"Cookie": ck, "Range": "bytes=6-10"})
        assert "206" in st, (st, b)
        assert b == b"world", b

        # upload a new file through the vault
        up = b"new content here"
        st, hd, b = http_req(
            conn,
            "POST",
            "/secret/?enc_put&dir=&name=new.txt",
            {"Cookie": ck, "Content-Type": "application/octet-stream"},
            up,
        )
        assert "200" in st, b
        assert not os.path.exists(os.path.join(sub, "new.txt"))
        st, hd, b = http_req(conn, "GET", "/secret/?ls=json", {"Cookie": ck})
        ls = json.loads(b)
        newf = [x for x in ls["files"] if x["name"] == "new.txt"]
        assert newf, ls["files"]
        nh = newf[0]["href"]
        if nh.startswith("."):
            nh = "/secret/" + nh
        st, hd, b = http_req(conn, "GET", nh, {"Cookie": ck})
        assert b == up, b

        # delete through the same route the web UI uses
        st, hd, b = http_req(
            conn, "POST", "/secret/?enc_put&dir=&name=delme.txt",
            {"Cookie": ck, "Content-Type": "application/octet-stream"}, b"x",
        )
        assert "200" in st, b
        st, hd, b = http_req(conn, "GET", "/secret/?ls=json", {"Cookie": ck})
        dh = [x for x in json.loads(b)["files"] if x["name"] == "delme.txt"][0]["href"]
        if dh.startswith("."):
            dh = "/secret/" + dh
        st, hd, b = http_req(conn, "POST", dh + "?delete", {"Cookie": ck}, b"")
        assert "200" in st, b
        st, hd, b = http_req(conn, "GET", "/secret/?ls=json", {"Cookie": ck})
        assert "delme.txt" not in [x["name"] for x in json.loads(b)["files"]]

        # raw access to vault internals is not allowed
        st, hd, b = http_req(conn, "GET", "/secret/.cpp_enc/meta.json", {"Cookie": ck})
        assert "404" in st, (st, b)

        # manual lock
        st, hd, b = http_req(
            conn,
            "POST",
            "/secret/?enc_lock",
            {"Cookie": ck, "Content-Type": "application/json"},
            b"{}",
        )
        assert "200" in st, b
        st, hd, b = http_req(conn, "GET", fid, {"Cookie": ck})
        assert "423" in st or "403" in st, st

        # remove encryption
        st, hd, b = http_req(
            conn,
            "POST",
            "/secret/?enc_remove",
            {"Content-Type": "application/json"},
            json.dumps({"password": "s3cret-pw"}).encode(),
        )
        assert "200" in st, b
        job = json.loads(b)["job"]
        wait_job(conn, job["id"])
        assert not crypt.is_vault(sub)
        assert open(os.path.join(sub, "hello.txt"), "rb").read() == b"hello world"
        assert open(os.path.join(sub, "new.txt"), "rb").read() == up
        print("test_http_flow ok")
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_http_unit_upload_race():
    """parallel encrypted uploads must not lose index entries"""
    td = tempfile.mkdtemp()
    sub = os.path.join(td, "v")
    os.makedirs(sub)
    conn = mk_conn(td)
    try:
        st, hd, b = http_req(
            conn,
            "POST",
            "/v/?enc_new",
            {"Content-Type": "application/json"},
            json.dumps({"password": "s3cret-pw", "confirm": "s3cret-pw"}).encode(),
        )
        assert "200" in st, b
        wait_job(conn, json.loads(b)["job"]["id"])
        st, hd, b = http_req(
            conn,
            "POST",
            "/v/?enc_unlock",
            {"Content-Type": "application/json"},
            json.dumps({"password": "s3cret-pw"}).encode(),
        )
        ck = get_cookie(hd)
        assert ck

        def up(n):
            c2 = mk_conn(td)
            c2.hsrv = conn.hsrv
            r = http_req(
                c2,
                "POST",
                "/v/?enc_put&dir=&name=f%d.txt" % (n,),
                {"Cookie": ck, "Content-Type": "application/octet-stream"},
                ("data-%d" % (n,)).encode(),
            )
            assert "200" in r[0], r[2]

        # separate connections share the session store
        threads = [threading.Thread(target=up, args=(i,)) for i in range(6)]
        [t.start() for t in threads]
        [t.join() for t in threads]

        vk, meta = crypt.unlock(sub, "s3cret-pw")
        idx = crypt.load_index(sub, vk)
        names = sorted(e["n"] for e in idx.e.values() if e["t"] == "f")
        assert names == sorted("f%d.txt" % i for i in range(6)), names
        print("test_http_unit_upload_race ok")
    finally:
        shutil.rmtree(td, ignore_errors=True)


if __name__ == "__main__":
    test_nested_reject()
    test_recover()
    test_crypt_roundtrip()
    test_http_flow()
    test_http_unit_upload_race()
    print("all enc tests passed")
