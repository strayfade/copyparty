"use strict";

/*
 * password-protected (encrypted) folders -- UI
 *
 * The server holds the folder key in RAM for a short idle window; this script
 * never stores the password anywhere. All crypto happens server-side.
 */
var ENCV = (function () {
    var r = {};
    var st = null;           // CGV.enc for the folder being viewed
    var poll_t = 0;
    var busy = false;

    function enc() {
        return (window.CGV && CGV.enc) || null;
    }

    r.active = function () {
        var e = enc();
        return !!(e && !e.locked);
    };

    r.locked = function () {
        var e = enc();
        return !!(e && e.locked);
    };

    function api(url, data, cb) {
        fetch(url, {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data || {})
        }).then(function (res) {
            return res.text().then(function (txt) {
                var j = null;
                try { j = JSON.parse(txt); } catch (e) { }
                if (!res.ok) {
                    var m = (j && j.msg) || txt || ("HTTP " + res.status);
                    throw new Error(m);
                }
                return j || {};
            });
        }).then(function (j) {
            if (cb) cb(null, j);
        }).catch(function (err) {
            if (cb) cb(err);
        });
    }

    function modal_ok(html, onok) {
        modal.show(html);
        var ok = ebi("modal-ok");
        if (ok) ok.onclick = function (e) {
            ev(e);
            if (onok() !== false)
                modal.hide();
        };
        var ng = ebi("modal-ng");
        if (ng) ng.onclick = function (e) {
            ev(e);
            modal.hide();
        };
    }

    var BTNS = '<div class="enc_btns"><a href="#" id="modal-ok">OK</a> ' +
        '<a href="#" id="modal-ng">Cancel</a></div>';
    var DLG = '<table class="enc_dlg">' +
        '<tr><td><input type="password" id="enc_pw" class="i" autocomplete="new-password" placeholder="Password" /></td></tr>' +
        '</table>';

    // ---------------------------------------------------------------- dialogs

    r.menu = function (what) {
        if (busy) return;
        var e = enc();
        var sf = null;
        try { sf = r.sel; } catch (ex) { sf = null; }

        if (what == "new") {
            if (!sf) return;
            dlg_encrypt(sf.url.split("?")[0]);
        }
        else if (what == "unlock") {
            var u = e ? e.base : (sf ? sf.url.split("?")[0] : location.pathname);
            dlg_unlock(u);
        }
        else if (what == "lock") {
            lock_now();
        }
        else if (what == "remove") {
            var ru = (sf && sf.encv) ? sf.url.split("?")[0] :
                (e ? e.base : location.pathname);
            dlg_remove(ru);
        }
        else if (what == "mkdir") {
            dlg_mkdir();
        }
        else if (what == "upload") {
            pick_files();
        }
    };

    function dlg_encrypt(url) {
        var html = '<h2>Encrypt folder</h2>' +
            '<p>Everything inside this folder will be encrypted on disk: file contents, ' +
            'names, extensions, sizes and timestamps. Nobody can read it without the password.</p>' +
            '<p class="enc_warn">There is no recovery if you forget the password. ' +
            'The folder will lock itself again after a few minutes without access.</p>' +
            DLG.replace("</table>", '<tr><td><input type="password" id="enc_pw2" class="i" autocomplete="new-password" placeholder="Confirm password" /></td></tr></table>') +
            '<div id="enc_msg" class="enc_err"></div>' + BTNS;
        modal_ok(html, function () {
            var a = ebi("enc_pw").value, b = ebi("enc_pw2").value;
            if (a.length < 8) { ebi("enc_msg").textContent = "Password must be at least 8 characters"; return false; }
            if (a != b) { ebi("enc_msg").textContent = "Passwords do not match"; return false; }
            modal.hide();
            start_job(url, "enc_new", { password: a, confirm: a }, "Encrypting folder");
            return false;
        });
        setTimeout(function () { var x = ebi("enc_pw"); if (x) x.focus(); }, 30);
    }

    function dlg_unlock(url) {
        var html = '<h2>Unlock folder</h2>' +
            '<p>Enter the password to view this folder. ' +
            'It will lock itself again when you stop using it.</p>' +
            DLG + '<div id="enc_msg" class="enc_err"></div>' + BTNS;
        modal_ok(html, function () {
            var pw = ebi("enc_pw").value;
            if (!pw) { ebi("enc_msg").textContent = "Password required"; return false; }
            var btn = ebi("modal-ok");
            if (btn) btn.textContent = "...";
            api(url + "?enc_unlock", { password: pw }, function (err) {
                if (err) {
                    if (btn) btn.textContent = "Unlock";
                    ebi("enc_msg").textContent = err.message;
                    return;
                }
                modal.hide();
                location.reload();
            });
            return false;
        });
        setTimeout(function () { var x = ebi("enc_pw"); if (x) x.focus(); }, 30);
    }

    function dlg_remove(url) {
        var html = '<h2>Remove password</h2>' +
            '<p class="enc_warn">This permanently decrypts every file in the folder back to ' +
            'normal files on disk. The password is required.</p>' +
            DLG + '<div id="enc_msg" class="enc_err"></div>' + BTNS;
        modal_ok(html, function () {
            var pw = ebi("enc_pw").value;
            if (!pw) { ebi("enc_msg").textContent = "Password required"; return false; }
            modal.hide();
            start_job(url, "enc_remove", { password: pw }, "Removing encryption");
            return false;
        });
    }

    function dlg_mkdir() {
        var html = '<h2>New folder</h2><p>Create a folder inside this encrypted folder.</p>' +
            '<table class="enc_dlg"><tr><td><input type="text" id="modali" class="i" placeholder="Folder name" /></td></tr></table>' +
            '<div id="enc_msg" class="enc_err"></div>' + BTNS;
        modal_ok(html, function () {
            var name = ebi("modali").value.trim();
            if (!name) { ebi("enc_msg").textContent = "Name required"; return false; }
            var e = enc();
            api(e.base + "?enc_mkdir&dir=" + encodeURIComponent(e.fid), { name: name }, function (err) {
                if (err) { ebi("enc_msg").textContent = err.message; return; }
                modal.hide();
                location.reload();
            });
            return false;
        });
    }

    // ---------------------------------------------------------------- jobs

    function start_job(url, action, data, title) {
        busy = true;
        modal.show('<h2>' + esc(title) + '</h2>' +
            '<div id="enc_jobmsg">starting...</div>' +
            '<div class="enc_bar"><div id="enc_bar"></div></div>' +
            '<div class="enc_note">You can leave this page open; progress continues on the server.</div>' +
            '<div id="enc_msg" class="enc_err"></div>' + BTNS);
        var ng = ebi("modal-ng");
        if (ng) ng.style.display = "none";

        api(url + "?" + action, data, function (err, j) {
            if (err) {
                busy = false;
                ebi("enc_jobmsg").textContent = "failed";
                ebi("enc_msg").textContent = err.message;
                modal.hide();
                toast.err(6, err.message);
                return;
            }
            poll_job(url, j.job.id, action == "enc_remove" ? url : "");
        });
    }

    function poll_job(url, jid, back) {
        fetch(url + "?enc_job=" + encodeURIComponent(jid), { credentials: "same-origin" })
            .then(function (x) { return x.json(); })
            .then(function (j) {
                var job = j.job;
                var msg = ebi("enc_jobmsg");
                var bar = ebi("enc_bar");
                if (!msg || !bar) return;  // modal was closed
                var pct = job.total_b ? Math.floor(100 * job.done_b / job.total_b) : 0;
                var phase = job.phase == "encrypting" ? "Encrypting" : job.phase == "decrypting" ? "Decrypting" : job.phase;
                msg.textContent = phase + ": " + job.done_f + "/" + job.total_f + " files (" +
                    humansize(job.done_b) + " / " + humansize(job.total_b) + ")";
                bar.style.width = pct + "%";
                if (job.error) {
                    busy = false;
                    ebi("enc_msg").textContent = job.error;
                    toast.err(8, job.error);
                    return;
                }
                if (job.done) {
                    busy = false;
                    msg.textContent = "Done";
                    setTimeout(function () {
                        if (back) location.href = back;
                        else location.reload();
                    }, 400);
                    return;
                }
                setTimeout(function () { poll_job(url, jid, back); }, 400);
            })
            .catch(function (err) {
                busy = false;
                toast.err(6, "job status failed: " + err);
            });
    }

    function lock_now() {
        var e = enc();
        if (!e) return;
        api(e.base + "?enc_lock", {}, function (err) {
            if (err) { toast.err(5, err.message); return; }
            location.reload();
        });
    }

    // ---------------------------------------------------------------- upload

    function pick_files() {
        var inp = ebi("enc_fup");
        if (!inp) {
            inp = mknod("input", "enc_fup");
            inp.type = "file";
            inp.multiple = true;
            inp.style.display = "none";
            document.body.appendChild(inp);
            inp.onchange = function () {
                var files = [];
                for (var a = 0; a < inp.files.length; a++) files.push(inp.files[a]);
                inp.value = "";
                upload_files(files);
            };
        }
        inp.click();
    }

    function upload_files(files) {
        if (!files || !files.length) return;
        var e = enc();
        if (!e) return;
        var list = [];
        for (var a = 0; a < files.length; a++) list.push(files[a]);

        modal.show('<h2>Uploading</h2><div id="enc_jobmsg">preparing...</div>' +
            '<div class="enc_bar"><div id="enc_bar"></div></div><div id="enc_msg" class="enc_err"></div>' + BTNS);
        var ng = ebi("modal-ng");
        if (ng) ng.style.display = "none";
        var i = 0;

        function next() {
            if (i >= list.length) {
                modal.hide();
                location.reload();
                return;
            }
            var f = list[i++];
            var url = e.base + "?enc_put&dir=" + encodeURIComponent(e.fid) +
                "&name=" + encodeURIComponent(f.name);
            var xhr = new XMLHttpRequest();
            xhr.open("POST", url, true);
            xhr.setRequestHeader("Content-Type", "application/octet-stream");
            xhr.upload.onprogress = function (ev) {
                var msg = ebi("enc_jobmsg"), bar = ebi("enc_bar");
                if (!msg || !bar) return;
                var pct = ev.lengthComputable ? Math.floor(100 * ev.loaded / ev.total) : 0;
                msg.textContent = "Uploading " + f.name + " (" + (i) + "/" + list.length + ")";
                bar.style.width = pct + "%";
            };
            xhr.onload = function () {
                if (xhr.status < 200 || xhr.status > 299) {
                    var t = xhr.responseText || ("HTTP " + xhr.status);
                    var m = ebi("enc_msg");
                    if (m) m.textContent = t;
                    toast.err(8, t);
                    return;
                }
                next();
            };
            xhr.onerror = function () {
                toast.err(8, "upload failed");
            };
            xhr.send(f);
        }
        next();
    }

    // ---------------------------------------------------------------- menu

    function show_item(id, vis) {
        var el = ebi(id);
        if (el) el.style.display = vis ? "" : "none";
    }

    r.menu_ready = function (sf) {
        r.sel = sf;
        var e = enc();
        var can_write = window.perms && has(perms, "write");
        var is_dir = sf && sf.type == "dir";
        var in_vault = !!(e && !e.locked);

        show_item("renc", is_dir && !sf.enc && !sf.encv && can_write);
        show_item("rencu", !!(sf && sf.encv && sf.encl));
        show_item("rencl", !!(sf && sf.encv && !sf.encl));
        show_item("rencr", !!(sf && sf.encv && !sf.encl && can_write));
        show_item("rnewd", in_vault && can_write);
        show_item("rupl", in_vault && can_write);
        if (sf && sf.encv) show_item("rzip", false);

        var any = false;
        var ids = ["renc", "rencu", "rencl", "rencr", "rnewd", "rupl"];
        for (var a = 0; a < ids.length; a++) {
            var el = ebi(ids[a]);
            if (el && el.style.display != "none") any = true;
        }
        var sep = ebi("rs_enc");
        if (sep) sep.style.display = any ? "" : "none";

        if (in_vault) {
            var adv = ["rrnm", "rcut", "rcpy", "rpst", "rzip", "rnfi"];
            for (var ai = 0; ai < adv.length; ai++) show_item(adv[ai], false);
        }
    };

    // ---------------------------------------------------------------- chrome

    r.draw_trail = function () {
        var e = enc();
        if (!e) return false;
        var rm = ebi("entree"), pathEl = ebi("path");
        if (!rm || !pathEl) return false;
        while (rm.nextSibling)
            rm.parentNode.removeChild(rm.nextSibling);
        var nodes = [[e.base, e.vpath ? e.vpath.split("/").pop() : "/"]];
        var trail = e.trail || [];
        for (var a = 0; a < trail.length; a++) nodes.push(trail[a]);

        var icon = mknod("span", null, e.locked ? "lock " : "lock_open ");
        icon.className = "mi enc_badge_icon";
        icon.title = e.locked ? "encrypted folder (locked)" : "encrypted folder (unlocked)";
        pathEl.insertBefore(icon, rm.nextSibling);

        for (var a = 0; a < nodes.length; a++) {
            var href = nodes[a][0], name = nodes[a][1];
            var o = mknod("a");
            o.setAttribute("href", href);
            o.textContent = name;
            pathEl.appendChild(mknod("i"));
            pathEl.appendChild(o);
        }
        return true;
    };

    function add_badge() {
        var ops = ebi("ops");
        if (!ops) return;
        var old = ebi("enc_badge");
        if (old) old.parentNode.removeChild(old);
        var e = enc();
        if (!e) return;
        var b = mknod("span", "enc_badge");
        b.className = "enc_badge";
        if (e.locked) {
            b.innerHTML = '<span class="mi">lock</span> encrypted';
            b.title = "This folder is encrypted; enter the password to view it";
        } else {
            b.innerHTML = '<span class="mi">lock_open</span> encrypted';
            b.title = "Encrypted; locks automatically when idle";
            var lk = mknod("a", null, "Lock now");
            lk.href = "#";
            lk.className = "enc_locknow";
            lk.onclick = function (ev2) { ev(ev2); lock_now(); };
            b.appendChild(lk);
            var rm = mknod("a", null, "Remove password");
            rm.href = "#";
            rm.className = "enc_locknow";
            rm.onclick = function (ev2) { ev(ev2); dlg_remove(e.base); };
            b.appendChild(rm);
        }
        ops.appendChild(b);
    }

    function lock_card() {
        if (ebi("enc_lock_card")) return;
        var e = enc();
        if (!e) return;
        var files = ebi("files");
        if (files) files.style.display = "none";
        var epi = ebi("epi");
        if (epi) epi.style.display = "none";
        var write_ids = ["opa_up", "opa_bup", "opa_mkd", "opa_new_md"];
        for (var wi = 0; wi < write_ids.length; wi++) {
            var wel = ebi(write_ids[wi]);
            if (wel) wel.style.display = "none";
        }
        var card = mknod("div", "enc_lock_card");
        card.innerHTML = '<h2><span class="mi">lock</span> This folder is password-protected</h2>' +
            '<p>Enter the password to unlock and view the contents.</p>' +
            '<div class="enc_unlockrow"><input type="password" id="enc_kpw" class="i" placeholder="Password" autocomplete="current-password" />' +
            '<a href="#" id="enc_kgo">Unlock</a></div>' +
            '<div id="enc_kmsg" class="enc_err"></div>' +
            '<p class="enc_note">Without the password the files cannot be recovered.</p>';
        var wrap = ebi("wrap");
        if (!wrap) return;
        wrap.insertBefore(card, wrap.firstChild);
        var inp = ebi("enc_kpw");
        if (inp) inp.focus();
        var go = ebi("enc_kgo");
        var submit = function (ev2) {
            if (ev2) ev(ev2);
            var pw = inp.value;
            if (!pw) return;
            go.textContent = "...";
            api(location.pathname.split("?")[0] + "?enc_unlock", { password: pw }, function (err) {
                if (err) {
                    go.textContent = "Unlock";
                    ebi("enc_kmsg").textContent = err.message;
                    return;
                }
                location.reload();
            });
        };
        if (go) go.onclick = submit;
        if (inp) inp.onkeydown = function (ev2) {
            if (ev2.keyCode == 13) submit(ev2);
        };
    }

    r.on_ls = function (e) {
        CGV.enc = e;
        if (!e) {
            var b = ebi("enc_badge");
            if (b) b.parentNode.removeChild(b);
            var c = ebi("enc_lock_card");
            if (c) c.parentNode.removeChild(c);
            var f = ebi("files");
            if (f) f.style.display = "";
            return;
        }
        add_badge();
        if (e.locked) {
            lock_card();
            return;
        }
        var c2 = ebi("enc_lock_card");
        if (c2) c2.parentNode.removeChild(c2);
        var f2 = ebi("files");
        if (f2) f2.style.display = "";
        r.draw_trail();
    };

    function poll_status() {
        if (!enc()) return;
        fetch(location.pathname.split("?")[0] + "?enc_status", { credentials: "same-origin" })
            .then(function (x) { return x.json(); })
            .then(function (j) {
                var e = enc();
                if (e && j && j.locked && !e.locked)
                    location.reload();
            })
            .catch(function () { });
    }

    // ---------------------------------------------------------------- init

    function init() {
        st = enc();
        if (!st) return;
        add_badge();
        if (st.locked) {
            lock_card();
            return;
        }
        r.draw_trail();
        clearInterval(poll_t);
        poll_t = setInterval(poll_status, 20000);

        // route the normal upload / new-folder buttons into the vault
        var ops = ebi("ops");
        if (ops) ops.addEventListener("click", function (e) {
            if (!r.active()) return;
            var a = e.target && e.target.closest && e.target.closest("a[data-dest]");
            if (!a) return;
            var d = a.getAttribute("data-dest");
            if (d == "up2k" || d == "bup") {
                e.preventDefault();
                e.stopPropagation();
                pick_files();
            } else if (d == "mkdir") {
                e.preventDefault();
                e.stopPropagation();
                dlg_mkdir();
            }
        }, true);
        if (ops) ops.addEventListener("click", function (e) {
            if (!r.active()) return;
            var a = e.target && e.target.closest && e.target.closest("a#opa_mod, a#opa_share");
            if (!a) return;
        }, true);

        // drag and drop
        window.addEventListener("dragover", function (e) {
            if (!r.active()) return;
            e.preventDefault();
            e.stopPropagation();
        }, true);
        window.addEventListener("drop", function (e) {
            if (!r.active()) return;
            var dt = e.dataTransfer;
            if (!dt || !dt.files || !dt.files.length) return;
            e.preventDefault();
            e.stopPropagation();
            upload_files(dt.files);
        }, true);
    }

    if (document.readyState == "loading")
        document.addEventListener("DOMContentLoaded", init);
    else
        init();
    setTimeout(init, 900);
    setTimeout(init, 2200);

    return r;
})();
