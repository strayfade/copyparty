"use strict";
var J_ENC = 1;

/* folder encryption UI - quantum-secure AES-256-GCM + Argon2id */
(function () {
    var enc_pw_key = function () {
        // use vpath without trailing slash as key; fallback to location.pathname
        var vp = (window.CGV && CGV.vpath) || location.pathname;
        // normalize
        vp = vp.replace(/\/+$/, "") || "/";
        return "enc_pw:" + vp;
    };
    var get_pw = function () {
        try {
            return sessionStorage.getItem(enc_pw_key()) || "";
        } catch (e) { return ""; }
    };
    var set_pw = function (pw) {
        try {
            if (pw) sessionStorage.setItem(enc_pw_key(), pw);
            else sessionStorage.removeItem(enc_pw_key());
        } catch (e) {}
        // also set cookie for direct file links (non-fetch)
        try {
            // cookie name enc_<hash> from server unlock sets; but we also set simple cookie for fallback
            // we set a cookie named enc_pw_simple that server checks via _enc_get_pw cookie loop
            if (pw) document.cookie = "enc_pw_simple=" + encodeURIComponent(pw) + "; path=/; SameSite=Lax";
            else document.cookie = "enc_pw_simple=; path=/; max-age=0";
        } catch (e) {}
    };

    // monkey-patch fetch to include X-Enc-PW
    (function () {
        var origFetch = window.fetch;
        if (!origFetch) return;
        window.fetch = function (input, init) {
            var pw = get_pw();
            if (pw) {
                init = init || {};
                init.headers = init.headers || {};
                // normalize headers to plain object
                if (init.headers instanceof Headers) {
                    init.headers.set("X-Enc-PW", pw);
                } else if (Array.isArray(init.headers)) {
                    init.headers.push(["X-Enc-PW", pw]);
                } else {
                    init.headers["X-Enc-PW"] = pw;
                    // also add as lower case for some servers
                    init.headers["x-enc-pw"] = pw;
                }
            }
            return origFetch.call(this, input, init);
        };
    })();

    // monkey-patch XHR
    (function () {
        var origOpen = XMLHttpRequest.prototype.open;
        var origSend = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.open = function () {
            this._enc_url = arguments[1];
            return origOpen.apply(this, arguments);
        };
        XMLHttpRequest.prototype.send = function () {
            try {
                var pw = get_pw();
                if (pw) {
                    this.setRequestHeader("X-Enc-PW", pw);
                }
            } catch (e) {}
            return origSend.apply(this, arguments);
        };
    })();

    // helpers to show modal
    function show_enc_modal(opts) {
        // opts: {title, desc, confirm, isEncrypt, cb}
        var html = '<h2>' + esc(opts.title) + '</h2>';
        if (opts.desc) html += '<p>' + opts.desc + '</p>';
        html += '<div style="margin:1em 0">'
        html += '<input type="password" id="enc_pw" class="i" placeholder="Password" style="width:90%;margin:0.3em 0" autocomplete="new-password" />'
        if (opts.isEncrypt) {
            html += '<input type="password" id="enc_pw2" class="i" placeholder="Confirm password" style="width:90%;margin:0.3em 0" autocomplete="new-password" />'
            html += '<div id="enc_warn" style="color:#b00;font-size:0.9em;margin-top:0.5em"></div>'
        }
        html += '</div>'
        html += '<div><a href="#" id="modal-ok">' + (opts.okLabel || 'OK') + '</a> <a href="#" id="modal-ng">Cancel</a></div>';
        modal.show(html);
        var inp = ebi('enc_pw');
        var inp2 = ebi('enc_pw2');
        var warn = ebi('enc_warn');
        if (inp) inp.focus();
        // strength check for encrypt
        if (opts.isEncrypt && warn) {
            var check = function () {
                var p = inp.value, p2 = inp2 ? inp2.value : "";
                var msg = "";
                if (p.length > 0 && p.length < 8) msg = "Password too short (min 8)";
                else if (p.length > 0 && p.length < 12) msg = "Weak password - consider longer";
                else if (p && p2 && p !== p2) msg = "Passwords do not match";
                else if (p && p.length >= 12 && p === p2) msg = "<span style=\"color:#0a0\">Passwords match \u2713</span>";
                warn.innerHTML = msg;
            };
            if (inp) inp.addEventListener('input', check);
            if (inp2) inp2.addEventListener('input', check);
        }
        // handle ok
        var origOk = ebi('modal-ok');
        if (origOk) {
            origOk.onclick = function (e) {
                e.preventDefault();
                var pw = inp ? inp.value : "";
                var pw2 = inp2 ? inp2.value : "";
                if (!pw) { toast.err(4, "Password required"); return; }
                if (opts.isEncrypt) {
                    if (pw.length < 4) { toast.err(4, "Password too short"); return; }
                    if (pw !== pw2) { toast.err(4, "Passwords do not match"); return; }
                }
                modal.hide();
                if (opts.cb) opts.cb(pw, pw2);
            };
        }
        var origNg = ebi('modal-ng');
        if (origNg) {
            origNg.onclick = function (e) {
                e.preventDefault();
                modal.hide();
            };
        }
    }

    function enc_action(action, pw, cb) {
        var url = location.pathname;
        // ensure trailing slash for folder
        if (url.slice(-1) !== "/") url += "/";
        var qs = action === "encrypt" ? "?encrypt" : action === "decrypt" ? "?decrypt" : "?enc_unlock";
        // use fetch with JSON
        var body = {password: pw};
        if (action === "encrypt") body.confirm = pw; // we already validated match, but send same
        // Also try to send confirm as same pw? For decrypt we only need password
        // For encrypt we need confirm field as used in backend _enc_json_pw2
        if (action === "encrypt") body.confirm = document.getElementById('enc_pw2') ? document.getElementById('enc_pw2').value : pw;
        fetch(url + qs, {
            method: "POST",
            headers: {"Content-Type": "application/json", "X-Enc-PW": pw},
            body: JSON.stringify(body)
        }).then(function (resp) {
            return resp.text().then(function (txt) {
                var j = null;
                try { j = JSON.parse(txt); } catch (e) {}
                if (!resp.ok) {
                    var msg = (j && j.msg) || txt || ("HTTP " + resp.status);
                    throw new Error(msg);
                }
                return j || txt;
            });
        }).then(function (j) {
            toast.ok(3, j.msg || (action + " ok"));
            if (action === "encrypt" || action === "decrypt") {
                set_pw(action === "encrypt" ? pw : "");
                // give server a sec to finish filesystem ops, then reload
                setTimeout(function () { location.reload(); }, 800);
            } else if (action === "unlock") {
                set_pw(pw);
                setTimeout(function () { location.reload(); }, 300);
            }
            if (cb) cb(null, j);
        }).catch(function (err) {
            toast.err(5, "Failed: " + err.message);
            if (cb) cb(err);
        });
    }

    function add_toolbar() {
        var ops = ebi('ops');
        if (!ops) return;
        // avoid double add
        if (ebi('enc_btns')) return;
        var cont = mknod('span', 'enc_btns', '');
        cont.style.marginLeft = "1em";
        // Determine state from CGV / IS_ENC globals
        var is_enc = false, is_locked = false;
        try {
            is_enc = (window.IS_ENC !== undefined ? IS_ENC : (CGV && CGV.is_enc)) || false;
            is_locked = (window.IS_LOCKED !== undefined ? IS_LOCKED : (CGV && CGV.is_locked)) || false;
            // Also check cgv via CGV.is_enc naming
            if (typeof is_enc === "string") is_enc = is_enc === "true";
        } catch (e) {}
        // Also fallback: check if page has lock banner
        var can_write = false;
        try { can_write = CGV && CGV.perms && CGV.perms.indexOf("write") !== -1; } catch (e) {}
        if (!is_enc) {
            // show encrypt button if writable
            if (can_write) {
                var b = mknod('a', null, '<span class="mi">lock</span> Encrypt folder');
                b.href = "#";
                b.className = "btn";
                b.title = "Encrypt this folder with a password (quantum-secure AES-256-GCM)";
                b.onclick = function (e) {
                    e.preventDefault();
                    show_enc_modal({
                        title: "Encrypt folder",
                        desc: '<span style="color:#b00">Warning: This will encrypt <b>all files</b> inside this folder. <b>There is no recovery without the password.</b> The folder will show a \uD83D\uDD12 lock icon when locked.</span><br>',
                        isEncrypt: true,
                        okLabel: "Encrypt",
                        cb: function (pw) { enc_action("encrypt", pw); }
                    });
                };
                cont.appendChild(b);
            }
        } else {
            if (is_locked) {
                var ub = mknod('a', null, '<span class="mi">lock_open</span> Unlock');
                ub.href = "#";
                ub.className = "btn";
                ub.style.background = "#fc0";
                ub.title = "Unlock folder with password";
                ub.onclick = function (e) {
                    e.preventDefault();
                    show_enc_modal({
                        title: "Unlock folder",
                        desc: "Enter password to unlock and view files.",
                        isEncrypt: false,
                        okLabel: "Unlock",
                        cb: function (pw) { enc_action("unlock", pw); }
                    });
                };
                cont.appendChild(ub);
            } else {
                // unlocked: show decrypt button
                if (can_write) {
                    var db = mknod('a', null, '<span class="mi">lock_open</span> Decrypt folder');
                    db.href = "#";
                    db.className = "btn";
                    db.title = "Permanently decrypt folder (remove encryption)";
                    db.onclick = function (e) {
                        e.preventDefault();
                        show_enc_modal({
                            title: "Decrypt folder",
                            desc: "Enter password to permanently decrypt this folder. Files will be restored to plaintext.",
                            isEncrypt: false,
                            okLabel: "Decrypt",
                            cb: function (pw) { enc_action("decrypt", pw); }
                        });
                    };
                    cont.appendChild(db);
                    var lu = mknod('a', null, '<span class="mi">lock</span> Lock');
                    lu.href = "#";
                    lu.className = "btn";
                    lu.title = "Lock folder (clear session password)";
                    lu.onclick = function (e) {
                        e.preventDefault();
                        set_pw("");
                        toast.ok(2, "Folder locked (password cleared from this browser)");
                        setTimeout(function(){ location.reload(); }, 400);
                    };
                    cont.appendChild(lu);
                }
            }
        }
        // status badge
        if (is_enc) {
            var badge = mknod('span', null, is_locked ? ' \uD83D\uDD12 Encrypted (locked)' : ' \uD83D\uDD13 Encrypted (unlocked)');
            badge.style.marginLeft = "0.7em";
            badge.style.fontWeight = "bold";
            badge.style.color = is_locked ? "#b00" : "#0a0";
            badge.title = is_locked ? "Folder is locked - password required" : "Folder is encrypted but unlocked in this browser session";
            cont.appendChild(badge);
        }
        ops.appendChild(cont);
    }

    function add_lock_icon_to_path() {
        try {
            var is_enc = (window.IS_ENC !== undefined ? IS_ENC : (CGV && CGV.is_enc));
            if (!is_enc) return;
            var is_locked = (window.IS_LOCKED !== undefined ? IS_LOCKED : (CGV && CGV.is_locked));
            var pathEl = ebi('path');
            if (!pathEl) return;
            // add icon before path
            var icon = mknod('span', null, is_locked ? '\uD83D\uDD12 ' : '\uD83D\uDD13 ');
            icon.title = is_locked ? "Encrypted & locked" : "Encrypted & unlocked";
            icon.style.fontSize = "1.2em";
            if (pathEl.firstChild) pathEl.insertBefore(icon, pathEl.firstChild);
            else pathEl.appendChild(icon);
            // also dim files table when locked
            if (is_locked) {
                var tbl = ebi('files');
                if (tbl) {
                    tbl.style.opacity = "0.35";
                    // add overlay message
                    var wrap = ebi('wrap');
                    if (wrap && !ebi('enc_lock_msg')) {
                        var msg = mknod('div', 'enc_lock_msg', '<h2 style="text-align:center;margin:2em">\uD83D\uDD12 This folder is encrypted and locked</h2><p style="text-align:center">Click <b>Unlock</b> above and enter the password to view files.</p><p style="text-align:center;color:#666">Without the correct password, files cannot be recovered.</p>');
                        msg.style.background = "#fff3cd";
                        msg.style.border = "1px solid #fc0";
                        msg.style.padding = "1em";
                        msg.style.margin = "1em";
                        wrap.insertBefore(msg, wrap.firstChild);
                    }
                }
            }
        } catch (e) {}
    }

    // init after DOM ready
    function init() {
        add_toolbar();
        add_lock_icon_to_path();
        // if locked, auto-prompt unlock? Not automatically, let user click
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
    // also re-run after a bit (browser.js may rebuild ops)
    setTimeout(init, 800);
    setTimeout(init, 2000);
})();
