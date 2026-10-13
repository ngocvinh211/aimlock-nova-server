import os, sqlite3, secrets, hashlib, hmac, json, time
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import Flask, request, redirect, url_for, session, render_template, flash, jsonify, abort, g

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("AIMLOCK_DB_PATH", os.path.join(BASE, "aimlock_nova.sqlite3"))
ADMIN_PASSWORD = os.environ.get("AIMLOCK_ADMIN_PASSWORD", "")
ADMIN2_USERNAME = os.environ.get("AIMLOCK_ADMIN2_USERNAME", "admin2")
ADMIN2_PASSWORD = os.environ.get("AIMLOCK_ADMIN2_PASSWORD", "")
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "")
ADMIN_API_TOKEN = os.environ.get("AIMLOCK_ADMIN_API_TOKEN", "")
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=64 * 1024,
)

def utcnow():
    return datetime.now(timezone.utc)

def stamp(dt=None):
    return (dt or utcnow()).isoformat(timespec="seconds")

def digest(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def connect_db():
    c = sqlite3.connect(DB_PATH, timeout=15)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA journal_mode=WAL")
    return c

def init_db():
    with connect_db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS admin_settings (
          setting TEXT PRIMARY KEY, value TEXT NOT NULL
        );
        INSERT OR IGNORE INTO admin_settings(setting,value) VALUES ('admin2_enabled','1');
        CREATE TABLE IF NOT EXISTS keys (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          key_hash TEXT NOT NULL UNIQUE,
          key_prefix TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','blocked','revoked')),
          created_at TEXT NOT NULL,
          expires_at TEXT,
          max_devices INTEGER NOT NULL DEFAULT 1 CHECK(max_devices BETWEEN 1 AND 100),
          note TEXT NOT NULL DEFAULT '',
          created_by TEXT NOT NULL DEFAULT 'admin'
        );
        CREATE TABLE IF NOT EXISTS devices (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          key_id INTEGER NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
          device_hash TEXT NOT NULL,
          device_label TEXT NOT NULL DEFAULT '',
          activated_at TEXT NOT NULL,
          last_seen_at TEXT NOT NULL,
          revoked_at TEXT,
          UNIQUE(key_id, device_hash)
        );
        CREATE TABLE IF NOT EXISTS logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          key_id INTEGER,
          event TEXT NOT NULL,
          device_hash TEXT,
          details TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_keys_status ON keys(status);
        CREATE INDEX IF NOT EXISTS idx_keys_prefix ON keys(key_prefix);
        CREATE INDEX IF NOT EXISTS idx_devices_key ON devices(key_id);
        CREATE INDEX IF NOT EXISTS idx_logs_created ON logs(created_at);
        """)
init_db()

def audit(event, key_id=None, device_hash="", details=""):
    with connect_db() as c:
        c.execute("INSERT INTO logs(key_id,event,device_hash,details,created_at) VALUES(?,?,?,?,?)",
                  (key_id, event, device_hash[:16], details[:500], stamp()))

@app.context_processor
def inject_template_values():
    return {"now_string": stamp()}

def csrf_token():
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token
    return token
app.jinja_env.globals["csrf_token"] = csrf_token

@app.before_request
def check_csrf():
    if request.method in ("POST", "PUT", "PATCH", "DELETE") and request.endpoint not in ("validate_key",):
        supplied = request.headers.get("X-CSRF-Token") or request.form.get("_csrf") or ""
        expected = session.get("_csrf", "")
        if not expected or not hmac.compare_digest(supplied, expected):
            # JSON API management uses bearer token instead of browser CSRF.
            if not (request.path.startswith("/api/admin/") and ADMIN_API_TOKEN and
                    hmac.compare_digest(request.headers.get("Authorization", ""), "Bearer " + ADMIN_API_TOKEN)):
                abort(403, description="CSRF check failed. Refresh the page and try again.")

def is_admin():
    if session.get("admin") is not True:
        return False
    if session.get("role") == "admin2":
        with connect_db() as c:
            row = c.execute("SELECT value FROM admin_settings WHERE setting='admin2_enabled'").fetchone()
        if not row or row["value"] != "1":
            session.clear()
            return False
    return True

def is_owner():
    return is_admin() and session.get("role") == "admin1"

def admin_page(fn):
    @wraps(fn)
    def inner(*args, **kwargs):
        if not is_admin():
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return inner

def admin_api(fn):
    @wraps(fn)
    def inner(*args, **kwargs):
        if not ADMIN_API_TOKEN:
            return jsonify(error="admin_api_disabled", message="Configure AIMLOCK_ADMIN_API_TOKEN on server"), 503
        auth = request.headers.get("Authorization", "")
        if not hmac.compare_digest(auth, "Bearer " + ADMIN_API_TOKEN):
            return jsonify(error="unauthorized"), 401
        return fn(*args, **kwargs)
    return inner

def key_state(row):
    if row["status"] != "active":
        return row["status"]
    if row["expires_at"] and datetime.fromisoformat(row["expires_at"]) <= utcnow():
        return "expired"
    return "active"

def make_key():
    # Required NOVA- prefix followed by 20 cryptographically random digits.
    # The original is shown only once; only its SHA-256 hash is stored.
    return "NOVA-" + "".join(secrets.choice("0123456789") for _ in range(20))

def create_key_record(days=None, max_devices=1, note="", created_by="admin"):
    exp = None
    if days is not None:
        if not isinstance(days, int) or days < 1 or days > 36500:
            raise ValueError("days must be 1..36500 or null")
        exp = stamp(utcnow() + timedelta(days=days))
    if not isinstance(max_devices, int) or not 1 <= max_devices <= 100:
        raise ValueError("max_devices must be 1..100")
    raw = make_key()
    with connect_db() as c:
        cur = c.execute("""INSERT INTO keys(key_hash,key_prefix,status,created_at,expires_at,max_devices,note,created_by)
                           VALUES(?,?,?,?,?,?,?,?)""",
                        (digest(raw), raw[:10], "active", stamp(), exp, max_devices, str(note)[:200], created_by[:100]))
        kid = cur.lastrowid
    audit("created", kid, details="Key created")
    return raw, kid

@app.route("/")
def home():
    return redirect(url_for("index") if is_admin() else url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "admin1").strip()
        password = request.form.get("password", "")
        role = None
        if username == "admin1" and ADMIN_PASSWORD and hmac.compare_digest(password, ADMIN_PASSWORD):
            role = "admin1"
        elif username == ADMIN2_USERNAME and ADMIN2_PASSWORD and hmac.compare_digest(password, ADMIN2_PASSWORD):
            with connect_db() as c:
                row = c.execute("SELECT value FROM admin_settings WHERE setting='admin2_enabled'").fetchone()
            if row and row["value"] == "1": role = "admin2"
        if role:
            session.clear()
            session["admin"] = True
            session["role"] = role
            session["username"] = username
            session.permanent = True
            session["_csrf"] = secrets.token_urlsafe(32)
            audit("admin_login", details=f"Successful login: {role}")
            return redirect(url_for("index"))
        audit("admin_login_failed", details=f"Invalid login: {username[:50]}")
        flash("Tài khoản hoặc mật khẩu không đúng, hoặc Admin 2 đã bị kick.", "error")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
@admin_page
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/admin")
@admin_page
def index():
    q = request.args.get("q", "").strip()[:100]
    state = request.args.get("status", "").strip()
    sql = """SELECT k.*,(SELECT COUNT(*) FROM devices d WHERE d.key_id=k.id AND d.revoked_at IS NULL) device_count
             FROM keys k WHERE 1=1"""
    args = []
    if q:
        sql += " AND (k.key_prefix LIKE ? OR k.note LIKE ? OR CAST(k.id AS TEXT)=?)"
        args += [f"%{q}%", f"%{q}%", q]
    if state in ("active", "blocked", "revoked", "expired"):
        if state == "expired":
            sql += " AND k.status='active' AND k.expires_at IS NOT NULL AND k.expires_at<=?"
            args.append(stamp())
        else:
            sql += " AND k.status=?"
            args.append(state)
    sql += " ORDER BY k.id DESC LIMIT 500"
    with connect_db() as c:
        keys = c.execute(sql, args).fetchall()
        totals = {
          "all": c.execute("SELECT COUNT(*) FROM keys").fetchone()[0],
          "active": c.execute("SELECT COUNT(*) FROM keys WHERE status='active' AND (expires_at IS NULL OR expires_at>?)", (stamp(),)).fetchone()[0],
          "blocked": c.execute("SELECT COUNT(*) FROM keys WHERE status='blocked'").fetchone()[0],
          "devices": c.execute("SELECT COUNT(*) FROM devices WHERE revoked_at IS NULL").fetchone()[0]
        }
    return render_template("index.html", keys=keys, totals=totals, q=q, status=state)

@app.route("/admin/keys/create", methods=["POST"])
@admin_page
def create_key_page():
    try:
        days_s = request.form.get("days", "").strip()
        days = int(days_s) if days_s else None
        max_devices = int(request.form.get("max_devices", "1"))
        raw, kid = create_key_record(days, max_devices, request.form.get("note", ""), session.get("role", "admin1"))
    except (ValueError, TypeError):
        flash("Thời hạn phải để trống hoặc là số ngày 1–36500; thiết bị từ 1–100.", "error")
        return redirect(url_for("index"))
    session["new_key_once"] = raw
    flash(f"Đã tạo key #{kid}. Sao chép key ngay; key gốc chỉ hiển thị một lần.", "success")
    return redirect(url_for("index"))

@app.route("/admin/keys/reveal-once", methods=["POST"])
@admin_page
def reveal_key_once():
    raw = session.pop("new_key_once", "")
    return jsonify({"key": raw})

@app.route("/admin/keys/<int:key_id>/status", methods=["POST"])
@admin_page
def status_key(key_id):
    new_status = request.form.get("status", "")
    if new_status not in ("active", "blocked", "revoked"):
        abort(400)
    with connect_db() as c:
        cur = c.execute("UPDATE keys SET status=? WHERE id=?", (new_status, key_id))
        if cur.rowcount == 0:
            abort(404)
    audit(new_status, key_id, details="Status changed by admin")
    flash(f"Đã cập nhật key #{key_id}: {new_status}.", "success")
    return redirect(url_for("index"))

@app.route("/admin/keys/<int:key_id>/delete", methods=["POST"])
@admin_page
def delete_key(key_id):
    # Both admins may delete keys; this action is irreversible.
    with connect_db() as c:
        row = c.execute("SELECT id FROM keys WHERE id=?", (key_id,)).fetchone()
        if not row:
            abort(404)
        c.execute("DELETE FROM devices WHERE key_id=?", (key_id,))
        c.execute("DELETE FROM keys WHERE id=?", (key_id,))
    audit("deleted", key_id, details=f"Key deleted by {session.get('role', 'admin')}")
    flash(f"Đã xóa KEY #{key_id}.", "success")
    return redirect(url_for("index"))

@app.route("/admin/keys/<int:key_id>/expiry", methods=["POST"])
@admin_page
def expiry_key(key_id):
    if not is_owner():
        abort(403)
    days_s = request.form.get("days", "").strip()
    try:
        exp = stamp(utcnow() + timedelta(days=int(days_s))) if days_s else None
        if days_s and not 1 <= int(days_s) <= 36500:
            raise ValueError()
    except ValueError:
        flash("Nhập số ngày từ 1 đến 36500 hoặc để trống để bỏ hạn.", "error")
        return redirect(url_for("index"))
    with connect_db() as c:
        cur = c.execute("UPDATE keys SET expires_at=? WHERE id=?", (exp, key_id))
        if not cur.rowcount:
            abort(404)
    audit("expiry_changed", key_id, details=f"Expiry updated to {exp or 'never'}")
    flash(f"Đã cập nhật thời hạn key #{key_id}.", "success")
    return redirect(url_for("index"))

@app.route("/admin/devices")
@admin_page
def devices_page():
    if not is_owner(): abort(403)
    with connect_db() as c:
        rows = c.execute("""SELECT d.*,k.key_prefix,k.id AS kid FROM devices d JOIN keys k ON k.id=d.key_id
                            ORDER BY d.id DESC LIMIT 500""").fetchall()
    return render_template("devices.html", devices=rows)

@app.route("/admin/devices/<int:device_id>/revoke", methods=["POST"])
@admin_page
def revoke_device(device_id):
    if not is_owner(): abort(403)
    with connect_db() as c:
        row = c.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        if not row:
            abort(404)
        c.execute("UPDATE devices SET revoked_at=? WHERE id=?", (stamp(), device_id))
    audit("device_revoked", row["key_id"], row["device_hash"], "Device revoked by admin")
    flash("Đã thu hồi thiết bị.", "success")
    return redirect(url_for("devices_page"))

@app.route("/admin/logs")
@admin_page
def logs_page():
    if not is_owner(): abort(403)
    with connect_db() as c:
        rows = c.execute("""SELECT l.*,k.key_prefix FROM logs l LEFT JOIN keys k ON k.id=l.key_id
                            ORDER BY l.id DESC LIMIT 500""").fetchall()
    return render_template("logs.html", logs=rows)

@app.route("/admin/admin2", methods=["GET", "POST"])
@admin_page
def admin2_page():
    if not is_owner(): abort(403)
    if request.method == "POST":
        action = request.form.get("action")
        if action == "kick":
            with connect_db() as c:
                c.execute("UPDATE admin_settings SET value='0' WHERE setting='admin2_enabled'")
            audit("admin2_kicked", details="Admin 1 revoked Admin 2 access")
            flash("Đã kick Admin 2 và thu hồi quyền đăng nhập.", "success")
        elif action == "restore":
            with connect_db() as c:
                c.execute("UPDATE admin_settings SET value='1' WHERE setting='admin2_enabled'")
            audit("admin2_restored", details="Admin 1 restored Admin 2 access")
            flash("Đã bật lại quyền đăng nhập Admin 2.", "success")
        return redirect(url_for("admin2_page"))
    with connect_db() as c:
        row = c.execute("SELECT value FROM admin_settings WHERE setting='admin2_enabled'").fetchone()
    return render_template("admin2.html", enabled=bool(row and row["value"] == "1"), username=ADMIN2_USERNAME, configured=bool(ADMIN2_PASSWORD))

# Public API for the future app
@app.route("/api/v1/validate", methods=["POST"])
def validate_key():
    data = request.get_json(silent=True) or {}
    raw = str(data.get("key", "")).strip()
    device_id = str(data.get("device_id", "")).strip()
    label = str(data.get("device_label", ""))[:100]
    if not raw or not device_id or len(raw) > 200 or len(device_id) > 300:
        return jsonify(ok=False, error="invalid_request"), 400
    kh, dh = digest(raw), digest(device_id)
    with connect_db() as c:
        key = c.execute("SELECT * FROM keys WHERE key_hash=?", (kh,)).fetchone()
        if not key:
            c.execute("INSERT INTO logs(event,device_hash,details,created_at) VALUES(?,?,?,?)",
                      ("validation_failed", dh[:16], "Unknown key", stamp()))
            return jsonify(ok=False, error="invalid_key"), 401
        if key_state(key) != "active":
            state = key_state(key)
            c.execute("INSERT INTO logs(key_id,event,device_hash,details,created_at) VALUES(?,?,?,?,?)",
                      (key["id"], "validation_failed", dh[:16], state, stamp()))
            return jsonify(ok=False, error="key_" + state), 403
        device = c.execute("SELECT * FROM devices WHERE key_id=? AND device_hash=? AND revoked_at IS NULL",
                           (key["id"], dh)).fetchone()
        if not device:
            count = c.execute("SELECT COUNT(*) FROM devices WHERE key_id=? AND revoked_at IS NULL",
                              (key["id"],)).fetchone()[0]
            if count >= key["max_devices"]:
                c.execute("INSERT INTO logs(key_id,event,device_hash,details,created_at) VALUES(?,?,?,?,?)",
                          (key["id"], "device_limit_reached", dh[:16], "Device limit reached", stamp()))
                return jsonify(ok=False, error="device_limit_reached"), 403
            c.execute("INSERT INTO devices(key_id,device_hash,device_label,activated_at,last_seen_at) VALUES(?,?,?,?,?)",
                      (key["id"], dh, label, stamp(), stamp()))
            c.execute("INSERT INTO logs(key_id,event,device_hash,details,created_at) VALUES(?,?,?,?,?)",
                      (key["id"], "activated", dh[:16], "Device activated", stamp()))
        else:
            c.execute("UPDATE devices SET last_seen_at=?,device_label=? WHERE id=?", (stamp(), label, device["id"]))
            c.execute("INSERT INTO logs(key_id,event,device_hash,details,created_at) VALUES(?,?,?,?,?)",
                      (key["id"], "validated", dh[:16], "Validation successful", stamp()))
    return jsonify(ok=True, status="active", message="key_valid"), 200

# Private admin API: requires a long bearer token configured only on the server.
@app.route("/api/admin/v1/keys", methods=["GET"])
@admin_api
def api_list_keys():
    q = request.args.get("q", "")[:100]
    with connect_db() as c:
        rows = c.execute("""SELECT k.id,k.key_prefix,k.status,k.created_at,k.expires_at,k.max_devices,k.note,
          (SELECT COUNT(*) FROM devices d WHERE d.key_id=k.id AND d.revoked_at IS NULL) device_count
          FROM keys k WHERE key_prefix LIKE ? OR note LIKE ? ORDER BY id DESC LIMIT 500""",
          (f"%{q}%", f"%{q}%")).fetchall()
    return jsonify(keys=[dict(r, effective_status=key_state(r)) for r in rows])

@app.route("/api/admin/v1/keys", methods=["POST"])
@admin_api
def api_create_key():
    data = request.get_json(silent=True) or {}
    try:
        days = data.get("days")
        if days == "" or days is None:
            days = None
        else:
            days = int(days)
        max_devices = int(data.get("max_devices", 1))
        raw, kid = create_key_record(days, max_devices, str(data.get("note", "")), "admin_api")
    except (ValueError, TypeError):
        return jsonify(error="invalid_days_or_device_limit"), 400
    return jsonify(id=kid, key=raw, warning="Save this key now; it will not be retrievable later."), 201

@app.route("/api/admin/v1/keys/<int:key_id>", methods=["PATCH"])
@admin_api
def api_update_key(key_id):
    data = request.get_json(silent=True) or {}
    updates, args = [], []
    if "status" in data:
        if data["status"] not in ("active", "blocked", "revoked"):
            return jsonify(error="invalid_status"), 400
        updates.append("status=?"); args.append(data["status"])
    if "days" in data:
        try:
            days = data["days"]
            exp = None if days is None or days == "" else stamp(utcnow() + timedelta(days=int(days)))
            if days not in (None, "") and not 1 <= int(days) <= 36500:
                raise ValueError()
        except (ValueError, TypeError):
            return jsonify(error="invalid_days"), 400
        updates.append("expires_at=?"); args.append(exp)
    if "max_devices" in data:
        try:
            n = int(data["max_devices"])
            if not 1 <= n <= 100: raise ValueError()
        except (ValueError, TypeError):
            return jsonify(error="invalid_max_devices"), 400
        updates.append("max_devices=?"); args.append(n)
    if not updates:
        return jsonify(error="no_valid_fields"), 400
    args.append(key_id)
    with connect_db() as c:
        cur = c.execute("UPDATE keys SET " + ",".join(updates) + " WHERE id=?", args)
        if not cur.rowcount:
            return jsonify(error="not_found"), 404
    audit("api_key_updated", key_id, details="Admin API update")
    return jsonify(ok=True, id=key_id)

@app.route("/api/admin/v1/logs", methods=["GET"])
@admin_api
def api_logs():
    with connect_db() as c:
        rows = c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 500").fetchall()
    return jsonify(logs=[dict(r) for r in rows])

@app.errorhandler(403)
def forbidden(err):
    if request.path.startswith("/api/"):
        return jsonify(error="forbidden", message=getattr(err, "description", "Forbidden")), 403
    return render_template("error.html", code=403, message="Yêu cầu bị từ chối. Hãy tải lại trang và thử lại."), 403

@app.errorhandler(404)
def not_found(err):
    if request.path.startswith("/api/"):
        return jsonify(error="not_found"), 404
    return render_template("error.html", code=404, message="Không tìm thấy trang."), 404

if __name__ == "__main__":
    if not ADMIN_PASSWORD:
        print("ERROR: Set AIMLOCK_ADMIN_PASSWORD before using this app.")
    if not FLASK_SECRET_KEY:
        print("WARNING: FLASK_SECRET_KEY is temporary; set a stable secret for deployment.")
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")), debug=False)
