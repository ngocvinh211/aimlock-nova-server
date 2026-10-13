import os, secrets, sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

ROOT = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.environ.get("AIMLOCK_DB_PATH", os.path.join(ROOT, "aimlock_nova.sqlite3"))
ADMIN1_PASSWORD = os.environ.get("AIMLOCK_ADMIN_PASSWORD", "")
ADMIN2_USERNAME = os.environ.get("AIMLOCK_ADMIN2_USERNAME", "admin2")
ADMIN2_PASSWORD = os.environ.get("AIMLOCK_ADMIN2_PASSWORD", "")
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "true").lower() == "true",
                  PERMANENT_SESSION_LIFETIME=timedelta(hours=8))

def db():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    c = sqlite3.connect(DB_PATH); c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c

def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def init_db():
    with db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS keys(
          id INTEGER PRIMARY KEY AUTOINCREMENT, key_value TEXT UNIQUE NOT NULL,
          note TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'active',
          created_by TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS logs(
          id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL,
          detail TEXT NOT NULL, created_at TEXT NOT NULL)""")
        c.execute("CREATE TABLE IF NOT EXISTS settings(name TEXT PRIMARY KEY, value TEXT NOT NULL)")
        c.execute("INSERT OR IGNORE INTO settings VALUES('admin2_enabled','1')")

def log(actor, action, detail):
    with db() as c:
        c.execute("INSERT INTO logs(actor,action,detail,created_at) VALUES(?,?,?,?)",
                  (actor, action, detail[:500], now()))

def admin2_on():
    with db() as c:
        r = c.execute("SELECT value FROM settings WHERE name='admin2_enabled'").fetchone()
        return bool(r and r["value"] == "1")

def required(fn):
    @wraps(fn)
    def wrap(*a, **kw):
        if not session.get("role"): return redirect(url_for("login"))
        return fn(*a, **kw)
    return wrap

def owner(fn):
    @wraps(fn)
    def wrap(*a, **kw):
        if not session.get("role"): return redirect(url_for("login"))
        if session.get("role") != "admin1": abort(403)
        return fn(*a, **kw)
    return wrap

@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "same-origin"
    return r

@app.route("/")
def home():
    return redirect(url_for("dashboard" if session.get("role") else "login"))

@app.route("/login", methods=["GET","POST"])
def login():
    if session.get("role"): return redirect(url_for("dashboard"))
    if request.method == "POST":
        u, p = request.form.get("username","").strip(), request.form.get("password","")
        if not ADMIN1_PASSWORD or not ADMIN2_PASSWORD:
            flash("Máy chủ chưa cấu hình đủ mật khẩu Admin trong Environment Variables.", "error")
        elif u == "admin1" and secrets.compare_digest(p, ADMIN1_PASSWORD):
            session.clear(); session.update(role="admin1", username="admin1"); session.permanent=True
            log("admin1","LOGIN","Đăng nhập thành công"); return redirect(url_for("dashboard"))
        elif u == ADMIN2_USERNAME and admin2_on() and secrets.compare_digest(p, ADMIN2_PASSWORD):
            session.clear(); session.update(role="admin2", username=ADMIN2_USERNAME); session.permanent=True
            log(ADMIN2_USERNAME,"LOGIN","Đăng nhập thành công"); return redirect(url_for("dashboard"))
        else:
            log(u or "unknown","LOGIN_FAILED","Đăng nhập thất bại")
            flash("Tên đăng nhập hoặc mật khẩu không đúng, hoặc Admin 2 đã bị khóa.", "error")
    return render_template("login.html")

@app.post("/logout")
@required
def logout():
    log(session.get("username","unknown"),"LOGOUT","Đăng xuất")
    session.clear(); return redirect(url_for("login"))

@app.route("/dashboard")
@required
def dashboard():
    with db() as c:
        keys=c.execute("SELECT * FROM keys ORDER BY id DESC").fetchall()
        total=c.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
        active=c.execute("SELECT COUNT(*) FROM keys WHERE status='active'").fetchone()[0]
        logs=c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 8").fetchall()
    return render_template("dashboard.html", keys=keys, total=total, active=active,
                           logs=logs, admin2_enabled=admin2_on())

@app.post("/keys/create")
@required
def create_key():
    key=request.form.get("key_value","").strip(); note=request.form.get("note","").strip()
    exp=request.form.get("expires_at","").strip() or None
    if not key or len(key)>160:
        flash("Key không được trống và tối đa 160 ký tự.", "error"); return redirect(url_for("dashboard"))
    if exp:
        try: datetime.strptime(exp,"%Y-%m-%d")
        except ValueError:
            flash("Ngày hết hạn không hợp lệ.", "error"); return redirect(url_for("dashboard"))
    try:
        with db() as c:
            c.execute("INSERT INTO keys(key_value,note,status,created_by,created_at,expires_at) VALUES(?,?,?,?,?,?)",
                      (key,note[:250],"active",session["username"],now(),exp))
        log(session["username"],"KEY_CREATE","Tạo key: "+key); flash("Đã tạo key.", "success")
    except sqlite3.IntegrityError: flash("Key này đã tồn tại.", "error")
    return redirect(url_for("dashboard"))

@app.post("/keys/<int:key_id>/toggle")
@required
def toggle_key(key_id):
    with db() as c:
        row=c.execute("SELECT * FROM keys WHERE id=?",(key_id,)).fetchone()
        if not row: abort(404)
        status="locked" if row["status"]=="active" else "active"
        c.execute("UPDATE keys SET status=? WHERE id=?",(status,key_id))
    log(session["username"],"KEY_STATUS",f"{row['key_value']} -> {status}")
    flash("Đã cập nhật trạng thái key.", "success"); return redirect(url_for("dashboard"))

@app.post("/keys/<int:key_id>/delete")
@required
def delete_key(key_id):
    with db() as c:
        row=c.execute("SELECT * FROM keys WHERE id=?",(key_id,)).fetchone()
        if not row: abort(404)
        c.execute("DELETE FROM keys WHERE id=?",(key_id,))
    log(session["username"],"KEY_DELETE","Xóa key: "+row["key_value"])
    flash("Đã xóa key.", "success"); return redirect(url_for("dashboard"))

@app.route("/logs")
@required
def logs_page():
    with db() as c: rows=c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 300").fetchall()
    return render_template("logs.html", logs=rows)

@app.post("/admin2/toggle")
@owner
def toggle_admin2():
    on=not admin2_on()
    with db() as c: c.execute("UPDATE settings SET value=? WHERE name='admin2_enabled'",("1" if on else "0",))
    log("admin1","ADMIN2_ACCESS","Bật Admin 2" if on else "Khóa Admin 2")
    flash("Đã "+("bật" if on else "khóa")+" quyền đăng nhập Admin 2.", "success")
    return redirect(url_for("dashboard"))

@app.errorhandler(403)
def forbidden(e): return render_template("error.html",code=403,message="Bạn không có quyền truy cập chức năng này."),403
@app.errorhandler(404)
def missing(e): return render_template("error.html",code=404,message="Không tìm thấy trang hoặc dữ liệu."),404

init_db()
if __name__ == "__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT","5000")),debug=False)
