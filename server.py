#!/usr/bin/env python3
"""Campus Care - student services & complaint management. Zero dependencies (Python 3.8+).
Run:  python server.py   ->  http://localhost:8000"""
import sqlite3, json, hashlib, secrets, os, re, csv, io, threading, time
import chatbot
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get("DB_PATH") or os.path.join(HERE, "campuscare.db")
PORT = int(os.environ.get("PORT", 8000))
HOST = os.environ.get("HOST") or ("0.0.0.0" if os.environ.get("PORT") else "127.0.0.1")  # Render sets PORT
PROD = bool(os.environ.get("ADMIN_PASSWORD"))  # production: no demo accounts, admin comes from environment
META = {
    "categories": ["Hostel", "Academics", "Library", "Canteen", "Transport", "IT / Wi-Fi", "Fees & Admin", "Health", "Harassment", "Other"],
    "statuses": ["Open", "In Progress", "Resolved", "Closed"],
    "priorities": ["Low", "Medium", "High", "Urgent"],
    "kinds": ["Complaint", "Service Request"],
}
SESS = {}
FAILS = {}
META["demo"] = not PROD
ESC = "(t.status IN ('Open','In Progress') AND ((t.priority='Urgent' AND julianday('now')-julianday(t.created)>1) OR (t.priority='High' AND julianday('now')-julianday(t.created)>3)))"


def notify(uids, tid, msg, skip=None):
    for i in set(uids):
        if i and i != skip:
            q("INSERT INTO notifications(user_id,ticket_id,msg) VALUES(?,?,?)", (i, tid, msg), w=True)


def staff_ids():
    return [r["id"] for r in q("SELECT id FROM users WHERE role IN('staff','admin')")]


class E(Exception):
    def __init__(self, code, msg):
        self.code, self.msg = code, msg


def q(sql, a=(), one=False, w=False):
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    try:
        cur = c.execute(sql, a)
        if w:
            c.commit()
            return cur.lastrowid
        r = cur.fetchall()
        return (dict(r[0]) if r else None) if one else [dict(x) for x in r]
    finally:
        c.close()


def hp(pw, salt=None):
    salt = salt or secrets.token_hex(8)
    return salt + "$" + hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100000).hex()


def check(pw, stored):
    return secrets.compare_digest(hp(pw, stored.split("$")[0]), stored)


def init():
    os.makedirs(os.path.dirname(os.path.abspath(DB)), exist_ok=True)
    c = sqlite3.connect(DB)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, pw TEXT, role TEXT DEFAULT 'student', roll TEXT, created TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS tickets(id INTEGER PRIMARY KEY, user_id INT, title TEXT, description TEXT, category TEXT, priority TEXT, kind TEXT,
        status TEXT DEFAULT 'Open', assigned_to INT, anonymous INT DEFAULT 0, rating INT, feedback TEXT,
        created TEXT DEFAULT CURRENT_TIMESTAMP, updated TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY, ticket_id INT, user_id INT, body TEXT, internal INT DEFAULT 0, created TEXT DEFAULT CURRENT_TIMESTAMP);
    """)
    c.execute("CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY, user_id INT, ticket_id INT, msg TEXT, seen INT DEFAULT 0, created TEXT DEFAULT CURRENT_TIMESTAMP)")
    for col in ("users ADD COLUMN dept TEXT", "users ADD COLUMN semester TEXT", "users ADD COLUMN phone TEXT",
                "tickets ADD COLUMN image TEXT", "tickets ADD COLUMN resolved TEXT"):
        try:
            c.execute("ALTER TABLE " + col)
        except sqlite3.OperationalError:
            pass
    if not c.execute("SELECT 1 FROM users").fetchone():
        for n, e, p, r, roll in ([("Administrator", os.environ.get("ADMIN_EMAIL", "admin@example.com").strip().lower(), os.environ["ADMIN_PASSWORD"], "admin", "")] if PROD else [("Administrator", "admin@campus.local", "admin123", "admin", ""),
                                 ("Support Staff", "staff@campus.local", "staff123", "staff", ""),
                                 ("Demo Student", "student@campus.local", "student123", "student", "STU-1001")]):
            c.execute("INSERT INTO users(name,email,pw,role,roll) VALUES(?,?,?,?,?)", (n, e, hp(p), r, roll))
    c.commit()
    c.close()


def pub(u):
    return {k: u.get(k) for k in ("id", "name", "email", "role", "roll", "dept", "semester", "phone")}


def need(u, *roles):
    if not u:
        raise E(401, "Please sign in")
    if roles and u["role"] not in roles:
        raise E(403, "You don't have access to this")


def get_ticket(u, tid):
    t = q("""SELECT t.*, us.name owner, us.roll owner_roll, st.name assignee, """ + ESC + """ esc FROM tickets t
             LEFT JOIN users us ON us.id=t.user_id LEFT JOIN users st ON st.id=t.assigned_to WHERE t.id=?""", (tid,), one=True)
    if not t or (u["role"] == "student" and t["user_id"] != u["id"]):
        raise E(404, "Ticket not found")
    if t["anonymous"] and u["role"] != "student":
        t["owner"], t["owner_roll"] = "Anonymous", ""
    return t


def route(h, m, p, qs, b):
    u = h.user()
    if p == "/meta":
        return META
    if p == "/login" and m == "POST":
        k = (h.headers.get("X-Forwarded-For") or h.client_address[0]).split(",")[0].strip() + "|" + b.get("email", "").strip().lower()
        now = time.time()
        FAILS[k] = [x for x in FAILS.get(k, []) if now - x < 600]
        if len(FAILS[k]) >= 5:
            raise E(429, "Too many failed attempts. Try again in 10 minutes.")
        r = q("SELECT * FROM users WHERE email=?", (b.get("email", "").strip().lower(),), one=True)
        if not r or not check(b.get("password", ""), r["pw"]):
            FAILS[k].append(now)
            raise E(401, "Wrong email or password")
        t = secrets.token_hex(16)
        SESS[t] = r["id"]
        return {"user": pub(r)}, {"Set-Cookie": f"sid={t}; HttpOnly; Path=/; SameSite=Lax" + ("; Secure" if h.headers.get("X-Forwarded-Proto") == "https" else "")}
    if p == "/register" and m == "POST":
        name, email, pw = b.get("name", "").strip(), b.get("email", "").strip().lower(), b.get("password", "")
        if not name or not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            raise E(400, "Enter your name and a valid email")
        if len(pw) < 6:
            raise E(400, "Password needs at least 6 characters")
        if q("SELECT 1 FROM users WHERE email=?", (email,), one=True):
            raise E(400, "That email is already registered")
        uid = q("INSERT INTO users(name,email,pw,role,roll) VALUES(?,?,?,'student',?)", (name, email, hp(pw), b.get("roll", "").strip()), w=True)
        t = secrets.token_hex(16)
        SESS[t] = uid
        return {"user": pub(q("SELECT * FROM users WHERE id=?", (uid,), one=True))}, {"Set-Cookie": f"sid={t}; HttpOnly; Path=/; SameSite=Lax" + ("; Secure" if h.headers.get("X-Forwarded-Proto") == "https" else "")}
    if p == "/logout":
        SESS.pop(h.sid(), None)
        return {"ok": True}, {"Set-Cookie": "sid=; Path=/; Max-Age=0"}
    if p == "/me":
        return {"user": pub(u) if u else None}
    need(u)

    if p == "/tickets" and m == "GET":
        sql = """SELECT t.*, us.name owner, st.name assignee, """ + ESC + """ esc FROM tickets t
                 LEFT JOIN users us ON us.id=t.user_id LEFT JOIN users st ON st.id=t.assigned_to WHERE 1=1"""
        a = []
        if u["role"] == "student":
            sql += " AND t.user_id=?"
            a.append(u["id"])
        for k in ("status", "category", "priority", "kind"):
            v = qs.get(k, [""])[0]
            if v:
                sql += f" AND t.{k}=?"
                a.append(v)
        if qs.get("mine", [""])[0] and u["role"] == "staff":
            sql += " AND t.assigned_to=?"
            a.append(u["id"])
        s = qs.get("q", [""])[0]
        if s:
            sql += " AND (t.title LIKE ? OR t.description LIKE ? OR CAST(t.id AS TEXT)=?)"
            a += [f"%{s}%", f"%{s}%", s.lstrip("#")]
        rows = q(sql + " ORDER BY t.id DESC", a)
        for t in rows:
            t["image"] = bool(t["image"])
            if t["anonymous"] and u["role"] != "student":
                t["owner"] = "Anonymous"
        return rows
    if p == "/tickets" and m == "POST":
        need(u, "student")
        title, desc = b.get("title", "").strip(), b.get("description", "").strip()
        if len(title) < 4 or len(desc) < 10:
            raise E(400, "Add a title (4+ characters) and a description (10+ characters)")
        cat, pr, kind = b.get("category"), b.get("priority", "Medium"), b.get("kind", "Complaint")
        if cat not in META["categories"] or pr not in META["priorities"] or kind not in META["kinds"]:
            raise E(400, "Choose a valid category, priority and type")
        img = b.get("image") or None
        if img and (not img.startswith("data:image/") or len(img) > 2_000_000):
            raise E(400, "Attach a picture (PNG, JPG or WebP) under 1.5 MB")
        tid = q("INSERT INTO tickets(user_id,title,description,category,priority,kind,anonymous,image) VALUES(?,?,?,?,?,?,?,?)",
                (u["id"], title, desc, cat, pr, kind, 1 if b.get("anonymous") else 0, img), w=True)
        notify(staff_ids(), tid, f"New {pr} ticket #{tid}: {title}")
        return {"id": tid}

    m1 = re.match(r"^/tickets/(\d+)(?:/(\w+))?$", p)
    if m1:
        tid, act = int(m1.group(1)), m1.group(2)
        t = get_ticket(u, tid)
        if not act and m == "GET":
            t["comments"] = q("""SELECT c.*, us.name author, us.role FROM comments c JOIN users us ON us.id=c.user_id
                                 WHERE ticket_id=? ORDER BY c.id""", (tid,))
            if u["role"] == "student":
                t["comments"] = [c for c in t["comments"] if not c["internal"]]
            return t
        if act == "comments" and m == "POST":
            body = b.get("body", "").strip()
            if not body:
                raise E(400, "Write a message first")
            internal = 1 if (b.get("internal") and u["role"] != "student") else 0
            q("INSERT INTO comments(ticket_id,user_id,body,internal) VALUES(?,?,?,?)", (tid, u["id"], body, internal), w=True)
            q("UPDATE tickets SET updated=CURRENT_TIMESTAMP WHERE id=?", (tid,), w=True)
            if not internal:
                who = [t["user_id"]] if u["role"] != "student" else ([t["assigned_to"]] if t["assigned_to"] else staff_ids())
                notify(who, tid, f"New message on ticket #{tid}", skip=u["id"])
            return {"ok": True}
        if act == "update" and m == "POST":
            need(u, "staff", "admin")
            st, pr, asg = b.get("status", t["status"]), b.get("priority", t["priority"]), b.get("assigned_to", t["assigned_to"]) or None
            if st not in META["statuses"] or pr not in META["priorities"]:
                raise E(400, "Invalid status or priority")
            if asg and not q("SELECT 1 FROM users WHERE id=? AND role IN('staff','admin')", (asg,), one=True):
                raise E(400, "Assignee must be a staff member")
            notes = []
            if st != t["status"]:
                notes.append(f"Status changed to {st}")
            if pr != t["priority"]:
                notes.append(f"Priority changed to {pr}")
            if asg != t["assigned_to"]:
                notes.append("Assigned to " + (q("SELECT name FROM users WHERE id=?", (asg,), one=True)["name"] if asg else "nobody"))
            q("UPDATE tickets SET status=?,priority=?,assigned_to=?,updated=CURRENT_TIMESTAMP,resolved=CASE WHEN ? IN ('Resolved','Closed') THEN COALESCE(resolved,CURRENT_TIMESTAMP) ELSE NULL END WHERE id=?",
              (st, pr, asg, st, tid), w=True)
            for n in notes:
                q("INSERT INTO comments(ticket_id,user_id,body) VALUES(?,?,?)", (tid, u["id"], "• " + n), w=True)
            if notes:
                notify([t["user_id"]], tid, f"Ticket #{tid}: " + "; ".join(notes))
            if asg and asg != t["assigned_to"]:
                notify([asg], tid, f"Ticket #{tid} was assigned to you", skip=u["id"])
            return {"ok": True}
        if act == "rating" and m == "POST":
            need(u, "student")
            r = int(b.get("rating") or 0)
            if t["status"] not in ("Resolved", "Closed") or not 1 <= r <= 5:
                raise E(400, "You can rate 1-5 stars once a ticket is resolved")
            q("UPDATE tickets SET rating=?,feedback=? WHERE id=?", (r, b.get("feedback", "").strip(), tid), w=True)
            return {"ok": True}
    if p == "/notifications":
        rows = q("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 50", (u["id"],))
        return {"items": rows, "unread": sum(1 for r in rows if not r["seen"])}
    if p == "/notifications/read" and m == "POST":
        q("UPDATE notifications SET seen=1 WHERE user_id=?", (u["id"],), w=True)
        return {"ok": True}
    if p == "/profile" and m == "POST":
        name = b.get("name", "").strip()
        if not name:
            raise E(400, "Name can't be empty")
        q("UPDATE users SET name=?,roll=?,dept=?,semester=?,phone=? WHERE id=?",
          (name, b.get("roll", "").strip(), b.get("dept", "").strip(), b.get("semester", "").strip(), b.get("phone", "").strip(), u["id"]), w=True)
        return {"user": pub(q("SELECT * FROM users WHERE id=?", (u["id"],), one=True))}
    if p == "/report.csv":
        need(u, "staff", "admin")
        y, mo = qs.get("year", [""])[0], qs.get("month", [""])[0]
        sql = """SELECT t.id,t.created,t.title,t.kind,t.category,t.priority,t.status,
                 CASE WHEN t.anonymous=1 THEN 'Anonymous' ELSE us.name END owner, CASE WHEN t.anonymous=1 THEN '' ELSE us.dept END dept,
                 st.name assignee,t.resolved,t.rating FROM tickets t LEFT JOIN users us ON us.id=t.user_id
                 LEFT JOIN users st ON st.id=t.assigned_to WHERE 1=1"""
        a = []
        if y:
            sql += " AND strftime('%Y',t.created)=?"
            a.append(y)
        if mo:
            sql += " AND strftime('%m',t.created)=?"
            a.append(mo.zfill(2))
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["ID", "Created", "Title", "Type", "Category", "Priority", "Status", "Raised by", "Department", "Assigned to", "Resolved", "Rating"])
        for r in q(sql + " ORDER BY t.id", a):
            w.writerow(["'" + v if isinstance(v, str) and v[:1] in "=+-@" else v for v in r.values()])
        return buf.getvalue().encode("utf-8-sig"), {"Content-Type": "text/csv; charset=utf-8", "Content-Disposition": "attachment; filename=campuscare-report.csv"}
    if p == "/chat" and m == "POST":
        qn = b.get("question", "").strip()[:300]
        if not qn:
            raise E(400, "Type a question first")
        return chatbot.answer(DB, qn)
    if p == "/chat/status":
        return chatbot.status(DB)
    if p == "/chat/refresh" and m == "POST":
        need(u, "admin")
        threading.Thread(target=chatbot.crawl, args=(DB,), daemon=True).start()
        return {"ok": True}
    if p == "/staff":
        need(u, "staff", "admin")
        return q("SELECT id,name,role FROM users WHERE role IN('staff','admin') ORDER BY name")
    if p == "/stats":
        need(u, "staff", "admin")
        return {
            "total": q("SELECT COUNT(*) n FROM tickets", one=True)["n"],
            "urgent": q("SELECT COUNT(*) n FROM tickets WHERE priority='Urgent' AND status IN('Open','In Progress')", one=True)["n"],
            "unassigned": q("SELECT COUNT(*) n FROM tickets WHERE assigned_to IS NULL AND status='Open'", one=True)["n"],
            "rating": q("SELECT ROUND(AVG(rating),1) a FROM tickets WHERE rating IS NOT NULL", one=True)["a"],
            "by_status": q("SELECT status k, COUNT(*) n FROM tickets GROUP BY status"),
            "by_category": q("SELECT category k, COUNT(*) n FROM tickets GROUP BY category ORDER BY n DESC"),
            "escalated": q("SELECT COUNT(*) n FROM tickets t WHERE " + ESC, one=True)["n"],
            "avg_hours": q("SELECT ROUND(AVG((julianday(resolved)-julianday(created))*24),1) a FROM tickets WHERE resolved IS NOT NULL", one=True)["a"],
            "monthly": q("SELECT strftime('%Y-%m',created) k, COUNT(*) n, SUM(resolved IS NOT NULL) done FROM tickets GROUP BY k ORDER BY k DESC LIMIT 12"),
            "by_dept": q("SELECT COALESCE(NULLIF(us.dept,''),'Not set') k, COUNT(*) n FROM tickets t JOIN users us ON us.id=t.user_id GROUP BY k ORDER BY n DESC"),
        }
    if p == "/users" and m == "GET":
        need(u, "admin")
        return q("SELECT id,name,email,role,roll,created FROM users ORDER BY id")
    m2 = re.match(r"^/users/(\d+)/role$", p)
    if m2 and m == "POST":
        need(u, "admin")
        if b.get("role") not in ("student", "staff", "admin") or int(m2.group(1)) == u["id"]:
            raise E(400, "Invalid role, or you tried to change your own role")
        q("UPDATE users SET role=? WHERE id=?", (b["role"], int(m2.group(1))), w=True)
        return {"ok": True}
    raise E(404, "Not found")


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def sid(self):
        m = re.search(r"sid=(\w+)", self.headers.get("Cookie", ""))
        return m.group(1) if m else None

    def user(self):
        uid = SESS.get(self.sid())
        return q("SELECT * FROM users WHERE id=?", (uid,), one=True) if uid else None

    def out(self, code, body, ctype="application/json", headers=None):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        hd = dict(headers or {})
        self.send_header("Content-Type", hd.pop("Content-Type", ctype))
        self.send_header("Content-Length", str(len(data)))
        for k, v in hd.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def handle_any(self, m):
        pu = urlparse(self.path)
        if not pu.path.startswith("/api"):
            with open(os.path.join(HERE, "index.html"), "rb") as f:
                return self.out(200, f.read(), "text/html; charset=utf-8")
        b = {}
        if m == "POST":
            ln = int(self.headers.get("Content-Length") or 0)
            if ln > 3_000_000:
                return self.out(413, {"error": "Request too large"})
            try:
                b = json.loads(self.rfile.read(ln) or b"{}")
            except ValueError:
                return self.out(400, {"error": "Bad request"})
        try:
            r = route(self, m, pu.path[4:], parse_qs(pu.query), b)
            body, hd = r if isinstance(r, tuple) else (r, None)
            self.out(200, body, headers=hd)
        except E as e:
            self.out(e.code, {"error": e.msg})
        except Exception as e:
            import traceback; traceback.print_exc()
            self.out(500, {"error": "Something went wrong on the server"})

    def do_GET(self):
        self.handle_any("GET")

    def do_POST(self):
        self.handle_any("POST")


if __name__ == "__main__":
    init()
    if os.environ.get("AUTO_CRAWL", "1" if PROD else "0") == "1" and not chatbot.status(DB)["chunks"]:
        threading.Thread(target=chatbot.crawl, args=(DB,), daemon=True).start()
    print(f"Campus Care running on {HOST}:{PORT}  (Ctrl+C to stop)")
    ThreadingHTTPServer((HOST, PORT), H).serve_forever()
