"""Campus Care help bot. Crawls the institute website (stdlib only), stores text passages in SQLite,
and answers by retrieving the best-matching passages (BM25) with links to the source pages."""
import re, math, time, sqlite3, urllib.request, urllib.robotparser
from urllib.parse import urljoin, urlparse, urldefrag
from html.parser import HTMLParser
from collections import Counter

# Edit this list: keep the official site(s) that work for your institute.
START_URLS = ["https://www.msijanakpuri.com/", "https://www.msi-ggsip.org/"]
MAX_PAGES, DELAY = 80, 1.0          # pages per site, seconds between requests
UA = "CampusCareBot/1.0 (student project; polite crawler)"
STOP = set("a an the is are was were be to of in on at for and or do does did i me my we you your can how what when where which who with from by about it this that there tell please give".split())
BLOCK = {"p", "div", "li", "br", "h1", "h2", "h3", "h4", "h5", "h6", "tr", "section", "ul", "table"}
SKIPT = {"script", "style", "noscript", "svg", "iframe"}
SYN = {"located": "address", "location": "address", "reach": "address", "call": "phone", "mobile": "phone", "contact": "phone email address", "mail": "email", "cost": "fee fees", "fees": "fee", "fee": "fees"}
STATE = {"running": False, "msg": "Website not loaded yet", "pages": 0}


class P(HTMLParser):
    def __init__(s):
        super().__init__()
        s.t, s.links, s.title, s.skip, s.intitle = [], [], "", 0, False

    def handle_starttag(s, tag, a):
        if tag in SKIPT: s.skip += 1
        elif tag == "title": s.intitle = True
        elif tag == "a" and dict(a).get("href"): s.links.append(dict(a)["href"])
        if tag in BLOCK: s.t.append("\n")

    def handle_endtag(s, tag):
        if tag in SKIPT: s.skip = max(0, s.skip - 1)
        elif tag == "title": s.intitle = False
        if tag in BLOCK: s.t.append("\n")

    def handle_data(s, d):
        if s.intitle: s.title += d
        elif not s.skip: s.t.append(d)


def get(url, html_only=True):
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=10) as r:
        if html_only and "html" not in r.headers.get("Content-Type", ""): return None
        return r.read(1_500_000).decode(r.headers.get_content_charset() or "utf-8", "replace")


def robots(start):
    rp = urllib.robotparser.RobotFileParser()
    try: rp.parse(get(urljoin(start, "/robots.txt"), False).splitlines())
    except Exception: rp.parse([])
    rp.modified()
    return rp


def passages(lines, size=550):
    buf = ""
    for l in lines:
        buf = (buf + " " + l).strip()
        if len(buf) >= size: yield buf; buf = ""
    if len(buf) > 40: yield buf


def crawl(db):
    if STATE["running"]: return
    STATE.update(running=True, msg="Reading the website...", pages=0)
    try:
        rows, seen_text = [], set()
        for start in START_URLS:
            host, rp = urlparse(start).netloc.replace("www.", ""), robots(start)
            queue, seen, n = [start], {start}, 0
            while queue and n < MAX_PAGES:
                url = queue.pop(0)
                if not rp.can_fetch(UA, url): continue
                try: html = get(url)
                except Exception: continue
                time.sleep(DELAY)
                if not html: continue
                n += 1; STATE["pages"] += 1; STATE["msg"] = f"Read {STATE['pages']} pages..."
                p = P(); p.feed(html)
                for h in p.links:
                    u = urldefrag(urljoin(url, h))[0]; pu = urlparse(u)
                    if pu.scheme in ("http", "https") and pu.netloc.replace("www.", "") == host and u not in seen \
                       and not re.search(r"\.(pdf|jpe?g|png|gif|webp|docx?|xlsx?|pptx?|zip|mp4)$", pu.path, re.I):
                        seen.add(u); queue.append(u)
                lines = [re.sub(r"\s+", " ", l).strip() for l in "".join(p.t).split("\n")]
                for body in passages([l for l in lines if len(l) > 2]):
                    if body not in seen_text:
                        seen_text.add(body); rows.append((url, p.title.strip(), body))
        if not rows:
            STATE["msg"] = "Could not read any pages. Check the internet connection and START_URLS in chatbot.py."
            return
        c = sqlite3.connect(db)
        c.execute("CREATE TABLE IF NOT EXISTS chunks(id INTEGER PRIMARY KEY, url TEXT, title TEXT, body TEXT, fetched TEXT DEFAULT CURRENT_TIMESTAMP)")
        c.execute("DELETE FROM chunks")
        c.executemany("INSERT INTO chunks(url,title,body) VALUES(?,?,?)", rows)
        c.commit(); c.close()
        STATE["msg"] = f"Done: {len(rows)} passages from {STATE['pages']} pages."
    except Exception as e:
        STATE["msg"] = "Update failed: " + str(e)
    finally:
        STATE["running"] = False


def status(db):
    try:
        c = sqlite3.connect(db)
        n, u, t = c.execute("SELECT COUNT(*),COUNT(DISTINCT url),MAX(fetched) FROM chunks").fetchone()
        c.close()
    except sqlite3.OperationalError:
        n = u = t = 0
    return {**STATE, "chunks": n, "pages_stored": u, "updated": t}


def tok(s):
    return [w for w in re.findall(r"[a-z0-9]+", s.lower()) if w not in STOP and len(w) > 1]


def answer(db, question):
    qt = set(tok(question))
    qt |= {x for w in list(qt) for x in SYN.get(w, '').split()}
    if not qt or qt <= {"hi", "hii", "hello", "hey", "thanks", "thank", "ok"}:
        return {"answer": "Hi! Ask me about admissions, courses, fees, placements, the library or contact details.", "sources": []}
    try:
        c = sqlite3.connect(db)
        rows = c.execute("SELECT url,title,body,fetched FROM chunks").fetchall()
        c.close()
    except sqlite3.OperationalError:
        rows = []
    if not rows:
        return {"answer": "I haven't read the college website yet. Ask an administrator to press Update from website.", "sources": []}
    docs = [tok(r[1] + " " + r[2]) for r in rows]
    N, avg = len(docs), (sum(map(len, docs)) / len(docs)) or 1
    df = Counter(w for d in docs for w in set(d))
    scored = []
    for r, d in zip(rows, docs):
        tf, s = Counter(d), 0
        for w in qt & set(tf):
            s += math.log(1 + (N - df[w] + .5) / (df[w] + .5)) * tf[w] * 2.2 / (tf[w] + 1.2 * (.25 + .75 * len(d) / avg))
        scored.append((s, r))
    scored.sort(key=lambda x: -x[0])
    if scored[0][0] < 0.5:
        return {"answer": "I couldn't find that on the college website. Try different words, or raise a ticket so staff can help.", "sources": []}
    top = [x for x in scored[:3] if x[0] >= scored[0][0] * .5]
    src, seen = [], set()
    for _, r in top:
        if r[0] not in seen: seen.add(r[0]); src.append({"url": r[0], "title": r[1] or r[0]})
    text = "\n\n".join(r[2] for _, r in top)
    return {"answer": "From the college website:\n" + text + f"\n\n(Website data as of {top[0][1][3][:10]}. Please confirm important details with the office.)", "sources": src}
