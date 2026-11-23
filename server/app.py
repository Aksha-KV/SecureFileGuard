#!/usr/bin/env python3
"""SecureFileGuard web lab - stdlib-only server around the C++ guard variants.

Safety design (this site is *about* path traversal, so it must not have one):
  * The jail root is fixed by the server; web users only supply a relative/absolute test string.
  * Responses contain decisions only for outside-jail queries - never file contents or outside paths.
  * Static files come from a fixed whitelist, not from the request path.
  * Binaries are run with an argument list (no shell), with timeouts and size limits.
  * POST endpoints enforce Host/Origin validation and Content-Type: application/json.
  * In-memory per-IP rate limiting protects against resource exhaustion.
Run:  make && python3 server/app.py [--host 127.0.0.1] [--port 8000] [--no-rate-limit]
"""
import argparse, csv, datetime, json, os, platform, re, subprocess, sys, threading, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
CLI = os.path.join(BASE, "build", "guard_cli")
RACE = os.path.join(BASE, "build", "toctou_race")
RUN_TESTS = os.path.join(BASE, "build", "run_tests")
FIX = os.path.join(BASE, "runtime", "fixtures")
STATIC = {"/": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/style.css": ("style.css", "text/css; charset=utf-8"),
          "/research": ("research.html", "text/html; charset=utf-8"),
          "/results": ("results.html", "text/html; charset=utf-8"),
          "/charts.js": ("charts.js", "text/javascript; charset=utf-8"),
          "/logo.svg": ("logo.svg", "image/svg+xml")}
RESULTS_CSV = os.path.join(BASE, "results", "results.csv")
MAX_BODY = 20000
JAIL = ""
race_lock = threading.Lock()
ALLOWED_HOSTS = set()
TRUST_PROXY = False


class RateLimiter:
    def __init__(self, enabled=True, max_keys=10000):
        self.enabled = enabled
        self.max_keys = max_keys
        self.lock = threading.Lock()
        self.requests = {}       # ip -> list of timestamps
        self.race_requests = {}  # ip -> list of timestamps

    def _prune(self, store, now):
        cutoff = now - 60.0
        # Evict keys with no active timestamps in the last 60 seconds
        stale_ips = [ip for ip, ts in store.items() if not ts or ts[-1] <= cutoff]
        for ip in stale_ips:
            del store[ip]
        # If still exceeding capacity limit, evict oldest by latest timestamp
        if len(store) > self.max_keys:
            sorted_ips = sorted(store.keys(), key=lambda k: store[k][-1] if store[k] else 0)
            for k in sorted_ips[:len(store) - self.max_keys]:
                del store[k]

    def check(self, ip, is_race=False):
        if not self.enabled:
            return True
        now = time.time()
        with self.lock:
            limit = 10 if is_race else 60
            store = self.race_requests if is_race else self.requests
            self._prune(store, now)
            timestamps = [t for t in store.get(ip, []) if t > (now - 60.0)]
            if len(timestamps) >= limit:
                store[ip] = timestamps
                return False
            timestamps.append(now)
            store[ip] = timestamps
            return True


RATE_LIMITER = RateLimiter(enabled=True)

VARIANT_INFO = [
    ("V0", "naive prefix", "Joins root + input and checks the raw string starts with root. Fooled by '..', by sibling folders like secure_files_backup, and by missing files."),
    ("V1", "lexically_normal", "Cleans '.' and '..' in the string, then compares path components. Never touches the disk, so symlinks are invisible to it."),
    ("V2", "weakly_canonical", "Resolves symlinks for the part of the path that exists. Stops symlink escapes but still checks first, opens later (race)."),
    ("V3", "canonical", "Resolves every symlink; the target must exist. Strongest 'check then open' design but still racy and does not check file type."),
    ("V4", "openat2 BENEATH", "Asks the kernel to resolve AND open in one call, refusing to leave the jail. No gap to race. Denies absolute symlinks even when they point inside."),
]

# (category, label, path template). 36 items corresponding to tests/test_cases.cpp.
PRESETS = [
    ("legit", "notes.txt", "notes.txt"),
    ("legit", "reports/marks.txt", "reports/marks.txt"),
    ("legit", "./notes.txt", "./notes.txt"),
    ("legit", "reports/../notes.txt", "reports/../notes.txt"),
    ("legit", "a..b.txt", "a..b.txt"),
    ("legit", "internal_link.txt", "internal_link.txt"),
    ("traversal", "../outside_secret.txt", "../outside_secret.txt"),
    ("traversal", "../../etc/passwd", "../../etc/passwd"),
    ("traversal", "reports/../../outside_secret.txt", "reports/../../outside_secret.txt"),
    ("traversal", "8x ../ then etc/passwd", "../../../../../../../../etc/passwd"),
    ("absolute", "/etc/passwd", "/etc/passwd"),
    ("absolute", "<root>/notes.txt (absolute)", "@ROOT@/notes.txt"),
    ("prefix", "../secure_files_backup/private.txt", "../secure_files_backup/private.txt"),
    ("symlink", "link_to_outside_file", "link_to_outside_file"),
    ("symlink", "link_to_outside_dir/secret.txt", "link_to_outside_dir/secret.txt"),
    ("symlink", "chain_a (2-hop chain)", "chain_a"),
    ("error", "missing.txt", "missing.txt"),
    ("error", "broken_link", "broken_link"),
    ("error", "(empty)", ""),
    ("error", "5000 x 'a'", "a" * 5000),
    ("special", ". (directory)", "."),
    ("special", "reports (directory)", "reports"),
    ("special", "fifo", "fifo"),
    ("legit", "reports//marks.txt", "reports//marks.txt"),
    ("traversal", "notes.txt/../../outside_secret.txt", "notes.txt/../../outside_secret.txt"),
    ("symlink", "loop_a (symlink loop)", "loop_a"),
    ("symlink", "abs_internal_link", "abs_internal_link"),
    ("encoded", "..%2f..%2fetc%2fpasswd", "..%2f..%2fetc%2fpasswd"),
    ("encoded", "backslashes", "..\\..\\etc\\passwd"),
    ("error", "notes.txt/ (trailing slash)", "notes.txt/"),
    # Part 3 edge cases
    ("error", "notes.txt... (trailing dots)", "notes.txt..."),
    ("traversal", "//etc/passwd (double-slash root)", "//etc/passwd"),
    ("symlink", "reports/sub_escape (symlink up & out)", "reports/sub_escape"),
    ("traversal", "link_to_reports/../../outside_secret.txt", "link_to_reports/../../outside_secret.txt"),
    ("legit", "200-component deep path (./ x 200)", ("./" * 200) + "notes.txt"),
    ("legit", "sécurité_🔒.txt (UTF-8 filename)", "sécurité_🔒.txt"),
]


def expand(t):
    return t.replace("@ROOT@", JAIL)


def get_environment():
    kernel = platform.release()
    try:
        wsl = "microsoft" in platform.uname().release.lower() or os.path.exists("/proc/sys/fs/binfmt_misc/WSLInterop")
    except Exception:
        wsl = False
    gxx_ver = "unknown"
    try:
        p = subprocess.run(["g++", "--version"], capture_output=True, text=True, timeout=2)
        if p.returncode == 0:
            gxx_ver = p.stdout.splitlines()[0]
    except Exception:
        pass
    return {
        "kernel": kernel,
        "compiler": gxx_ver,
        "cpus": os.cpu_count() or 1,
        "wsl": wsl,
        "oracle": "realpath(3) (independent POSIX resolution)"
    }


def run_cli(path):
    p = subprocess.run([CLI, JAIL], input=path.encode("utf-8", "replace"), capture_output=True, timeout=5)
    if p.returncode != 0:
        raise RuntimeError("guard_cli failed")
    return json.loads(p.stdout.decode("utf-8", "replace"))


def suite():
    rows, names = [], None
    tot = {}
    for i, (cat, label, tpl) in enumerate(PRESETS):
        r = run_cli(expand(tpl))
        names = names or [v["id"] for v in r["variants"]]
        rows.append({
            "id": i,
            "category": cat,
            "label": label,
            "expected": r["expected"],
            "reason": r["reason"],
            "variants": r["variants"]
        })
        is_attack = ((cat in ("traversal", "symlink", "prefix", "absolute") and r["expected"] == "DENY")
                     or ("broken_link" in label) or ("sub_escape" in label))
        if "NUL" in label:
            is_attack = True
        is_type = (cat == "special")
        is_missing = (cat in ("error", "encoded") and not is_attack)
        is_legit = (r["expected"] == "ALLOW")

        for v in r["variants"]:
            t = tot.setdefault(v["id"], {
                "name": v["name"],
                "ta": 0, "tb": 0,
                "containment_failures": 0,
                "type_mismatches": 0,
                "policy_mismatches": 0,
                "false_blocks": 0,
                "attacks_total": 0,
                "attacks_denied": 0,
                "legit_total": 0,
                "legit_allowed": 0,
                "type_total": 0,
                "missing_total": 0,
                "total": 0
            })
            t["total"] += 1
            if is_attack:
                t["attacks_total"] += 1
                if v["decision"] == "DENY":
                    t["attacks_denied"] += 1
            elif is_type:
                t["type_total"] += 1
            elif is_missing:
                t["missing_total"] += 1
            elif is_legit:
                t["legit_total"] += 1
                if v["decision"] == "ALLOW":
                    t["legit_allowed"] += 1

            verd = v["verdict"]
            if verd == "correct":
                if r["expected"] == "ALLOW":
                    t["ta"] += 1
                else:
                    t["tb"] += 1
            elif verd in ("containment_failure", "false_allow"):
                t["containment_failures"] += 1
            elif verd == "type_mismatch":
                t["type_mismatches"] += 1
            elif verd == "policy_mismatch":
                t["policy_mismatches"] += 1
            elif verd == "false_block":
                t["false_blocks"] += 1

    metrics = []
    for vid in names:
        t = tot[vid]
        att = t["attacks_total"]
        leg = t["legit_total"]
        typ = t["type_total"]
        mis = t["missing_total"]
        tb = t["attacks_denied"]
        ta = t["legit_allowed"]
        cf = t["containment_failures"]
        tm = t["type_mismatches"]
        pm = t["policy_mismatches"]
        fb = t["false_blocks"]
        correct = t["ta"] + t["tb"]

        safe_cnt = att - cf
        type_cnt = typ - tm
        mis_cnt = mis - pm

        metrics.append({
            "id": vid,
            "name": t["name"],
            # Four core percentage metrics with counts:
            "containment_safe_rate": round(100.0 * safe_cnt / att, 1) if att else 100.0,
            "containment_safe_count": f"{safe_cnt}/{att}",
            "type_policy_rate": round(100.0 * type_cnt / typ, 1) if typ else 100.0,
            "type_policy_count": f"{type_cnt}/{typ}",
            "missing_policy_rate": round(100.0 * mis_cnt / mis, 1) if mis else 100.0,
            "missing_policy_count": f"{mis_cnt}/{mis}",
            "allow_rate": round(100.0 * ta / leg, 1) if leg else 0.0,
            "allow_count": f"{ta}/{leg}",
            # Raw counts:
            "containment_failures": cf,
            "type_mismatches": tm,
            "policy_mismatches": pm,
            "false_blocks": fb,
            "attacks_total": att,
            "attacks_denied": tb,
            "legit_total": leg,
            "legit_allowed": ta,
            "type_total": typ,
            "missing_total": mis,
            # Backwards compatibility
            "block_rate": round(100.0 * tb / att, 1) if att else None,
            "accuracy": round(100.0 * correct / len(PRESETS), 1),
            "false_allows": cf
        })
    try:
        save_suite_to_csv(rows)
    except Exception as e:
        print("Notice: could not save suite to CSV:", e)
    return {"rows": rows, "metrics": metrics, "n": len(PRESETS)}


def save_suite_to_csv(rows, target_path=RESULTS_CSV):
    try:
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with open(target_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "variant", "technique", "test_id", "category", "path",
                "expected", "actual", "verdict", "containment", "type_check", "policy_check"
            ])
            for r in rows:
                for v in r.get("variants", []):
                    verd = v.get("verdict", "")
                    cont = "FAIL" if verd in ("containment_failure", "false_allow") else "PASS"
                    typ = "FAIL" if verd == "type_mismatch" else "PASS"
                    pol = "FAIL" if verd == "policy_mismatch" else "PASS"
                    clean_path = r.get("label", "")
                    if len(clean_path) > 36:
                        clean_path = clean_path[:28] + "...(len=" + str(len(clean_path)) + ")"
                    writer.writerow([
                        v.get("id", ""),
                        v.get("name", ""),
                        r.get("id", 0),
                        r.get("category", ""),
                        clean_path,
                        r.get("expected", ""),
                        v.get("decision", ""),
                        verd,
                        cont,
                        typ,
                        pol
                    ])
        static_csv = os.path.join(HERE, "static", "results.csv")
        try:
            import shutil
            shutil.copyfile(target_path, static_csv)
        except Exception:
            pass
    except Exception as e:
        print("Warning: unable to save suite to CSV:", e)


def ensure_results_csv():
    """Ensure results/results.csv exists and is readable. Auto-generates if missing."""
    if os.path.exists(RESULTS_CSV) and os.path.getsize(RESULTS_CSV) > 0:
        return True

    os.makedirs(os.path.dirname(RESULTS_CSV), exist_ok=True)
    static_csv = os.path.join(HERE, "static", "results.csv")
    if os.path.exists(static_csv) and os.path.getsize(static_csv) > 0:
        try:
            import shutil
            shutil.copyfile(static_csv, RESULTS_CSV)
            return True
        except Exception:
            pass

    # Try running build/run_tests if binary and fixtures are present
    if os.path.exists(RUN_TESTS) and os.path.exists(FIX):
        try:
            p = subprocess.run([RUN_TESTS, FIX, RESULTS_CSV], capture_output=True, timeout=30)
            if p.returncode == 0 and os.path.exists(RESULTS_CSV) and os.path.getsize(RESULTS_CSV) > 0:
                try:
                    import shutil
                    shutil.copyfile(RESULTS_CSV, static_csv)
                except Exception:
                    pass
                return True
        except Exception as e:
            print("Notice: build/run_tests in ensure_results_csv failed:", e)

    # Fallback to generating via suite() if CLI binary is present
    if os.path.exists(CLI):
        try:
            suite()
            if os.path.exists(RESULTS_CSV) and os.path.getsize(RESULTS_CSV) > 0:
                return True
        except Exception as e:
            print("Notice: suite() generation in ensure_results_csv failed:", e)

    return os.path.exists(RESULTS_CSV) and os.path.getsize(RESULTS_CSV) > 0


def fixtures_tree():
    out = []
    base = os.path.dirname(JAIL)
    for d, dirs, files in os.walk(base):
        for name in sorted(dirs + files):
            full = os.path.join(d, name)
            rel = os.path.relpath(full, base)
            if os.path.islink(full):
                out.append({"path": rel, "type": "symlink", "target": os.readlink(full)})
            elif os.path.isdir(full):
                out.append({"path": rel, "type": "dir"})
            else:
                import stat
                m = os.lstat(full).st_mode
                out.append({"path": rel, "type": "fifo" if stat.S_ISFIFO(m) else "file"})
    return sorted(out, key=lambda e: e["path"])


def race(iters, runs=1):
    if not race_lock.acquire(blocking=False):
        return 429, {"error": "A race demo is already running. Try again in a few seconds."}
    try:
        p = subprocess.run([RACE, str(iters), str(runs)], capture_output=True, timeout=180)
        text = p.stdout.decode("utf-8", "replace")
        # Try JSON output first from toctou_race
        try:
            m = re.search(r"JSON_OUTPUT_START\s*(\{.*?\})\s*JSON_OUTPUT_END", text, re.DOTALL)
            if m:
                data = json.loads(m.group(1))
                return 200, data
        except Exception:
            pass

        rows = []
        for ln in text.splitlines():
            m = re.match(r"^(V\d.*?)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$", ln)
            if m:
                rows.append({
                    "variant": m.group(1).strip(),
                    "attempts": int(m.group(2)),
                    "allowed": int(m.group(3)),
                    "opened": int(m.group(4)),
                    "escapes": int(m.group(5)),
                    "escapes_min": int(m.group(5)),
                    "escapes_max": int(m.group(5)),
                    "escapes_total": int(m.group(5)),
                    "runs": [int(m.group(5))]
                })
        return 200, {"iterations": iters, "runs": runs, "rows": rows, "environment": get_environment()}
    except subprocess.TimeoutExpired:
        return 504, {"error": "Race demo timed out."}
    finally:
        race_lock.release()


def results_summary():
    """Aggregate results/results.csv (written by build/run_tests) into per-variant metrics."""
    ensure_results_csv()
    with open(RESULTS_CSV, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    order, per, detail = [], {}, {}
    for r in rows:
        v = r["variant"]
        if v not in per:
            order.append(v)
            per[v] = {
                "id": v,
                "name": r["technique"],
                "attacks_total": 0,
                "attacks_denied": 0,
                "legit_total": 0,
                "legit_allowed": 0,
                "type_total": 0,
                "missing_total": 0,
                "containment_failures": 0,
                "type_mismatches": 0,
                "policy_mismatches": 0,
                "false_blocks": 0,
                "correct": 0,
                "total": 0
            }
        p = per[v]
        p["total"] += 1
        cat = r.get("category", "")
        exp = r["expected"]
        act = r["actual"]
        verd = r.get("verdict", "")

        is_attack = ((cat in ("traversal", "symlink", "prefix", "absolute") and exp == "DENY")
                     or ("broken_link" in r.get("path", "")) or ("sub_escape" in r.get("path", "")))
        is_type = (cat == "special")
        is_missing = (cat in ("error", "encoded") and not is_attack)
        is_legit = (exp == "ALLOW")

        if is_attack:
            p["attacks_total"] += 1
            if act == "DENY":
                p["attacks_denied"] += 1
        elif is_type:
            p["type_total"] += 1
        elif is_missing:
            p["missing_total"] += 1
        elif is_legit:
            p["legit_total"] += 1
            if act == "ALLOW":
                p["legit_allowed"] += 1

        if verd == "correct":
            p["correct"] += 1
        elif verd in ("containment_failure", "false_allow"):
            p["containment_failures"] += 1
        elif verd == "type_mismatch":
            p["type_mismatches"] += 1
        elif verd == "policy_mismatch":
            p["policy_mismatches"] += 1
        elif verd == "false_block":
            p["false_blocks"] += 1

        d = detail.setdefault(int(r["test_id"]), {
            "id": int(r["test_id"]),
            "category": r["category"],
            "path": r["path"],
            "expected": r["expected"],
            "results": {},
            "actual": {}
        })
        d["results"][v] = verd
        d["actual"][v] = act

    out = []
    for v in order:
        p = per[v]
        att = p["attacks_total"]
        leg = p["legit_total"]
        typ = p["type_total"]
        mis = p["missing_total"]
        cf = p["containment_failures"]
        tm = p["type_mismatches"]
        pm = p["policy_mismatches"]

        safe_cnt = att - cf
        type_cnt = typ - tm
        mis_cnt = mis - pm

        p["containment_safe_rate"] = round(100.0 * safe_cnt / att, 1) if att else 100.0
        p["containment_safe_count"] = f"{safe_cnt}/{att}"
        p["type_policy_rate"] = round(100.0 * type_cnt / typ, 1) if typ else 100.0
        p["type_policy_count"] = f"{type_cnt}/{typ}"
        p["missing_policy_rate"] = round(100.0 * mis_cnt / mis, 1) if mis else 100.0
        p["missing_policy_count"] = f"{mis_cnt}/{mis}"
        p["allow_rate"] = round(100.0 * p["legit_allowed"] / leg, 1) if leg else 0.0
        p["allow_count"] = f"{p['legit_allowed']}/{leg}"

        p["block_rate"] = round(100.0 * p["attacks_denied"] / att, 1) if att else None
        p["success_rate"] = round(100.0 * p["legit_allowed"] / leg, 1) if leg else None
        p["accuracy"] = round(100.0 * p["correct"] / p["total"], 1) if p["total"] else None
        p["false_allow"] = cf
        p["false_block"] = p["false_blocks"]
        p["unauthorised"] = att
        p["blocked_ok"] = p["attacks_denied"]
        p["legitimate"] = leg
        p["allowed_ok"] = p["legit_allowed"]
        out.append(p)

    first = per[order[0]] if order else {"attacks_total": 0, "legit_total": 0, "total": 0}
    return {
        "tests": first["total"],
        "unauthorised": first.get("attacks_total", 0),
        "legitimate": first.get("legit_total", 0),
        "variants": out,
        "tests_detail": [detail[k] for k in sorted(detail)]
    }


def is_host_allowed(host_str, allowed_set):
    """Checks if a Host header or Origin netloc matches the allowed host specifications.
    Supports exact host:port, host-only (defaulting any port), wildcard subdomains (*.example.com), or wildcard *."""
    if not host_str:
        return False
    host_str = host_str.lower().strip()
    if "*" in allowed_set:
        return True
    if host_str in allowed_set:
        return True
    host_only = host_str.split(":")[0]
    if host_only in allowed_set:
        return True
    for entry in allowed_set:
        if entry == "*":
            return True
        entry_only = entry.split(":")[0]
        if ":" not in entry and host_only == entry_only:
            return True
        if entry.startswith("*."):
            suffix = entry[2:]
            if host_only.endswith("." + suffix) or host_only == suffix:
                return True
    return False


class H(BaseHTTPRequestHandler):
    server_version = "SFGLab"
    timeout = 10  # A3: per-connection socket timeout

    def log_message(self, fmt, *a):
        sys.stderr.write("[%s] %s\n" % (self.address_string(), fmt % a))

    def get_client_ip(self):
        if TRUST_PROXY:
            xff = self.headers.get("X-Forwarded-For")
            if xff:
                return xff.split(",")[0].strip()
        return self.client_address[0]

    def get_allowed_hosts(self):
        server_host = self.server.server_address[0]
        server_port = self.server.server_address[1]
        allowed = set(ALLOWED_HOSTS)
        if server_host in ("127.0.0.1", "localhost", "::1", "0.0.0.0"):
            allowed.update({
                f"127.0.0.1:{server_port}", "127.0.0.1",
                f"localhost:{server_port}", "localhost"
            })
        else:
            allowed.update({
                f"{server_host}:{server_port}", server_host,
                f"127.0.0.1:{server_port}", "127.0.0.1",
                f"localhost:{server_port}", "localhost"
            })
        return {h.lower() for h in allowed}

    def validate_host_and_origin(self):
        allowed = self.get_allowed_hosts()
        host_header = self.headers.get("Host", "").strip().lower()
        if not host_header or not is_host_allowed(host_header, allowed):
            self.send(403, {"error": "forbidden host: invalid Host header"})
            return False

        origin_header = self.headers.get("Origin")
        if origin_header:
            parsed = urllib.parse.urlparse(origin_header)
            origin_netloc = parsed.netloc.lower()
            if not is_host_allowed(origin_netloc, allowed):
                self.send(403, {"error": "forbidden origin"})
                return False
        return True

    def send(self, code, body, ctype="application/json; charset=utf-8", headers=None):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        if headers:
            for k, val in (headers.items() if isinstance(headers, dict) else headers):
                self.send_header(k, str(val))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self.validate_host_and_origin():
            return

        client_ip = self.get_client_ip()
        route = self.path.split("?", 1)[0]
        if route.startswith("/api/") and not RATE_LIMITER.check(client_ip, is_race=False):
            return self.send(429, {"error": "rate limit exceeded: too many requests"})

        if route in STATIC:
            fn, ct = STATIC[route]
            with open(os.path.join(HERE, "static", fn), "rb") as f:
                return self.send(200, f.read(), ct)
        if route in ("/results.csv", "/api/results.csv"):
            ensure_results_csv()
            try:
                with open(RESULTS_CSV, "rb") as f:
                    csv_data = f.read()
                return self.send(
                    200,
                    csv_data,
                    "text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="results.csv"'}
                )
            except OSError:
                return self.send(404, {"error": "results/results.csv not found"})
        if route == "/api/results":
            ensure_results_csv()
            try:
                return self.send(200, results_summary())
            except (OSError, KeyError, ValueError) as err:
                return self.send(404, {"error": f"results/results.csv missing or unreadable: {err}"})
        if route == "/api/info":
            return self.send(200, {
                "root": JAIL,
                "policy": "strict (missing = deny)",
                "oracle_method": "realpath(3)",
                "environment": get_environment(),
                "test_cases_count": len(PRESETS),
                "date_generated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "variants": [{"id": a, "name": b, "desc": c} for a, b, c in VARIANT_INFO],
                "presets": [{"id": i, "category": c, "label": l, "path": (expand(t) if len(t) <= 200 else None)}
                            for i, (c, l, t) in enumerate(PRESETS)],
                "tree": fixtures_tree()
            })
        self.send(404, {"error": "not found"})

    def do_POST(self):
        if not self.validate_host_and_origin():
            return

        content_type = self.headers.get("Content-Type", "")
        media_type = content_type.split(";")[0].strip().lower()
        if media_type != "application/json":
            return self.send(403, {"error": "Content-Type must be application/json"})

        client_ip = self.get_client_ip()
        route = self.path.split("?", 1)[0]
        is_race = (route == "/api/race")
        if not RATE_LIMITER.check(client_ip, is_race=is_race):
            return self.send(429, {"error": "rate limit exceeded: too many requests"})

        try:
            n = int(self.headers.get("Content-Length", "0"))
            if n < 0 or n > MAX_BODY:
                return self.send(413, {"error": "body too large"})
            data = json.loads(self.rfile.read(n) or b"{}")
            if not isinstance(data, dict):
                raise ValueError
        except Exception:
            return self.send(400, {"error": "bad JSON"})

        try:
            if route == "/api/check":
                if "preset" in data:
                    i = int(data["preset"])
                    if not 0 <= i < len(PRESETS):
                        return self.send(400, {"error": "bad preset"})
                    path = expand(PRESETS[i][2])
                else:
                    path = data.get("path", "")
                    if not isinstance(path, str) or len(path) > 6000:
                        return self.send(400, {"error": "path must be a string up to 6000 chars"})
                r = run_cli(path)
                return self.send(200, r)
            if route == "/api/suite":
                return self.send(200, suite())
            if route == "/api/race":
                it = max(1000, min(100000, int(data.get("iterations", 20000))))
                rn = max(1, min(5, int(data.get("runs", 1))))
                code, body = race(it, rn)
                return self.send(code, body)
        except subprocess.TimeoutExpired:
            return self.send(504, {"error": "timeout"})
        except Exception as e:
            return self.send(500, {"error": "internal error: %s" % type(e).__name__})
        self.send(404, {"error": "not found"})


def check_kernel_and_openat2():
    if sys.platform != "linux":
        print("WARNING: Non-Linux platform (%s). V4 (openat2) requires Linux kernel >= 5.6." % sys.platform)
        return

    rel = platform.release()
    m = re.match(r"^(\d+)\.(\d+)", rel)
    if m:
        major, minor = int(m.group(1)), int(m.group(2))
        if (major, minor) < (5, 6):
            sys.exit("ERROR: Linux kernel >= 5.6 is required for openat2 RESOLVE_BENEATH. Detected kernel: %s" % rel)

    try:
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        SYS_openat2 = 437
        class OpenHow(ctypes.Structure):
            _fields_ = [("flags", ctypes.c_uint64),
                        ("mode", ctypes.c_uint64),
                        ("resolve", ctypes.c_uint64)]
        how = OpenHow(os.O_RDONLY, 0, 0x08)
        ret = libc.syscall(SYS_openat2, -100, b".", ctypes.byref(how), ctypes.sizeof(how))
        if ret < 0:
            err = ctypes.get_errno()
            if err == 38:  # ENOSYS
                sys.exit("ERROR: openat2(2) syscall returned ENOSYS. Kernel does not support openat2 or syscall is blocked.")
        else:
            os.close(ret)
    except Exception:
        pass


def main():
    global JAIL, TRUST_PROXY
    env_host = os.environ.get("HOST", "127.0.0.1")
    env_port_str = os.environ.get("PORT")
    env_port = int(env_port_str) if env_port_str and env_port_str.isdigit() else 8000
    env_allowed = os.environ.get("ALLOWED_HOSTS") or os.environ.get("ALLOWED_HOST", "")
    env_trust_proxy = os.environ.get("TRUST_PROXY", "").lower() in ("1", "true", "yes")
    env_no_rate_limit = os.environ.get("NO_RATE_LIMIT", "").lower() in ("1", "true", "yes")

    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=env_host, help="Host to bind server to (or set HOST env var)")
    ap.add_argument("--port", type=int, default=env_port, help="Port to bind server to (or set PORT env var)")
    ap.add_argument("--no-rate-limit", action="store_true", default=env_no_rate_limit, help="Disable in-memory rate limiting")
    ap.add_argument("--allowed-host", action="append", default=[], help="Explicit allowed Host header (can repeat)")
    ap.add_argument("--trust-proxy", action="store_true", default=env_trust_proxy, help="Trust X-Forwarded-For header for client IP")
    a = ap.parse_args()

    if a.no_rate_limit:
        RATE_LIMITER.enabled = False

    if env_allowed:
        for item in re.split(r"[,;\s]+", env_allowed):
            if item.strip():
                ALLOWED_HOSTS.add(item.strip().lower())
    if a.allowed_host:
        for entry in a.allowed_host:
            for item in re.split(r"[,;\s]+", entry):
                if item.strip():
                    ALLOWED_HOSTS.add(item.strip().lower())

    TRUST_PROXY = a.trust_proxy

    check_kernel_and_openat2()

    for b in (CLI, RACE):
        if not os.path.exists(b):
            sys.exit("Missing %s - run `make` first." % b)
    subprocess.run(["bash", os.path.join(BASE, "tools", "make_fixtures.sh"), FIX], check=True, stdout=subprocess.DEVNULL)
    JAIL = os.path.realpath(os.path.join(FIX, "secure_files"))
    os.makedirs(os.path.join(BASE, "results"), exist_ok=True)
    ensure_results_csv()
    print("Jail root: %s\nOpen http://%s:%d" % (JAIL, a.host, a.port))
    if a.host not in ("127.0.0.1", "localhost"):
        print("WARNING: listening beyond localhost. Run inside a container/VM; the race demo is CPU heavy.")
    ThreadingHTTPServer((a.host, a.port), H).serve_forever()


if __name__ == "__main__":
    main()
