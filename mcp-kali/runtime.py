"""Durable jobs, cross-process admission control and bounded artifact storage."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import threading
import time

LOCAL = threading.local()
TERMINAL = ("completed", "failed", "cancelled")
try:
    BOOT_ID = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
except OSError:
    BOOT_ID = "local"


class Cancelled(RuntimeError):
    pass


def root():
    path = Path(os.environ.get("MCP_KALI_STATE_DIR", "/opt/kali-mcp/state"))
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def identity(pid=None):
    pid = pid or os.getpid()
    try:
        # The start tick avoids mistaking a reused PID for a surviving worker.
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return None if fields[0] in ("Z", "X") else BOOT_ID + ":" + fields[19]
    except OSError:
        return "local" if pid == os.getpid() else None


def alive(pid, stamp):
    return stamp is not None and identity(pid) == stamp


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()


def db():
    conn = sqlite3.connect(root() / "runtime.sqlite3", timeout=15, isolation_level=None, factory=ClosingConnection)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=15000")
    conn.executescript("""
      CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT UNIQUE, pid INTEGER,
        stamp TEXT, memory INTEGER, state TEXT, created REAL);
      CREATE TABLE IF NOT EXISTS workers (
        name TEXT PRIMARY KEY, chain_name TEXT, pid INTEGER, stamp TEXT,
        orphan INTEGER DEFAULT 0, created REAL);
      CREATE TABLE IF NOT EXISTS jobs (
        id TEXT PRIMARY KEY, kind TEXT, request TEXT, state TEXT, cancel INTEGER DEFAULT 0,
        created REAL, updated REAL, expires REAL, pid INTEGER, stamp TEXT,
        progress TEXT, result TEXT, error TEXT);
      CREATE TABLE IF NOT EXISTS artifacts (
        id TEXT PRIMARY KEY, name TEXT, size INTEGER, sha256 TEXT, created REAL, expires REAL);
      CREATE TABLE IF NOT EXISTS validations (
        command TEXT, image TEXT, level TEXT, checked REAL, passed INTEGER, detail TEXT,
        PRIMARY KEY(command,image));
    """)
    return conn


@contextmanager
def transaction():
    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def cancelled():
    job = getattr(LOCAL, "job", None)
    if job:
        with db() as conn:
            row = conn.execute("SELECT cancel FROM jobs WHERE id=?", (job,)).fetchone()
        return row is None or bool(row[0])
    return False


def check_cancelled():
    if cancelled():
        raise Cancelled("Job cancelled")


def limits():
    return {"max_running": int(os.environ.get("MCP_KALI_MAX_RUNNING", "2")),
            "memory_mb": int(os.environ.get("MCP_KALI_MEMORY_BUDGET_MB", "2048")),
            "max_queued": int(os.environ.get("MCP_KALI_MAX_QUEUED", "32"))}


def _dead_tickets(conn):
    for row in conn.execute("SELECT id,pid,stamp FROM tickets").fetchall():
        if not alive(row["pid"], row["stamp"]):
            conn.execute("DELETE FROM tickets WHERE id=?", (row["id"],))


@contextmanager
def admission(memory):
    """FIFO across all server processes; a large job cannot be starved by small ones."""
    budget = limits()
    if memory > budget["memory_mb"]:
        raise ValueError("Requested memory exceeds the execution budget")
    token = secrets.token_hex(16)
    start = time.monotonic()
    with transaction() as conn:
        _dead_tickets(conn)
        waiting = conn.execute("SELECT count(*) FROM tickets WHERE state='queued'").fetchone()[0]
        if waiting >= budget["max_queued"]:
            raise ValueError("Execution queue is full; retry later")
        conn.execute("INSERT INTO tickets(token,pid,stamp,memory,state,created) VALUES(?,?,?,?,?,?)",
                     (token, os.getpid(), identity(), memory, "queued", time.time()))
    try:
        while True:
            check_cancelled()
            with transaction() as conn:
                _dead_tickets(conn)
                first = conn.execute("SELECT token FROM tickets WHERE state='queued' ORDER BY id LIMIT 1").fetchone()
                active = conn.execute("SELECT count(*),coalesce(sum(memory),0) FROM tickets WHERE state='running'").fetchone()
                workers = conn.execute("SELECT pid,stamp,orphan FROM workers").fetchall()
                orphans = any(row["orphan"] or not alive(row["pid"], row["stamp"]) for row in workers)
                if not orphans and first and first[0] == token and active[0] < budget["max_running"] and active[1] + memory <= budget["memory_mb"]:
                    conn.execute("UPDATE tickets SET state='running' WHERE token=?", (token,))
                    break
            if time.monotonic() - start > int(os.environ.get("MCP_KALI_QUEUE_TIMEOUT_S", "1200")):
                raise TimeoutError("Execution queue wait exceeded its time limit")
            time.sleep(0.2)
        yield int((time.monotonic() - start) * 1000)
    finally:
        with transaction() as conn:
            conn.execute("DELETE FROM tickets WHERE token=?", (token,))


def queue_status():
    with transaction() as conn:
        _dead_tickets(conn)
        rows = conn.execute("SELECT state,count(*) n,coalesce(sum(memory),0) memory FROM tickets GROUP BY state").fetchall()
    stats = {row["state"]: {"count": row["n"], "memory_mb": row["memory"]} for row in rows}
    return {"limits": limits(), "running": stats.get("running", {"count": 0, "memory_mb": 0}),
            "queued": stats.get("queued", {"count": 0, "memory_mb": 0})}


def register_worker(name, chain):
    with transaction() as conn:
        conn.execute("INSERT INTO workers(name,chain_name,pid,stamp,created) VALUES(?,?,?,?,?)",
                     (name, chain, os.getpid(), identity(), time.time()))


def unregister_worker(name):
    with transaction() as conn:
        conn.execute("DELETE FROM workers WHERE name=?", (name,))


def orphan_worker(name):
    with transaction() as conn:
        conn.execute("UPDATE workers SET orphan=1 WHERE name=?", (name,))


def stale_workers():
    with db() as conn:
        rows = conn.execute("SELECT * FROM workers").fetchall()
    return [dict(row) for row in rows if row["orphan"] or not alive(row["pid"], row["stamp"])]


def validate_token(token):
    if not re.fullmatch(r"[0-9a-f]{64}", token):
        raise ValueError("Unknown or expired identifier")


def submit(kind, request):
    token, now = secrets.token_hex(32), time.time()
    with transaction() as conn:
        retained = conn.execute("SELECT count(*) FROM jobs").fetchone()[0]
        if retained >= int(os.environ.get("MCP_KALI_MAX_RETAINED_JOBS", "1000")):
            raise ValueError("Job retention storage is full; retry after expiry cleanup")
        count = conn.execute("SELECT count(*) FROM jobs WHERE state NOT IN ('completed','failed','cancelled')").fetchone()[0]
        if count >= limits()["max_queued"]:
            raise ValueError("Background job queue is full; retry later")
        conn.execute("INSERT INTO jobs(id,kind,request,state,created,updated,expires,progress) VALUES(?,?,?,?,?,?,?,?)",
                     (token, kind, json.dumps(request), "queued", now, now, now+86400, "Waiting for a worker"))
    return job_status(token)


def job_status(token, include_result=False):
    validate_token(token)
    with db() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE id=? AND expires>?", (token, time.time())).fetchone()
    if row is None:
        raise ValueError("Unknown or expired identifier")
    result = {key: row[key] for key in ("id", "kind", "state", "created", "updated", "expires", "progress", "error")}
    result["cancel_requested"] = bool(row["cancel"])
    result["poll_after_s"] = 1 if row["state"] not in TERMINAL else 0
    if include_result:
        result["result"] = json.loads(row["result"]) if row["result"] else None
    return result


def cancel_job(token):
    validate_token(token)
    with transaction() as conn:
        row = conn.execute("SELECT state FROM jobs WHERE id=? AND expires>?", (token, time.time())).fetchone()
        if row is None:
            raise ValueError("Unknown or expired identifier")
        if row[0] not in TERMINAL:
            conn.execute("UPDATE jobs SET cancel=1,updated=?,state=CASE WHEN state='queued' THEN 'cancelled' ELSE state END WHERE id=?",
                         (time.time(), token))
    return job_status(token)


def progress(message):
    token = getattr(LOCAL, "job", None)
    if token:
        with transaction() as conn:
            conn.execute("UPDATE jobs SET progress=?,updated=? WHERE id=?", (message[:512], time.time(), token))


def _claim():
    with transaction() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE state='queued' AND cancel=0 AND expires>? ORDER BY created LIMIT 1", (time.time(),)).fetchone()
        if row:
            conn.execute("UPDATE jobs SET state='running',pid=?,stamp=?,updated=?,progress=? WHERE id=?",
                         (os.getpid(), identity(), time.time(), "Waiting for execution capacity", row["id"]))
            return dict(row)


def recover_jobs():
    with transaction() as conn:
        for row in conn.execute("SELECT id,pid,stamp FROM jobs WHERE state='running'").fetchall():
            if not alive(row["pid"], row["stamp"]):
                conn.execute("UPDATE jobs SET state='failed',error=?,updated=? WHERE id=?",
                             ("Worker stopped before completion; resubmit explicitly to avoid repeating side effects", time.time(), row["id"]))


def _worker(stop, handlers):
    while not stop.is_set():
        job = _claim()
        if job is None:
            stop.wait(0.3)
            continue
        LOCAL.job = job["id"]
        result, error, state = None, None, "completed"
        try:
            check_cancelled()
            result = handlers[job["kind"]](**json.loads(job["request"]))
            if hasattr(result, "model_dump"):
                result = result.model_dump(mode="json")
            check_cancelled()
        except Cancelled:
            state = "cancelled"
        except Exception as exc:
            state, error = "failed", str(exc)[:2000]
        finally:
            with transaction() as conn:
                # Cancellation and completion are resolved atomically.
                row = conn.execute("SELECT cancel FROM jobs WHERE id=?", (job["id"],)).fetchone()
                if row and row[0]:
                    state = "cancelled"
                conn.execute("UPDATE jobs SET state=?,result=?,error=?,progress=?,updated=? WHERE id=?",
                             (state, json.dumps(result) if result is not None else None, error, state, time.time(), job["id"]))
            LOCAL.job = None


def start_workers(handlers, maintenance):
    recover_jobs()
    stop = threading.Event()
    threads = [threading.Thread(target=_worker, args=(stop, handlers), daemon=True,
                                name=f"kali-job-{i}") for i in range(limits()["max_running"])]
    def upkeep():
        import logging
        while not stop.is_set():
            try:
                recover_jobs()
                maintenance()
                purge()
            except Exception:
                logging.exception("Kali runtime maintenance failed")
            stop.wait(30)
    threads.append(threading.Thread(target=upkeep, daemon=True, name="kali-maintenance"))
    for thread in threads:
        thread.start()
    return stop, threads


def artifact_info(token):
    validate_token(token)
    with db() as conn:
        row = conn.execute("SELECT * FROM artifacts WHERE id=? AND expires>?", (token, time.time())).fetchone()
    if row is None or not (root() / "artifacts" / token).is_file():
        raise ValueError("Unknown or expired identifier")
    base = os.environ.get("MCP_KALI_PUBLIC_URL", "https://kali.khosa.co:9443").rstrip("/")
    return {**dict(row), "uri": f"kali://artifacts/{token}", "url": f"{base}/artifacts/{token}"}


def save_artifact(name, data):
    maximum = int(os.environ.get("MCP_KALI_ARTIFACT_MAX_BYTES", "8388608"))
    if len(data) > maximum:
        raise ValueError("Artifact exceeds the per-file limit")
    token, now = secrets.token_hex(32), time.time()
    folder = root() / "artifacts"
    folder.mkdir(exist_ok=True, mode=0o700)
    path = folder / token
    with transaction() as conn:
        used = conn.execute("SELECT coalesce(sum(size),0) FROM artifacts").fetchone()[0]
        if used + len(data) > int(os.environ.get("MCP_KALI_ARTIFACT_BUDGET_BYTES", "1073741824")):
            raise ValueError("Artifact storage is full; retry after retention cleanup")
        try:
            with path.open("xb") as stream:
                stream.write(data)
            conn.execute("INSERT INTO artifacts VALUES(?,?,?,?,?,?)", (token, Path(name).name[:128], len(data),
                         hashlib.sha256(data).hexdigest(), now, now+86400))
        except BaseException:
            path.unlink(missing_ok=True)
            raise
    return artifact_info(token)


def read_artifact(token):
    info = artifact_info(token)
    return info, (root() / "artifacts" / token).read_bytes()


def purge():
    with transaction() as conn:
        conn.execute("UPDATE jobs SET state='failed',error='Expired before execution' WHERE expires<? AND state='queued'", (time.time(),))
        for row in conn.execute("SELECT id FROM artifacts WHERE expires<?", (time.time(),)).fetchall():
            (root() / "artifacts" / row[0]).unlink(missing_ok=True)
            conn.execute("DELETE FROM artifacts WHERE id=?", (row[0],))
        conn.execute("DELETE FROM jobs WHERE expires<? AND state IN ('completed','failed','cancelled')", (time.time(),))
        folder = root() / "artifacts"
        if folder.exists():
            known = {row[0] for row in conn.execute("SELECT id FROM artifacts")}
            for path in folder.iterdir():
                if re.fullmatch(r"[0-9a-f]{64}", path.name) and path.name not in known:
                    path.unlink(missing_ok=True)


def record_validation(command, image, level, passed, detail):
    with transaction() as conn:
        conn.execute("INSERT OR REPLACE INTO validations VALUES(?,?,?,?,?,?)",
                     (command, image, level, time.time(), int(passed), detail[:1000]))


def validations(image):
    with db() as conn:
        return [dict(row) for row in conn.execute("SELECT * FROM validations WHERE image=? ORDER BY command", (image,))]
