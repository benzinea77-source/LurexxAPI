import os
import json
import secrets
import time
from contextlib import contextmanager

try:
    import psycopg2
    import psycopg2.extras
except Exception:
    psycopg2 = None

_DSN = (os.environ.get("DATABASE_URL")
        or os.environ.get("POSTGRES_URL")
        or os.environ.get("DATABASE_URL_UNPOOLED")
        or os.environ.get("POSTGRES_URL_NON_POOLING"))

_MEM = {"loaders": {}, "sids": {}, "keys": {}, "acl": {}, "delegates": {}, "audit": []}
_ready = False

HWID_RESET_COOLDOWN = 2 * 24 * 3600

_SCHEMA = """
CREATE TABLE IF NOT EXISTS fine_loaders (
    hash    TEXT PRIMARY KEY,
    sid     TEXT UNIQUE NOT NULL,
    code    TEXT NOT NULL,
    name    TEXT,
    frozen  BOOLEAN NOT NULL DEFAULT FALSE,
    created BIGINT,
    updated BIGINT
);
ALTER TABLE fine_loaders ADD COLUMN IF NOT EXISTS free        BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE fine_loaders ADD COLUMN IF NOT EXISTS silent      BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE fine_loaders ADD COLUMN IF NOT EXISTS engine      TEXT NOT NULL DEFAULT 'LUREX';
ALTER TABLE fine_loaders ADD COLUMN IF NOT EXISTS owner       TEXT;
ALTER TABLE fine_loaders ADD COLUMN IF NOT EXISTS source      TEXT;
ALTER TABLE fine_loaders ADD COLUMN IF NOT EXISTS panel_title TEXT;
ALTER TABLE fine_loaders ADD COLUMN IF NOT EXISTS panel_desc  TEXT;
ALTER TABLE fine_loaders ADD COLUMN IF NOT EXISTS panel_color TEXT;
ALTER TABLE fine_loaders ADD COLUMN IF NOT EXISTS panel_hwid_resets BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE fine_loaders ADD COLUMN IF NOT EXISTS panel_show_redeem BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE fine_loaders ADD COLUMN IF NOT EXISTS panel_show_get_script BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE fine_loaders ADD COLUMN IF NOT EXISTS panel_show_hwid BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE fine_loaders ADD COLUMN IF NOT EXISTS panel_show_buyer BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE fine_loaders ADD COLUMN IF NOT EXISTS panel_show_key_info BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE fine_loaders ADD COLUMN IF NOT EXISTS panel_emojis BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE fine_loaders ADD COLUMN IF NOT EXISTS panel_luarmor_look BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE fine_loaders ADD COLUMN IF NOT EXISTS panel_buyer_role TEXT;
ALTER TABLE fine_loaders ADD COLUMN IF NOT EXISTS panel_whitelist_role TEXT;
ALTER TABLE fine_loaders ADD COLUMN IF NOT EXISTS panel_admin_role TEXT;
CREATE TABLE IF NOT EXISTS fine_keys (
    key        TEXT PRIMARY KEY,
    project    TEXT NOT NULL,
    hwid       TEXT,
    hwid_reset BIGINT,
    discord_id TEXT,
    label      TEXT,
    created    BIGINT
);
CREATE INDEX IF NOT EXISTS fine_keys_project_idx ON fine_keys (project);
CREATE INDEX IF NOT EXISTS fine_keys_owner_idx   ON fine_keys (project, discord_id);
CREATE TABLE IF NOT EXISTS fine_delegates (
    project    TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    created BIGINT,
    PRIMARY KEY (project, subject_type, subject_id, scope)
);
CREATE TABLE IF NOT EXISTS fine_audit (
    id BIGSERIAL PRIMARY KEY,
    project TEXT,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    metadata JSONB,
    created BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS fine_audit_created_idx ON fine_audit (created DESC);
CREATE TABLE IF NOT EXISTS fine_acl (
    project    TEXT NOT NULL,
    discord_id TEXT NOT NULL,
    status     TEXT NOT NULL,
    PRIMARY KEY (project, discord_id)
);
"""


def enabled():
    return bool(_DSN and psycopg2)


@contextmanager
def _conn():
    global _ready
    conn = psycopg2.connect(_DSN, connect_timeout=10)
    conn.autocommit = True
    try:
        if not _ready:
            with conn.cursor() as cur:
                cur.execute(_SCHEMA)
            _ready = True
        yield conn
    finally:
        conn.close()


def _dict_cursor(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


def new_key():
    # Human-readable LUREX key: LUREX-123-456-789.
    return "LUREX-{:03d}-{:03d}-{:03d}".format(
        secrets.randbelow(1000), secrets.randbelow(1000), secrets.randbelow(1000)
    )


def set_delegate(project, subject_type, subject_id, scope, enabled=True):
    subject_type = str(subject_type or "member")
    subject_id = str(subject_id or "")
    scope = str(scope or "all")
    if not subject_id:
        return False
    if enabled:
        if enabled_db := globals().get("enabled"):
            if enabled_db():
                with _conn() as conn, conn.cursor() as cur:
                    cur.execute("INSERT INTO fine_delegates (project, subject_type, subject_id, scope, created) VALUES (%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING", (project, subject_type, subject_id, scope, int(time.time())))
            else:
                _MEM["delegates"][(project, subject_type, subject_id, scope)] = {"project": project, "subject_type": subject_type, "subject_id": subject_id, "scope": scope, "created": int(time.time())}
    else:
        if enabled_db := globals().get("enabled"):
            if enabled_db():
                with _conn() as conn, conn.cursor() as cur:
                    cur.execute("DELETE FROM fine_delegates WHERE project=%s AND subject_type=%s AND subject_id=%s AND scope=%s", (project, subject_type, subject_id, scope))
            else:
                _MEM["delegates"].pop((project, subject_type, subject_id, scope), None)
    return True

def list_delegates(project):
    if enabled():
        with _conn() as conn, _dict_cursor(conn) as cur:
            cur.execute("SELECT * FROM fine_delegates WHERE project=%s ORDER BY created DESC", (project,))
            return [dict(r) for r in cur.fetchall()]
    return list(_MEM["delegates"].values())

def can_delegate(project, subject_id, scope):
    subject_id = str(subject_id or "")
    if enabled():
        with _conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1 FROM fine_delegates WHERE project=%s AND subject_id=%s AND scope IN (%s,'all') LIMIT 1", (project, subject_id, scope))
            return cur.fetchone() is not None
    return any(v.get("project") == project and v.get("subject_id") == subject_id and v.get("scope") in (scope, "all") for v in _MEM["delegates"].values())

def add_audit(project, actor_id, action, target=None, metadata=None):
    row = {"project": project, "actor_id": str(actor_id), "action": action, "target": target, "metadata": metadata or {}, "created": int(time.time())}
    if enabled():
        import json
        with _conn() as conn, conn.cursor() as cur:
            cur.execute("INSERT INTO fine_audit (project, actor_id, action, target, metadata, created) VALUES (%s,%s,%s,%s,%s,%s)", (project, str(actor_id), action, target, json.dumps(metadata or {}), row["created"]))
    else:
        _MEM["audit"].append(row)
    return row

def list_audit(project=None, limit=100):
    if enabled():
        with _conn() as conn, _dict_cursor(conn) as cur:
            if project:
                cur.execute("SELECT * FROM fine_audit WHERE project=%s ORDER BY created DESC LIMIT %s", (project, limit))
            else:
                cur.execute("SELECT * FROM fine_audit ORDER BY created DESC LIMIT %s", (limit,))
            return [dict(r) for r in cur.fetchall()]
    rows = [r for r in _MEM["audit"] if not project or r.get("project") == project]
    return list(reversed(rows[-limit:]))

def list_by_user(user_id, limit=50):
    user_id = str(user_id or "")

    def owner_matches(owner):
        if not isinstance(owner, str):
            return False
        try:
            meta = json.loads(owner)
            return str(meta.get("user_id") or "") == user_id or str(meta.get("discord_id") or "") == user_id
        except Exception:
            return user_id in owner

    if enabled():
        with _conn() as conn, _dict_cursor(conn) as cur:
            cur.execute("SELECT hash, sid, name, owner, free, silent, engine, created, updated FROM fine_loaders WHERE owner IS NOT NULL ORDER BY created DESC")
            rows = [dict(r) for r in cur.fetchall() if owner_matches(r.get("owner"))]
            return rows[:limit]
    rows = []
    for h, record in _MEM["loaders"].items():
        owner = record.get("owner")
        if owner_matches(owner):
            rows.append({"hash": h, "sid": record.get("sid"), "name": record.get("name"), "owner": owner, "free": record.get("free", False), "silent": record.get("silent", False), "engine": record.get("engine", "LUREX"), "created": record.get("created"), "updated": record.get("updated")})
    rows.sort(key=lambda row: row.get("created") or 0, reverse=True)
    return rows[:limit]


def owner_view(limit=100):
    if enabled():
        with _conn() as conn, _dict_cursor(conn) as cur:
            cur.execute("SELECT hash, sid, name, owner, created, updated FROM fine_loaders ORDER BY created DESC LIMIT %s", (limit,))
            return {"scripts": [dict(r) for r in cur.fetchall()], "audit": list_audit(limit=limit)}
    return {"scripts": [{"hash": h, "sid": r.get("sid"), "name": r.get("name"), "owner": r.get("owner"), "created": r.get("created"), "updated": r.get("updated")} for h, r in list(_MEM["loaders"].items())[-limit:]], "audit": list_audit(limit=limit)}

# ---------------- loaders / projects ----------------

def save_loader(loader_hash, script_id, code, name, owner=None, free=False, source=None, silent=False, engine="LUREX"):
    now = int(time.time())
    record = {"code": code, "sid": script_id, "name": name, "frozen": False,
              "free": bool(free), "silent": bool(silent), "engine": str(engine or "LUREX"), "owner": owner, "source": source,
              "panel_title": None, "panel_desc": None, "panel_color": None,
              "panel_hwid_resets": True, "panel_show_redeem": True,
              "panel_show_get_script": True, "panel_show_hwid": True,
              "panel_show_buyer": True, "panel_show_key_info": True,
              "panel_emojis": False, "panel_luarmor_look": False,
              "panel_buyer_role": None, "panel_whitelist_role": None, "panel_admin_role": None,
              "created": now, "updated": now}
    if enabled():
        with _conn() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO fine_loaders (hash, sid, code, name, frozen, free, silent, engine, owner, source, created, updated) "
                "VALUES (%s, %s, %s, %s, FALSE, %s, %s, %s, %s, %s, %s, %s)",
                (loader_hash, script_id, code, name, bool(free), bool(silent), str(engine or "LUREX"), owner, source, now, now))
    else:
        _MEM["loaders"][loader_hash] = record
        _MEM["sids"][script_id] = loader_hash
    return record


def load_loader(loader_hash):
    if enabled():
        with _conn() as conn, _dict_cursor(conn) as cur:
            cur.execute("SELECT * FROM fine_loaders WHERE hash = %s", (loader_hash,))
            row = cur.fetchone()
            return dict(row) if row else None
    return _MEM["loaders"].get(loader_hash)


def _sid_candidates(script_id):
    value = str(script_id or "").strip().strip("`")
    if value.lower().startswith("script_id:"):
        value = value.split(":", 1)[1].strip()
    if not value:
        return []
    candidates = [value]
    if value.lower().startswith("script_id-"):
        candidates.append("SCRIPT_ID-" + value.split("-", 1)[1])
    elif not value.upper().startswith("SCRIPT_ID-"):
        candidates.append("SCRIPT_ID-" + value)
    return list(dict.fromkeys(candidates))


def resolve_sid(script_id):
    candidates = _sid_candidates(script_id)
    if not candidates:
        return None, None
    if enabled():
        with _conn() as conn, _dict_cursor(conn) as cur:
            for candidate in candidates:
                cur.execute("SELECT * FROM fine_loaders WHERE sid = %s", (candidate,))
                row = cur.fetchone()
                if row:
                    return row["hash"], dict(row)
            return None, None
    for candidate in candidates:
        loader_hash = _MEM["sids"].get(candidate)
        if loader_hash:
            return loader_hash, _MEM["loaders"].get(loader_hash)
    return None, None


def resolve_owner(owner_key):
    owner_key = str(owner_key or "")
    if not owner_key:
        return None, None
    if enabled():
        with _conn() as conn, _dict_cursor(conn) as cur:
            cur.execute("SELECT * FROM fine_loaders WHERE owner LIKE %s ORDER BY created DESC", (f"%owner_key%{owner_key}%",))
            row = cur.fetchone()
            if not row:
                return None, None
            return row["hash"], dict(row)
    for loader_hash, record in _MEM["loaders"].items():
        owner = record.get("owner")
        if isinstance(owner, str) and owner_key in owner:
            return loader_hash, record
    return None, None


def update_code(loader_hash, record, code, source=None):
    now = int(time.time())
    if source is None:
        source = record.get("source")
    if enabled():
        with _conn() as conn, conn.cursor() as cur:
            cur.execute("UPDATE fine_loaders SET code = %s, name = %s, source = %s, updated = %s WHERE hash = %s",
                        (code, record.get("name"), source, now, loader_hash))
    else:
        record["code"] = code
        record["source"] = source
        record["updated"] = now
        _MEM["loaders"][loader_hash] = record
    return record


def set_panel(loader_hash, record, title=None, desc=None, color=None,
              hwid_resets=True, show_redeem=True, show_get_script=True,
              show_hwid=True, show_buyer=True, show_key_info=True, emojis=False, luarmor_look=False,
              buyer_role=None, whitelist_role=None, admin_role=None):
    now = int(time.time())
    values = {
        "panel_title": title, "panel_desc": desc, "panel_color": color,
        "panel_hwid_resets": bool(hwid_resets),
        "panel_show_redeem": bool(show_redeem),
        "panel_show_get_script": bool(show_get_script),
        "panel_show_hwid": bool(show_hwid),
        "panel_show_buyer": bool(show_buyer),
        "panel_show_key_info": bool(show_key_info),
        "panel_emojis": bool(emojis),
        "panel_luarmor_look": bool(luarmor_look),
        "panel_buyer_role": str(buyer_role or "") or None,
        "panel_whitelist_role": str(whitelist_role or "") or None,
        "panel_admin_role": str(admin_role or "") or None,
    }
    record.update(values)
    record["updated"] = now
    if enabled():
        with _conn() as conn, conn.cursor() as cur:
            cur.execute("""UPDATE fine_loaders SET panel_title = %s, panel_desc = %s, panel_color = %s,
                panel_hwid_resets = %s, panel_show_redeem = %s, panel_show_get_script = %s,
                panel_show_hwid = %s, panel_show_buyer = %s, panel_show_key_info = %s,
                panel_emojis = %s, panel_luarmor_look = %s,
                panel_buyer_role = %s, panel_whitelist_role = %s, panel_admin_role = %s,
                updated = %s WHERE hash = %s""",
                (title, desc, color, bool(hwid_resets), bool(show_redeem), bool(show_get_script),
                 bool(show_hwid), bool(show_buyer), bool(show_key_info), bool(emojis), bool(luarmor_look),
                 str(buyer_role or "") or None, str(whitelist_role or "") or None, str(admin_role or "") or None,
                 now, loader_hash))
    else:
        _MEM["loaders"][loader_hash] = record
    return record


def set_frozen(loader_hash, record, frozen):
    now = int(time.time())
    if enabled():
        with _conn() as conn, conn.cursor() as cur:
            cur.execute("UPDATE fine_loaders SET frozen = %s, updated = %s WHERE hash = %s",
                        (bool(frozen), now, loader_hash))
    else:
        record["frozen"] = bool(frozen)
        record["updated"] = now
        _MEM["loaders"][loader_hash] = record
    return record


def set_settings(loader_hash, record, name=None, free=None, silent=None, engine=None):
    now = int(time.time())
    if name is not None:
        record["name"] = str(name)
    if free is not None:
        record["free"] = bool(free)
    if silent is not None:
        record["silent"] = bool(silent)
    if engine is not None:
        record["engine"] = str(engine)
    record["updated"] = now
    if enabled():
        with _conn() as conn, conn.cursor() as cur:
            cur.execute("UPDATE fine_loaders SET name = COALESCE(%s, name), free = COALESCE(%s, free), silent = COALESCE(%s, silent), engine = COALESCE(%s, engine), updated = %s WHERE hash = %s", (name, None if free is None else bool(free), None if silent is None else bool(silent), engine, now, loader_hash))
    else:
        _MEM["loaders"][loader_hash] = record
    return record


def set_free(loader_hash, record, free):
    now = int(time.time())
    if enabled():
        with _conn() as conn, conn.cursor() as cur:
            cur.execute("UPDATE fine_loaders SET free = %s, updated = %s WHERE hash = %s",
                        (bool(free), now, loader_hash))
    else:
        record["free"] = bool(free)
        record["updated"] = now
        _MEM["loaders"][loader_hash] = record
    return record


def remove(loader_hash, script_id):
    if enabled():
        with _conn() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM fine_loaders WHERE hash = %s", (loader_hash,))
            cur.execute("DELETE FROM fine_keys WHERE project = %s", (loader_hash,))
            cur.execute("DELETE FROM fine_acl WHERE project = %s", (loader_hash,))
    else:
        _MEM["loaders"].pop(loader_hash, None)
        _MEM["sids"].pop(script_id, None)
        for k, v in list(_MEM["keys"].items()):
            if v.get("project") == loader_hash:
                _MEM["keys"].pop(k, None)
        _MEM["acl"].pop(loader_hash, None)


# ---------------- keys ----------------

def create_keys(project, count=1, label=None):
    now = int(time.time())
    out = []
    for _ in range(max(1, min(int(count), 100))):
        key = new_key()
        rec = {"key": key, "project": project, "hwid": None, "hwid_reset": None,
               "discord_id": None, "label": label, "created": now}
        if enabled():
            with _conn() as conn, conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO fine_keys (key, project, label, created) VALUES (%s, %s, %s, %s)",
                    (key, project, label, now))
        else:
            _MEM["keys"][key] = rec
        out.append(key)
    return out


def get_key(key):
    if enabled():
        with _conn() as conn, _dict_cursor(conn) as cur:
            cur.execute("SELECT * FROM fine_keys WHERE key = %s", (key,))
            row = cur.fetchone()
            return dict(row) if row else None
    return _MEM["keys"].get(key)


def get_project_key(project, key):
    rec = get_key(key)
    if rec and rec.get("project") == project:
        return rec
    return None


def delete_key(project, key):
    if enabled():
        with _conn() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM fine_keys WHERE key = %s AND project = %s", (key, project))
            return cur.rowcount > 0
    rec = _MEM["keys"].get(key)
    if rec and rec.get("project") == project:
        _MEM["keys"].pop(key, None)
        return True
    return False


def list_keys(project):
    if enabled():
        with _conn() as conn, _dict_cursor(conn) as cur:
            cur.execute("SELECT * FROM fine_keys WHERE project = %s ORDER BY created DESC", (project,))
            return [dict(r) for r in cur.fetchall()]
    return [v for v in _MEM["keys"].values() if v.get("project") == project]


def key_for_discord(project, discord_id):
    if enabled():
        with _conn() as conn, _dict_cursor(conn) as cur:
            cur.execute("SELECT * FROM fine_keys WHERE project = %s AND discord_id = %s "
                        "ORDER BY created DESC LIMIT 1", (project, discord_id))
            row = cur.fetchone()
            return dict(row) if row else None
    for v in _MEM["keys"].values():
        if v.get("project") == project and v.get("discord_id") == discord_id:
            return v
    return None


def bind_discord(key, discord_id):
    if enabled():
        with _conn() as conn, conn.cursor() as cur:
            cur.execute("UPDATE fine_keys SET discord_id = %s WHERE key = %s", (discord_id, key))
    else:
        _MEM["keys"][key]["discord_id"] = discord_id


def assign_hwid(key, hwid):
    if enabled():
        with _conn() as conn, conn.cursor() as cur:
            cur.execute("UPDATE fine_keys SET hwid = %s WHERE key = %s", (hwid, key))
    else:
        _MEM["keys"][key]["hwid"] = hwid


def reset_hwid(key):
    now = int(time.time())
    if enabled():
        with _conn() as conn, conn.cursor() as cur:
            cur.execute("UPDATE fine_keys SET hwid = NULL, hwid_reset = %s WHERE key = %s", (now, key))
    else:
        _MEM["keys"][key]["hwid"] = None
        _MEM["keys"][key]["hwid_reset"] = now


def reset_available_in(record):
    last = record.get("hwid_reset")
    if not last:
        return 0
    remaining = (last + HWID_RESET_COOLDOWN) - int(time.time())
    return remaining if remaining > 0 else 0


# ---------------- acl (whitelist / blacklist) ----------------

def set_acl(project, discord_id, status):
    if status not in ("white", "black"):
        return
    if enabled():
        with _conn() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO fine_acl (project, discord_id, status) VALUES (%s, %s, %s) "
                "ON CONFLICT (project, discord_id) DO UPDATE SET status = EXCLUDED.status",
                (project, discord_id, status))
    else:
        _MEM["acl"].setdefault(project, {})[discord_id] = status


def clear_acl(project, discord_id):
    if enabled():
        with _conn() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM fine_acl WHERE project = %s AND discord_id = %s",
                        (project, discord_id))
    else:
        _MEM["acl"].get(project, {}).pop(discord_id, None)


def get_acl(project, discord_id):
    if enabled():
        with _conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT status FROM fine_acl WHERE project = %s AND discord_id = %s",
                        (project, discord_id))
            row = cur.fetchone()
            return row[0] if row else None
    return _MEM["acl"].get(project, {}).get(discord_id)


def list_acl(project):
    if enabled():
        with _conn() as conn, _dict_cursor(conn) as cur:
            cur.execute("SELECT discord_id, status FROM fine_acl WHERE project = %s", (project,))
            return [dict(r) for r in cur.fetchall()]
    return [{"discord_id": d, "status": s} for d, s in _MEM["acl"].get(project, {}).items()]
