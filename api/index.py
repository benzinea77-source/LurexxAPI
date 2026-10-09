from http.server import BaseHTTPRequestHandler
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from darcobfuscator import __version__
from darcobfuscator.obfuscator import obfuscate
import fine_store
try:
    import web_app
except Exception:
    web_app = None

_ALLOWED = {"name", "silent", "fast", "rename", "on_fail", "seed", "engine", "preset"}
_PROMETHEUS_ROOT = Path(__file__).resolve().parent.parent / "prometheus"
_UNIVERSAL_ANTI_TAMPER = '''local _lurex_mt_ok, _lurex_mt = pcall(getmetatable, "")
if not _lurex_mt_ok or typeof(_lurex_mt) ~= "table" or _lurex_mt.__index ~= string or _lurex_mt.__metatable ~= "The metatable is locked" then
    error("LUREX: Fail", 0)
end
local _lurex_part_ok, _lurex_part_valid = pcall(function()
    local _lurex_part = Instance.new("Part")
    _lurex_part.Color = Color3.fromRGB(45, 45, 45)
    _lurex_part.Material = Enum.Material.SmoothPlastic
    return _lurex_part.Material == Enum.Material.SmoothPlastic and _lurex_part.Color == Color3.fromRGB(45, 45, 45)
end)
if not _lurex_part_ok or not _lurex_part_valid then
    error("LUREX: Fail 2", 0)
end
local _lurex_object_ok, _lurex_object_valid = pcall(function()
    local _bindable = Instance.new("BindableFunction")
    if not _bindable or typeof(_bindable) ~= "Instance" then return false end
    local _object_value = Instance.new("ObjectValue")
    if not _object_value or typeof(_object_value) ~= "Instance" then return false end
    if not Enum or typeof(Enum) ~= "Enums" then return false end
    local _remote = Instance.new("RemoteEvent")
    if not _remote or typeof(_remote) ~= "Instance" then return false end
    local _players = game:GetService("Players")
    local _player_list = _players:GetPlayers()
    for _, _player in ipairs(_player_list) do
        if not _player:IsA("Player") then return false end
    end
    return true
end)
if not _lurex_object_ok or not _lurex_object_valid then
    error("LUREX: Fail 3", 0)
end
{success_line}
'''


def _prometheus_build(source, preset="Strong", silent=False):
    if not (_PROMETHEUS_ROOT / "cli.lua").exists():
        raise RuntimeError("Prometheus engine is not installed on the API service.")
    runtime = next((candidate for candidate in ("lua5.1", "lua") if __import__("shutil").which(candidate)), None)
    if not runtime:
        raise RuntimeError("Prometheus requires a Lua 5.1 runtime on the API service.")
    preset = "Strong"
    anti_tamper = _UNIVERSAL_ANTI_TAMPER.format(success_line="" if silent else 'print("Pass")')
    source = anti_tamper + "\n" + source
    with tempfile.TemporaryDirectory(prefix="lurex-prometheus-") as workdir:
        input_path = Path(workdir) / "input.lua"
        output_path = Path(workdir) / "input.obfuscated.lua"
        input_path.write_text(source, encoding="utf-8")
        completed = subprocess.run([runtime, str(_PROMETHEUS_ROOT / "cli.lua"), "--preset", preset, str(input_path)], cwd=workdir, capture_output=True, text=True, timeout=30)
        if completed.returncode != 0 or not output_path.exists():
            detail = (completed.stderr or completed.stdout or "Prometheus could not obfuscate the source.").strip()
            raise RuntimeError(detail[-1600:])
        return output_path.read_text(encoding="utf-8")
_MAX_BYTES = int(os.environ.get("MAX_BYTES", "1000000"))
_BOT_SECRET = os.environ.get("BOT_SHARED_SECRET")
_OWNER_VIEW_IDS = {x.strip() for x in os.environ.get("OWNER_VIEW_IDS", "").split(",") if x.strip()}

OWNER_ACTIONS = {"update", "freeze", "unfreeze", "delete", "info", "set_free", "set_settings",
                 "reobfuscate", "set_panel", "genkey", "delkey", "listkeys",
                 "whitelist", "blacklist", "unlist", "listacl", "setadmin", "setwl", "rmwl",
                 "owner_view"}
PANEL_ACTIONS = {"panel_info", "redeem", "get_script", "reset_hwid",
                 "buyer_check", "key_info"}

_GATEWAY = r"""local ok=pcall(function()
    local HS=game:GetService("HttpService")
    local key=""
    pcall(function() if script_key~=nil then key=tostring(script_key) end end)
    if key=="" and getgenv then pcall(function() local g=getgenv().script_key if g~=nil then key=tostring(g) end end) end
    local hwid=""
    pcall(function() hwid=tostring(game:GetService("RbxAnalyticsService"):GetClientId()) end)
    if hwid=="" and gethwid then pcall(function() hwid=tostring(gethwid()) end) end
    local url="__BASE__/verify/__HASH__?key="..HS:UrlEncode(key).."&hwid="..HS:UrlEncode(hwid)
    local body=game:HttpGet(url)
    local f=loadstring(body)
    if f then f() end
end)"""


def _clean(options):
    if not isinstance(options, dict):
        return {}
    opts = {k: v for k, v in options.items() if k in _ALLOWED}
    opts["target"] = "executor"
    return opts


_GOOFYSCATOR_URL = os.environ.get("GOOFYSCATOR_URL", "https://goofyscator.lua.cz/obfuscate").strip()


def _goofyscator_build(source, options):
    # Keep the requested Roblox integrity layer in the input, then let Goofyscator
    # add its own antiTamper, Luau-runtime, string, proxy, and control-flow passes.
    silent = bool(options.get("silent"))
    anti_tamper = _UNIVERSAL_ANTI_TAMPER.format(success_line="" if silent else 'print("Pass")')
    protected_source = anti_tamper + "\n" + source
    settings = {
        "encryptStrings": True,
        "proxifyLocals": True,
        "proxifyFunctions": True,
        "antiTamper": True,
        "isLuauRuntime": True,
        "controlFlowFlattening": True,
        "loaderVMDepth": 3,
    }
    body = json.dumps({"source": protected_source, "settings": settings}).encode("utf-8")
    request = urllib.request.Request(_GOOFYSCATOR_URL, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:1200]
        raise RuntimeError(f"Goofyscator returned HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"Goofyscator unavailable: {exc}") from exc
    try:
        result = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Goofyscator returned non-JSON output.") from exc
    output = result.get("result") if isinstance(result, dict) and result.get("status") == "success" else None
    if not isinstance(output, str) or not output.strip():
        raise RuntimeError(f"Goofyscator returned no obfuscated result: {str(result)[:800]}")
    return output


def _build(source, options):
    engine = str(options.get("engine") or "LUREX").upper()
    if engine == "PROMETHEUS":
        return _prometheus_build(source, str(options.get("preset") or "Medium"), silent=bool(options.get("silent")))
    return _goofyscator_build(source, options)


def _base(handler):
    env = os.environ.get("PUBLIC_BASE_URL")
    if env:
        return env.rstrip("/")
    host = handler.headers.get("host") or "localhost"
    proto = handler.headers.get("x-forwarded-proto") or (
        "http" if host.startswith("localhost") or host.startswith("127.") else "https")
    return proto + "://" + host


def _loadstring(url):
    return 'loadstring(game:HttpGet("' + url + '"))()'


def _keyed_loadstring(url, key):
    safe_key = str(key or "").replace("\\", "\\\\").replace('"', '\\"')
    return 'script_key = "' + safe_key + '"\n' + _loadstring(url)


def _owner_id():
    return "OWNER-" + secrets.token_urlsafe(18).rstrip("=")
def _script_id():
    return "SCRIPT_ID-" + secrets.token_urlsafe(18).rstrip("=")
def _project_id(loader_hash):
    return "PROJECT-" + str(loader_hash)


def _loader_hash(value):
    value = str(value or "")
    return value[len("PROJECT-"):] if value.startswith("PROJECT-") else value


def _gateway(base, loader_hash):
    return _GATEWAY.replace("__BASE__", base).replace("__HASH__", loader_hash)


def _kick(msg):
    safe = msg.replace("\\", "\\\\").replace('"', '\\"')
    return 'local p=game:GetService("Players").LocalPlayer;if p then p:Kick("' + safe + '")end'


def _hex_hash(path, query):
    raw = ""
    q = parse_qs(query)
    if q.get("file"):
        raw = q["file"][0]
    elif q.get("h"):
        raw = q["h"][0]
    else:
        raw = path.rsplit("/", 1)[-1]
    if raw.endswith(".lua"):
        raw = raw[:-4]
    return "".join(c for c in raw if c in "0123456789abcdef")


_GW_CACHE = {}


def _obf_gateway(base, loader_hash):
    ck = base + "|" + loader_hash
    hit = _GW_CACHE.get(ck)
    if hit is not None:
        return hit
    src = _gateway(base, loader_hash)
    try:
        out = obfuscate(src, {"target": "executor", "roblox_check": False,
                              "silent": True, "fast": True})
    except Exception:
        out = src
    if len(_GW_CACHE) > 400:
        _GW_CACHE.clear()
    _GW_CACHE[ck] = out
    return out


_SECOND_CHECK = (
    'do\n'
    'local HS=game:GetService("HttpService")\n'
    'local k="" pcall(function() if script_key~=nil then k=tostring(script_key) end end)\n'
    'if k=="" and getgenv then pcall(function() local g=getgenv().script_key if g~=nil then k=tostring(g) end end) end\n'
    'local h="" pcall(function() h=tostring(game:GetService("RbxAnalyticsService"):GetClientId()) end)\n'
    'if h=="" and gethwid then pcall(function() h=tostring(gethwid()) end) end\n'
    'local ok,b=pcall(function() return game:HttpGet("__BASE__/check/__HASH__?key="..HS:UrlEncode(k).."&hwid="..HS:UrlEncode(h)) end)\n'
    'if ok and b and #b>0 then local f=loadstring(b) if f then f() end end\n'
    'end\n')


def _second_check(base, loader_hash):
    return _SECOND_CHECK.replace("__BASE__", base).replace("__HASH__", loader_hash)


def _validate(loader_hash, record, key, hwid):
    if record.get("frozen"):
        return False, "LUREX: Script Frozen"
    if record.get("free"):
        return True, None
    if not key:
        return False, "LUREX: No Key Provided."
    krec = fine_store.get_project_key(loader_hash, key)
    if not krec:
        return False, "LUREX: Invalid Key."
    if krec.get("discord_id") and fine_store.get_acl(loader_hash, krec["discord_id"]) == "black":
        return False, "LUREX: Access Revoked."
    if not hwid:
        return False, "LUREX: HWID Unavailable."
    if not krec.get("hwid"):
        fine_store.assign_hwid(key, hwid)
    elif krec.get("hwid") != hwid:
        return False, "LUREX: HWID Mismatch"
    return True, None


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        query = parsed.query
        q = parse_qs(query, keep_blank_values=True)
        # On Vercel every request is rewritten to /api/index with the original
        # path carried in ?vpath=... . Locally (no rewrite) fall back to the path.
        if "vpath" in q:
            vp = q["vpath"][0]
            p = "/" + vp.lstrip("/") if vp and vp != ":vpath*" else "/"
        else:
            p = parsed.path
        if p.startswith("/verify/"):
            return self._serve_verify(p, query)
        if p.startswith("/check/"):
            return self._serve_check(p, query)
        if p.startswith("/loaders/") or p.rstrip("/").endswith("/loader"):
            return self._serve_loader(p, query)
        if p in ("/api", "/api/", "/api/index") or p.rstrip("/").endswith("/health"):
            return self._json(200, {"name": "LUREX", "version": __version__, "status": "ok",
                                    "engine": "local",
                                    "external_obfuscator": False,
                                    "storage": "postgres" if fine_store.enabled() else "ephemeral"})
        return self._serve_site()

    def _serve_site(self):
        html = None
        if web_app is not None:
            html = web_app.HTML
        if html is None:
            root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            try:
                with open(os.path.join(root, "web", "app.html"), encoding="utf-8") as f:
                    html = f.read()
            except Exception:
                html = "<!doctype html><title>LUREX</title><h1>LUREX</h1><p>Control panel unavailable.</p>"
        html = html.replace("__VERSION__", __version__)
        data = html.encode()
        self.send_response(200)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("content-length", str(len(data)))
        self.send_header("access-control-allow-origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def _serve_loader(self, path, query):
        loader_hash = _hex_hash(path, query)
        if not loader_hash:
            return self._text(404, "-- not found")
        try:
            record = fine_store.load_loader(loader_hash)
        except Exception as e:
            return self._text(502, "-- storage error: " + str(e))
        if not record:
            return self._text(404, "-- not found")
        if record.get("frozen"):
            return self._text(200, _kick("LUREX: Script Frozen"))
        if record.get("free"):
            # Free scripts do not need a key/HWID gateway. Returning the protected
            # chunk directly also avoids executor-specific failures in the wrapper.
            return self._text(200, record.get("code") or "")
        self._text(200, _obf_gateway(_base(self), loader_hash))

    def _serve_verify(self, path, query):
        loader_hash = _hex_hash(path, query)
        q = parse_qs(query)
        key = (q.get("key") or [""])[0].strip()
        hwid = (q.get("hwid") or [""])[0].strip()
        try:
            record = fine_store.load_loader(loader_hash)
        except Exception:
            return self._text(200, _kick("LUREX: Server Error"))
        if not record:
            return self._text(200, _kick("LUREX: Invalid Script"))
        ok, msg = _validate(loader_hash, record, key, hwid)
        if not ok:
            return self._text(200, _kick(msg))
        self._text(200, record.get("code") or "")

    def _serve_check(self, path, query):
        loader_hash = _hex_hash(path, query)
        q = parse_qs(query)
        key = (q.get("key") or [""])[0].strip()
        hwid = (q.get("hwid") or [""])[0].strip()
        try:
            record = fine_store.load_loader(loader_hash)
        except Exception:
            return self._text(200, "")
        if not record:
            return self._text(200, _kick("LUREX: Invalid Script") + ';error("f")')
        ok, msg = _validate(loader_hash, record, key, hwid)
        if not ok:
            return self._text(200, _kick(msg) + ';error("f")')
        self._text(200, "")

    def _text(self, code, body):
        data = body.encode()
        self.send_response(code)
        self.send_header("content-type", "text/plain; charset=utf-8")
        self.send_header("content-length", str(len(data)))
        self.send_header("access-control-allow-origin", "*")
        self.send_header("cache-control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_POST(self):
        try:
            length = int(self.headers.get("content-length") or 0)
        except ValueError:
            return self._json(400, {"error": "invalid content-length"})
        if length > _MAX_BYTES:
            return self._json(413, {"error": "payload too large"})
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._json(400, {"error": "invalid JSON body"})

        action = payload.get("action")
        if action in PANEL_ACTIONS:
            return self._panel(action, payload)
        if action in OWNER_ACTIONS:
            return self._manage(action, payload)
        if action and action != "obfuscate":
            return self._json(400, {"error": "unknown action: " + str(action)})
        return self._obfuscate(payload)

    def _obfuscate(self, payload):
        source = payload.get("source")
        if not isinstance(source, str) or not source.strip():
            return self._json(400, {"error": "missing 'source'"})
        options = payload.get("options") or {}
        name = options.get("name") or payload.get("name") or "script"
        free = bool(options.get("free") if options.get("free") is not None else payload.get("free"))
        engine = str(options.get("engine") or "LUREX").upper()
        if engine not in ("LUREX", "PROMETHEUS"):
            return self._json(400, {"error": "engine must be LUREX or PROMETHEUS"})
        owner = payload.get("owner")
        loader_hash = hashlib.md5(secrets.token_bytes(16)).hexdigest()
        script_id = _script_id()
        owner_key = _owner_id()
        owner_meta = {"user_id": "", "server_id": "", "owner_key": owner_key}
        if isinstance(owner, str):
            try:
                owner_meta.update(json.loads(owner))
            except Exception:
                pass
        owner_meta["owner_key"] = owner_key
        build_source = source if free else _second_check(_base(self), loader_hash) + source

        try:
            output = _build(build_source, {**options, "name": name})
        except SyntaxError as e:
            return self._json(400, {"error": "syntax error: " + str(e)})
        except Exception as e:
            return self._json(500, {"error": str(e)})
        try:
            fine_store.save_loader(loader_hash, script_id, output, name,
                                   owner=json.dumps(owner_meta), free=free, source=source, silent=bool(options.get("silent")), engine=engine)
        except Exception as e:
            return self._json(502, {"error": "storage unavailable: " + str(e)})

        url = _base(self) + "/loaders/" + loader_hash + ".lua"
        self._json(200, {
            "name": name,
            "project_id": _project_id(loader_hash),
            "url": url,
            "loadstring": _loadstring(url),
            "script_id": script_id,
            "owner_key": owner_key,
            "free": free,
            "engine": engine,
            "preset": "Strong" if engine == "PROMETHEUS" else None,
            "output": output,
            "bytes": len(output),
            "ephemeral_storage": not fine_store.enabled(),
        })

    # ---------------- owner management (script_id) ----------------

    def _manage(self, action, payload):
        actor_id = str(payload.get("actor_id") or "")
        if action == "owner_view":
            if actor_id not in _OWNER_VIEW_IDS:
                return self._json(403, {"error": "owner view is restricted"})
            return self._json(200, fine_store.owner_view())
        if action == "list_mine":
            rows = fine_store.list_by_user(actor_id)
            for row in rows:
                loader_hash = row.get("hash")
                url = _base(self) + "/loaders/" + str(loader_hash) + ".lua"
                row.update(script_id=row.get("sid"), project_id=_project_id(loader_hash), url=url, loadstring=_loadstring(url))
            return self._json(200, {"scripts": rows})
        script_id = payload.get("script_id")
        owner_key = payload.get("owner_key")
        project_value = payload.get("project")
        actor_id = str(payload.get("actor_id") or "")
        delegated = bool(project_value and actor_id)
        if delegated:
            loader_hash = _loader_hash(project_value)
            record = fine_store.load_loader(loader_hash)
            scope = "all"
            if action in ("whitelist", "unlist"): scope = "whitelist"
            elif action == "blacklist": scope = "blacklist"
            elif action == "genkey": scope = "bulkgen" if int(payload.get("count") or 1) > 1 else "generate"
            elif action == "listkeys": scope = "generate"
            elif action in ("setadmin", "setwl", "info", "listacl", "set_free", "set_settings", "freeze", "unfreeze", "update", "reobfuscate", "delete", "set_panel"): scope = "all"
            if not fine_store.can_delegate(loader_hash, actor_id, scope):
                return self._json(403, {"error": "you are not delegated for this project"})
        elif action == "set_panel" and project_value:
            loader_hash = _loader_hash(project_value)
            record = fine_store.load_loader(loader_hash)
        else:
            if isinstance(owner_key, str) and owner_key:
                loader_hash, record = fine_store.resolve_owner(owner_key)
            else:
                if not isinstance(script_id, str) or not script_id:
                    return self._json(400, {"error": "missing 'script_id' or 'owner_key'"})
                loader_hash, record = fine_store.resolve_sid(script_id)
        if not record:
            return self._json(404, {"error": "unknown or expired script or owner credential"})
        if actor_id and script_id and not delegated and action != "owner_view":
            try:
                owner_meta = json.loads(record.get("owner") or "{}")
            except Exception:
                owner_meta = {}
            if owner_meta.get("user_id") and owner_meta.get("user_id") != actor_id:
                return self._json(403, {"error": "only the script creator can use this owner action"})
        url = _base(self) + "/loaders/" + loader_hash + ".lua"

        if action in ("setadmin", "setwl", "rmwl"):
            try:
                owner_meta = json.loads(record.get("owner") or "{}")
            except Exception:
                owner_meta = {}
            if actor_id and owner_meta.get("user_id") and owner_meta.get("user_id") != actor_id:
                return self._json(403, {"error": "only the script creator can change permissions"})
            subject_type = str(payload.get("subject_type") or "member")
            subject_id = str(payload.get("subject_id") or "")
            if subject_type not in ("member", "role") or not subject_id:
                return self._json(400, {"error": "subject_type must be member or role and subject_id is required"})
            scope = "all" if action == "setadmin" else str(payload.get("scope") or "all")
            if scope not in ("all", "whitelist", "blacklist", "generate", "bulkgen"):
                return self._json(400, {"error": "invalid delegation scope"})
            enabled = False if action == "rmwl" else bool(payload.get("enabled", True))
            if action == "rmwl" and scope == "all":
                for revoke_scope in ("all", "whitelist", "blacklist", "generate", "bulkgen"):
                    fine_store.set_delegate(loader_hash, subject_type, subject_id, revoke_scope, False)
            else:
                fine_store.set_delegate(loader_hash, subject_type, subject_id, scope, enabled)
            fine_store.add_audit(loader_hash, actor_id or script_id, action, subject_id, {"subject_type": subject_type, "scope": scope, "enabled": enabled})
            return self._json(200, {"updated": True, "subject_type": subject_type, "subject_id": subject_id, "scope": scope, "enabled": enabled})
        if action == "info":
            keys = fine_store.list_keys(loader_hash)
            return self._json(200, {
                "name": record.get("name"), "project_id": _project_id(loader_hash), "url": url,
                "loadstring": _loadstring(url), "frozen": record.get("frozen", False),
                "free": record.get("free", False), "engine": record.get("engine", "LUREX"), "keys": len(keys),
                "has_source": bool(record.get("source")),
                "panel_title": record.get("panel_title"),
                "panel_desc": record.get("panel_desc"),
                "panel_color": record.get("panel_color"),
                "panel_hwid_resets": record.get("panel_hwid_resets", True),
                "panel_show_redeem": record.get("panel_show_redeem", True),
                "panel_show_get_script": record.get("panel_show_get_script", True),
                "panel_show_hwid": record.get("panel_show_hwid", True),
                "panel_show_buyer": record.get("panel_show_buyer", True),
                "panel_show_key_info": record.get("panel_show_key_info", True),
                "panel_emojis": record.get("panel_emojis", False),
                "panel_luarmor_look": record.get("panel_luarmor_look", False),
                "buyer_role": record.get("panel_buyer_role"),
                "whitelist_role": record.get("panel_whitelist_role"),
                "admin_role": record.get("panel_admin_role"),
                "acl": len(fine_store.list_acl(loader_hash)),
                "created": record.get("created"), "updated": record.get("updated"),
                "bytes": len(record.get("code") or ""),
            })
        if action == "delete":
            fine_store.remove(loader_hash, script_id)
            return self._json(200, {"deleted": True})
        if action in ("freeze", "unfreeze"):
            fine_store.set_frozen(loader_hash, record, action == "freeze")
            return self._json(200, {"frozen": action == "freeze", "url": url})
        if action == "set_free":
            free = bool(payload.get("free"))
            fine_store.set_free(loader_hash, record, free)
            return self._json(200, {"free": free})
        if action == "set_settings":
            options = payload.get("options") or {}
            name = str(options.get("name") or record.get("name") or "script")[:80]
            free = bool(options.get("free")) if "free" in options else None
            silent = bool(options.get("silent")) if "silent" in options else None
            engine = str(options.get("engine") or record.get("engine") or "LUREX").upper()
            engine_changed = "engine" in options and engine != str(record.get("engine") or "LUREX").upper()
            if engine not in ("LUREX", "PROMETHEUS"):
                return self._json(400, {"error": "engine must be LUREX or PROMETHEUS"})
            if record.get("source") and (free is not None or silent is not None or engine_changed or name != record.get("name")) :
                next_free = record.get("free", False) if free is None else free
                next_silent = record.get("silent", False) if silent is None else silent
                build_source = record.get("source") if next_free else _second_check(_base(self), loader_hash) + record.get("source")
                try:
                    output = _build(build_source, {"name": name, "silent": next_silent, "engine": engine, "preset": "Strong"})
                except Exception as e:
                    return self._json(500, {"error": str(e)})
                fine_store.update_code(loader_hash, record, output, source=record.get("source"))
            fine_store.set_settings(loader_hash, record, name=name, free=free, silent=silent, engine=engine)
            return self._json(200, {"updated": True, "name": record.get("name"), "free": record.get("free", False), "silent": record.get("silent", False), "engine": record.get("engine", "LUREX"), "url": url, "loadstring": _loadstring(url)})
        if action == "set_panel":
            fine_store.set_panel(
                loader_hash, record, payload.get("title"), payload.get("desc"), payload.get("color"),
                payload.get("hwid_resets", True), payload.get("show_redeem", True),
                payload.get("show_get_script", True), payload.get("show_hwid", True),
                payload.get("show_buyer", True), payload.get("show_key_info", True),
                payload.get("emojis", False), payload.get("luarmor_look", False),
                payload.get("buyer_role"), payload.get("whitelist_role"), payload.get("admin_role"))
            return self._json(200, {"panel": {
                "title": record.get("panel_title"), "desc": record.get("panel_desc"),
                "color": record.get("panel_color"),
                "hwid_resets": record.get("panel_hwid_resets", True),
                "show_redeem": record.get("panel_show_redeem", True),
                "show_get_script": record.get("panel_show_get_script", True),
                "show_hwid": record.get("panel_show_hwid", True),
                "show_buyer": record.get("panel_show_buyer", True),
                "show_key_info": record.get("panel_show_key_info", True),
                "emojis": record.get("panel_emojis", False),
                "luarmor_look": record.get("panel_luarmor_look", False),
                "buyer_role": record.get("panel_buyer_role"),
                "whitelist_role": record.get("panel_whitelist_role"),
                "admin_role": record.get("panel_admin_role")}})
        if action == "reobfuscate":
            src = record.get("source")
            if not src:
                return self._json(400, {"error": "no stored source; re-upload via 'update' to re-obfuscate"})
            free = record.get("free")
            build_source = src if free else _second_check(_base(self), loader_hash) + src
            try:
                output = _build(build_source, {"name": record.get("name") or "script", "engine": record.get("engine", "LUREX")})
            except Exception as e:
                return self._json(500, {"error": str(e)})
            fine_store.update_code(loader_hash, record, output, source=src)
            return self._json(200, {"reobfuscated": True, "name": record.get("name"),
                                    "url": url, "loadstring": _loadstring(url), "bytes": len(output)})
        if action == "update":
            source = payload.get("source")
            if not isinstance(source, str) or not source.strip():
                return self._json(400, {"error": "missing 'source'"})
            options = payload.get("options") or {}
            name = options.get("name") or record.get("name") or "script"
            free = record.get("free")
            build_source = source if free else _second_check(_base(self), loader_hash) + source
            try:
                output = _build(build_source, {**options, "name": name, "engine": record.get("engine", "LUREX"), "preset": "Strong"})
            except SyntaxError as e:
                return self._json(400, {"error": "syntax error: " + str(e)})
            except Exception as e:
                return self._json(500, {"error": str(e)})
            record["name"] = name
            fine_store.update_code(loader_hash, record, output, source=source)
            return self._json(200, {
                "updated": True, "name": name, "url": url,
                "loadstring": _loadstring(url), "output": output, "bytes": len(output),
            })
        if action == "genkey":
            count = payload.get("count", 1)
            label = payload.get("label")
            keys = fine_store.create_keys(loader_hash, count, label)
            return self._json(200, {"keys": keys, "count": len(keys)})
        if action == "delkey":
            key = payload.get("key")
            if not key:
                return self._json(400, {"error": "missing 'key'"})
            ok = fine_store.delete_key(loader_hash, key)
            return self._json(200, {"deleted": ok})
        if action == "listkeys":
            keys = fine_store.list_keys(loader_hash)
            return self._json(200, {"keys": [{
                "key": k.get("key"), "hwid_bound": bool(k.get("hwid")),
                "discord_id": k.get("discord_id"), "label": k.get("label"),
                "created": k.get("created")} for k in keys]})
        if action in ("whitelist", "blacklist"):
            did = str(payload.get("discord_id") or "")
            if not did:
                return self._json(400, {"error": "missing 'discord_id'"})
            fine_store.set_acl(loader_hash, did, "white" if action == "whitelist" else "black")
            return self._json(200, {"discord_id": did, "status": "white" if action == "whitelist" else "black"})
        if action == "unlist":
            did = str(payload.get("discord_id") or "")
            fine_store.clear_acl(loader_hash, did)
            return self._json(200, {"discord_id": did, "status": "cleared"})
        if action == "listacl":
            return self._json(200, {"acl": fine_store.list_acl(loader_hash)})
        return self._json(400, {"error": "unknown action: " + str(action)})

    # ---------------- public panel (project id + discord id) ----------------

    def _panel(self, action, payload):
        if _BOT_SECRET and (self.headers.get("x-lurex-auth") or self.headers.get("x-fine-auth")) != _BOT_SECRET:
            return self._json(401, {"error": "unauthorized"})
        project = payload.get("project")
        if not isinstance(project, str) or not project:
            return self._json(400, {"error": "missing 'project'"})
        project = _loader_hash(project)
        record = fine_store.load_loader(project)
        if not record:
            return self._json(404, {"error": "unknown project"})
        url = _base(self) + "/loaders/" + project + ".lua"

        if action == "panel_info":
            return self._json(200, {"name": record.get("name"), "free": record.get("free", False),
                                    "frozen": record.get("frozen", False),
                                    "panel_title": record.get("panel_title"),
                                    "panel_desc": record.get("panel_desc"),
                                    "panel_color": record.get("panel_color"),
                                    "panel_hwid_resets": record.get("panel_hwid_resets", True),
                                    "panel_show_redeem": record.get("panel_show_redeem", True),
                                    "panel_show_get_script": record.get("panel_show_get_script", True),
                                    "panel_show_hwid": record.get("panel_show_hwid", True),
                                    "panel_show_buyer": record.get("panel_show_buyer", True),
                                    "panel_show_key_info": record.get("panel_show_key_info", True),
                                    "panel_emojis": record.get("panel_emojis", False),
                                    "panel_luarmor_look": record.get("panel_luarmor_look", False)})

        did = str(payload.get("discord_id") or "")
        if not did:
            return self._json(400, {"error": "missing 'discord_id'"})
        if fine_store.get_acl(project, did) == "black":
            return self._json(403, {"error": "You are blacklisted from this script."})

        if action == "redeem":
            key = (payload.get("key") or "").strip()
            if not key:
                return self._json(400, {"error": "missing 'key'"})
            krec = fine_store.get_project_key(project, key)
            if not krec:
                return self._json(404, {"error": "Invalid key for this script."})
            if krec.get("discord_id") and krec["discord_id"] != did:
                return self._json(409, {"error": "That key was already redeemed by someone else."})
            fine_store.bind_discord(key, did)
            return self._json(200, {"redeemed": True, "key": key})

        if action == "get_script":
            krec = fine_store.key_for_discord(project, did)
            whitelisted = fine_store.get_acl(project, did) == "white"
            if not krec and not record.get("free") and not whitelisted:
                return self._json(404, {"error": "Redeem a key first or ask the owner to whitelist you."})
            if not krec and whitelisted and not record.get("free"):
                generated_key = fine_store.create_keys(project, 1, label=f"whitelist:{did}")[0]
                fine_store.bind_discord(generated_key, did)
                krec = fine_store.get_key(generated_key)
            key = krec.get("key") if krec else None
            if key:
                full = _keyed_loadstring(url, key)
            else:
                full = _loadstring(url)
            return self._json(200, {"loadstring": full, "key": key, "url": url})

        if action == "reset_hwid":
            if not record.get("panel_hwid_resets", True):
                return self._json(403, {"error": "HWID resets are disabled for this panel."})
            krec = fine_store.key_for_discord(project, did)
            if not krec:
                return self._json(404, {"error": "You have no redeemed key to reset."})
            remaining = fine_store.reset_available_in(krec)
            if remaining > 0:
                return self._json(429, {"error": "HWID reset on cooldown.", "reset_in": remaining})
            fine_store.reset_hwid(krec["key"])
            return self._json(200, {"reset": True})

        if action == "buyer_check":
            krec = fine_store.key_for_discord(project, did)
            eligible = bool(krec) or bool(record.get("free")) or fine_store.get_acl(project, did) == "white"
            return self._json(200, {"eligible": eligible})

        if action == "key_info":
            krec = fine_store.key_for_discord(project, did)
            if not krec:
                return self._json(200, {"redeemed": False, "free": record.get("free", False)})
            return self._json(200, {
                "redeemed": True, "key": krec.get("key"),
                "hwid_bound": bool(krec.get("hwid")),
                "reset_in": fine_store.reset_available_in(krec),
                "free": record.get("free", False),
            })
        return self._json(400, {"error": "unknown action: " + str(action)})

    def _cors(self):
        self.send_header("access-control-allow-origin", "*")
        self.send_header("access-control-allow-methods", "GET, POST, OPTIONS")
        self.send_header("access-control-allow-headers", "content-type, x-lurex-auth, x-fine-auth")

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass
