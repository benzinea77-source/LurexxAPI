from __future__ import annotations

import os
import random
import re
import string as _string

from . import __version__
from .parser import parse
from .compiler import (compile_source_to_proto, apply_fusions,
                       shuffle_constants, scramble_cfg)
from .serialize_binary import encode_program, ascii85_encode
from . import vmgen

HEADER = f"--[[ Protected by LUREX v{__version__} | @qjycc ]]"
TEMPLATES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")


def _read_template(name: str) -> str:
    with open(os.path.join(TEMPLATES, name)) as f:
        return f.read()


def bytes_to_lua_string(bs: bytes) -> str:
    out = ['"']
    for b in bs:
        if b == 0x22:
            out.append('\\"')
        elif b == 0x5C:
            out.append("\\\\")
        elif 32 <= b < 127:
            out.append(chr(b))
        else:
            out.append("\\%03d" % b)
    out.append('"')
    return "".join(out)


def lua_literal(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif o < 32:
            out.append("\\%d" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def quote_base85(s: str) -> str:
    out = ['"']
    for ch in s:
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def strip_comments(src: str) -> str:
    out = []
    i, n = 0, len(src)
    while i < n:
        ch = src[i]
        if ch in ("'", '"'):
            q = ch
            out.append(ch); i += 1
            while i < n:
                c = src[i]
                out.append(c)
                if c == "\\" and i + 1 < n:
                    out.append(src[i + 1]); i += 2; continue
                i += 1
                if c == q:
                    break
            continue
        if ch == "[" and i + 1 < n and src[i + 1] in "[=":
            m = re.match(r"\[(=*)\[", src[i:])
            if m:
                close = "]" + m.group(1) + "]"
                end = src.find(close, i + m.end())
                seg = src[i:] if end < 0 else src[i:end + len(close)]
                out.append(seg)
                i += len(seg)
                continue
        if ch == "-" and i + 1 < n and src[i + 1] == "-":
            j = i + 2
            m = re.match(r"\[(=*)\[", src[j:])
            if m:
                close = "]" + m.group(1) + "]"
                end = src.find(close, j + m.end())
                i = n if end < 0 else end + len(close)
            else:
                nl = src.find("\n", j)
                i = n if nl < 0 else nl
            continue
        out.append(ch); i += 1
    return "".join(out)


def minify_ws(src: str) -> str:
    lines = []
    for line in src.splitlines():
        s = line.strip()
        if s:
            lines.append(s)
    return " ".join(lines)


class NameGen:
    def __init__(self, seed=None):
        self.rng = random.Random(seed)
        self.used = set()

    def new(self) -> str:
        # Use confusable chars: Il0O to make names hard to read
        alpha = "IlO0ocQ"
        while True:
            name = self.rng.choice("Il") + "".join(
                self.rng.choice(alpha) for _ in range(self.rng.randint(6, 12)))
            if name not in self.used:
                self.used.add(name)
                return name


def rename_identifiers(src: str, names: list[str], gen: NameGen) -> str:
    mapping = {name: gen.new() for name in names}
    pattern = re.compile(r"\b(" + "|".join(re.escape(n) for n in
                         sorted(names, key=len, reverse=True)) + r")\b")

    def sub_code(seg: str) -> str:
        return pattern.sub(lambda m: mapping[m.group(1)], seg)

    out = []
    i, n = 0, len(src)
    seg_start = 0
    while i < n:
        ch = src[i]
        if ch == "'" or ch == '"':
            out.append(sub_code(src[seg_start:i]))
            q = ch
            j = i + 1
            while j < n:
                c = src[j]
                if c == "\\" and j + 1 < n:
                    j += 2
                    continue
                j += 1
                if c == q:
                    break
            out.append(src[i:j])
            i = j
            seg_start = i
        else:
            i += 1
    out.append(sub_code(src[seg_start:]))
    return "".join(out)


_LEGIT_GLOBALS = [
    "string", "table", "math", "os", "coroutine", "utf8", "bit32", "buffer",
    "debug", "task", "pairs", "ipairs", "next", "print", "warn", "tostring",
    "tonumber", "type", "typeof", "select", "pcall", "xpcall", "error", "assert",
    "setmetatable", "getmetatable", "rawget", "rawset", "rawequal", "rawlen",
    "unpack", "require", "tick", "wait", "spawn", "delay", "game", "workspace",
    "script", "Instance", "Vector3", "Vector2", "CFrame", "Color3", "UDim",
    "UDim2", "Enum", "Ray", "Region3", "TweenInfo", "BrickColor", "Random",
    "DateTime", "NumberRange", "NumberSequence", "ColorSequence", "Rect", "Faces",
    "_G", "_VERSION", "shared", "newproxy", "collectgarbage", "gcinfo", "loadstring",
    "load", "getfenv", "setfenv", "getconstants", "getupvalue", "getinfo", "sethook",
    "traceback", "profilebegin", "profileend", "concat", "insert", "remove", "sort",
    "find", "create", "freeze", "clear", "byte", "char", "sub", "gsub", "match",
    "format", "rep", "len", "upper", "lower", "floor", "ceil", "abs", "max", "min",
    "huge", "pi", "random", "wait", "spawn", "defer", "delay", "cancel",
]


def _fnv1a(s: str, basis: int) -> int:
    h = basis
    for ch in s.encode("utf-8"):
        x = h % 256
        h = h - x + (x ^ ch)
        lo = h % 65536
        hi = h // 65536
        h = ((hi * 16777619 % 65536) * 65536 + lo * 16777619) % 4294967296
    return h


def _enc_str_lua(s: str, k: int) -> str:
    return bytes_to_lua_string(bytes((ord(c) + k) & 0xFF for c in s))


# ── Decompiler poison ─────────────────────────────────────────────────────────

def decompiler_poison() -> str:
    """
    Returns Lua comments/tokens that are valid Lua but crash or confuse
    common decompiler/beautifier tools:
    - UTF-8 BOM inside a comment  (breaks C-string based parsers)
    - Semicolon trap              (beautifiers miscount statement boundaries)
    - Long-comment with ]]; trick (confuses comment-end detection)
    """
    return (
        "--\xEF\xBB\xBF\n"          # UTF-8 BOM comment — valid Lua, breaks many parsers
        "--;;\n"                      # Semicolon trap
        "--[[;]]\n"                   # Long-comment semicolon
    )


# ── Active anti-analysis trap ─────────────────────────────────────────────────

def active_trap_src() -> str:
    """
    pcall(unpack, {}, 0, 2^31-1) reliably segfaults Lua 5.1 interpreters
    (the C stack overflows on the huge range).  In Luau the pcall catches it.
    We wrap it so it becomes a silent check: if we are in a hostile Lua 5.1
    dump tool, it crashes before it reads our payload.
    """
    return (
        "do\n"
        "  local _u = table.unpack or unpack\n"
        "  local _ok = pcall(_u, {}, 0, 2147483647)\n"
        "  -- In Luau _ok==true; in Lua 5.1 dump tools: crash\n"
        "end\n"
    )


# ── Watermark embedding ───────────────────────────────────────────────────────

def watermark_src(seed: int) -> str:
    """
    Embeds an invisible per-obfuscation watermark as a dead constant.
    The value is derived from the seed so each output is traceable.
    """
    wk = (seed * 7919) % 999983
    return f"local __WM = ({wk} * 1) -- lurex-{seed & 0xFFFF:04X}\n"


# ── Guard builder ─────────────────────────────────────────────────────────────

def build_guards(opts: dict, rng) -> tuple[str, str]:
    defs = []
    conds = []

    k = rng.randrange(1, 256)
    dec_helper = f"""
local function __DARC_DEC_STR__(s)
    local t = {{}}
    for i = 1, #s do t[i] = __schar((__sbyte(s, i) - {k}) % 256) end
    return __tconc(t)
end"""
    defs.append(dec_helper)

    def enc(s: str) -> str:
        return _enc_str_lua(s, k)

    blocks = []

    if opts.get("roblox_check", True):
        roblox_def = f"""
local function __ROBLOX_OK__(E)
    local g = __rawget(E, __DARC_DEC_STR__({enc("game")})) or E.game
    local tg = E.typeof
    if not tg then return false end
    if tg(g) ~= __DARC_DEC_STR__({enc("Instance")}) then return false end
    if not E.workspace then return false end
    if not E.task then return false end
    local inst = E.Instance
    if not inst or not inst.new then return false end
    local ok, cls = __pcall(function() return g.ClassName end)
    if not ok or cls ~= __DARC_DEC_STR__({enc("DataModel")}) then return false end
    return true
end"""
        blocks.append((roblox_def, "__ROBLOX_OK__(ENV)",
                       "not a Roblox DataModel environment"))

        def d(s: str) -> str:
            return f"__DARC_DEC_STR__({enc(s)})"

        genuine_def = f"""
local function __GENUINE__(E)
    local g = __rawget(E, {d("game")}) or E.game
    if __type(g) ~= {d("userdata")} then return false end
    if __type(E[{d("workspace")}]) ~= {d("userdata")} then return false end
    if __type(__gmt(g)) == {d("table")} then return false end
    local T = E[{d("table")}]
    if __type(T) ~= {d("table")} then return false end
    if __type(T[{d("create")}]) ~= {d("function")} then return false end
    if __type(T[{d("freeze")}]) ~= {d("function")} then return false end
    if __type(E[{d("task")}]) ~= {d("table")} then return false end
    local ok, r = __pcall(function()
        local tf = E[{d("typeof")}]
        local In = E[{d("Instance")}]
        local v = E[{d("Vector3")}][{d("new")}](1, 2, 3)
        if tf(v) ~= {d("Vector3")} or v[{d("X")}] ~= 1 then return false end
        local inst = In[{d("new")}]({d("Part")})
        if __type(inst) ~= {d("userdata")} then return false end
        if tf(inst) ~= {d("Instance")} or inst[{d("ClassName")}] ~= {d("Part")} then return false end
        if E[{d("tostring")}](inst) ~= {d("Part")} then return false end
        local isa = inst[{d("IsA")}]
        if isa(inst, {d("Part")}) ~= true then return false end
        if isa(inst, {d("__no_such_class__")}) ~= false then return false end
        if __pcall(In[{d("new")}], {d(chr(1) + chr(2) + "invalidclass" + chr(3))}) then return false end
        if __pcall(__smt, inst, {{}}) then return false end
        return true
    end)
    return ok and r == true
end"""
        blocks.append((genuine_def, "__GENUINE__(ENV)",
                       "emulated / fake Roblox environment"))

    if opts.get("anti_tamper", True):
        env_def = f"""
local function __ENV_OK__(E)
    if __gmt(E) ~= nil then return false end
    local g = __rawget(E, "_G")
    if g ~= nil and __gmt(g) ~= nil then return false end
    local gm = __rawget(E, __DARC_DEC_STR__({enc("game")})) or E.game
    if gm ~= nil and __type(__gmt(gm)) == __DARC_DEC_STR__({enc("table")}) then return false end
    if __type(__type) ~= __DARC_DEC_STR__({enc("function")}) then return false end
    if __tostr(1) ~= "1" or __tostr(true) ~= __DARC_DEC_STR__({enc("true")}) then return false end
    return true
end"""
        blocks.append((env_def, "__ENV_OK__(ENV)",
                       "environment proxy/metatable detected"))

        suspects = [
            "getgenv", "getrenv", "getreg", "getgc", "getrawmetatable",
            "setrawmetatable", "hookfunction", "hookmetamethod", "newcclosure",
            "islclosure", "checkcaller", "getnamecallmethod", "getcallingscript",
            "saveinstance", "decompile", "getscriptbytecode", "dumpstring",
            "setreadonly", "make_writeable", "getfunctionhash", "iscclosure",
            "getsenv", "getinstances", "firesignal", "getconnections",
            # Additional executor-specific globals
            "syn", "KRNL_loaded", "peregrine_running", "is_sirhurt_closure",
            "fluxteam", "carbon", "Sentinel", "electron", "Delta",
        ]
        dbg_names = ["getconstants", "getupvalues", "getproto",
                     "setconstant", "getstack", "getprotos", "setstack",
                     "getprotos", "getcode"]
        basis = rng.randrange(1, 4294967296)
        for _ in range(64):
            block_set = {_fnv1a(s, basis) for s in suspects + dbg_names}
            if not any(_fnv1a(g, basis) in block_set for g in _LEGIT_GLOBALS):
                break
            basis = rng.randrange(1, 4294967296)
        env_hashes = ", ".join(f"[{_fnv1a(s, basis)}]=1" for s in suspects)
        dbg_hashes = ", ".join(f"[{_fnv1a(s, basis)}]=1" for s in dbg_names)
        untampered_def = f"""
local function __UNTAMPERED__(E)
    local B = {{ {env_hashes} }}
    local D = {{ {dbg_hashes} }}
    local function H(s)
        local h = {basis}
        for i = 1, #s do
            local c = __sbyte(s, i)
            local x = h % 256
            local r, p, a, b = 0, 1, x, c
            for _ = 1, 8 do
                local aa, bb = a % 2, b % 2
                if aa ~= bb then r = r + p end
                a = (a - aa) / 2; b = (b - bb) / 2; p = p * 2
            end
            h = h - x + r
            local lo = h % 65536
            local hi = (h - lo) / 65536
            h = ((hi * 16777619 % 65536) * 65536 + lo * 16777619) % 4294967296
        end
        return h
    end
    local k = __next(E)
    while k ~= nil do
        if __type(k) == "string" and B[H(k)] then return false end
        k = __next(E, k)
    end
    local dbg = E.debug
    if __type(dbg) == "table" then
        local dk = __next(dbg)
        while dk ~= nil do
            if __type(dk) == "string" and D[H(dk)] then return false end
            dk = __next(dbg, dk)
        end
    end
    return true
end"""
        blocks.append((untampered_def, "__UNTAMPERED__(ENV)",
                       "executor/introspection global detected"))

        m1, m2, m3 = (rng.randint(1, 250), rng.randint(1, 250), rng.randint(1, 250))
        marker = "".join(rng.choice("abcdefghijklmnop") for _ in range(6))
        trap_def = f"""
local function __TRAP_OK__()
    local M = __DARC_DEC_STR__({enc(marker)})
    local mt = {{
        __add = function() return {m1} end,
        __index = function() return {m2} end,
        __call = function() return {m3} end,
        __concat = function() return M end,
        __eq = function() return true end,
    }}
    local t = __smt({{}}, mt)
    local u = __smt({{}}, mt)
    if t + 1 ~= {m1} then return false end
    if t.zzz ~= {m2} then return false end
    if t() ~= {m3} then return false end
    if (t .. "") ~= M then return false end
    if not (t == u) then return false end
    return true
end"""
        blocks.append((trap_def, "__TRAP_OK__()",
                       "metamethod hook / metatable tamper detected"))

        line_def = r"""
local function __LINE_OK__()
    local ok, err = __pcall(function() error("e") end)
    if ok then return false end
    local ln = __smatch(__tostr(err), ":(%d+):")
    if ln ~= nil and ln ~= "1" then return false end
    return true
end"""
        blocks.append((line_def, "__LINE_OK__()",
                       "code was reformatted / beautified"))

        probe_def = r"""
local function __DARC_PROBE__()
    local sb, sc, tc = string.byte, string.char, table.concat
    if sb("AZ", 1) ~= 65 or sb("AZ", 2) ~= 90 then return false end
    if sc(72, 105) ~= "Hi" then return false end
    if tc({ "a", "b", "c" }, "") ~= "abc" then return false end
    if ("darc"):sub(2, 3) ~= "ar" then return false end
    return true
end"""
        blocks.append((probe_def, "__DARC_PROBE__()",
                       "core library function hook detected"))

        # New: hook detection on specific functions used in dumps
        hook_check_def = f"""
local function __HOOK_OK__()
    -- Detect hooks on functions commonly patched by dump scripts
    local _orig_bxor = bit32 and bit32.bxor
    if _orig_bxor then
        local _test = _orig_bxor(0xAB, 0xCD)
        if _test ~= 0x66 then return false end
    end
    local _sc = string.char
    if _sc(65) ~= "A" or _sc(90) ~= "Z" then return false end
    local _sb = string.byte
    if _sb("A") ~= 65 then return false end
    return true
end"""
        blocks.append((hook_check_def, "__HOOK_OK__()",
                       "bit32/string function hook detected"))

    # Upgrade 4: Luau type fingerprint
    luau_def, luau_cond, luau_lbl = luau_type_fingerprint_guard(enc)
    blocks.append((luau_def, luau_cond, luau_lbl))

    # Upgrade 7: KeyForge-style device / HWID fingerprint guard.
    # Only injected when opts["target"] == "executor" (the build is destined for
    # an executor-side key system) AND a target_hwid is supplied in opts.
    # The guard hashes the collected HWID with a per-build salt and compares the
    # low 32 bits against the expected digest — enough to bind a build to a
    # specific machine without storing the raw HWID in the output.
    #
    # Collection priority (mirrors the existing _GATEWAY loader):
    #   1. game:GetService("RbxAnalyticsService"):GetClientId()  — Roblox HWID
    #   2. gethwid()  — executor-provided HWID (syn/wave/etc.)
    #   3. combined fallback: game.JobId .. game.PlaceId .. tostring(game.PlaceVersion)
    if opts.get("target") == "executor" and opts.get("target_hwid"):
        hwid_def, hwid_cond, hwid_lbl = hwid_fingerprint_guard(enc, opts["target_hwid"], rng)
        blocks.append((hwid_def, hwid_cond, hwid_lbl))

    rng.shuffle(blocks)
    for d_, c, lbl in blocks:
        defs.append(d_)
        conds.append((c, lbl))

    return "\n".join(defs), conds


# ── Decoy service prelude ─────────────────────────────────────────────────────

_DECOY_SERVICES = [
    "Players", "Lighting", "RunService", "UserInputService", "ReplicatedStorage",
    "TweenService", "HttpService", "StarterGui", "SoundService", "Debris",
    "CollectionService", "TextService", "Teams", "MarketplaceService",
    "LocalizationService", "ContextActionService", "GuiService",
]
_DECOY_READS = [
    "typeof(game)", "typeof(workspace)", "tostring(tick())", "tick()",
    "game.Name", "game.ClassName", "workspace.Name", "game.PlaceId",
    "game.JobId", "os.time()",
]


def decoy_prelude(rng) -> str:
    stmts = []
    for s in rng.sample(_DECOY_SERVICES, rng.randint(5, 10)):
        stmts.append(f'pcall(function() return game:GetService("{s}") end)')
    for r in rng.sample(_DECOY_READS, rng.randint(3, 7)):
        stmts.append(f'pcall(function() return {r} end)')
    rng.shuffle(stmts)
    return "do " + " ".join(stmts) + " end\n"


# ── Main obfuscate ────────────────────────────────────────────────────────────

def obfuscate(source: str, opts: dict | None = None) -> str:
    opts = opts or {}

    if opts.get("target") == "executor":
        opts = {**opts, "anti_tamper": False}

    fast = bool(opts.get("fast"))
    if fast:
        opts = {**opts, "roblox_check": False}

    # CPS (Luraph-style) dispatch mode — strongest but slightly larger output.
    # fast=True forces flat dispatch: Luau's JIT handles a linear if/elseif
    # chain ~15% faster than the binary-split tree because the hot paths
    # (GETLOCAL, SETLOCAL, JMP, CALL) sit at the top of the flat chain,
    # while the tree always walks O(log n) comparisons regardless of frequency.
    cps_mode = bool(opts.get("cps", not fast))

    silent = bool(opts.get("silent"))
    name = opts.get("name")
    if name and not silent:
        banner = f"{name} loaded successfully (obfuscated with LUREX v{__version__})"
        source = f"print({lua_literal(banner)});\n{source}"

    seed = opts.get("seed")
    gen  = NameGen(seed)
    rng  = gen.rng

    anti_log = opts.get("anti_log")
    if anti_log is None:
        anti_log = opts.get("target") == "executor"
    if fast:
        anti_log = False
    if anti_log:
        source = decoy_prelude(rng) + source

    fusion_specs = vmgen.select_fusions(rng)
    fusion_map   = {pair: spec[0] for pair, spec in fusion_specs.items()}
    fused_names  = [spec[0] for spec in fusion_specs.values()]
    opmap        = vmgen.build_opmap(rng, fused_names)

    # Upgrade 6: anti_env composite — prepend to source so it runs inside VM
    # Default is True: catches env swaps that slip past the outer guards.
    if opts.get("anti_env_composite", True) and not fast:
        source = _anti_env_composite_lua(rng) + source

    proto = compile_source_to_proto(parse(source))
    shuffle_constants(proto, rng)
    apply_fusions(proto, fusion_map)
    if not fast:
        scramble_cfg(proto, rng)
    enc = encode_program(proto, opmap, rng)

    # Upgrade 8: SafeEnv decrypt-key binding — scramble OSEED against live
    # DataModel properties so static dumps cannot derive the true decrypt key.
    _oseed_expr: str
    if opts.get("safe_env_place_id") and not fast:
        _scrambled_oseed, _oseed_expr = safe_env_key_derive(enc["oseed"], opts, rng)
    else:
        _oseed_expr = str(enc["oseed"])

    decoder = _read_template("decoder.lua")
    vm = vmgen.render_vm(
        _read_template("vm.lua"),
        opmap, rng, fusion_specs,
        cps_mode=cps_mode,
    )

    blob85 = quote_base85(ascii85_encode(enc["cipher"]))
    cipher_len = len(enc["cipher"])

    guard_defs, guard_conds = build_guards(opts, rng)
    on_fail = opts.get("on_fail", "error")
    if on_fail == "silent":
        fail_stmt = "return"
    else:
        fail_stmt = "return error(nil, 0)"

    diagnostic = opts.get("diagnostic", False)

    def guard_check() -> str:
        if not guard_conds:
            return ""
        if diagnostic:
            return "\n".join(
                f'if not ({c}) then return error("darc: guard failed - {lbl}", 0) end'
                for c, lbl in guard_conds)
        combined = " and ".join(c for c, _ in guard_conds)
        return f"if not ({combined}) then {fail_stmt} end"

    gcheck = guard_check()

    # ── __DARC_RECHECK__: combined checker closure for the continuous VM monitor
    # Wraps every active guard condition into a single function the VM's
    # background thread can call with (ENV) → bool without knowing guard names
    # (which get renamed at minify time).  fast=True skips guards entirely so
    # no recheck closure is needed there.
    if guard_conds and not fast:
        recheck_body = " and ".join(f"({c})" for c, _ in guard_conds)
        recheck_src = (
            f"local function __DARC_RECHECK__(E)\n"
            f"    local ENV = E\n"
            f"    return {recheck_body}\n"
            f"end\n"
        )
    else:
        # Emit a no-op so the VM template reference never errors.
        recheck_src = "local __DARC_RECHECK__ = nil\n"

    # ── Assemble output ───────────────────────────────────────────────────────

    # Opaque predicates (upgrade 1) — injected inside guard scope
    opaques = opaque_predicates(rng)

    # Decompiler poison goes at the very top (before any code)
    poison = decompiler_poison()

    # Active anti-analysis trap (before guards)
    antitrap = active_trap_src()

    # Watermark
    wm = watermark_src(seed if seed is not None else rng.randint(0, 0xFFFFFFFF))

    body = f"""
{decoder}
{vm}
return (function(...)
    local __ssub, __sbyte, __spack, __sgsub = string.sub, string.byte, string.pack, string.gsub
    local __schar, __gmt, __rawget, __type, __pcall, __tconc, __tostr = string.char, getmetatable, rawget, type, pcall, table.concat, tostring
    local __smt, __next, __smatch = setmetatable, next, string.match
    local function __DARC_B85__(s)
        s = __sgsub(s, "z", "!!!!!")
        return (__sgsub(s, ".....", function(g)
            local a, b, c, d, e = __sbyte(g, 1, 5)
            return __spack("<I4", (a-33)*52200625 + (b-33)*614125 + (c-33)*7225 + (d-33)*85 + (e-33))
        end))
    end
    local ENV = (getfenv and getfenv(0)) or _G
{antitrap}
{wm}
{opaques}
{guard_defs}
{recheck_src}
    {gcheck}
    local B = __ssub(__DARC_B85__({blob85}), 1, {cipher_len})
    local PROGRAM = __DARC_DECODE__(B, {_oseed_expr}, {enc['cseed']}, {enc['iv']}, {enc['checksum']}, {enc['plain_len']})
    {gcheck}
    local TOP = __DARC_VM__(PROGRAM, ENV, __DARC_RECHECK__)
    return TOP(...)
end)(...)
"""

    src = strip_comments(body)
    src = minify_ws(src)
    if opts.get("mutate_strings", True):
        src = mutate_string_constants(src, rng)

    if opts.get("rename", True):
        rename_targets = [
            "__DARC_VM__", "__DARC_DECODE__", "__ROBLOX_OK__", "__UNTAMPERED__",
            "__GENUINE__", "__TRAP_OK__", "__LINE_OK__",
            "__ENV_OK__", "__DARC_DEC_STR__", "__DARC_PROBE__", "__DARC_B85__",
            "__HOOK_OK__",
            # Upgrade 4: Luau type fingerprint (was missing from rename pass)
            "__LUAU_TYPE_OK__",
            # Upgrade 7: HWID fingerprint (was missing from rename pass)
            "__HWID_OK__",
            # Upgrade 6 + v4 monitor symbols
            "__DARC_RECHECK__", "__DARC_KILLED",
            "_hb_check", "_hb", "_hb_last", "_monitor_active",
            "_fnv1a_str", "_rc_hash",
            "__ssub", "__sbyte", "__spack", "__sgsub",
            "__schar", "__gmt", "__rawget", "__type", "__pcall", "__tconc", "__tostr",
            "__smt", "__next", "__smatch",
            "makeClosure", "readproto",
        ]
        src = rename_identifiers(src, rename_targets, gen)

    return HEADER + "\n" + poison + src + "\n"


# ── UPGRADE 1: Opaque Predicates ─────────────────────────────────────────────

def opaque_predicates(rng) -> str:
    snippets = []
    n = rng.randint(2, 999)
    v1 = "".join(rng.choice("IlOocQ") for _ in range(8))
    snippets.append(
        f"local {v1}={n}\n"
        f"if ({v1}*{v1}+{v1})%2~=0 then error(nil,0) end"
    )
    a = rng.randint(1, 20)
    power = a**7
    v2 = "".join(rng.choice("IlOocQ") for _ in range(8))
    snippets.append(
        f"local {v2}={a}\n"
        f"if ({power}-{a})%7~=0 then return nil end"
    )
    bits = rng.choice([8, 16, 24])
    mask = (1 << bits) - 1
    v3 = "".join(rng.choice("IlOocQ") for _ in range(8))
    snippets.append(
        f"local {v3}={mask}\n"
        f"if bit32 and bit32.band({v3},{mask})~={mask} then error(nil,0) end"
    )
    rng.shuffle(snippets)
    return "\n".join(snippets) + "\n"


# ── UPGRADE 2: String Constant Mutator ───────────────────────────────────────

def mutate_string_constants(src: str, rng) -> str:
    base_k = rng.randint(1, 255)
    helper_name = "".join(rng.choice("IlOocQ") for _ in range(10))
    helper = (
        f"local function {helper_name}(t,k)\n"
        f"local r={{}}for i=1,#t do\n"
        f"r[i]=string.char(bit32.bxor(t[i],(k+i*7)%256))\n"
        f"end return table.concat(r) end\n"
    )

    def encode_str(s: str) -> str:
        encoded = [((ord(c) ^ ((base_k + (i+1)*7) % 256))) for i, c in enumerate(s)]
        return f"{helper_name}({{{','.join(map(str, encoded))}}},{base_k})"

    def should_mangle(s: str) -> bool:
        return (4 <= len(s) <= 32
                and all(32 <= ord(c) < 127 for c in s)
                and not s.startswith("__")
                and s not in ("true", "false", "nil", "and", "or", "not",
                              "DataModel", "Instance", "Vector3", "Part",
                              "userdata", "table", "function", "string",
                              "buffer", "number", "boolean"))

    import re
    pattern = re.compile(r'"([^"\\\n]{4,32})"')
    def replacer(m):
        s = m.group(1)
        return encode_str(s) if should_mangle(s) else m.group(0)

    return helper + pattern.sub(replacer, src)


# ── UPGRADE 4: Luau Type Fingerprint Guard ───────────────────────────────────

def luau_type_fingerprint_guard(enc_fn) -> tuple:
    d = f"""
local function __LUAU_TYPE_OK__()
    local ok,v3=pcall(function() return Vector3 and Vector3.new(1,0,0) end)
    if not ok or not v3 then return false end
    local tf=typeof
    if not tf then return false end
    if tf(v3)~={enc_fn("Vector3")} then return false end
    if not buffer then return false end
    local ok2,b=pcall(buffer.create,4)
    if not ok2 then return false end
    if type(b)~={enc_fn("buffer")} then return false end
    if not task or not task.defer then return false end
    if not string.split then return false end
    local parts=string.split("a,b,c",",")
    if #parts~=3 or parts[2]~={enc_fn("b")} then return false end
    return true
end"""
    return d, "__LUAU_TYPE_OK__()", "not genuine Luau runtime"


# ── UPGRADE 6: Anti-env composite (optional per-script header) ───────────────
#
# Generates a short Lua snippet that re-validates the environment at the very
# top of the *compiled source*, so it runs inside the VM as bytecode — not as
# outer Lua text.  This catches env swaps that happen after the outer guards
# pass (e.g. a deobfuscator that patches getfenv() mid-run, or a sandbox that
# defers environment injection until the first I/O call).
#
# Three checks, randomised order:
#   1. typeof(Vector3.new()) == "Vector3"  — genuine Luau type system
#   2. getmetatable(game) is not a plain table  — real locked instance
#   3. rawget(ENV, "_G") metatable is nil  — no proxy _G injection
#
# Returns a Lua source string.  The caller prepends it to `source` before
# compile_source_to_proto so it becomes bytecode instructions, not readable
# Lua text, and lives inside the VM rather than the outer wrapper.

def _anti_env_composite_lua(rng) -> str:
    # Three independent checks; shuffle order so static analysis can't skip
    # by pattern-matching the opening bytes.
    checks = []

    v1 = "".join(rng.choice("IlOocQ") for _ in range(7))
    checks.append(
        f"local {v1}=pcall(function()\n"
        f"  if not(typeof and Vector3)then error(nil,0)end\n"
        f"  local _v=Vector3.new(1,0,0)\n"
        f"  if typeof(_v)~='Vector3'then error(nil,0)end\n"
        f"end)\n"
        f"if not {v1} then return end\n"
    )

    v2 = "".join(rng.choice("IlOocQ") for _ in range(7))
    checks.append(
        f"local {v2}=pcall(function()\n"
        f"  local _g=rawget(_G,'game')or game\n"
        f"  if type(getmetatable(_g))=='table'then error(nil,0)end\n"
        f"end)\n"
        f"if not {v2} then return end\n"
    )

    v3 = "".join(rng.choice("IlOocQ") for _ in range(7))
    checks.append(
        f"local {v3}=pcall(function()\n"
        f"  local _gg=rawget(_G,'_G')\n"
        f"  if _gg~=nil and getmetatable(_gg)~=nil then error(nil,0)end\n"
        f"end)\n"
        f"if not {v3} then return end\n"
    )

    rng.shuffle(checks)
    return "".join(checks)


# ── UPGRADE 7: KeyForge-style HWID / device fingerprint guard ────────────────
#
# Produces a guard that collects the device HWID at runtime, hashes it with a
# per-build salt, and compares the result against the expected digest.  The raw
# HWID never appears in the output — only the salt and the expected hash do.
#
# Algorithm (matches the Python side in fine_store / api/index.py for parity):
#   hash = fnv1a_32(hwid_string, basis=salt)   (same _fnv1a used in obfuscator)
#   low32 = hash % 2^32
#   compare low32 == expected_low32
#
# Lua side reimplements FNV-1a in pure Lua (no bit32 required, pure integer
# arithmetic, safe on Luau's number type which is double, max exact int 2^53).

def hwid_fingerprint_guard(enc_fn, target_hwid: str, rng) -> tuple:
    salt = rng.randrange(1, 4294967296)
    expected = _fnv1a(target_hwid, salt) % 4294967296

    # Per-build variable names
    vg  = "".join(rng.choice("IlOocQ") for _ in range(8))  # collected hwid string
    vh  = "".join(rng.choice("IlOocQ") for _ in range(8))  # hash accumulator
    vi  = "".join(rng.choice("IlOocQ") for _ in range(8))  # loop index
    vc  = "".join(rng.choice("IlOocQ") for _ in range(8))  # char byte
    vx  = "".join(rng.choice("IlOocQ") for _ in range(8))  # xor temp
    vlo = "".join(rng.choice("IlOocQ") for _ in range(8))
    vhi = "".join(rng.choice("IlOocQ") for _ in range(8))

    d = f"""
local function __HWID_OK__()
    -- collect HWID from three sources, first non-empty wins
    local {vg} = ""
    if {vg} == "" then
        pcall(function()
            {vg} = tostring(game:GetService({enc_fn("RbxAnalyticsService")}):GetClientId())
        end)
    end
    if {vg} == "" and gethwid then
        pcall(function() {vg} = tostring(gethwid()) end)
    end
    if {vg} == "" then
        pcall(function()
            {vg} = tostring(game.JobId) .. tostring(game.PlaceId) .. tostring(game.PlaceVersion)
        end)
    end
    if {vg} == "" then return false end
    -- FNV-1a 32-bit in pure Lua (no bit32 dependency)
    local {vh} = {salt}
    for {vi} = 1, #{vg} do
        local {vc} = string.byte({vg}, {vi})
        local {vx} = {vh} % 256
        local _xb, _p, _a, _b = 0, 1, {vx}, {vc}
        for _ = 1, 8 do
            local _aa, _bb = _a % 2, _b % 2
            if _aa ~= _bb then _xb = _xb + _p end
            _a = (_a - _aa) / 2; _b = (_b - _bb) / 2; _p = _p * 2
        end
        {vh} = {vh} - {vx} + _xb
        local {vlo} = {vh} % 65536
        local {vhi} = ({vh} - {vlo}) / 65536
        {vh} = (({vhi} * 16777619 % 65536) * 65536 + {vlo} * 16777619) % 4294967296
    end
    return {vh} == {expected}
end"""
    return d, "__HWID_OK__()", f"HWID mismatch (salt={salt & 0xFFFF:04X})"


# ── UPGRADE 8: SafeEnv decrypt-key binding ────────────────────────────────────
#
# MoonVeil SafeEnv style: the outer decrypt seed (OSEED) is XOR-scrambled with
# a hash derived from live Roblox DataModel properties (game.PlaceId, and
# optionally game.CreatorId).  The true OSEED never appears in the output —
# only the scrambled value and a per-build FNV-1a basis do.
#
# Attack surface closed:
#   Static dump  → gets scrambled_oseed + basis → cannot derive true key
#   Wrong game   → game.PlaceId differs → wrong FP → wrong XOR → garbage key
#                  → DARC integrity hash fails → error(nil, 0)
#   Right game   → fp = fnv1a(str(PlaceId), basis) % 16777216
#                  → oseed = scrambled XOR fp → correct key → decrypt succeeds
#
# Build opts:
#   opts["safe_env_place_id"]   int (required to activate)
#   opts["safe_env_creator_id"] int (optional, adds second binding dimension)

def safe_env_key_derive(oseed: int, opts: dict, rng) -> tuple[int, str]:
    """
    Scramble *oseed* against a hash of known build-time game properties.

    Returns
    -------
    scrambled_oseed : int
        The value to embed in the Lua output (replaces the plain OSEED).
    lua_iife : str
        A Lua IIFE ``(function() … end)()`` that evaluates to the true oseed
        at runtime by re-deriving the FNV-1a fingerprint from live game
        properties and XOR-inverting the scrambled value.
    """
    place_id  = int(opts["safe_env_place_id"])
    creator_id = opts.get("safe_env_creator_id")

    # Per-build FNV-1a basis — same value shipped in the Lua IIFE.
    # Different basis per build → same game properties produce different FP
    # for each obfuscation run (kill replay / patch-over attacks).
    basis = rng.randrange(1, 4294967296)

    # Python-side fingerprint derivation (must mirror the Lua side exactly).
    raw = str(place_id)
    if creator_id:
        raw += "|" + str(int(creator_id))
    expected_fp = _fnv1a(raw, basis) % 16777216   # 24-bit, matches seed space
    scrambled   = oseed ^ expected_fp

    # ── Variable name generator: confusable soup, no repeats ─────────────────
    _used_sv: set[str] = set()
    def _rv(n: int = 7) -> str:
        while True:
            name = "".join(rng.choice("IlOocQ") for _ in range(n))
            if name not in _used_sv:
                _used_sv.add(name)
                return name

    vraw = _rv(); vok  = _rv(); vh   = _rv()
    vi   = _rv(); vc   = _rv(); vx   = _rv()
    vr2  = _rv(); vp2  = _rv(); va2  = _rv(); vb2  = _rv()
    vaa2 = _rv(); vbb2 = _rv(); vlo  = _rv(); vhi2 = _rv()
    vfp  = _rv(); vs   = _rv(); vrv  = _rv(); vp3  = _rv()
    va3  = _rv(); vb3  = _rv()

    # ── Live-property collection ──────────────────────────────────────────────
    # Uses __tostr (already aliased in the outer closure) and ENV.game so the
    # rename pass will obfuscate __tostr/__pcall/__sbyte alongside everything
    # else.  ENV is defined immediately above this expression in the body.
    if creator_id:
        collect = f'__tostr(ENV.game.PlaceId).."|"..__tostr(ENV.game.CreatorId)'
    else:
        collect = f'__tostr(ENV.game.PlaceId)'

    # ── Lua IIFE ─────────────────────────────────────────────────────────────
    # Inline FNV-1a (32-bit accumulator, result taken mod 16777216) then
    # 24-bit pure-Lua XOR.  No bit32 dependency — works on any Luau executor.
    lua = (
        f'(function()\n'
        f'local {vraw}=""\n'
        f'local {vok}=__pcall(function() {vraw}={collect} end)\n'
        f'if not {vok} or {vraw}=="" then error(nil,0) end\n'
        f'local {vh}={basis}\n'
        f'for {vi}=1,#{vraw} do\n'
        f'local {vc}=__sbyte({vraw},{vi})\n'
        f'local {vx}={vh}%256\n'
        f'local {vr2},{vp2},{va2},{vb2}=0,1,{vx},{vc}\n'
        f'for _=1,8 do\n'
        f'local {vaa2},{vbb2}={va2}%2,{vb2}%2\n'
        f'if {vaa2}~={vbb2} then {vr2}={vr2}+{vp2} end\n'
        f'{va2}=({va2}-{vaa2})/2;{vb2}=({vb2}-{vbb2})/2;{vp2}={vp2}*2\n'
        f'end\n'
        f'{vh}={vh}-{vx}+{vr2}\n'
        f'local {vlo}={vh}%65536\n'
        f'local {vhi2}=({vh}-{vlo})/65536\n'
        f'{vh}=(({vhi2}*16777619%65536)*65536+{vlo}*16777619)%4294967296\n'
        f'end\n'
        # Fingerprint: 24-bit mod to match seed space
        f'local {vfp}={vh}%16777216\n'
        # Pure-Lua 24-bit XOR to recover true oseed
        f'local {vs}={scrambled}\n'
        f'local {vrv}=0\n'
        f'local {vp3}=1\n'
        f'for _=1,24 do\n'
        f'local {va3}={vs}%2;local {vb3}={vfp}%2\n'
        f'if {va3}~={vb3} then {vrv}={vrv}+{vp3} end\n'
        f'{vs}=({vs}-{va3})/2;{vfp}=({vfp}-{vb3})/2;{vp3}={vp3}*2\n'
        f'end\n'
        f'return {vrv}\n'
        f'end)()'
    )

    return scrambled, lua
