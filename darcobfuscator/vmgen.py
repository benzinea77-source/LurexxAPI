from __future__ import annotations

from .bytecode import OPCODES, OpcodeMap

# ── Base stack-VM handlers ────────────────────────────────────────────────────

HANDLERS: list[tuple[str, str]] = [
    ("LOADK",       "sp = sp + 1; S[sp] = K[ins[2]]"),
    ("LOADNIL",     "sp = sp + 1; S[sp] = nil"),
    ("LOADTRUE",    "sp = sp + 1; S[sp] = true"),
    ("LOADFALSE",   "sp = sp + 1; S[sp] = false"),
    ("GETLOCAL",    "sp = sp + 1; S[sp] = L[ins[2]][1]"),
    ("SETLOCAL",    "L[ins[2]][1] = S[sp]; S[sp] = nil; sp = sp - 1"),
    ("NEWLOCAL",    "L[ins[2]] = { S[sp] }; S[sp] = nil; sp = sp - 1"),
    ("GETUPVAL",    "sp = sp + 1; S[sp] = upvals[ins[2]][1]"),
    ("SETUPVAL",    "upvals[ins[2]][1] = S[sp]; S[sp] = nil; sp = sp - 1"),
    ("GETGLOBAL",   "sp = sp + 1; S[sp] = ENV[K[ins[2]]]"),
    ("SETGLOBAL",   "ENV[K[ins[2]]] = S[sp]; S[sp] = nil; sp = sp - 1"),
    ("NEWTABLE",    "sp = sp + 1; S[sp] = {}"),
    ("GETINDEX",
     "local k = S[sp]; local t = S[sp - 1]\n"
     "S[sp - 1] = t[k]; S[sp] = nil; sp = sp - 1"),
    ("SETINDEX",
     "local v = S[sp]; local k = S[sp - 1]; local t = S[sp - 2]\n"
     "t[k] = v; S[sp] = nil; S[sp - 1] = nil; S[sp - 2] = nil; sp = sp - 3"),
    ("SETFIELD",
     "local v = S[sp]; local k = S[sp - 1]; local t = S[sp - 2]\n"
     "t[k] = v; S[sp] = nil; S[sp - 1] = nil; sp = sp - 2"),
    ("SETARRAYIDX",
     "local v = S[sp]; local t = S[sp - 1]\n"
     "t[ins[2]] = v; S[sp] = nil; sp = sp - 1"),
    ("APPENDLIST",
     "local arr = S[sp]; local t = S[sp - 1]; local base = ins[2]\n"
     "if table.move then table.move(arr, 1, arr.n, base, t)\n"
     "else for i = 1, arr.n do t[base + i - 1] = arr[i] end end\n"
     "S[sp] = nil; sp = sp - 1"),
    ("ADD",     "local b=S[sp]; S[sp]=nil; sp=sp-1; S[sp]=S[sp]+b"),
    ("SUB",     "local b=S[sp]; S[sp]=nil; sp=sp-1; S[sp]=S[sp]-b"),
    ("MUL",     "local b=S[sp]; S[sp]=nil; sp=sp-1; S[sp]=S[sp]*b"),
    ("DIV",     "local b=S[sp]; S[sp]=nil; sp=sp-1; S[sp]=S[sp]/b"),
    ("IDIV",    "local b=S[sp]; S[sp]=nil; sp=sp-1; S[sp]=floor(S[sp]/b)"),
    ("MOD",     "local b=S[sp]; S[sp]=nil; sp=sp-1; S[sp]=S[sp]%b"),
    ("POW",     "local b=S[sp]; S[sp]=nil; sp=sp-1; S[sp]=S[sp]^b"),
    ("CONCAT",  "local b=S[sp]; S[sp]=nil; sp=sp-1; S[sp]=S[sp]..b"),
    ("EQ",      "local b=S[sp]; S[sp]=nil; sp=sp-1; S[sp]=(S[sp]==b)"),
    ("NE",      "local b=S[sp]; S[sp]=nil; sp=sp-1; S[sp]=(S[sp]~=b)"),
    ("LT",      "local b=S[sp]; S[sp]=nil; sp=sp-1; S[sp]=(S[sp]<b)"),
    ("LE",      "local b=S[sp]; S[sp]=nil; sp=sp-1; S[sp]=(S[sp]<=b)"),
    ("GT",      "local b=S[sp]; S[sp]=nil; sp=sp-1; S[sp]=(S[sp]>b)"),
    ("GE",      "local b=S[sp]; S[sp]=nil; sp=sp-1; S[sp]=(S[sp]>=b)"),
    ("BAND",    "local b=S[sp]; S[sp]=nil; sp=sp-1; S[sp]=band(S[sp],b)"),
    ("BOR",     "local b=S[sp]; S[sp]=nil; sp=sp-1; S[sp]=bor(S[sp],b)"),
    ("BXOR",    "local b=S[sp]; S[sp]=nil; sp=sp-1; S[sp]=bxor(S[sp],b)"),
    ("SHL",     "local b=S[sp]; S[sp]=nil; sp=sp-1; S[sp]=lshift(S[sp],b)"),
    ("SHR",     "local b=S[sp]; S[sp]=nil; sp=sp-1; S[sp]=rshift(S[sp],b)"),
    ("UNM",     "S[sp] = -S[sp]"),
    ("NOT",     "S[sp] = not S[sp]"),
    ("LEN",     "S[sp] = #S[sp]"),
    ("BNOT",    "S[sp] = bnot(S[sp])"),
    ("DUP",     "sp = sp + 1; S[sp] = S[sp - 1]"),
    ("POP",     "S[sp] = nil; sp = sp - 1"),
    ("SWAP",    "local x = S[sp]; S[sp] = S[sp - 1]; S[sp - 1] = x"),
    ("ROT3",
     "local a = S[sp - 2]; S[sp - 2] = S[sp - 1]; S[sp - 1] = S[sp]; S[sp] = a"),
    ("JMP",         "pc = ins[2] + 1"),
    ("JMPIFFALSE",
     "local v = S[sp]; S[sp] = nil; sp = sp - 1\n"
     "if not v then pc = ins[2] + 1 end"),
    ("JMPIFTRUE",
     "local v = S[sp]; S[sp] = nil; sp = sp - 1\n"
     "if v then pc = ins[2] + 1 end"),
    ("JMPIFNIL",
     "local v = S[sp]; S[sp] = nil; sp = sp - 1\n"
     "if v == nil then pc = ins[2] + 1 end"),
    ("NEWARR",  "sp = sp + 1; S[sp] = { n = 0 }"),
    ("ARRPUSH",
     "local v = S[sp]; local arr = S[sp - 1]\n"
     "arr.n = arr.n + 1; arr[arr.n] = v; S[sp] = nil; sp = sp - 1"),
    ("ARREXTEND",
     "local src = S[sp]; local arr = S[sp - 1]\n"
     "for i = 1, src.n do arr.n = arr.n + 1; arr[arr.n] = src[i] end\n"
     "S[sp] = nil; sp = sp - 1"),
    ("EXPAND",
     "local arr = S[sp]; S[sp] = nil; sp = sp - 1\n"
     "local want = ins[2]\n"
     "for i = 1, want do sp = sp + 1; S[sp] = arr[i] end"),
    ("CALL",
     "local arr = S[sp]; local fn = S[sp - 1]\n"
     "S[sp] = nil; S[sp - 1] = nil; sp = sp - 2\n"
     "local r = pack(fn(unpack(arr, 1, arr.n)))\n"
     "sp = sp + 1; S[sp] = r[1]"),
    ("CALLM",
     "local arr = S[sp]; local fn = S[sp - 1]\n"
     "S[sp] = nil; S[sp - 1] = nil; sp = sp - 2\n"
     "local r = pack(fn(unpack(arr, 1, arr.n)))\n"
     "sp = sp + 1; S[sp] = r"),
    ("CALLVOID",
     "local arr = S[sp]; local fn = S[sp - 1]\n"
     "S[sp] = nil; S[sp - 1] = nil; sp = sp - 2\n"
     "fn(unpack(arr, 1, arr.n))"),
    ("RETURN", "return S[sp]"),
    ("CLOSURE",
     "local child = protos[ins[2]]\n"
     "local u = {}\n"
     "local descs = child.u\n"
     "for i = 1, #descs do\n"
     "    local d = descs[i]\n"
     "    if d[1] == 1 then u[i] = L[d[2]] else u[i] = upvals[d[2]] end\n"
     "end\n"
     "sp = sp + 1; S[sp] = makeClosure(child, u)"),
    ("VARARG1",  "sp = sp + 1; S[sp] = varargs and varargs[1] or nil"),
    ("VARARGM",  "sp = sp + 1; S[sp] = varargs or { n = 0 }"),
    ("FORTEST",
     "local step = S[sp]; local limit = S[sp - 1]; local i = S[sp - 2]\n"
     "S[sp] = nil; S[sp - 1] = nil; sp = sp - 2\n"
     "if step > 0 then S[sp] = (i <= limit) else S[sp] = (i >= limit) end"),
    ("ISNIL",    "S[sp] = (S[sp] == nil)"),
]

assert [n for n, _ in HANDLERS] == list(OPCODES), "vmgen/HANDLERS drift vs OPCODES"

# ── Fused superoperators ──────────────────────────────────────────────────────

FUSIONS: dict[tuple[str, str], tuple[str, str]] = {
    ("LOADK",    "ADD"):       ("F_KADD",    "S[sp] = S[sp] + K[ins[2]]"),
    ("LOADK",    "SUB"):       ("F_KSUB",    "S[sp] = S[sp] - K[ins[2]]"),
    ("LOADK",    "MUL"):       ("F_KMUL",    "S[sp] = S[sp] * K[ins[2]]"),
    ("LOADK",    "CONCAT"):    ("F_KCONCAT", "S[sp] = S[sp] .. K[ins[2]]"),
    ("LOADK",    "EQ"):        ("F_KEQ",     "S[sp] = (S[sp] == K[ins[2]])"),
    ("LOADK",    "GETINDEX"):  ("F_KINDEX",  "S[sp] = S[sp][K[ins[2]]]"),
    ("GETLOCAL", "ADD"):       ("F_LADD",    "S[sp] = S[sp] + L[ins[2]][1]"),
    ("GETLOCAL", "SUB"):       ("F_LSUB",    "S[sp] = S[sp] - L[ins[2]][1]"),
    ("GETLOCAL", "MUL"):       ("F_LMUL",    "S[sp] = S[sp] * L[ins[2]][1]"),
    ("GETLOCAL", "LT"):        ("F_LLT",     "S[sp] = (S[sp] < L[ins[2]][1])"),
    ("GETLOCAL", "LE"):        ("F_LLE",     "S[sp] = (S[sp] <= L[ins[2]][1])"),
    ("GETLOCAL", "GETINDEX"):  ("F_LINDEX",  "S[sp] = S[sp][L[ins[2]][1]]"),
    ("GETUPVAL", "GETINDEX"):  ("F_UINDEX",  "S[sp] = S[sp][upvals[ins[2]][1]]"),
    ("GETGLOBAL","GETINDEX"):  ("F_GINDEX",  "S[sp] = S[sp][ENV[K[ins[2]]]]"),
    # Additional fusions for common patterns
    ("LOADK",    "SETGLOBAL"): ("F_KSETG",   "ENV[K[ins[2]]] = K[ins[2]]"),
    ("GETLOCAL", "SETLOCAL"):  ("F_LMOV",    "L[ins[2]][1] = L[ins[2]][1]"),
    ("GETGLOBAL","CALL"):      (
        "F_GCALL",
        "local _gfn = ENV[K[ins[2]]]; local _garr = S[sp]; sp = sp - 1\n"
        "sp = sp + 1; S[sp] = pack(_gfn(unpack(_garr,1,_garr.n)))[1]"
    ),
    # Upgrade 5: NOP-equivalent fused op for instruction noise injection
    # sp delta = 0; hostile tracers see an extra op with no semantic effect.
    # F_NOP is always included in select_fusions so it is always in the opmap.
    ("NOP_NOISE", "NOP_NOISE"): (
        "F_NOP",
        "do local __nsp = sp; sp = __nsp end  -- nop"
    ),
}

# ── Decoy handlers (never reached, confuse static analysis) ──────────────────

_DECOY_BODIES = [
    "sp = sp + 1; S[sp] = ins[2]",
    "S[sp] = S[sp]; sp = sp - 0",
    "local x = S[sp]; S[sp] = x",
    "sp = sp + 1; S[sp] = -ins[2]",
    "S[sp - 1] = S[sp]; S[sp] = nil; sp = sp - 1",
    "local t = S[sp]; S[sp] = t and t or ins[2]",
    "sp = sp + 1; S[sp] = { ins[2] }",
    # Extra decoys that mimic real patterns
    "do local _dc = ins[2]; _dc = _dc + 0 end",
    "S[sp] = not not S[sp]",
    "local _dd = ENV; _dd = nil",
]


def select_fusions(rng) -> dict[tuple[str, str], tuple[str, str]]:
    # F_NOP must always be present: inject_instruction_noise unconditionally
    # emits it, so the opmap and VM dispatch must always carry its handler.
    _NOP_KEY = ("NOP_NOISE", "NOP_NOISE")
    _nop_entry = FUSIONS[_NOP_KEY]
    items = [(k, v) for k, v in FUSIONS.items() if k != _NOP_KEY]
    rng.shuffle(items)
    k = rng.randint(max(1, len(items) // 2), len(items))
    result = {pair: spec for pair, spec in items[:k]}
    result[_NOP_KEY] = _nop_entry   # guaranteed — always in the returned map
    return result


def build_opmap(rng, fused_names: list[str]) -> OpcodeMap:
    return OpcodeMap.randomized(rng, extra_names=fused_names)


def _clause(keyword: str, num: int, body: str) -> str:
    return f"{keyword} op == {num} then\n{body}\n"


def render_dispatch(opmap: OpcodeMap, rng, fused: dict,
                    n_decoys: int = 8, cps_mode: bool = False) -> str:
    """
    Render the opcode dispatch block.

    cps_mode=False (default): standard if/elseif chain (fast).
    cps_mode=True: Luraph-style nested binary-split dispatch tree
                   (harder to analyse statically, resists LuaHunt probe).

    UPGRADE 2 (v4): randomly selects 3-4 "hot" handler opcodes and appends
    an inline _hb_check() call to them.  These are independent of the
    background task thread — if the thread is killed the heartbeat stalls
    and the next hot-handler execution fires error(nil, 0).
    """
    # Pick 3-4 hot handlers to receive the inline liveness check.
    # Hot = frequently executed in typical scripts → CALL, CALLM, CLOSURE,
    # GETGLOBAL, GETLOCAL, SETLOCAL, ADD.  Pick randomly so the pattern
    # differs per build.
    _hot_candidates = ["CALL", "CALLM", "CLOSURE", "GETGLOBAL",
                       "GETLOCAL", "SETLOCAL", "ADD", "CALLVOID"]
    _n_hot = rng.randint(3, 4) if rng is not None else 0
    _hot_set = set(rng.sample(_hot_candidates, _n_hot)) if rng is not None else set()

    entries = []
    for name, body in HANDLERS:
        body = _mutate_handler_body(body, rng) if rng is not None else body
        # UPGRADE 2: inject inline heartbeat check into selected hot handlers
        if name in _hot_set:
            body = body + "\n_hb_check()"
        entries.append((opmap[name], body))
    for (_p1, _p2), (fname, body) in fused.items():
        body = _mutate_handler_body(body, rng) if rng is not None else body
        entries.append((opmap[fname], body))

    used = {num for num, _ in entries}
    if rng is not None:
        top = max(used)
        decoy_nums = list(range(top + 1, top + 1 + n_decoys))
        for dn in decoy_nums:
            entries.append((dn, _DECOY_BODIES[rng.randrange(len(_DECOY_BODIES))]))
        rng.shuffle(entries)

    if cps_mode:
        return _render_cps_dispatch(entries)
    else:
        return _render_flat_dispatch(entries)


def _render_flat_dispatch(entries: list) -> str:
    """Simple if/elseif chain."""
    parts = []
    for i, (num, body) in enumerate(entries):
        parts.append(_clause("if" if i == 0 else "elseif", num, body))
    parts.append("else\nerror(nil)\nend")
    return "".join(parts)


def _render_cps_dispatch(entries: list) -> str:
    """
    Luraph-style nested binary-split dispatch tree.
    Splits the opcode space at the median at each level, producing a
    balanced binary tree of if/elseif checks.  Much harder for LuaHunt
    to map because it can't linearly probe op→handler.
    """
    sorted_entries = sorted(entries, key=lambda x: x[0])

    def build_tree(items: list, depth: int = 0) -> str:
        if not items:
            return "error(nil)\n"
        if len(items) == 1:
            num, body = items[0]
            return f"if op == {num} then\n{body}\nelse\nerror(nil)\nend\n"
        mid = len(items) // 2
        pivot = items[mid][0]
        left  = items[:mid]
        right = items[mid:]
        indent = "  " * depth
        l_tree = build_tree(left, depth + 1)
        r_tree = build_tree(right, depth + 1)
        return (
            f"if op < {pivot} then\n"
            f"{l_tree}\n"
            f"else\n"
            f"{r_tree}\n"
            f"end\n"
        )

    return build_tree(sorted_entries)


def render_vm(vm_template: str, opmap: OpcodeMap, rng,
              fused: dict | None = None,
              cps_mode: bool = False) -> str:
    dispatch = render_dispatch(opmap, rng, fused or {}, cps_mode=cps_mode)
    return vm_template.replace("--@DISPATCH@", dispatch)


# ── UPGRADE 1 (v4): Handler body dirtying ────────────────────────────────────
#
# Two-phase per-build mutation applied to every handler body:
#
#   Phase 1 — local rename (existing): replace short temp-local names with
#             confusable soup so LLM fingerprinters can't match handler
#             templates against known patterns.
#
#   Phase 2 — semantic noise injection (NEW): insert opaque arithmetic,
#             dead stores, and net-zero stack push/pop BETWEEN real statements.
#             Net effect on VM state: zero.  Effect on emulator: forces it to
#             track dead temporaries, mis-count stack depth between statements,
#             and evaluate arithmetic that never escapes its local scope.
#
# Noise patterns (all guaranteed semantically neutral):
#   N0  opaque cancel  local v=ins[2]+C; local w=v*v-v*v; v=nil; w=nil
#   N1  dead pc read   local v=pc+0; v=v-pc; v=nil
#   N2  dead sp copy   local v=sp; local w=v+0; v=nil; w=nil
#   N3  Fermat dead    n*(n-1)*(n+1) is always /6 — store and discard
#   N4  net-zero push  sp=sp+1; S[sp]=nil; sp=sp-1
#   N5  dead stack rd  do local v=S[sp] end   (reads top but discards)

def _inject_handler_noise(body: str, rng) -> str:
    """
    Phase 2: inject opaque noise between real handler statements.
    Called AFTER phase-1 rename so the renamed names also appear in noise
    (making the soup denser for static matchers).
    """
    alpha = "IlOocQ"
    def rv(n: int = 7) -> str:
        return "".join(rng.choice(alpha) for _ in range(n))

    def noise() -> str:
        kind = rng.randint(0, 5)
        v1, v2 = rv(), rv()
        c  = rng.randint(1, 254)
        if kind == 0:
            # Opaque cancel: (ins[2]+c)^2 - (ins[2]+c)^2 = 0
            return (f"local {v1}=ins[2]+{c};"
                    f"local {v2}={v1}*{v1}-{v1}*{v1};"
                    f"{v1}=nil;{v2}=nil")
        elif kind == 1:
            # Dead read of pc — requires emulator to model pc aliasing
            return f"local {v1}=pc+0;{v1}={v1}-pc;{v1}=nil"
        elif kind == 2:
            # Dead copy of sp — forces alias-tracking
            return f"local {v1}=sp;local {v2}={v1}+0;{v1}=nil;{v2}=nil"
        elif kind == 3:
            # Fermat: n*(n-1)*(n+1) always /6 — dead integer division
            n  = rng.randint(2, 12)
            p  = n * (n - 1) * (n + 1)
            return f"local {v1}={p};{v1}={v1}/6;{v1}=nil"
        elif kind == 4:
            # Net-zero push nil / pop — emulator must track depth change
            return f"sp=sp+1;S[sp]=nil;sp=sp-1"
        else:
            # Dead read of current stack top into a local, immediately discard
            return f"do local {v1}=S[sp] end"

    # Split on newline (bodies already use \n as statement separator)
    stmts = [s for s in body.split("\n") if s.strip()]
    result = []
    for stmt in stmts:
        result.append(stmt)
        # ~35% chance of injecting 1 noise snippet after this statement.
        # Skip if statement looks like a block opener (ends with "then", "do",
        # "else") to avoid injecting into multi-line compound blocks.
        tail = stmt.strip().rstrip(";").lower()
        if (rng.random() < 0.35
                and not tail.endswith(("then", " do", "else", "end"))
                and "error" not in tail
                and "return" not in tail):
            result.append(noise())
    return "\n".join(result)


def _mutate_handler_body(body: str, rng) -> str:
    """
    Full two-phase handler dirtying:
      Phase 1 — rename short temp locals to confusable soup
      Phase 2 — inject opaque noise between statements
    """
    import re

    # ── Phase 1: rename temps ────────────────────────────────────────────────
    found = re.findall(r"\blocal\s+([a-z_][a-z_0-9]*)\b", body)
    targets = {n for n in found if len(n) <= 4 and n not in
               ("sp", "pc", "op", "ins", "arr", "src", "nil", "pack", "want",
                "step", "base", "kind", "idx", "fn", "r", "u")}
    alpha = "IlOocQcI"
    def fresh():
        return "".join(rng.choice(alpha) for _ in range(rng.randint(6, 10)))
    mapping = {t: fresh() for t in targets}
    for old, new in mapping.items():
        body = re.sub(rf"\b{re.escape(old)}\b", new, body)

    # ── Phase 2: semantic noise injection ────────────────────────────────────
    body = _inject_handler_noise(body, rng)

    return body



# ── UPGRADE 3 (v4): Dynamic superoperator generator ──────────────────────────

def _generate_dynamic_fusions(rng) -> dict[tuple[str, str], tuple[str, str]]:
    """
    Per-build 3-op fusions, context-sensitive gate, and decoy fusions.

    Genuine 3-op fusions: GETLOCAL + ARITH + implicit SETLOCAL — in-place
    arithmetic on a local slot.  Different opname per build.

    Context-sensitive fusion: one handler whose body depends on a per-build
    flag; deobfuscator must evaluate flag to know the branch taken.

    Decoys: 3-5 fusions that occupy opmap slots and appear in the dispatch
    tree but are NEVER emitted by the serializer.  Widen the apparent ISA;
    frustrate timing-based op-prober attacks.
    """
    alpha = "IlOocQ"
    def rv(n: int = 8) -> str:
        return "".join(rng.choice(alpha) for _ in range(n))

    dynamic: dict[tuple[str, str], tuple[str, str]] = {}

    # ── 2-3 genuine 3-op fusions ─────────────────────────────────────────────
    _arith = [("ADD","+"),("SUB","-"),("MUL","*"),("DIV","/"),("MOD","%")]
    n_dyn  = rng.randint(2, 3)
    chosen = rng.sample(_arith, n_dyn)
    for i, (opname, sym) in enumerate(chosen):
        key   = (f"DYN_{i}_A", f"DYN_{i}_B")
        fname = f"F_D{rv(4)}"
        va, vb = rv(), rv()
        # In-place: L[ins[2]][1] op= S[sp]; consume top of stack
        body  = (f"local {va}=S[sp];sp=sp-1;"
                 f"local {vb}=L[ins[2]][1];"
                 f"L[ins[2]][1]={vb}{sym}{va};{va}=nil;{vb}=nil")
        dynamic[key] = (fname, body)

    # ── Context-sensitive fusion ──────────────────────────────────────────────
    flag_val = rng.randint(0, 1)
    cs_key   = ("CS_GATE_A", "CS_GATE_B")
    cs_name  = f"F_CS{rv(4)}"
    vt       = rv()
    if flag_val == 1:
        # Branch A: pop, then add a random dead constant to top (cancels)
        dead_c = rng.randint(1, 999)
        cs_body = (f"local {vt}=S[sp];sp=sp-1;"
                   f"S[sp]=S[sp]+{dead_c}-{dead_c};{vt}=nil")
    else:
        # Branch B: pop, multiply top by 1 — identity
        cs_body = (f"local {vt}=S[sp];sp=sp-1;"
                   f"S[sp]=S[sp]*1;{vt}=nil")
    dynamic[cs_key] = (cs_name, cs_body)

    # ── 3-5 decoy fusions (never emitted into bytecode) ──────────────────────
    decoy_pool = [
        f"local {rv()}=ins[2];sp=sp+1;S[sp]={rv(4)};sp=sp-1",
        f"local {rv()}=K[ins[2]];{rv()}=nil",
        f"sp=sp+1;S[sp]=L[ins[2]][1];sp=sp-1",
        f"local {rv()}=ENV;{rv()}=nil",
        f"do local {rv()}=pc+ins[2] end",
        f"local {rv()}=ins[2]*ins[2]-ins[2]*ins[2]",
        f"local {rv()}=S[sp];{rv()}=nil;sp=sp+0",
    ]
    n_decoys = rng.randint(3, 5)
    for i in range(n_decoys):
        dk = (f"DECOY_{i}_A", f"DECOY_{i}_B")
        df = f"F_DC{rv(4)}"
        dynamic[dk] = (df, decoy_pool[i % len(decoy_pool)])

    return dynamic


# ── Override select_fusions to include dynamic fusions ───────────────────────
_original_select_fusions = select_fusions

def select_fusions(rng) -> dict[tuple[str, str], tuple[str, str]]:  # noqa: F811
    """
    UPGRADE 3 wrapper: static subset + per-build dynamic/decoy fusions.
    F_NOP is always included.
    """
    result = _original_select_fusions(rng)
    result.update(_generate_dynamic_fusions(rng))
    return result
