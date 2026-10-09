-- Lurex VM — Darc Stack Engine v4
-- UPGRADE 2 (v4): self-defending monitor
--   • __DARC_RECHECK__ now passed as explicit parameter (fixes scoping bug —
--     it was previously a nil global lookup inside __DARC_VM__)
--   • Closure integrity hash: FNV-1a over tostring(__DARC_RECHECK__) stored
--     at startup; re-verified on every poll tick — detects function swap attacks
--   • Heartbeat counter: monitor increments it each cycle; a second sentinel
--     closure (injected into hot handlers at random) checks it's still rising —
--     if the task thread was killed the counter stalls and the handler fires
--   • Inline handler checks (injected by vmgen render_dispatch via
--     --@HOT_CHECK@ marker) — independent of the background thread
local function __DARC_VM__(PROGRAM, ENV, __DARC_RECHECK__)
    local unpack = table.unpack or unpack
    local pack = table.pack or function(...) return {n=select('#',...), ...} end
    local floor = math.floor

    local band, bor, bxor, bnot, lshift, rshift
    if bit32 then
        band, bor, bxor, bnot = bit32.band, bit32.bor, bit32.bxor, bit32.bnot
        lshift, rshift = bit32.lshift, bit32.rshift
    else
        local function tobits(x) return x % 0x100000000 end
        band  = function(a,b) local r,c=0,1 a,b=tobits(a),tobits(b) for _=1,32 do if a%2==1 and b%2==1 then r=r+c end a,b,c=floor(a/2),floor(b/2),c*2 end return r end
        bor   = function(a,b) local r,c=0,1 a,b=tobits(a),tobits(b) for _=1,32 do if a%2==1 or b%2==1 then r=r+c end a,b,c=floor(a/2),floor(b/2),c*2 end return r end
        bxor  = function(a,b) local r,c=0,1 a,b=tobits(a),tobits(b) for _=1,32 do if a%2~=b%2 then r=r+c end a,b,c=floor(a/2),floor(b/2),c*2 end return r end
        bnot  = function(a) return 0xFFFFFFFF - tobits(a) end
        lshift= function(a,b) return tobits(floor(a)*(2^b)) end
        rshift= function(a,b) return floor(tobits(a)/(2^b)) end
    end

    -- Active anti-analysis trap: Lua 5.1 pcall(unpack,{},0,2^31) segfaults
    -- Luau pcall catches it safely; hostile Lua 5.1 dump tools crash here
    local _trap_ok = pcall(unpack or table.unpack, {}, 0, 2147483647)

    -- ── UPGRADE 2 (v4): Self-defending continuous monitor ───────────────────
    --
    -- Three-layer defence:
    --
    -- Layer 1 — Background poll (existing, now fixed):
    --   task.spawn loop calls __DARC_RECHECK__(ENV) every ~4s with ±20% jitter.
    --   FIXED: __DARC_RECHECK__ is now passed as a parameter (not a global
    --   lookup) so it is ALWAYS in scope inside __DARC_VM__.
    --
    -- Layer 2 — Closure integrity hash:
    --   FNV-1a hash of tostring(__DARC_RECHECK__) computed once at startup and
    --   stored in _rc_hash.  Every poll tick re-hashes and compares.
    --   A swap attack (replace __DARC_RECHECK__ with a stub that returns true)
    --   changes the function pointer → tostring changes → hash changes → kill.
    --
    -- Layer 3 — Heartbeat liveness:
    --   Monitor increments _hb each tick.  Hot handler inline checks (injected
    --   by vmgen via --@HOT_CHECK@) compare _hb against _hb_last:
    --     if _hb == _hb_last (thread killed or stalled) → error(nil, 0)
    --   Stops the "just nop the background task.spawn" attack.

    local __DARC_KILLED = false
    local _hb      = 0      -- heartbeat counter, incremented by monitor thread
    local _hb_last = -1     -- last value seen by inline handler check

    -- FNV-1a (32-bit) over a string — pure Lua, no bit32 dependency
    local function _fnv1a_str(s)
        local h = 2166136261
        for i = 1, #s do
            local c = string.byte(s, i)
            local x = h % 256
            local r, p, a, b = 0, 1, x, c
            for _ = 1, 8 do
                local aa, bb = a % 2, b % 2
                if aa ~= bb then r = r + p end
                a = (a-aa)/2; b = (b-bb)/2; p = p*2
            end
            h = h - x + r
            local lo = h % 65536
            local hi = (h - lo) / 65536
            h = ((hi * 16777619 % 65536) * 65536 + lo * 16777619) % 4294967296
        end
        return h
    end

    -- Capture closure hash at startup (Layer 2)
    local _rc_hash = 0
    if __DARC_RECHECK__ then
        local _ok, _ts = pcall(tostring, __DARC_RECHECK__)
        if _ok then _rc_hash = _fnv1a_str(_ts) end
    end

    if task and task.spawn and __DARC_RECHECK__ then
        local _ts_fn   = task.spawn
        local _tw      = task.wait
        local _rc      = __DARC_RECHECK__
        local _interval_base = 4
        _ts_fn(function()
            while not __DARC_KILLED do
                -- Jitter: sleep base * [0.8, 1.2]
                local _jitter = _interval_base * (0.8 + (tick() % 100) * 0.004)
                _tw(_jitter)
                if __DARC_KILLED then break end

                -- Layer 2: integrity check — did someone swap _rc?
                local _ok_ts, _cur_ts = pcall(tostring, _rc)
                if not _ok_ts or _fnv1a_str(_cur_ts) ~= _rc_hash then
                    __DARC_KILLED = true
                    error(nil, 0)
                end

                -- Layer 1: environment check
                local _ok, _pass = pcall(_rc, ENV)
                if not _ok or not _pass then
                    __DARC_KILLED = true
                    error(nil, 0)
                end

                -- Layer 3: increment heartbeat so inline checks know we're alive
                _hb = _hb + 1
            end
        end)
    end

    -- Inline liveness sentinel — called from hot handler injections
    -- Returns true if the monitor thread appears alive (heartbeat advanced)
    -- or if the monitor was never started (task not available).
    local _monitor_active = (task and task.spawn and __DARC_RECHECK__) and true or false
    local function _hb_check()
        if not _monitor_active then return end
        -- Give the monitor thread a grace window: only arm after first tick
        if _hb == 0 then _hb_last = -1; return end
        if _hb == _hb_last then
            -- Heartbeat stalled — thread was killed
            __DARC_KILLED = true
            error(nil, 0)
        end
        _hb_last = _hb
    end
    -- ─────────────────────────────────────────────────────────────────────────

    local exec
    local function makeClosure(proto, upvals)
        return function(...) local a = pack(...) local res = exec(proto, upvals, a) return unpack(res, 1, res.n) end
    end

    exec = function(proto, upvals, args)
        local K = proto.k
        local code = proto.c
        local ncode = #code
        local protos = proto.p
        local tc = table.create
        local L = tc and tc(np + 1) or {}
        local S = tc and tc(32) or {}
        local sp = 0
        local np = proto.np
        for i = 1, np do L[i] = { args[i] } end
        local varargs
        if proto.va then
            local n = args.n or #args
            local vn = n - np; if vn < 0 then vn = 0 end
            varargs = { n = vn }
            for i = 1, vn do varargs[i] = args[np + i] end
        end
        local pc = 1
        while pc <= ncode do
            local ins = code[pc]
            local op = ins[1]
            pc = pc + 1
            --@DISPATCH@
        end
        return { n = 0 }
    end

    local main = PROGRAM
    local top = makeClosure(main, {})
    return top
end
