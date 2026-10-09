-- DARC-ARX decoder v5
-- Mirrors serialize_binary.py exactly.
-- Three operations at every cipher layer: Add · Rotate · XOR (ARX).
-- No LCG keystream. No pure-XOR stream cipher.
local function __DARC_DECODE__(B, OSEED, CSEED, IV, CKS, PLEN)
    local schar   = string.char
    local sbyte   = string.byte
    local sunpack = string.unpack
    local floor   = math.floor

    -- ── bit helpers ──────────────────────────────────────────────────────────
    local bxb   -- 8-bit XOR (used for opcode layer, unchanged from v4)
    local bxor32 -- 32-bit XOR (used in ARX quarter-round)
    local rotl32 -- 32-bit left rotation
    local rot8   -- 8-bit left rotation (new for outer/const ARX layers)

    if bit32 then
        bxb     = bit32.bxor
        bxor32  = bit32.bxor
        rotl32  = bit32.lrotate or function(x, n)
            return bit32.bor(bit32.lshift(x, n), bit32.rshift(x, 32-n))
        end
    else
        -- Pure-Lua fallbacks (bit-by-bit, exact for values < 2^32)
        local function _bx(a, b, bits)
            local r,c=0,1
            for _=1,bits do
                if a%2~=b%2 then r=r+c end
                a=floor(a/2); b=floor(b/2); c=c*2
            end
            return r
        end
        bxb    = function(a,b) return _bx(a,b,8) end
        bxor32 = function(a,b) return _bx(a,b,32) end
        rotl32 = function(x, n)
            x=x%4294967296; n=n%32
            if n==0 then return x end
            local top=32-n
            local lo=x%(2^top); local hi=x-lo
            return lo*(2^n)+floor(hi/(2^top))
        end
    end

    rot8 = function(x, n)
        x=x%256; n=n%8
        if n==0 then return x end
        return ((x*(2^n))%256)+floor(x/(2^(8-n)))
    end

    -- ── ARX keystream (mirrors arx_stream() in serialize_binary.py) ──────────
    local M = 4294967296  -- 2^32

    local function arx_qr(a,b,c,d)
        a=(a+b)%M; d=rotl32(bxor32(d,a),16)
        c=(c+d)%M; b=rotl32(bxor32(b,c),12)
        a=(a+b)%M; d=rotl32(bxor32(d,a),8)
        c=(c+d)%M; b=rotl32(bxor32(b,c),7)
        return a,b,c,d
    end

    local function arx_stream(seed, count)
        -- Init: expand 24-bit seed into 4×32-bit state
        local s  = seed % M
        local w0 = (s * 0x9E3779B9 + 0x61707865) % M
        local w1 = rotl32(bxor32(bxor32(w0, s), 0x3320646E), 13)
        local w2 = (w1 + 0x79622D32) % M
        local w3 = rotl32(bxor32(bxor32(w2, s), 0x6B206574), 7)
        -- Two warm-up rounds
        w0,w1,w2,w3 = arx_qr(w0,w1,w2,w3)
        w0,w1,w2,w3 = arx_qr(w3,w0,w1,w2)
        -- Stream generation
        local out = {}; local ctr = 0
        while #out < count do
            local pa = bxor32(w0, ctr)
            local pb = bxor32(w1, rotl32(ctr, 16))
            local pc, pd = w2, w3
            for _ = 1, 4 do
                pa,pb,pc,pd = arx_qr(pa,pb,pc,pd)
                pa,pb,pc,pd = arx_qr(pc,pa,pd,pb)
            end
            for _, w in ipairs({pa,pb,pc,pd}) do
                for _, sh in ipairs({0,8,16,24}) do
                    if #out < count then
                        out[#out+1] = floor(w%(2^(sh+8))/(2^sh))%256
                    end
                end
            end
            ctr = (ctr+1)%M
        end
        return out
    end

    -- ── Key derivation ────────────────────────────────────────────────────────
    local KLEN, CLEN = 16, 8
    local KEY  = arx_stream(OSEED, KLEN)
    local ls   = arx_stream(CSEED, CLEN + 2)
    local CKEY = {}
    for i = 1, CLEN do CKEY[i] = ls[i] end
    local OPXOR  = ls[CLEN + 1]
    local OPSTEP = ls[CLEN + 2]
    if OPSTEP % 2 == 0 then OPSTEP = OPSTEP + 1 end

    -- ── Outer ARX decrypt (mirrors encrypt() in serialize_binary.py) ──────────
    --
    -- Encrypt per byte i (Python):
    --     mixed = rot8(b + KEY[i % KLEN], 3) ^ rot8(prev, 5)
    --     prev  = mixed
    --
    -- Decrypt per byte i (here):
    --     c_xored = c_raw ^ rot8(prev, 5)      -- undo XOR
    --     b       = rot8(c_xored, 5) - KEY[..]  -- undo ROT (8-3=5), then SUB
    --     prev    = c_raw
    --
    local n     = #B
    local prev  = IV
    local h     = 0
    local chars = table.create and table.create(n) or {}
    for i = 1, n do
        local c_raw  = sbyte(B, i)
        local ks     = KEY[((i-1) % KLEN) + 1]
        local c_xored = bxb(c_raw, rot8(prev, 5))      -- undo XOR
        local b       = (rot8(c_xored, 5) - ks) % 256  -- undo ROT then SUB
        prev = c_raw
        chars[i] = schar(b)
        h = (h * 131 + b) % 16777216
    end
    if h ~= CKS then error(nil, 0) end
    local payload = table.concat(chars)

    -- ── Decompress (unchanged LZSS) ───────────────────────────────────────────
    local plain
    if sbyte(payload, 1) == 1 then
        local out = {}; local outn = 0; local rp = 2
        while outn < PLEN do
            local ctrl = sbyte(payload, rp); rp = rp + 1
            for _ = 1, 8 do
                if outn >= PLEN then break end
                local flag = ctrl % 2; ctrl = floor(ctrl / 2)
                if flag == 1 then
                    outn=outn+1; out[outn]=sbyte(payload,rp); rp=rp+1
                else
                    local b1=sbyte(payload,rp); local b2=sbyte(payload,rp+1); rp=rp+2
                    local length=(b2%16)+3; local offset=b1+floor(b2/16)*256
                    for _ = 1, length do
                        outn=outn+1; out[outn]=out[outn-offset]
                    end
                end
            end
        end
        local t={}; for i=1,outn do t[i]=schar(out[i]) end; plain=table.concat(t)
    else
        plain = string.sub(payload, 2)
    end

    -- ── Proto parser ──────────────────────────────────────────────────────────
    local pos = 1
    local cc  = 0
    local function u8()  local v=sbyte(plain,pos); pos=pos+1; return v end
    local function uvar()
        local result,shift=0,1
        while true do
            local by=sbyte(plain,pos); pos=pos+1
            result=result+(by%128)*shift
            if by<128 then break end
            shift=shift*128
        end
        return result
    end

    -- Lazy ARX constant decryption (mirrors _Ctx.const_byte in Python)
    --
    -- Python encrypt per const byte at counter cc:
    --     ks  = ckey[cc % CLEN]
    --     km  = rot8((ks + cc) & 0xFF, cc & 7)
    --     c   = (b + km) & 0xFF
    --     c  ^= ckey[(cc+1) % CLEN]
    --
    -- Lua decrypt (inverse):
    --     ks  = CKEY[(cci % CLEN) + 1]
    --     km  = rot8((ks + cci) % 256, cci % 8)
    --     b_a = bxb(c_enc, CKEY[((cci+1) % CLEN) + 1])  -- undo XOR
    --     b   = (b_a - km) % 256                          -- undo ADD
    local function decodeConst(kenc, t, i)
        local d = kenc[i]
        if not d then return nil end
        local tag, raw, cc0 = d[1], d[2], d[3]
        local out = {}
        for j = 1, #raw do
            local cci = cc0 + j - 1
            local ks  = CKEY[(cci % CLEN) + 1]
            local km  = rot8((ks + cci) % 256, cci % 8)
            local c_enc = sbyte(raw, j)
            local b_a   = bxb(c_enc, CKEY[((cci + 1) % CLEN) + 1])  -- undo XOR
            out[j]      = schar((b_a - km) % 256)                     -- undo ADD
        end
        local dec = table.concat(out)
        local v
        if     tag == 1 then v = dec
        elseif tag == 2 then v = sunpack("<i8", dec)
        else                 v = sunpack("<d",  dec) end
        rawset(t, i, v)
        kenc[i] = nil
        return v
    end

    local function readproto()
        local p  = {}
        p.np = uvar()
        p.va = (u8() == 1)
        local nk   = uvar()
        local kenc = {}
        for i = 1, nk do
            local tag = u8()
            local nb  = 8
            if tag == 1 then nb = uvar() end
            kenc[i] = { tag, string.sub(plain, pos, pos+nb-1), cc }
            pos = pos + nb
            cc  = cc  + nb
        end
        p.k = setmetatable({}, { __index = function(t, i) return decodeConst(kenc, t, i) end })
        local ncode = uvar()
        local code  = {}
        for i = 1, ncode do
            local enc   = uvar()
            local opkey = (OPXOR + (i-1) * OPSTEP) % 256
            local op    = bxb(enc, opkey)
            local a     = uvar()
            code[i]     = { op, a }
        end
        p.c = code
        local npr   = uvar()
        local protos= {}
        for i = 1, npr do protos[i] = readproto() end
        p.p = protos
        local nu  = uvar()
        local ups = {}
        for i = 1, nu do
            local kind = u8(); local idx = uvar()
            ups[i] = { kind, idx }
        end
        p.u = ups
        return p
    end

    return readproto()
end
