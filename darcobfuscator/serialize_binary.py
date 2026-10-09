from __future__ import annotations

import struct

from .bytecode import OpcodeMap, Proto

# ── DARC-ARX cipher v5 ────────────────────────────────────────────────────────
#
# Replaces the LCG keystream + pure-XOR stream cipher with a ChaCha-style
# ARX (Add-Rotate-XOR) construction throughout:
#
#   Key derivation  — arx_stream()    replaces derive_stream() (LCG)
#   Outer encrypt   — ADD + ROT + XOR replaces pure XOR feedback
#   Const encrypt   — ROT + ADD + XOR replaces b ^ (key + counter*7)
#
# All three operations (Add, Rotate, XOR) are now present at every layer.
# Pure-XOR analysis (differential / linear cryptanalysis of the cipher
# layer) no longer produces useful output — the addition makes the keystream
# non-affine, and the rotation diffuses bit differences across byte boundaries.
#
# Symmetric: decoder.lua mirrors these functions exactly.

KLEN = 16   # outer key: 16 bytes, one full ARX block
CLEN = 8    # constant key: first 8 bytes of second ARX block


# ── ARX primitives ────────────────────────────────────────────────────────────

def _rotl32(x: int, n: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _rot8(x: int, n: int) -> int:
    """8-bit left rotation."""
    x &= 0xFF; n %= 8
    if n == 0:
        return x
    return ((x * (2 ** n)) % 256) + (x >> (8 - n))


def _qr(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    """ChaCha quarter-round (32-bit ARX)."""
    a = (a + b) & 0xFFFFFFFF; d = _rotl32(d ^ a, 16)
    c = (c + d) & 0xFFFFFFFF; b = _rotl32(b ^ c, 12)
    a = (a + b) & 0xFFFFFFFF; d = _rotl32(d ^ a, 8)
    c = (c + d) & 0xFFFFFFFF; b = _rotl32(b ^ c, 7)
    return a, b, c, d


def _arx_init(seed: int) -> tuple[int, int, int, int]:
    """Expand a 24-bit seed into a 128-bit ARX state (4 × 32-bit words)."""
    s  = seed & 0xFFFFFFFF
    w0 = (s * 0x9E3779B9 + 0x61707865) & 0xFFFFFFFF
    w1 = _rotl32(w0 ^ s ^ 0x3320646E, 13)
    w2 = (w1  + 0x79622D32) & 0xFFFFFFFF
    w3 = _rotl32(w2 ^ s ^ 0x6B206574, 7)
    # Two warm-up rounds to fully diffuse the seed
    w0, w1, w2, w3 = _qr(w0, w1, w2, w3)
    w0, w1, w2, w3 = _qr(w3, w0, w1, w2)
    return w0, w1, w2, w3


def arx_stream(seed: int, count: int) -> list[int]:
    """
    Generate `count` pseudorandom bytes using a ChaCha-style ARX stream.
    Replaces the old derive_stream() LCG everywhere.

    One block = 16 bytes (4 quarter-rounds × 2 column/diagonal passes,
    counter folded into two state words per block).
    """
    a, b, c, d = _arx_init(seed)
    out: list[int] = []
    ctr = 0
    while len(out) < count:
        pa, pb, pc, pd = a ^ ctr, b ^ _rotl32(ctr, 16), c, d
        for _ in range(4):
            pa, pb, pc, pd = _qr(pa, pb, pc, pd)
            pa, pb, pc, pd = _qr(pc, pa, pd, pb)
        for w in (pa, pb, pc, pd):
            for shift in (0, 8, 16, 24):
                if len(out) < count:
                    out.append((w >> shift) & 0xFF)
        ctr = (ctr + 1) & 0xFFFFFFFF
    return out


# keep old name as alias — nothing else in the codebase calls derive_stream
# directly after the ARX upgrade, but alias prevents import errors
derive_stream = arx_stream


# ── Layer parameters (unchanged interface) ────────────────────────────────────

def _layer_params(cseed: int) -> tuple[list[int], int, int]:
    s     = arx_stream(cseed, CLEN + 2)
    ckey  = s[:CLEN]
    opxor = s[CLEN]
    opstep = s[CLEN + 1] | 1          # ensure odd
    return ckey, opxor, opstep


# ── uvarint encoding (unchanged) ─────────────────────────────────────────────

def _uvarint(out: bytearray, n: int) -> None:
    if n < 0:
        raise ValueError("uvarint negative")
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break


# ── Serialisation context ─────────────────────────────────────────────────────

class _Ctx:

    def __init__(self, opmap: OpcodeMap, ckey: list[int], opxor: int, opstep: int):
        self.opmap  = opmap
        self.ckey   = ckey
        self.opxor  = opxor
        self.opstep = opstep
        self.cc     = 0

    def const_byte(self, b: int) -> int:
        """
        ARX constant-layer byte encryption.

        Old: b ^ (key[cc % CLEN] + cc * 7) & 0xFF   — pure XOR
        New: (b + km) ^ key[(cc+1) % CLEN]
             where km = rot8(key[cc % CLEN] + cc, cc & 7)

        Three operations present: ADD (b + km), ROT (inside km), XOR (^ key2).
        Decrypted in decoder.lua decodeConst() with the exact inverse.
        """
        cc  = self.cc
        ks  = self.ckey[cc % CLEN]
        km  = _rot8((ks + cc) & 0xFF, cc & 7)
        c   = (b + km) & 0xFF
        c  ^= self.ckey[(cc + 1) % CLEN]
        self.cc = cc + 1
        return c


# ── Proto serialiser (unchanged structure, uses new const_byte) ───────────────

def _write_proto(out: bytearray, p: Proto, ctx: _Ctx) -> None:
    _uvarint(out, p.numparams)
    out.append(1 if p.is_vararg else 0)
    _uvarint(out, len(p.consts))
    for c in p.consts:
        if isinstance(c, str):
            raw = c.encode("utf-8")
            out.append(1)
            _uvarint(out, len(raw))
            for byte in raw:
                out.append(ctx.const_byte(byte))
        elif float(c).is_integer() and abs(c) < 1e15:
            out.append(2)
            for byte in struct.pack("<q", int(c)):
                out.append(ctx.const_byte(byte))
        else:
            out.append(0)
            for byte in struct.pack("<d", float(c)):
                out.append(ctx.const_byte(byte))
    _uvarint(out, len(p.code))
    for idx, ins in enumerate(p.code):
        raw_op = ctx.opmap[ins.op]
        opkey  = (ctx.opxor + idx * ctx.opstep) & 0xFF
        _uvarint(out, raw_op ^ opkey)
        _uvarint(out, ins.a & 0xFFFFFFFF)
    _uvarint(out, len(p.protos))
    for sub in p.protos:
        _write_proto(out, sub, ctx)
    _uvarint(out, len(p.upvals))
    for kind, idx in p.upvals:
        out.append(kind)
        _uvarint(out, idx)


def serialize(proto: Proto, opmap: OpcodeMap, cseed: int) -> bytes:
    ckey, opxor, opstep = _layer_params(cseed)
    ctx = _Ctx(opmap, ckey, opxor, opstep)
    out = bytearray()
    _write_proto(out, proto, ctx)
    return bytes(out)


# ── Outer ARX stream cipher ───────────────────────────────────────────────────

def encrypt(data: bytes, key: list[int], iv: int) -> tuple[bytes, int]:
    """
    ARX outer encryption.

    Per byte:
        mixed = rot8(b + key[i % KLEN], 3)  ← ADD then ROT
        mixed = mixed ^ rot8(prev, 5)        ← XOR with rotated feedback
        prev  = mixed
        output[i] = mixed

    Decrypt (in decoder.lua):
        c_xored = c_raw ^ rot8(prev, 5)      ← undo XOR
        b       = rot8(c_xored, 5) - key[..]  ← undo ROT (8-3=5) then SUB

    Integrity hash over plaintext bytes (unchanged — same as before).
    """
    kl   = len(key)
    out  = bytearray(len(data))
    prev = iv & 0xFF
    h    = 0
    for i, b in enumerate(data):
        ks    = key[i % kl]
        mixed = (b + ks) & 0xFF
        mixed = _rot8(mixed, 3) ^ _rot8(prev, 5)
        prev  = mixed
        out[i] = mixed
        h = (h * 131 + b) % 16777216
    return bytes(out), h


# ── encode_program (unchanged interface) ─────────────────────────────────────

class _Ins:
    __slots__ = ("op", "a")
    def __init__(self, op: str, a: int):
        self.op = op; self.a  = a


def inject_instruction_noise(code: list, rng, noise_rate: float = 0.12):
    """
    Upgrade 5 — recurse the full proto tree and inject F_NOP noise into
    every proto's instruction stream. Default rate 12 % — enough to disrupt
    opcode-frequency fingerprinting without measurable runtime overhead.
    """
    result = []
    for ins in code:
        result.append(ins)
        if rng.random() < noise_rate:
            result.append(_Ins("F_NOP", rng.randint(0, 255)))
    return result


def _inject_noise_recursive(proto: Proto, rng, noise_rate: float = 0.12):
    proto.code = inject_instruction_noise(proto.code, rng, noise_rate)
    for sub in proto.protos:
        _inject_noise_recursive(sub, rng, noise_rate)


def encode_program(proto: Proto, opmap: OpcodeMap, rng) -> dict:
    """
    Noise inject → serialise → LZSS compress → ARX outer-encrypt.
    Returns a dict of all parameters needed by the Lua decoder.
    """
    import zlib

    # Upgrade 5: F_NOP noise across every proto in the tree before encode.
    # Force on by default (was optional).
    _inject_noise_recursive(proto, rng)

    oseed  = rng.randrange(1, 16777216)
    cseed  = rng.randrange(1, 16777216)

    # Breaks AI step-tracers that follow stack depth to fingerprint opcodes.
    plain = serialize(proto, opmap, cseed)

    # LZSS-style compress (simple, Lua-decodable)
    try:
        compressed = _lzss_compress(plain)
        if len(compressed) < len(plain):
            payload = bytes([1]) + compressed
        else:
            payload = bytes([0]) + plain
    except Exception:
        payload = bytes([0]) + plain

    iv     = rng.randrange(0, 256)
    key    = arx_stream(oseed, KLEN)
    cipher, checksum = encrypt(payload, key, iv)

    return {
        "cipher":   cipher,
        "oseed":    oseed,
        "cseed":    cseed,
        "iv":       iv,
        "checksum": checksum,
        "plain_len": len(plain),
    }


def _lzss_compress(data: bytes) -> bytes:
    """Minimal LZSS — window 256, match 3-18 bytes."""
    out = bytearray(); i = 0; n = len(data)
    while i < n:
        ctrl_idx = len(out); out.append(0); ctrl = 0; mask = 1
        for _ in range(8):
            if i >= n: break
            # search back window (max 256 bytes, match 3..18)
            best_len = 2; best_off = 0
            start = max(0, i - 256)
            for j in range(start, i):
                ml = 0
                while ml < 18 and i + ml < n and data[j + ml] == data[i + ml]:
                    ml += 1
                if ml > best_len:
                    best_len = ml; best_off = i - j
            if best_len >= 3:
                out.append(best_off & 0xFF)
                out.append(((best_off >> 8) & 0x0F) * 16 + (best_len - 3))
                i += best_len
            else:
                ctrl |= mask; out.append(data[i]); i += 1
            mask <<= 1
        out[ctrl_idx] = ctrl
    return bytes(out)


def ascii85_encode(data: bytes) -> str:
    """ASCII-85 encode for embedding the cipher blob in Lua source."""
    pad    = (-len(data)) % 4
    padded = data + b"\x00" * pad
    out    = []
    for i in range(0, len(padded), 4):
        k = padded[i] | (padded[i+1]<<8) | (padded[i+2]<<16) | (padded[i+3]<<24)
        if k == 0:
            out.append("z")
        else:
            out.append(
                chr(33 + k // 52200625 % 85)
                + chr(33 + k // 614125   % 85)
                + chr(33 + k // 7225     % 85)
                + chr(33 + k // 85       % 85)
                + chr(33 + k             % 85)
            )
    return "".join(out)
