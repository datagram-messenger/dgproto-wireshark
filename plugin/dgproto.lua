-- dgproto.lua — Wireshark Lua dissector for DGProto v1
-- Place in: %APPDATA%\Wireshark\plugins\  or load via -X lua_script:dgproto.lua
-- Self-contained: ChaCha20-Poly1305 decryption runs in pure Lua (no Python).

local dgproto = Proto("dgproto", "DGProto v1")

-- ── Preferences ──────────────────────────────────────────────────────────────
local prefs = dgproto.prefs
prefs.tcp_port    = Pref.uint  ("TCP Port",        9900,   "TCP port DGProto listens on")
prefs.keylog_file = Pref.string(
    "Keylog File",
    "",
    "Path to dgproto_keylog.txt (overrides DGPROTO_KEYLOG env var)"
)

-- ── Protocol fields ───────────────────────────────────────────────────────────
local f = dgproto.fields

-- Header
f.magic          = ProtoField.string ("dgproto.magic",           "Magic",           base.ASCII)
f.version        = ProtoField.uint8  ("dgproto.version",         "Version",         base.HEX)
f.flags          = ProtoField.uint8  ("dgproto.flags",           "Flags",           base.HEX)
f.flag_obfuscated= ProtoField.bool   ("dgproto.flags.obfuscated","FlagObfuscated",  8, {"Set","Not set"}, 0x01)
f.flag_padding   = ProtoField.bool   ("dgproto.flags.padding",   "FlagPadding",     8, {"Set","Not set"}, 0x02)
f.msg_type       = ProtoField.uint8  ("dgproto.msg_type",        "MessageType",     base.HEX)
f.reserved1      = ProtoField.bytes  ("dgproto.reserved1",       "Reserved1")
f.session_id     = ProtoField.bytes  ("dgproto.session_id",      "SessionID")
f.sequence       = ProtoField.uint64 ("dgproto.sequence",        "Sequence",        base.DEC)
f.payload_len    = ProtoField.uint32 ("dgproto.payload_len",     "PayloadLength",   base.DEC)
f.pad_len        = ProtoField.uint8  ("dgproto.pad_len",         "PadLength",       base.DEC)
f.reserved2      = ProtoField.bytes  ("dgproto.reserved2",       "Reserved2")

-- Payload / crypto
f.payload_raw    = ProtoField.bytes  ("dgproto.payload_raw",     "Payload (ciphertext)")
f.aead_tag       = ProtoField.bytes  ("dgproto.aead_tag",        "AEAD Tag")
f.padding        = ProtoField.bytes  ("dgproto.padding",         "Padding")
f.plaintext      = ProtoField.bytes  ("dgproto.plaintext",       "Plaintext (decrypted)")

-- EncryptedData (0x03)
f.stream_id      = ProtoField.uint16 ("dgproto.stream_id",       "StreamID",        base.DEC)
f.app_msg_type   = ProtoField.uint8  ("dgproto.app_msg_type",    "AppMsgType",      base.HEX)
f.app_reserved   = ProtoField.uint8  ("dgproto.app_reserved",    "Reserved",        base.HEX)
f.tlv_data       = ProtoField.bytes  ("dgproto.tlv_data",        "TLV Fields")

-- Ping/Pong (0x04)
f.is_response    = ProtoField.uint8  ("dgproto.is_response",     "IsResponse",      base.DEC, {[0]="Ping",[1]="Pong"})
f.ping_nonce     = ProtoField.bytes  ("dgproto.ping_nonce",      "Nonce")

-- SessionClose (0x05)
f.close_code     = ProtoField.uint16 ("dgproto.close_code",      "CloseCode",       base.DEC,
                       {[0]="Normal",[1]="AuthExpired",[2]="ProtocolError",[3]="Idle"})
f.close_reason   = ProtoField.bytes  ("dgproto.close_reason",    "TLV Reason")

-- Ack (0x06)
f.acked_count    = ProtoField.uint8  ("dgproto.acked_count",     "AckedCount",      base.DEC)
f.acked_seqs     = ProtoField.bytes  ("dgproto.acked_seqs",      "AckedSequences")

-- RekeyInit (0x08)
f.rekey_epoch    = ProtoField.uint32 ("dgproto.rekey_epoch",     "Epoch",           base.DEC)
f.key_confirm    = ProtoField.bytes  ("dgproto.key_confirm",     "KeyConfirm")

-- Error (0x09)
f.error_code     = ProtoField.uint16 ("dgproto.error_code",      "ErrorCode",       base.DEC)
f.error_context  = ProtoField.string ("dgproto.error_context",   "Context",         base.UNICODE)

-- Expert info
-- NOTE: expert.group.* / expert.severity.* live in the GLOBAL `expert` table.
-- Do not shadow it with `local expert = dgproto.experts` — that makes
-- `expert.group` nil and breaks loading.
local ef_handshake = ProtoExpert.new(
    "dgproto.handshake", "DGProto Handshake",
    expert.group.PROTOCOL, expert.severity.NOTE
)
local ef_encrypted = ProtoExpert.new(
    "dgproto.encrypted", "DGProto Encrypted frame",
    expert.group.PROTOCOL, expert.severity.CHAT
)
local ef_error = ProtoExpert.new(
    "dgproto.error", "DGProto Error/Close",
    expert.group.PROTOCOL, expert.severity.WARN
)
local ef_decrypt_ok = ProtoExpert.new(
    "dgproto.decrypt_ok", "Decryption successful",
    expert.group.DECRYPTION, expert.severity.CHAT
)
local ef_decrypt_fail = ProtoExpert.new(
    "dgproto.decrypt_fail", "Decryption failed",
    expert.group.DECRYPTION, expert.severity.WARN
)
dgproto.experts = { ef_handshake, ef_encrypted, ef_error, ef_decrypt_ok, ef_decrypt_fail }

-- ── Constants ─────────────────────────────────────────────────────────────────
local MAGIC        = "DGP1"
local HEADER_LEN   = 40
local AEAD_TAG_LEN = 16

local MSG_NAMES = {
    [0x01] = "HandshakeInit",
    [0x02] = "HandshakeResponse",
    [0x03] = "EncryptedData",
    [0x04] = "Ping/Pong",
    [0x05] = "SessionClose",
    [0x06] = "Ack",
    [0x07] = "ResumptionTicket",
    [0x08] = "RekeyInit",
    [0x09] = "Error",
}

-- Types without AEAD tag
local NO_TAG = { [0x01]=true, [0x02]=true }

-- ── Keylog cache ──────────────────────────────────────────────────────────────
-- keys[session_id_hex][direction][epoch] = key_hex
local keylog_cache   = {}
local keylog_keys    = {}   -- keylog_keys[sid] = { distinct key_hex values }
local keylog_path_cached = nil

local function bytes_to_hex(buf, offset, len)
    local t = {}
    for i = 0, len-1 do
        t[#t+1] = string.format("%02x", buf(offset+i, 1):uint())
    end
    return table.concat(t)
end

local function find_keylog_path()
    if prefs.keylog_file and prefs.keylog_file ~= "" then
        return prefs.keylog_file
    end
    local env = os.getenv("DGPROTO_KEYLOG")
    if env and env ~= "" then return env end
    local appdata = os.getenv("APPDATA") or ""
    if appdata ~= "" then
        return appdata .. "\\Wireshark\\dgproto_keylog.txt"
    end
    return nil
end

local function load_keylog(path)
    if not path then return end
    local f_handle = io.open(path, "r")
    if not f_handle then return end
    keylog_cache = {}
    keylog_keys  = {}
    for line in f_handle:lines() do
        -- DGPROTO_SESSION_KEY <session_id_hex> <direction> <epoch> <key_hex>
        local sid, dir, epoch, key = line:match(
            "^DGPROTO_SESSION_KEY%s+(%x+)%s+(%S+)%s+(%d+)%s+(%x+)%s*$")
        if sid then
            sid = sid:lower()
            key = key:lower()
            if not keylog_cache[sid] then keylog_cache[sid] = {} end
            if not keylog_cache[sid][dir] then keylog_cache[sid][dir] = {} end
            keylog_cache[sid][dir][tonumber(epoch)] = key
            -- Collect every DISTINCT key seen for this session. Both peers may
            -- write to the same keylog, so direction labels are unreliable;
            -- decryption tries them all and keeps whichever authenticates.
            local list = keylog_keys[sid]
            if not list then list = {}; keylog_keys[sid] = list end
            local seen = false
            for _, k in ipairs(list) do if k == key then seen = true; break end end
            if not seen then list[#list + 1] = key end
        end
    end
    f_handle:close()
end

local function ensure_keylog()
    local path = find_keylog_path()
    if path ~= keylog_path_cached then
        keylog_path_cached = path
        load_keylog(path)
        return
    end
    -- Reload if file changed (best-effort: check via open)
    if path then
        local fh = io.open(path, "r")
        if fh then fh:close() end
        -- Simple reload every dissection pass (acceptable for debug tool)
        load_keylog(path)
    end
end

-- ── ChaCha20-Poly1305 decryption (pure Lua) ────────────────────────────────────
-- Pure-Lua ChaCha20-Poly1305 (RFC 8439). Wireshark 4.2 embeds Lua 5.2,
-- while newer builds may use Lua 5.3+. Keep the source parseable by Lua 5.2
-- and route all 32-bit operations through bit32 (or LuaJIT's compatible bit
-- module). The limb arithmetic below was verified against RFC 8439 and 300
-- random vectors before being ported here; a self-test also runs at load time.

local UINT32 = 4294967296
local bits = bit32
if not bits then
    local ok, module = pcall(require, "bit32")
    if ok then bits = module end
end
if not bits then
    local ok, module = pcall(require, "bit")
    if ok then bits = module end
end
assert(bits, "DGProto requires bit32 or a compatible bit module")

local function u32(x) return x % UINT32 end
local function band(...) return u32(bits.band(...)) end
local function bor(...) return u32(bits.bor(...)) end
local function bxor(...) return u32(bits.bxor(...)) end
local function lshift(x, n)
    if n >= 32 then return 0 end
    return u32(bits.lshift(u32(x), n))
end
local function rshift(x, n)
    if n >= 32 then return 0 end
    return u32(bits.rshift(u32(x), n))
end
local function high_shift(x, n) return math.floor(x / (2 ^ n)) end

local function rotl32(x, n)
    return bor(lshift(x, n), rshift(x, 32 - n))
end

-- hex string -> byte array (1-indexed, with .n length)
local function hex_to_bytes(hex)
    local t, n = {}, 0
    for i = 1, #hex, 2 do
        n = n + 1
        t[n] = tonumber(hex:sub(i, i + 1), 16) or 0
    end
    t.n = n
    return t
end

local function bytes_to_hexstr(t, from, len)
    local parts = {}
    for i = from, from + len - 1 do
        parts[#parts + 1] = string.format("%02x", t[i])
    end
    return table.concat(parts)
end

-- read a 32-bit little-endian word from byte array t at 1-based index i
local function u32le(t, i)
    return bor(t[i] or 0, lshift(t[i+1] or 0, 8),
        lshift(t[i+2] or 0, 16), lshift(t[i+3] or 0, 24))
end

-- ChaCha20 block -> 64 bytes (1-indexed)
local function chacha20_block(key, counter, nonce)
    local st = {}
    st[0] = 0x61707865; st[1] = 0x3320646e; st[2] = 0x79622d32; st[3] = 0x6b206574
    for j = 0, 7 do st[4 + j] = u32le(key, 1 + j * 4) end
    st[12] = u32(counter)
    for j = 0, 2 do st[13 + j] = u32le(nonce, 1 + j * 4) end

    local x = {}
    for i = 0, 15 do x[i] = st[i] end

    local function qr(a, b, c, d)
        x[a] = u32(x[a] + x[b]); x[d] = bxor(x[d], x[a]); x[d] = rotl32(x[d], 16)
        x[c] = u32(x[c] + x[d]); x[b] = bxor(x[b], x[c]); x[b] = rotl32(x[b], 12)
        x[a] = u32(x[a] + x[b]); x[d] = bxor(x[d], x[a]); x[d] = rotl32(x[d], 8)
        x[c] = u32(x[c] + x[d]); x[b] = bxor(x[b], x[c]); x[b] = rotl32(x[b], 7)
    end

    for _ = 1, 10 do
        qr(0,4,8,12);  qr(1,5,9,13);  qr(2,6,10,14); qr(3,7,11,15)
        qr(0,5,10,15); qr(1,6,11,12); qr(2,7,8,13);  qr(3,4,9,14)
    end

    local out, p = {}, 0
    for i = 0, 15 do
        local w = u32(x[i] + st[i])
        out[p+1] = band(w, 0xff)
        out[p+2] = band(rshift(w, 8), 0xff)
        out[p+3] = band(rshift(w, 16), 0xff)
        out[p+4] = band(rshift(w, 24), 0xff)
        p = p + 4
    end
    return out
end

-- XOR first `dlen` bytes of `data` with the keystream from block `counter`
local function chacha20_xor(key, counter, nonce, data, dlen)
    local out, blk = {}, nil
    for i = 0, dlen - 1 do
        local j = i % 64
        if j == 0 then blk = chacha20_block(key, counter + math.floor(i / 64), nonce) end
        out[i + 1] = bxor(data[i + 1], blk[j + 1])
    end
    out.n = dlen
    return out
end

-- Poly1305 (RFC 8439), 26-bit limbs. msg: byte array, mlen bytes. key: 32 bytes.
local function poly1305_mac(msg, mlen, key)
    -- Ten 13-bit limbs keep every product exact on Lua 5.2's double numbers.
    local base13 = 8192

    local function add_bit_value(limbs, bitpos, value)
        local limb = math.floor(bitpos / 13)
        local offset = bitpos % 13
        limbs[limb] = (limbs[limb] or 0) + value * (2 ^ offset)
        while limbs[limb] >= base13 do
            local carry = math.floor(limbs[limb] / base13)
            limbs[limb] = limbs[limb] % base13
            limb = limb + 1
            limbs[limb] = (limbs[limb] or 0) + carry
        end
    end

    local function bytes_to_limbs(bytes, count, append_one)
        local limbs = {}
        for i = 0, 9 do limbs[i] = 0 end
        for i = 1, count do add_bit_value(limbs, (i - 1) * 8, bytes[i]) end
        if append_one then add_bit_value(limbs, count * 8, 1) end
        return limbs
    end

    local rbytes = {}
    for i = 1, 16 do rbytes[i] = key[i] end
    rbytes[4] = band(rbytes[4], 15); rbytes[8] = band(rbytes[8], 15)
    rbytes[12] = band(rbytes[12], 15); rbytes[16] = band(rbytes[16], 15)
    rbytes[5] = band(rbytes[5], 252); rbytes[9] = band(rbytes[9], 252)
    rbytes[13] = band(rbytes[13], 252)
    local r = bytes_to_limbs(rbytes, 16, false)
    local h = {}
    for i = 0, 9 do h[i] = 0 end

    local offset = 0
    while offset < mlen do
        local count = math.min(16, mlen - offset)
        local block = {}
        for i = 1, count do block[i] = msg[offset + i] end
        local n = bytes_to_limbs(block, count, true)
        for i = 0, 9 do h[i] = h[i] + n[i] end

        local product = {}
        for i = 0, 18 do product[i] = 0 end
        for i = 0, 9 do
            for j = 0, 9 do product[i + j] = product[i + j] + h[i] * r[j] end
        end
        for i = 18, 10, -1 do product[i - 10] = product[i - 10] + product[i] * 5 end
        for _ = 1, 3 do
            for i = 0, 9 do
                local carry = math.floor(product[i] / base13)
                product[i] = product[i] % base13
                if i < 9 then
                    product[i + 1] = product[i + 1] + carry
                else
                    product[0] = product[0] + carry * 5
                end
            end
        end
        for i = 0, 9 do h[i] = product[i] end
        offset = offset + count
    end

    -- Canonicalize modulo 2^130-5 before adding the second half of the key.
    local p_limbs = {8187,8191,8191,8191,8191,8191,8191,8191,8191,8191}
    local ge_p = true
    for i = 9, 0, -1 do
        if h[i] ~= p_limbs[i + 1] then ge_p = h[i] > p_limbs[i + 1]; break end
    end
    if ge_p then
        local borrow = 0
        for i = 0, 9 do
            local value = h[i] - p_limbs[i + 1] - borrow
            if value < 0 then value = value + base13; borrow = 1 else borrow = 0 end
            h[i] = value
        end
    end

    local mac, carry = {}, 0
    for byte_index = 0, 15 do
        local bitpos = byte_index * 8
        local limb = math.floor(bitpos / 13)
        local shift = bitpos % 13
        local value = math.floor(h[limb] / (2 ^ shift))
        if shift > 5 and limb < 9 then value = value + h[limb + 1] * (2 ^ (13 - shift)) end
        value = (value % 256) + key[17 + byte_index] + carry
        mac[byte_index + 1] = value % 256
        carry = math.floor(value / 256)
    end
    return mac
end

local function pad16_len(n) return (16 - (n % 16)) % 16 end

-- AEAD decrypt. Returns (plaintext_bytes, ptlen) on success, or nil on auth fail.
local function aead_decrypt(key, nonce, aad, aadlen, cttag, cttaglen)
    if cttaglen < 16 then return nil end
    local ctlen = cttaglen - 16
    local otk = chacha20_block(key, 0, nonce)  -- first 32 bytes are the Poly1305 key

    -- mac_data = aad | pad | ciphertext | pad | len(aad) | len(ct)  (lengths LE64)
    local m, mi = {}, 0
    for k = 1, aadlen do mi = mi + 1; m[mi] = aad[k] end
    for _ = 1, pad16_len(aadlen) do mi = mi + 1; m[mi] = 0 end
    for k = 1, ctlen do mi = mi + 1; m[mi] = cttag[k] end
    for _ = 1, pad16_len(ctlen) do mi = mi + 1; m[mi] = 0 end
    for k = 0, 7 do mi = mi + 1; m[mi] = high_shift(aadlen, 8*k) % 256 end
    for k = 0, 7 do mi = mi + 1; m[mi] = high_shift(ctlen, 8*k) % 256 end

    local tag = poly1305_mac(m, mi, otk)
    local diff = 0
    for k = 1, 16 do diff = bor(diff, bxor(tag[k], cttag[ctlen + k])) end
    if diff ~= 0 then return nil end  -- authentication failed

    return chacha20_xor(key, 1, nonce, cttag, ctlen), ctlen
end

-- Forward-declared: true once the load-time self-test confirms the crypto.
local CRYPTO_SELFTEST_OK

-- Cache results so a frame is only decrypted once (Wireshark re-dissects on
-- every scroll/redraw). Values: hex plaintext string, "AUTH_FAIL", or false.
local decrypt_cache = {}

-- Same signature as before (hex in, hex out) so the rest of the dissector is
-- unchanged. No external process is ever spawned.
local function decrypt_payload(key_hex, nonce_hex, aad_hex, ct_hex)
    if CRYPTO_SELFTEST_OK == false then return nil end

    local cache_key = key_hex .. "|" .. nonce_hex .. "|" .. aad_hex .. "|" .. ct_hex
    local cached = decrypt_cache[cache_key]
    if cached ~= nil then
        if cached == false then return nil end
        return cached
    end

    local key   = hex_to_bytes(key_hex)
    local nonce = hex_to_bytes(nonce_hex)
    local aad   = hex_to_bytes(aad_hex)
    local cttag = hex_to_bytes(ct_hex)

    local result
    if key.n ~= 32 or nonce.n ~= 12 or cttag.n < 16 then
        result = nil
    else
        local pt, ptlen = aead_decrypt(key, nonce, aad, aad.n, cttag, cttag.n)
        result = pt and bytes_to_hexstr(pt, 1, ptlen) or "AUTH_FAIL"
    end

    decrypt_cache[cache_key] = (result ~= nil) and result or false
    return result
end

-- ── SHA-256 + HMAC-SHA256 (pure Lua) ─────────────────────────────────────────
-- Needed to follow the protocol's rekey ratchet. The keylog only records the
-- epoch-1 traffic keys; after a rekey (every 2^32 frames OR 10 minutes) the key
-- becomes K_next = HMAC-SHA256(K, "DGPv1 Rekey Send Key") and the sequence
-- resets to 1. We derive the chain so later epochs still decrypt.

local SHA_K = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
}

local function str_to_bytes(s)
    local t = {}
    for i = 1, #s do t[i] = string.byte(s, i) end
    t.n = #s
    return t
end

-- SHA-256 over byte array `msg` (1-indexed) of length `mlen`. Returns 32 bytes.
local function sha256(msg, mlen)
    local H0,H1,H2,H3 = 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a
    local H4,H5,H6,H7 = 0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19

    local m = {}
    for i = 1, mlen do m[i] = msg[i] end
    local bitlen = mlen * 8
    m[#m + 1] = 0x80
    while (#m % 64) ~= 56 do m[#m + 1] = 0 end
    for i = 7, 0, -1 do m[#m + 1] = high_shift(bitlen, i * 8) % 256 end

    local function rotr(x, n)
        return bor(rshift(x, n), lshift(x, 32 - n))
    end

    local W = {}
    local nblocks = math.floor(#m / 64)
    for blk = 0, nblocks - 1 do
        local base = blk * 64
        for t = 0, 15 do
            local o = base + t * 4
            W[t] = bor(lshift(m[o+1], 24), lshift(m[o+2], 16),
                lshift(m[o+3], 8), m[o+4])
        end
        for t = 16, 63 do
            local x15, x2 = W[t-15], W[t-2]
            local s0 = bxor(rotr(x15,7), rotr(x15,18), rshift(x15,3))
            local s1 = bxor(rotr(x2,17), rotr(x2,19), rshift(x2,10))
            W[t] = u32(W[t-16] + s0 + W[t-7] + s1)
        end
        local a,b,c,d,e,g,h,i8 = H0,H1,H2,H3,H4,H5,H6,H7
        for t = 0, 63 do
            local S1   = bxor(rotr(e,6), rotr(e,11), rotr(e,25))
            local ch   = bxor(band(e,g), band(bits.bnot(e),h))
            local t1   = u32(i8 + S1 + ch + SHA_K[t+1] + W[t])
            local S0   = bxor(rotr(a,2), rotr(a,13), rotr(a,22))
            local maj  = bxor(band(a,b), band(a,c), band(b,c))
            local t2   = u32(S0 + maj)
            i8 = h; h = g; g = e; e = u32(d + t1)
            d = c; c = b; b = a; a = u32(t1 + t2)
        end
        H0=u32(H0+a); H1=u32(H1+b); H2=u32(H2+c); H3=u32(H3+d)
        H4=u32(H4+e); H5=u32(H5+g); H6=u32(H6+h); H7=u32(H7+i8)
    end

    local Hs = {H0,H1,H2,H3,H4,H5,H6,H7}
    local out, p = {}, 0
    for i = 1, 8 do
        local w = Hs[i]
        out[p+1]=band(rshift(w,24),0xff); out[p+2]=band(rshift(w,16),0xff)
        out[p+3]=band(rshift(w,8),0xff); out[p+4]=band(w,0xff)
        p = p + 4
    end
    out.n = 32
    return out
end

local function hmac_sha256(key, klen, msg, mlen)
    local bkey = {}
    if klen > 64 then
        local hk = sha256(key, klen)
        for i = 1, 32 do bkey[i] = hk[i] end
        for i = 33, 64 do bkey[i] = 0 end
    else
        for i = 1, klen do bkey[i] = key[i] end
        for i = klen + 1, 64 do bkey[i] = 0 end
    end
    local inner = {}
    for i = 1, 64 do inner[i] = bxor(bkey[i], 0x36) end
    for i = 1, mlen do inner[64 + i] = msg[i] end
    local ih = sha256(inner, 64 + mlen)
    local outer = {}
    for i = 1, 64 do outer[i] = bxor(bkey[i], 0x5c) end
    for i = 1, 32 do outer[64 + i] = ih[i] end
    return sha256(outer, 96)  -- 32 bytes
end

-- ── Rekey key ratchet ────────────────────────────────────────────────────────
local REKEY_LABEL   = str_to_bytes("DGPv1 Rekey Send Key")
local MAX_EPOCHS    = 32          -- try up to this many epochs per base key
local ratchet_cache = {}          -- base_key_hex -> { epoch1_hex, epoch2_hex, ... }

local function key_chain(base_hex)
    local chain = ratchet_cache[base_hex]
    if chain then return chain end
    chain = {}
    local cur = hex_to_bytes(base_hex)   -- 32 bytes
    for e = 1, MAX_EPOCHS do
        chain[e] = bytes_to_hexstr(cur, 1, 32)
        cur = hmac_sha256(cur, 32, REKEY_LABEL, REKEY_LABEL.n)
    end
    ratchet_cache[base_hex] = chain
    return chain
end

-- Every key worth trying for a session: each epoch-1 key from the keylog plus
-- its forward-ratcheted epochs. The Poly1305 tag tells us which one is right.
local function candidate_keys(session_id_hex)
    local bases = keylog_keys[session_id_hex:lower()]
    if not bases then return {} end
    local out = {}
    for _, b in ipairs(bases) do
        for _, k in ipairs(key_chain(b)) do out[#out + 1] = k end
    end
    return out
end

-- ── Load-time self-test (RFC 8439 §2.8.2) ────────────────────────────────────
CRYPTO_SELFTEST_OK = (function()
    local key   = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
    local nonce = "070000004041424344454647"
    local aad   = "50515253c0c1c2c3c4c5c6c7"
    local cttag = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
               .. "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
               .. "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
               .. "3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691"
    local got = decrypt_payload(key, nonce, aad, cttag)
    if type(got) ~= "string" then return false end
    local want_text = "Ladies and Gentlemen of the class of '99: If I could offer "
                   .. "you only one tip for the future, sunscreen would be it."
    local exp = {}
    for i = 1, #want_text do exp[i] = string.format("%02x", string.byte(want_text, i)) end
    decrypt_cache = {}  -- drop the self-test entry
    if got ~= table.concat(exp) then return false end

    -- HMAC-SHA256 known-answer test (RFC 4231 test case 2) — guards the rekey ratchet.
    local mac = hmac_sha256(str_to_bytes("Jefe"), 4,
                            str_to_bytes("what do ya want for nothing?"), 28)
    local want = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    return bytes_to_hexstr(mac, 1, 32) == want
end)()

-- If the self-test ever fails (e.g. a future Lua change), say so loudly instead
-- of silently mis-decrypting. Harmless in the GUI (no stdout attached).
if not CRYPTO_SELFTEST_OK then
    io.stderr:write("[dgproto] WARNING: ChaCha20-Poly1305 self-test FAILED; "
                 .. "decryption disabled.\n")
end

-- Build the 12-byte nonce: four zero bytes followed by the wire-order LE64 sequence.
local function build_nonce_hex(buf, seq_offset)
    -- nonce: 00 00 00 00 + seq[0..7] (already LE in packet)
    local t = {"00000000"}
    for i = 0, 7 do
        t[#t+1] = string.format("%02x", buf(seq_offset + i, 1):uint())
    end
    return table.concat(t)
end

-- ── Plaintext sub-dissection ──────────────────────────────────────────────────
local function dissect_plaintext(pt_tvb, msg_type, tree)
    if msg_type == 0x03 then  -- EncryptedData
        if pt_tvb:len() < 4 then return end
        tree:add_le(f.stream_id,    pt_tvb(0, 2))
        tree:add   (f.app_msg_type, pt_tvb(2, 1))
        tree:add   (f.app_reserved, pt_tvb(3, 1))
        if pt_tvb:len() > 4 then
            tree:add(f.tlv_data, pt_tvb(4))
        end

    elseif msg_type == 0x04 then  -- Ping/Pong
        if pt_tvb:len() < 9 then return end
        tree:add(f.is_response, pt_tvb(0, 1))
        tree:add(f.ping_nonce,  pt_tvb(1, 8))

    elseif msg_type == 0x05 then  -- SessionClose
        if pt_tvb:len() < 2 then return end
        tree:add_le(f.close_code, pt_tvb(0, 2))
        if pt_tvb:len() > 2 then
            tree:add(f.close_reason, pt_tvb(2))
        end

    elseif msg_type == 0x06 then  -- Ack
        if pt_tvb:len() < 1 then return end
        local count = pt_tvb(0,1):uint()
        tree:add(f.acked_count, pt_tvb(0, 1))
        if pt_tvb:len() >= 1 + count * 8 then
            tree:add(f.acked_seqs, pt_tvb(1, count * 8))
        end

    elseif msg_type == 0x08 then  -- RekeyInit
        if pt_tvb:len() < 36 then return end
        tree:add_le(f.rekey_epoch, pt_tvb(0, 4))
        tree:add   (f.key_confirm, pt_tvb(4, 32))

    elseif msg_type == 0x09 then  -- Error
        if pt_tvb:len() < 2 then return end
        tree:add_le(f.error_code,    pt_tvb(0, 2))
        if pt_tvb:len() > 2 then
            tree:add(f.error_context, pt_tvb(2))
        end
    end
end

-- ── Hex string → ByteArray → Tvb ─────────────────────────────────────────────
local function hex_to_tvb(hex_str, name)
    local ba = ByteArray.new(hex_str)
    return ByteArray.tvb(ba, name)
end

-- ── Main dissection of one DGProto frame ─────────────────────────────────────
-- Returns number of bytes consumed, or 0 on error.
local function dissect_one(buf, pinfo, tree, offset)
    local buf_len = buf:len()
    local remaining = buf_len - offset

    -- Need at least the header
    if remaining < HEADER_LEN then
        pinfo.desegment_offset = offset
        pinfo.desegment_len    = HEADER_LEN - remaining
        return 0
    end

    -- Check magic
    local magic_bytes = buf(offset, 4):string()
    if magic_bytes ~= MAGIC then
        return -1  -- not our protocol
    end

    local msg_type   = buf(offset + 6,  1):uint()
    local payload_len= buf(offset + 32, 4):le_uint()
    local pad_len    = buf(offset + 36, 1):uint()

    -- HandshakeFinish (Noise message 3) reuses msg_type 0x03 but is sent with an
    -- all-zero session ID *before* a session is established. Unlike EncryptedData
    -- (also 0x03) it carries NO AEAD tag and must not be decrypted.
    local session_zero = true
    for i = 0, 15 do
        if buf(offset + 8 + i, 1):uint() ~= 0 then session_zero = false; break end
    end
    local is_handshake_finish = (msg_type == 0x03) and session_zero

    local has_tag    = (not NO_TAG[msg_type]) and (not is_handshake_finish)
    local tag_len    = has_tag and AEAD_TAG_LEN or 0

    local total_len  = HEADER_LEN + payload_len + tag_len + pad_len

    if remaining < total_len then
        pinfo.desegment_offset = offset
        pinfo.desegment_len    = total_len - remaining
        return 0
    end

    -- ── Build subtree ──────────────────────────────────────────────────────
    local frame_tvb  = buf(offset, total_len)
    local proto_tree = tree:add(dgproto, frame_tvb, "DGProto v1")

    -- Header subtree
    local hdr_tree = proto_tree:add(dgproto, buf(offset, HEADER_LEN), "Header")
    hdr_tree:add            (f.magic,       buf(offset,      4))
    hdr_tree:add            (f.version,     buf(offset + 4,  1))
    local flags_item = hdr_tree:add(f.flags, buf(offset + 5, 1))
    flags_item:add          (f.flag_obfuscated, buf(offset + 5, 1))
    flags_item:add          (f.flag_padding,    buf(offset + 5, 1))
    hdr_tree:add            (f.msg_type,    buf(offset + 6,  1))
    hdr_tree:add            (f.reserved1,   buf(offset + 7,  1))
    hdr_tree:add            (f.session_id,  buf(offset + 8,  16))
    hdr_tree:add_le         (f.sequence,    buf(offset + 24, 8))
    hdr_tree:add_le         (f.payload_len, buf(offset + 32, 4))
    hdr_tree:add            (f.pad_len,     buf(offset + 36, 1))
    hdr_tree:add            (f.reserved2,   buf(offset + 37, 3))

    -- Payload
    if payload_len > 0 then
        proto_tree:add(f.payload_raw, buf(offset + HEADER_LEN, payload_len))
    end

    -- AEAD tag
    if has_tag and tag_len > 0 then
        proto_tree:add(f.aead_tag, buf(offset + HEADER_LEN + payload_len, AEAD_TAG_LEN))
    end

    -- Padding
    if pad_len > 0 then
        proto_tree:add(f.padding, buf(offset + HEADER_LEN + payload_len + tag_len, pad_len))
    end

    -- ── Expert info & column ───────────────────────────────────────────────
    local msg_name = MSG_NAMES[msg_type] or string.format("Unknown(0x%02x)", msg_type)
    local seq_val  = buf(offset + 24, 8):le_uint64()

    local info_str
    if msg_type == 0x01 or msg_type == 0x02 then
        info_str = string.format("[%s]", msg_name)
        proto_tree:add_proto_expert_info(ef_handshake)
    elseif is_handshake_finish then
        info_str = "[HandshakeFinish]"
        proto_tree:add_proto_expert_info(ef_handshake)
    elseif msg_type == 0x03 then
        info_str = string.format("[EncryptedData seq=%s]", tostring(seq_val))
        proto_tree:add_proto_expert_info(ef_encrypted)
    elseif msg_type == 0x04 then
        info_str = string.format("[Ping seq=%s]", tostring(seq_val))
        proto_tree:add_proto_expert_info(ef_encrypted)
    elseif msg_type == 0x05 or msg_type == 0x09 then
        info_str = string.format("[%s seq=%s]", msg_name, tostring(seq_val))
        proto_tree:add_proto_expert_info(ef_error)
    else
        info_str = string.format("[%s seq=%s]", msg_name, tostring(seq_val))
        proto_tree:add_proto_expert_info(ef_encrypted)
    end

    pinfo.cols.protocol:set("DGProto")
    pinfo.cols.info:append(info_str .. "  ")

    -- ── Decryption (only for types with AEAD tag and non-zero payload) ─────
    if has_tag and payload_len > 0 then
        ensure_keylog()

        local session_id_hex = bytes_to_hex(buf, offset + 8, 16)
        -- Direction labels in the keylog are ambiguous (both peers may write to
        -- the same file), so don't guess by port: try EVERY key recorded for
        -- this session and let the Poly1305 tag prove which one is correct.
        local candidates = candidate_keys(session_id_hex)

        if #candidates > 0 then
            local nonce_hex = build_nonce_hex(buf, offset + 24)
            -- AAD = header[0:40] + padding
            local aad_hex   = bytes_to_hex(buf, offset, HEADER_LEN)
            if pad_len > 0 then
                aad_hex = aad_hex .. bytes_to_hex(buf, offset + HEADER_LEN + payload_len + tag_len, pad_len)
            end
            -- Ciphertext with tag
            local ct_hex = bytes_to_hex(buf, offset + HEADER_LEN, payload_len + AEAD_TAG_LEN)

            local pt_hex = nil
            for _, k in ipairs(candidates) do
                local r = decrypt_payload(k, nonce_hex, aad_hex, ct_hex)
                if r and r ~= "" and r ~= "AUTH_FAIL" then
                    pt_hex = r
                    break
                end
                pt_hex = r  -- remember last failure (AUTH_FAIL / nil) for the message
            end

            if pt_hex and pt_hex ~= "" and pt_hex ~= "AUTH_FAIL" then
                local pt_tvb = hex_to_tvb(pt_hex, "Plaintext")
                local dec_tree = proto_tree:add(dgproto, pt_tvb(), "Decrypted Payload")
                dec_tree:add(f.plaintext, pt_tvb())
                dissect_plaintext(pt_tvb, msg_type, dec_tree)
                proto_tree:add_proto_expert_info(ef_decrypt_ok)

                -- Enrich info column for EncryptedData
                if msg_type == 0x03 and pt_tvb:len() >= 2 then
                    local stream_id = pt_tvb(0,2):le_uint()
                    -- Replace last info entry
                    local new_info = string.format("[EncryptedData seq=%s stream=%d]",
                        tostring(seq_val), stream_id)
                    -- Append corrected info (column already has the old one)
                    pinfo.cols.info:append(new_info .. "  ")
                end
            else
                local reason
                if pt_hex == "AUTH_FAIL" then
                    reason = "auth tag mismatch (wrong key / nonce / AAD)"
                else
                    reason = "decryption failed (crypto self-test?)"
                end
                proto_tree:add_proto_expert_info(ef_decrypt_fail, reason)
            end
        else
            proto_tree:add_proto_expert_info(ef_decrypt_fail, "session key not in keylog")
        end
    end

    return total_len
end

-- ── TCP dissector entry point ─────────────────────────────────────────────────
function dgproto.dissector(buf, pinfo, tree)
    local buf_len = buf:len()
    if buf_len < 4 then return 0 end

    pinfo.cols.protocol:set("DGProto")

    local offset = 0
    while offset < buf_len do
        local consumed = dissect_one(buf, pinfo, tree, offset)
        if consumed < 0 then
            -- Magic mismatch — not our data
            return 0
        elseif consumed == 0 then
            -- Need more data (desegment fields already set)
            return
        end
        offset = offset + consumed
    end
end

-- ── Heuristic dissector ───────────────────────────────────────────────────────
local function heuristic_dissect(buf, pinfo, tree)
    if buf:len() < 4 then return false end
    if buf(0, 4):string() ~= MAGIC then return false end
    dgproto.dissector(buf, pinfo, tree)
    return true
end

-- ── Registration ─────────────────────────────────────────────────────────────
local tcp_table = DissectorTable.get("tcp.port")

-- Apply preferences change
function dgproto.prefs_changed()
    tcp_table:remove(prefs.tcp_port, dgproto)
    tcp_table:add(prefs.tcp_port, dgproto)
end

tcp_table:add(9900, dgproto)
dgproto:register_heuristic("tcp", heuristic_dissect)

-- ── Init ──────────────────────────────────────────────────────────────────────
function dgproto.init()
    keylog_cache = {}
    keylog_keys = {}
    keylog_path_cached = nil
end
