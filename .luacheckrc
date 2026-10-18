std = "lua52"
max_line_length = 120
codes = true

-- Wireshark injects these globals into its Lua runtime.
globals = {
    "Proto", "Pref", "ProtoField", "ProtoExpert", "DissectorTable",
    "ByteArray", "base", "expert"
}

-- Protocol callbacks and the crypto guard are intentionally visible to Wireshark.
read_globals = { "CRYPTO_SELFTEST_OK" }
