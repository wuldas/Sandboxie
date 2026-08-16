#!/usr/bin/env python3
"""Regenerate HPACK C headers from RFC 7541 (Appendix B Huffman table,
Appendix A static table, Appendix C test vectors).

Usage:  python gen_hpack.py [path/to/rfc7541.txt]
Output: ../SbieCapture/hpack_huffman.h
        ../SbieCapture/hpack_static.h
        ./hpack_tests_data.h

Self-checks: Huffman encode/decode round-trip and byte-exact match against
RFC C.4.1 ("www.example.com") and C.4.2 ("no-cache").
"""
import os, re, sys

RFC = sys.argv[1] if len(sys.argv) > 1 else "rfc7541.txt"
HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.normpath(os.path.join(HERE, "..", "SbieCapture"))

txt = open(RFC, encoding="utf-8", errors="replace").read()

# ---------- Appendix B: Huffman table ----------
b_m = re.search(r"^Appendix B\.  Huffman Code\s*$", txt, re.M)
c_m = re.search(r"^Appendix C\.  Examples\s*$", txt, re.M)
if not b_m or not c_m:
    sys.exit("FAIL: appendix anchors not found")
bsec = txt[b_m.end():c_m.start()]

huff = {}  # symbol -> (code, bits)
for line in bsec.splitlines():
    m = re.search(r"\(\s*(\d+)\)", line)
    if not m:
        continue
    sym = int(m.group(1))
    mb = re.search(r"([0-9a-f]+)\s+\[\s*(\d+)\]", line)
    if not mb:
        continue
    huff[sym] = (int(mb.group(1), 16), int(mb.group(2)))

if len(huff) != 257:
    sys.exit("FAIL: expected 257 huffman symbols, got %d" % len(huff))

trie_nodes = [{"left": -1, "right": -1, "sym": -1}]
def insert(code, bits, sym):
    node = 0
    for i in range(bits - 1, -1, -1):
        bit = (code >> i) & 1
        child = trie_nodes[node]["left"] if bit == 0 else trie_nodes[node]["right"]
        if child == -1:
            child = len(trie_nodes)
            trie_nodes.append({"left": -1, "right": -1, "sym": -1})
            if bit == 0:
                trie_nodes[node]["left"] = child
            else:
                trie_nodes[node]["right"] = child
        node = child
    if trie_nodes[node]["sym"] != -1:
        sys.exit("FAIL: duplicate trie leaf at %d" % sym)
    trie_nodes[node]["sym"] = sym

for s in range(257):
    c, b = huff[s]
    insert(c, b, s)

def huffman_encode(data):
    acc = 0
    nbits = 0
    out = bytearray()
    for byte in data:
        c, b = huff[byte]
        acc = (acc << b) | c
        nbits += b
        while nbits >= 8:
            nbits -= 8
            out.append((acc >> nbits) & 0xFF)
    if nbits > 0:
        acc = (acc << (8 - nbits)) | ((1 << (8 - nbits)) - 1)
        out.append(acc & 0xFF)
    return bytes(out)

def huffman_decode(data):
    out = bytearray()
    node = 0
    for byte in data:
        for i in range(7, -1, -1):
            bit = (byte >> i) & 1
            node = trie_nodes[node]["left"] if bit == 0 else trie_nodes[node]["right"]
            if node == -1:
                return None
            sym = trie_nodes[node]["sym"]
            if sym >= 0:
                if sym == 256:
                    return bytes(out)
                out.append(sym)
                node = 0
    return bytes(out)

assert huffman_encode(b"www.example.com") == bytes.fromhex("f1e3c2e5f23a6ba0ab90f4ff")
assert huffman_decode(bytes.fromhex("f1e3c2e5f23a6ba0ab90f4ff")) == b"www.example.com"
assert huffman_encode(b"no-cache") == bytes.fromhex("a8eb10649cbf")
print("Huffman self-check OK (257 symbols)")

def emit_huffman():
    lines = ["/* Generated from RFC 7541 Appendix B. Do not edit by hand. */",
             "#ifndef _MY_HPACK_HUFFMAN_H", "#define _MY_HPACK_HUFFMAN_H", "",
             "#define HPACK_HUFF_SYMBOLS 257", "",
             "typedef struct _HPACK_HUFF_CODE { ULONG code; UCHAR bits; } HPACK_HUFF_CODE;",
             "static const HPACK_HUFF_CODE HpackHuffCode[HPACK_HUFF_SYMBOLS] = {"]
    for s in range(257):
        c, b = huff[s]
        lines.append("    {0x%08xul, %d}, /* %d */" % (c, b, s))
    lines.append("};")
    lines.append("")
    lines.append("typedef struct _HPACK_HUFF_NODE { short left; short right; short symbol; } HPACK_HUFF_NODE;")
    lines.append("#define HPACK_HUFF_TRIE_NODES %d" % len(trie_nodes))
    lines.append("static const HPACK_HUFF_NODE HpackHuffTrie[HPACK_HUFF_TRIE_NODES] = {")
    for n in trie_nodes:
        lines.append("    {%d, %d, %d}," % (n["left"], n["right"], n["sym"]))
    lines.append("};")
    lines.append("")
    lines.append("#endif /* _MY_HPACK_HUFFMAN_H */")
    return "\n".join(lines) + "\n"

static_table = [
    (":authority", ""), (":method", "GET"), (":method", "POST"),
    (":path", "/"), (":path", "/index.html"), (":scheme", "http"),
    (":scheme", "https"), (":status", "200"), (":status", "204"),
    (":status", "206"), (":status", "304"), (":status", "400"),
    (":status", "404"), (":status", "500"), ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"), ("accept-language", ""),
    ("accept-ranges", ""), ("accept", ""), ("access-control-allow-origin", ""),
    ("age", ""), ("allow", ""), ("authorization", ""), ("cache-control", ""),
    ("content-disposition", ""), ("content-encoding", ""), ("content-language", ""),
    ("content-length", ""), ("content-location", ""), ("content-range", ""),
    ("content-type", ""), ("cookie", ""), ("date", ""), ("etag", ""),
    ("expect", ""), ("expires", ""), ("from", ""), ("host", ""),
    ("if-match", ""), ("if-modified-since", ""), ("if-none-match", ""),
    ("if-range", ""), ("if-unmodified-since", ""), ("last-modified", ""),
    ("link", ""), ("location", ""), ("max-forwards", ""),
    ("proxy-authenticate", ""), ("proxy-authorization", ""), ("range", ""),
    ("referer", ""), ("refresh", ""), ("retry-after", ""), ("server", ""),
    ("set-cookie", ""), ("strict-transport-security", ""),
    ("transfer-encoding", ""), ("user-agent", ""), ("vary", ""), ("via", ""),
    ("www-authenticate", ""),
]
assert len(static_table) == 61

def emit_static():
    lines = ["/* Generated from RFC 7541 Appendix A. Do not edit by hand. */",
             "#ifndef _MY_HPACK_STATIC_H", "#define _MY_HPACK_STATIC_H", "",
             "#define HPACK_STATIC_COUNT 61", "",
             "typedef struct _HPACK_STATIC_ENTRY {",
             "    const char *name;", "    const char *value;",
             "} HPACK_STATIC_ENTRY;", "",
             "static const HPACK_STATIC_ENTRY HpackStatic[HPACK_STATIC_COUNT] = {"]
    for n, v in static_table:
        lines.append('    {"%s", "%s"},' % (n, v))
    lines.append("};")
    lines.append("")
    lines.append("#endif /* _MY_HPACK_STATIC_H */")
    return "\n".join(lines) + "\n"

# ---------- Appendix C: test vectors ----------
csec = txt[c_m.start():]
sec_pat = re.compile(r"^C\.(\d+)\.(\d+)\.", re.M)
secs = [(int(m.group(1)), int(m.group(2)), m.start(), m.end())
        for m in sec_pat.finditer(csec)]

vectors = []
for i, (x, y, s, e) in enumerate(secs):
    if x == 1:
        continue
    end = secs[i + 1][2] if i + 1 < len(secs) else len(csec)
    body = csec[e:end]
    hm = re.search(r"Header list to encode:\s*\n(.*?)\n\s*Hex dump", body, re.S)
    if not hm:
        continue
    headers = []
    for line in hm.group(1).splitlines():
        m2 = re.match(r"^\s+(.+?):\s*(.*)$", line)
        if m2:
            headers.append((m2.group(1), m2.group(2)))
    hx = re.search(r"Hex dump of encoded data:\s*\n(.*?)(?:\n\s*\n|\n   [A-Z]|\Z)", body, re.S)
    if not hx:
        continue
    hexbytes = []
    for line in hx.group(1).splitlines():
        left = line.split("|")[0]
        for t in re.findall(r"[0-9a-fA-F]{4}|[0-9a-fA-F]{2}", left):
            v = int(t, 16)
            if len(t) == 4:
                hexbytes.append((v >> 8) & 0xFF)
                hexbytes.append(v & 0xFF)
            else:
                hexbytes.append(v)
    vectors.append({"x": x, "y": y, "headers": headers, "data": hexbytes})

if not vectors:
    sys.exit("FAIL: no Appendix C vectors parsed")

def emit_tests():
    lines = ["/* Generated from RFC 7541 Appendix C. Do not edit by hand. */",
             "#ifndef _MY_HPACK_TESTS_DATA_H", "#define _MY_HPACK_TESTS_DATA_H", "",
             "typedef struct _HPACK_TEST_HEADER { const char *name; const char *value; } HPACK_TEST_HEADER;",
             "typedef struct _HPACK_TEST_VECTOR {",
             "    int series;", "    int sub;", "    const UCHAR *data;",
             "    ULONG data_len;", "    const HPACK_TEST_HEADER *headers;",
             "    ULONG header_count;", "} HPACK_TEST_VECTOR;", ""]
    for i, v in enumerate(vectors):
        lines.append("static const UCHAR HpackVec%dData[%d] = {" % (i, len(v["data"])))
        for j in range(0, len(v["data"]), 12):
            lines.append("    " + ",".join("0x%02x" % b for b in v["data"][j:j + 12]) + ",")
        lines.append("};")
        lines.append("static const HPACK_TEST_HEADER HpackVec%dHeaders[%d] = {" % (i, len(v["headers"])))
        for n, val in v["headers"]:
            lines.append('    {"%s", "%s"},' % (n, val))
        lines.append("};")
        lines.append("")
    lines.append("static const HPACK_TEST_VECTOR HpackTestVectors[%d] = {" % len(vectors))
    for i, v in enumerate(vectors):
        lines.append("    {%d, %d, HpackVec%dData, %d, HpackVec%dHeaders, %d},"
                     % (v["x"], v["y"], i, len(v["data"]), i, len(v["headers"])))
    lines.append("};")
    lines.append("")
    lines.append("#define HPACK_TEST_VECTOR_COUNT %d" % len(vectors))
    lines.append("")
    lines.append("#endif /* _MY_HPACK_TESTS_DATA_H */")
    return "\n".join(lines) + "\n"

open(os.path.join(OUT_DIR, "hpack_huffman.h"), "w", encoding="utf-8", newline="\n").write(emit_huffman())
open(os.path.join(OUT_DIR, "hpack_static.h"), "w", encoding="utf-8", newline="\n").write(emit_static())
open(os.path.join(HERE, "hpack_tests_data.h"), "w", encoding="utf-8", newline="\n").write(emit_tests())
print("Wrote hpack_huffman.h, hpack_static.h, hpack_tests_data.h (%d vectors)" % len(vectors))
