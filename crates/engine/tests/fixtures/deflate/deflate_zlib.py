# Makes deflate-zlib.json: DEFLATE (RFC 1951), zlib (RFC 1950) and gzip (RFC 1952) streams
# written by the zlib C library (through Python's zlib module), and damaged ones, for the
# engine's `inflate`, `zlib_inflate` and `gzip_inflate` (`crates/engine/tests/schemes_xml.rs`).
#
#   python -I deflate_zlib.py deflate-zlib.json
#
# Each case is a stream and either the bytes it inflates to (`output`, or `zeros`: that many
# zero bytes) or the fact that it must be refused (`output` null). The version of zlib is
# written into the file.
#
# Provenance only: the tests read deflate-zlib.json and never run Python.
import json
import struct
import sys
import zlib

TEXT = (b"<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_1\"/>" * 7)
BINARY = bytes(range(256)) * 9
INPUTS = {"empty": b"", "one": b"a", "text": TEXT, "binary": BINARY}


def raw(data, level=6, strategy=zlib.Z_DEFAULT_STRATEGY):
    c = zlib.compressobj(level, zlib.DEFLATED, -15, 9, strategy)
    return c.compress(data) + c.flush()


def wrapped(data, wbits, level=6, **kw):
    c = zlib.compressobj(level, zlib.DEFLATED, wbits, 9, zlib.Z_DEFAULT_STRATEGY, **kw)
    return c.compress(data) + c.flush()


def gzip_with_fields(data):
    # FTEXT, FHCRC, FEXTRA, FNAME and FCOMMENT all set, MTIME and OS given.
    flags = 1 | 2 | 4 | 8 | 16
    header = b"\x1f\x8b\x08" + bytes([flags]) + struct.pack("<I", 1700000000) + b"\x00\x03"
    header += struct.pack("<H", 6) + b"AB\x02\x00xy"
    header += b"name.xml\x00" + b"a comment\x00"
    header += struct.pack("<H", zlib.crc32(header) & 0xFFFF)
    return header + raw(data) + struct.pack("<II", zlib.crc32(data), len(data) & 0xFFFFFFFF)


cases = []


def ok(name, framing, stream, output):
    cases.append({"name": name, "framing": framing, "stream": stream.hex(), "output": output.hex()})


def refused(name, framing, stream):
    cases.append({"name": name, "framing": framing, "stream": stream.hex(), "output": None})


for name, data in INPUTS.items():
    for level in (0, 1, 6, 9):
        ok(f"raw-{name}-level{level}", "raw", raw(data, level), data)
    ok(f"raw-{name}-fixed", "raw", raw(data, 6, zlib.Z_FIXED), data)
    ok(f"raw-{name}-huffman-only", "raw", raw(data, 6, zlib.Z_HUFFMAN_ONLY), data)
    ok(f"zlib-{name}", "zlib", zlib.compress(data), data)
    ok(f"zlib-{name}-level9-small-window", "zlib", wrapped(data, 9, 9), data)
    ok(f"gzip-{name}", "gzip", wrapped(data, 31), data)
    ok(f"gzip-{name}-all-fields", "gzip", gzip_with_fields(data), data)

z = zlib.compress(TEXT)
g = wrapped(TEXT, 31)
r = raw(TEXT)
refused("raw-truncated", "raw", r[:-3])
refused("raw-trailing-byte", "raw", r + b"\x00")
refused("raw-reserved-block-type", "raw", b"\x07\x00")
refused("zlib-wrong-adler32", "zlib", z[:-1] + bytes([z[-1] ^ 1]))
refused("zlib-bad-fcheck", "zlib", bytes([z[0], z[1] ^ 1]) + z[2:])
refused("zlib-preset-dictionary", "zlib", wrapped(TEXT, 15, 6, zdict=b"samlp:AuthnRequest"))
refused("zlib-trailing-byte", "zlib", z + b"\x00")
refused("zlib-not-deflate", "zlib", b"\x79\x9c" + z[2:])
refused("gzip-wrong-crc32", "gzip", g[:-8] + bytes([g[-8] ^ 1]) + g[-7:])
refused("gzip-wrong-length", "gzip", g[:-1] + bytes([g[-1] ^ 1]))
refused("gzip-wrong-header-crc", "gzip", gzip_with_fields(TEXT).replace(b"a comment\x00", b"a commenT\x00"))
refused("gzip-reserved-flag", "gzip", g[:3] + b"\x20" + g[4:])
refused("gzip-two-members", "gzip", g + g)
refused("gzip-truncated-trailer", "gzip", g[:-2])
refused("gzip-not-deflate", "gzip", g[:2] + b"\x07" + g[3:])
# Bombs: 4 MiB of zeros, over the 1 MiB cap of one inflation.
BOMB = bytes(4 * 1024 * 1024)
refused("raw-bomb-4mib", "raw", raw(BOMB, 9))
refused("zlib-bomb-4mib", "zlib", zlib.compress(BOMB, 9))
refused("gzip-bomb-4mib", "gzip", wrapped(BOMB, 31, 9))
# Exactly at the cap, and one byte over.
CAP = 1024 * 1024
cases.append({"name": "raw-at-the-cap", "framing": "raw", "stream": raw(bytes(CAP), 9).hex(), "zeros": CAP})
refused("raw-one-over-the-cap", "raw", raw(bytes(CAP + 1), 9))

with open(sys.argv[1], "w", encoding="utf-8", newline="\n") as f:
    json.dump({"zlib": zlib.ZLIB_RUNTIME_VERSION, "cases": cases}, f, indent=0)
    f.write("\n")
print(len(cases))
