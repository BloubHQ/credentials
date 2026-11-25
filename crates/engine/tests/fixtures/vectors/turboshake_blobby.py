# Makes turboshake-rfc9861.json from the test data of the `turboshake` 0.7.1 crate
# (tests/data/turboshake{128,256}_{6,7}.blb, the TurboSHAKE vectors of RFC 9861 section 5;
# see README.md).
#
#   python -I turboshake_blobby.py <crate>/tests/data turboshake-rfc9861.json
#
# A .blb file (the `blobby` format of RustCrypto): count of blobs, count of shared blobs, the
# shared blobs (length, bytes), then the blobs, each a number v: odd, the shared blob v >> 1;
# even, v >> 1 bytes that follow. Numbers are the varint below. Each record has four blobs:
# input, input pattern length (8 bytes big-endian; the input is then j % 251 for j below it),
# output, and the number of output bytes skipped before it (8 bytes big-endian).
import json
import os
import sys


def varint(data, at):
    # Big-endian groups of 7 bits, each continuation adding one (as Git's offsets).
    byte = data[at]
    at += 1
    value = byte & 0x7F
    while byte & 0x80:
        byte = data[at]
        at += 1
        value = ((value + 1) << 7) | (byte & 0x7F)
    return value, at


def blobs(data):
    total, at = varint(data, 0)
    shared_count, at = varint(data, at)
    shared = []
    for _ in range(shared_count):
        n, at = varint(data, at)
        shared.append(data[at : at + n])
        at += n
    out = []
    for _ in range(total):
        v, at = varint(data, at)
        if v & 1:
            out.append(shared[v >> 1])
        else:
            n = v >> 1
            out.append(data[at : at + n])
            at += n
    assert at == len(data), "trailing bytes"
    return out


def number(blob):
    return int.from_bytes(blob, "big") if blob else 0


src, dst = sys.argv[1], sys.argv[2]
records = []
for level in (128, 256):
    for domain in (6, 7):
        name = f"turboshake{level}_{domain}.blb"
        with open(os.path.join(src, name), "rb") as f:
            items = blobs(f.read())
        for i in range(0, len(items), 4):
            message, pattern, output, skip = items[i : i + 4]
            records.append(
                {
                    "level": level,
                    "domain": domain,
                    "message": message.hex(),
                    "pattern_len": number(pattern),
                    "skip": number(skip),
                    "output": output.hex(),
                }
            )
with open(dst, "w", encoding="utf-8", newline="\n") as f:
    f.write("[\n")
    f.write(",\n".join(json.dumps(r, separators=(",", ":")) for r in records))
    f.write("\n]\n")
print(len(records))
