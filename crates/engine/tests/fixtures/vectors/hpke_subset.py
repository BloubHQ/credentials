# Makes hpke-rfc9180.json from the CFRG test vectors of RFC 9180 (see README.md): every
# suite and mode, all exports, and the encryptions at sequence numbers 0, 1, 255 and 256.
#
#   python -I hpke_subset.py test-vectors-5f503c5.json hpke-rfc9180.json
import json
import sys

src, dst = sys.argv[1], sys.argv[2]
with open(src, encoding="utf-8") as f:
    vectors = json.load(f)
KEEP = (0, 1, 255, 256)
out = []
for t in vectors:
    kept = []
    for i, x in enumerate(t["encryptions"]):
        if i in KEEP:
            x = dict(x)
            x["seq"] = i
            kept.append(x)
    t = dict(t)
    t["encryptions"] = kept
    out.append(t)
with open(dst, "w", encoding="utf-8", newline="\n") as f:
    f.write("[\n")
    f.write(",\n".join(json.dumps(t, separators=(",", ":")) for t in out))
    f.write("\n]\n")
print(len(out), sum(len(t["encryptions"]) for t in out), sum(len(t["exports"]) for t in out))
