# Checks what crates/engine/tests/schemes_xml.rs produced with implementations that are not
# the engine's: Python's zlib for the DEFLATE streams, libxml2 (lxml) for the canonical forms
# of the signed XML, and the OpenSSL command line for every signature.
#
#   CREDENTIALS_INTEROP_DIR=<dir> cargo test -p engine --test schemes_xml
#   python -I check.py <dir> <rsa2048-cert.pem>
#
# Prints one line per check and exits non-zero when one fails.
#
# A manual cross-check, not part of `cargo test`: no test runs it or needs Python. It needs
# lxml and the openssl command line, which are not part of this repository's toolchain.
import base64
import hashlib
import os
import subprocess
import sys
import tempfile
import urllib.parse
import zlib

from lxml import etree

DIR, CERT = sys.argv[1], sys.argv[2]
DS = "http://www.w3.org/2000/09/xmldsig#"
WSU = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
# RFC 6979 A.2.5 P-256 public key, as SubjectPublicKeyInfo DER.
P256_SPKI = bytes.fromhex(
    "3059301306072a8648ce3d020106082a8648ce3d030107034200"
    "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
    "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
)
failed = 0


def report(name, ok):
    global failed
    print(("ok   " if ok else "FAIL ") + name)
    failed += 0 if ok else 1


def openssl_verify(public_pem, message, signature):
    with tempfile.TemporaryDirectory() as tmp:
        paths = [os.path.join(tmp, n) for n in ("pub.pem", "msg", "sig")]
        for path, data in zip(paths, (public_pem, message, signature)):
            with open(path, "wb") as f:
                f.write(data)
        run = subprocess.run(["openssl", "dgst", "-sha256", "-verify", paths[0], "-signature", paths[2], paths[1]],
                             capture_output=True)
        return run.returncode == 0


def der_int(b):
    b = b.lstrip(b"\x00") or b"\x00"
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b


def ecdsa_der(raw):
    body = der_int(raw[:32]) + der_int(raw[32:])
    return b"\x30" + bytes([len(body)]) + body


rsa_public = subprocess.run(["openssl", "x509", "-in", CERT, "-noout", "-pubkey"], capture_output=True,
                            check=True).stdout
p256_public = b"-----BEGIN PUBLIC KEY-----\n" + base64.encodebytes(P256_SPKI) + b"-----END PUBLIC KEY-----\n"

# DEFLATE, zlib, gzip.
for name in sorted(os.listdir(DIR)):
    if name.startswith("deflate-") and name.endswith(".in"):
        stem = name[:-3]
        data = open(os.path.join(DIR, name), "rb").read()
        for ext, wbits in ((".raw", -15), (".zlib", 15), (".gz", 31)):
            stream = open(os.path.join(DIR, stem + ext), "rb").read()
            d = zlib.decompressobj(wbits)
            out = d.decompress(stream) + d.flush()
            report(f"zlib reads {stem}{ext}", out == data and d.eof and not d.unused_data)

# HTTP-Redirect signatures.
for name, public, convert in (("redirect-rsa-sha256.query", rsa_public, lambda s: s),
                              ("redirect-ecdsa-sha256.query", p256_public, ecdsa_der)):
    target = open(os.path.join(DIR, name), encoding="ascii").read()
    pairs = [p.split("=", 1) for p in target.split("?", 1)[1].split("&")]
    signed = "&".join(f"{k}={v}" for k, v in pairs[:3]).encode()
    signature = base64.b64decode(urllib.parse.unquote(pairs[3][1]))
    report(f"openssl verifies {name}", openssl_verify(public, signed, convert(signature)))
    xml = zlib.decompress(base64.b64decode(urllib.parse.unquote(pairs[0][1])), -15)
    report(f"zlib inflates the SAMLRequest of {name}", xml.startswith(b"<samlp:AuthnRequest "))


def check_signature(name, ids):
    tree = etree.parse(os.path.join(DIR, name), etree.XMLParser(resolve_entities=False, no_network=True))
    signature = tree.find(f".//{{{DS}}}Signature")
    signed_info = signature.find(f"{{{DS}}}SignedInfo")
    for reference in signed_info.findall(f"{{{DS}}}Reference"):
        uri = reference.get("URI")[1:]
        element = next(e for e in tree.iter() if any(e.get(a) == uri for a in ids))
        transforms = [t.get("Algorithm") for t in reference.iter(f"{{{DS}}}Transform")]
        copy = etree.fromstring(etree.tostring(element))
        if "http://www.w3.org/2000/09/xmldsig#enveloped-signature" in transforms:
            for s in copy.findall(f".//{{{DS}}}Signature"):
                s.getparent().remove(s)
        canonical = etree.tostring(copy, method="c14n", exclusive=True, with_comments=False)
        digest = base64.b64encode(hashlib.sha256(canonical).digest()).decode()
        report(f"libxml2 digest of #{uri} in {name}", digest == reference.findtext(f"{{{DS}}}DigestValue"))
    canonical = etree.tostring(signed_info, method="c14n", exclusive=True, with_comments=False)
    value = base64.b64decode(signature.findtext(f"{{{DS}}}SignatureValue"))
    report(f"openssl verifies the SignedInfo of {name}", openssl_verify(rsa_public, canonical, value))


check_signature("post-authn-request.xml", ["ID"])
check_signature("wss-envelope.xml", [f"{{{WSU}}}Id"])
sys.exit(1 if failed else 0)
