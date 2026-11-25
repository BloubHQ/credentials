# Test fixtures

`rsa2048.pem` is an RSA 2048-bit private key in PKCS#8 PEM form. It was generated for the
tests in `../flow.rs` (`rsa_keys_sign_jwts`), which sign a JWT with
`rsa_sign_pkcs1_sha256(pem(key), ...)` and verify the signature with `ring`.

The key is public by being in this repository. It protects nothing, is not used by any
service, and must never be used for anything but these tests. GitHub secret scanning skips
this directory (see `.github/secret_scanning.yml`).

To replace it, generate a new key and keep the file name:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa2048.pem
```
