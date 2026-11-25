# Test certificates

Keys and certificates for the TLS tests only. They protect nothing: never trust `ca.pem`
outside these tests. They were made once with OpenSSL (P-256, valid for 100 years), so the
tests need no certificate generator and its dependencies.

| File | Subject | Issued by | Use |
| --- | --- | --- | --- |
| `ca.pem` | test CA | itself | the root the tests trust |
| `api`, `other`, `imap` | `api.test`, `other.test`, `imap.test` | test CA | servers |
| `client` | `client.test` | test CA | client certificate for mutual TLS |
| `stranger-api` | `api.test` | stranger CA (`stranger-ca.pem`) | a server the roots do not trust |

The CA keys were discarded. To make a new set, create two CAs and issue the leaves with
`openssl req -x509` and `openssl x509 -req -extfile` (with `subjectAltName=DNS:<name>` and
`extendedKeyUsage=serverAuth` or `clientAuth`).
