# host

The program on the parent instance of an AWS Nitro Enclave that runs a credentials node,
run as `credentials host`. The `credentials` tool ([crates/cli](../cli)) only parses the
command line and calls `host::run`; the wire to the enclave is the [`relay`](../relay)
crate, and the log files are those of `server::logfile`.

`credentials host` runs on the Linux parent instance of an AWS Nitro Enclave that runs the
[`enclave`](../enclave) node (see "Running in a Nitro Enclave" in the
[README](../../README.md#running-in-a-nitro-enclave)). On other systems it exits with a usage
error: it needs vsock.

```sh
credentials host --enclave-cid 16 --log-dir /var/lib/credentials \
  --listen 127.0.0.1:8700 --allow api.github.com:443 --allow oauth2.googleapis.com:443
```

It does three things, each on its own vsock port (the defaults match the enclave program):

- **HTTP forwarding.** Each TCP connection to `--listen` is carried to vsock port
  `--http-port` (5000) of the enclave `--enclave-cid`, where the node answers the endpoints
  of `credentials serve` ([crates/cli](../cli#the-server)) plus
  `GET /attestation?nonce=<base64url>` (`{"identity": ..., "document": <base64url NSM
  attestation document>}`). At most `--max-connections` (64) are open at once; beyond that
  it answers 503, and 502 when the enclave is unreachable. Like `serve`, it speaks plain HTTP:
  terminate TLS in front of it and limit who can connect.
- **Egress relay** (vsock port `--egress-port`, 5001). The node sends `CONNECT host:port`; the
  host connects over TCP within 10 s and answers `OK`, or `ERR <reason>`, then copies bytes
  both ways (a connection silent for 130 s is closed). TLS ends inside the enclave, so the host
  carries ciphertext only. Without `--allow` it connects wherever the node asks (the node only
  asks for destinations of signed policies); with `--allow`, only to the listed `host:port`
  (host compared without case).
- **Log writer** (vsock port `--log-port`, 5002). The node says hello with its log key; the
  host opens `<log-dir>/<log key>.jsonl` (the log of `credentials serve`, kept by
  `server::logfile`: one entry per line, each written, flushed and `sync_data`'d before the
  host confirms it, an incomplete last line cut on open, a failed write cut back) and answers with the last entry it holds. A restarted enclave is a
  new node with a new key, so it gets a new file. Checkpoints go to
  `<log key>.jsonl.head.json`. Check a log with
  `credentials verify <log-dir>/<key>.jsonl <key> --head <key>.jsonl.head.json`.
