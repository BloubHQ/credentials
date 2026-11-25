// A smoke test of the web package: node smoke.mjs <directory of the wasm-bindgen output>.
//
// It loads the module as a browser would (the `web` target, from bytes), then runs every
// function that needs no node: keys, nonces, a refused attestation, policies, records, pins,
// revocations, device changes and calls. Randomness and time come from JavaScript here
// (crypto.getRandomValues, Date.now), which is what this test checks beyond the host tests.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const dir = resolve(process.argv[2] ?? "pkg");
const client = await import(pathToFileURL(join(dir, "client.js")).href);
await client.default({ module_or_path: await readFile(join(dir, "client_bg.wasm")) });

const { KeyKind } = client;

function code(f) {
  try {
    f();
  } catch (e) {
    assert.ok(e instanceof Error);
    return [e.code, e.reason];
  }
  assert.fail("no error thrown");
}

// Keys.
const device = client.generateKey(KeyKind.Device);
const user = client.generateKey(KeyKind.User);
const caller = client.generateKey(KeyKind.Caller);
for (const key of [device, user, caller]) assert.equal(key.length, 43);
assert.notEqual(device, client.generateKey(KeyKind.Device));
assert.equal(client.importKey(KeyKind.Device, device + "\n"), device);
assert.deepEqual(code(() => client.importKey(KeyKind.User, "nope")), ["invalid_key", undefined]);
const devicePublic = client.publicKey(KeyKind.Device, device);
const callerPublic = client.publicKey(KeyKind.Caller, caller);
assert.deepEqual(code(() => client.publicKey(KeyKind.User, user)), ["invalid_key", undefined]);

// A nonce, and a document that is not one.
const nonce = client.nonce();
assert.equal(nonce.bytes().length, 32);
assert.equal(nonce.toB64().length, 43);
const identity = JSON.stringify({ log_key: devicePublic, seal_key: callerPublic });
const measurements = JSON.stringify({
  release: "v0",
  pcr0: "01".repeat(48),
  pcr1: "01".repeat(48),
  pcr2: "01".repeat(48),
});
assert.deepEqual(
  code(() => client.verifyNode(new Uint8Array([0, 1]), nonce, measurements, identity)),
  ["attestation_refused", "not_cbor"],
);
assert.deepEqual(
  code(() => client.verifyNode(new Uint8Array([0, 1]), nonce, measurements, identity)),
  ["nonce_rejected", undefined],
);

// The owner's documents.
const policy = JSON.stringify({
  fields: [{ name: "key", secret: true }],
  callers: [{ name: "app", key: callerPublic, operations: ["mac"] }],
  operations: [
    {
      name: "mac",
      input: { raw: { max_len: 64 } },
      steps: [{ do: "return", template: "{{ hex(hmac_sha256(key, $input)) }}" }],
    },
  ],
});
const signed = client.signPolicy(device, policy);
const fields = new Map([["key", new TextEncoder().encode("0123456789abcdef0123456789abcdef")]]);
const record = client.sealRecord(user, signed, "mac", "alice", fields);
assert.equal(JSON.parse(record).generation, 1);
assert.deepEqual(
  code(() => client.sealRecord(user, signed, "mac", "alice", new Map([["key", "text"]]))),
  ["invalid_input", undefined],
);
assert.equal(JSON.parse(client.rewrapRecord(user, record, signed)).generation, 2);
assert.equal(JSON.parse(client.pinRecord(device, record)).generation, 1);
const revocation = JSON.parse(client.revoke(device, "alice", identity));
assert.ok(Math.abs(revocation.issued_ms - Date.now()) < 60_000, "the time comes from Date.now()");
const other = client.publicKey(KeyKind.Device, client.generateKey(KeyKind.Device));
assert.equal(JSON.parse(client.endorseDevice(device, "alice", identity, other)).device, other);
assert.equal(JSON.parse(client.retireDevice(device, "alice", identity, other)).device, other);

// A call.
const call = JSON.parse(
  client.signDeriveCall(caller, "app", identity, record, "mac", new TextEncoder().encode("hi")),
);
assert.equal(call.operation, "mac");
assert.equal(call.body.kind, "derive");
const generic = JSON.parse(
  client.signCall(caller, "app", identity, record, "mac", JSON.stringify({ kind: "derive", input: "aGk" })),
);
assert.equal(generic.body.input, "aGk");

console.log("web package: smoke test passed");
