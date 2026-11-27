// A smoke test of the web package: node smoke.mjs <directory of the wasm-bindgen output>.
//
// It loads the module as a browser would (the `web` target, from bytes), then runs every
// function that needs no node: keys, nonces, a refused attestation, policies, records, pins,
// revocations, device changes, calls, policy summaries, the JSON Schema, kinds of item and
// approvals. Randomness and time come from JavaScript here
// (crypto.getRandomValues, Date.now), which is what this test checks beyond the host tests.
// At the end it looks for the keys in the module's memory: the client erases its copies.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const dir = resolve(process.argv[2] ?? "pkg");
const client = await import(pathToFileURL(join(dir, "client.js")).href);
const wasm = await client.default({ module_or_path: await readFile(join(dir, "client_bg.wasm")) });

/// How many times `text` is in the module's linear memory.
function inMemory(text) {
  const memory = Buffer.from(wasm.memory.buffer);
  const needle = Buffer.from(text);
  let count = 0;
  for (let at = memory.indexOf(needle); at !== -1; at = memory.indexOf(needle, at + 1)) count++;
  return count;
}

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

// After each part below, no key is left in the module's memory: the client erases its
// copies, also those a buffer or the stack would keep (#55). (The JavaScript strings are
// another matter: they stay in the JavaScript heap until garbage-collected.)
const tracked = { device, user, caller };
function track(label) {
  const counts = Object.fromEntries(Object.entries(tracked).map(([name, key]) => [name, inMemory(key)]));
  assert.ok(Object.values(counts).every((n) => n === 0), `key text in wasm memory after ${label}: ${JSON.stringify(counts)}`);
}
track("keys");

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

track("nonce");

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

track("owner documents");

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

track("call");

// A summary of a policy in the step language, with its risk flags: any bytes in, and the
// whole response body of a wildcard destination back.
const wide = JSON.stringify({
  fields: [{ name: "key", secret: true }, { name: "token", secret: true }],
  callers: [{ name: "app", key: callerPublic, operations: ["mac", "fetch"] }],
  operations: [
    {
      name: "mac",
      input: { raw: {} },
      steps: [{ do: "return", template: "{{ hex(hmac_sha256(key, $input)) }}" }],
    },
    {
      name: "fetch",
      steps: [
        { do: "open", connection: "https", destinations: [{ host: "*.api.example", port: 443 }] },
        {
          do: "send",
          request: { from: "caller", methods: ["GET"], paths: ["/v1/**"] },
          inject: [{ target: { kind: "header", name: "Authorization" }, template: "Bearer {{token}}" }],
        },
        { do: "return", response: { body: "all" } },
      ],
    },
  ],
});
const summary = JSON.parse(client.summarize(wide, policy));
const flags = summary.flags.map((f) => f.code);
for (const flag of ["raw_input", "wildcard", "response_all", "wider"]) {
  assert.ok(flags.includes(flag), `${flag} in ${flags}`);
}
const token = summary.secrets.find((s) => s.field === "token");
assert.deepEqual(token.uses[0].form, { in: "header", name: "Authorization" });
assert.equal(JSON.parse(client.summarize(policy)).flags.length, 0);
assert.deepEqual(code(() => client.summarize("{")), ["invalid_input", undefined]);

track("summary");

// The schema, the reviewed kinds, a custom kind.
assert.equal(JSON.parse(client.policyJsonSchema()).$defs.Policy.type, "object");
const kinds = JSON.parse(client.itemKinds()).kinds.map((k) => k.name);
assert.ok(kinds.includes("card") && kinds.includes("ssh"), kinds);
const kind = {
  name: "door",
  description: "A door code.",
  fields: [{ name: "code", disclosure: "secret", guessable: true }],
  shape: { connections: ["none"], destinations: { from: "owner" }, returns: "status" },
};
assert.equal(JSON.parse(client.signKind(device, JSON.stringify(kind))).kind.name, "door");
assert.deepEqual(
  code(() => client.signKind(device, JSON.stringify({ ...kind, name: "card" }))),
  ["refused", undefined],
);

track("kinds");

// A describe call, and an approval of a summary of this node, now.
const describe = JSON.parse(client.signDescribeCall(caller, "app", identity, record));
assert.equal(describe.operation, ":describe");
assert.deepEqual(describe.body, { kind: "describe" });
const open = JSON.stringify({
  id: "AAAAAAAAAAAAAAAAAAAAAA",
  node: devicePublic,
  owner: "alice",
  record_id: "mac",
  generation: 1,
  caller: "app",
  operation: "mac",
  lines: ["Sign one message"],
  created_ms: Date.now() - 1000,
  expires_ms: Date.now() + 60_000,
});
assert.equal(client.approvalHash(open).length, 43);
const approval = JSON.parse(client.approve(device, identity, open));
assert.equal(approval.device, devicePublic);
assert.ok(Math.abs(approval.issued_ms - Date.now()) < 60_000);

track("describe and approve");

// Operations that wait: the pending operation the node hands back is approved as is, a code
// challenge is answered by the device (sealed to the node), the app resumes with the id, the
// device signs spending limits and renews a value of the record.
const waiting = JSON.stringify({ kind: "approval_required", id: "AAAAAAAAAAAAAAAAAAAAAA", summary: JSON.parse(open) });
assert.equal(JSON.parse(client.approve(device, identity, waiting)).id, "AAAAAAAAAAAAAAAAAAAAAA");
const challenge = JSON.stringify({
  kind: "challenge",
  id: "AQEBAQEBAQEBAQEBAQEBAQ",
  challenge: "sms",
  hint: "The code the bank texts you",
  expires_ms: Date.now() + 60_000,
});
const answer = JSON.parse(
  client.answerChallenge(device, "alice", identity, challenge, new TextEncoder().encode("123456")),
);
assert.ok(answer.enc.length > 0 && answer.ciphertext.length > 0);
assert.ok(!JSON.stringify(answer).includes("123456"), "the code is sealed");
assert.deepEqual(
  code(() => client.answerChallenge(device, "alice", identity, waiting, new Uint8Array([1]))),
  ["invalid_input", undefined],
);
const resume = JSON.parse(
  client.signResumeCall(caller, "app", identity, record, "mac", "AQEBAQEBAQEBAQEBAQEBAQ"),
);
assert.deepEqual(resume.body, { kind: "resume", id: "AQEBAQEBAQEBAQEBAQEBAQ" });
const limits = JSON.parse(
  client.signLimits(device, "alice", identity, "mac", JSON.stringify([{ currency: "EUR", per_day: "100" }])),
);
assert.equal(limits.rules[0].per_day, "100");
assert.ok(Math.abs(limits.issued_ms - Date.now()) < 60_000);
assert.deepEqual(
  code(() => client.signLimits(device, "alice", identity, "mac", JSON.stringify([{ currency: "eur", per_day: "1" }]))),
  ["refused", undefined],
);
const renewed = client.updateRecord(user, record, new Map([["key", new TextEncoder().encode("fedcba9876543210fedcba9876543210")]]));
assert.equal(JSON.parse(renewed).generation, 2);

track("waiting operations");

// Node continuity: a successor statement that is not one is refused, and spends the nonce.
const successorNonce = client.nonce();
assert.deepEqual(
  code(() =>
    client.verifySuccessor(new Uint8Array([0]), successorNonce, new Uint8Array([123]), new Uint8Array([123]), "v1.0.0", identity),
  ),
  ["successor_refused", "bundle_invalid"],
);
assert.deepEqual(
  code(() => client.verifyNode(new Uint8Array([0, 1]), successorNonce, measurements, identity)),
  ["nonce_rejected", undefined],
);

track("continuity");

// Key backup: a blob that opens only with its backup key, for its owner.
const keys = JSON.stringify([
  { kind: "device", key: device },
  { kind: "user", key: user },
]);
const backupKey = client.generateBackupKey();
tracked.backupKey = backupKey;
const blob = client.wrapKeys(backupKey, "alice", keys);
track("wrapKeys");
assert.equal(JSON.parse(blob).format, "credentials-key-backup/v1");
assert.ok(!blob.includes(device) && !blob.includes(user));
assert.deepEqual(JSON.parse(client.unwrapKeys(backupKey, "alice", blob)), JSON.parse(keys));
assert.deepEqual(code(() => client.unwrapKeys(client.generateBackupKey(), "alice", blob)), ["backup_refused", undefined]);
assert.deepEqual(code(() => client.unwrapKeys(backupKey, "bob", blob)), ["backup_refused", undefined]);

track("backup");

// Device transfer with a 6-digit code (SPAKE2): the right code moves the keys...
const sender = client.startTransfer();
assert.match(sender.code(), /^[0-9]{6}$/);
const receiver = client.joinTransfer(sender.code(), sender.offer());
const sealedKeys = sender.seal(receiver.answer(), "alice", keys);
assert.ok(!sealedKeys.includes(device) && !sealedKeys.includes(user));
const moved = JSON.parse(receiver.open(sealedKeys));
assert.equal(moved.owner, "alice");
assert.deepEqual(moved.keys, JSON.parse(keys));
track("transfer");

// ...and wrong codes are counted until the code is dead.
const guarded = client.startTransfer();
const wrong = guarded.code() === "000000" ? "000001" : "000000";
for (let left = 2; left >= 0; left--) {
  const guess = client.joinTransfer(wrong, guarded.offer());
  assert.deepEqual(code(() => guarded.seal(guess.answer(), "alice", keys)), ["transfer_refused", undefined]);
  assert.equal(guarded.attemptsLeft(), left);
}
assert.deepEqual(code(() => guarded.offer()), ["transfer_refused", undefined]);

track("wrong codes");

// Key objects: a key that stays in wasm memory while the object lives, used by reference,
// and wiped by free().
const deviceObject = client.DeviceKey.generate();
const deviceText = deviceObject.exportKey();
assert.equal(deviceText.length, 43);
assert.equal(inMemory(deviceText), 1, "the object holds its key, once");
assert.equal(deviceObject.publicKey(), client.publicKey(KeyKind.Device, deviceText));
const userObject = client.UserKey.fromString(user + "\n");
assert.equal(userObject.exportKey(), user);
const callerObject = client.CallerKey.fromString(caller);
assert.equal(callerObject.publicKey(), callerPublic);
assert.deepEqual(code(() => client.UserKey.fromString("nope")), ["invalid_key", undefined]);
const signedByObject = deviceObject.signPolicy(policy);
const objectRecord = userObject.sealRecord(signedByObject, "mac", "alice", fields);
assert.equal(JSON.parse(objectRecord).generation, 1);
assert.equal(JSON.parse(userObject.rewrapRecord(objectRecord, signedByObject)).generation, 2);
assert.equal(JSON.parse(deviceObject.pinRecord(objectRecord)).generation, 1);
assert.equal(JSON.parse(deviceObject.revoke("alice", identity)).owner, "alice");
const objectCall = JSON.parse(
  callerObject.signDeriveCall("app", identity, objectRecord, "mac", new TextEncoder().encode("hi")),
);
assert.equal(objectCall.operation, "mac");
assert.equal(JSON.parse(callerObject.signDescribeCall("app", identity, objectRecord)).operation, ":describe");
for (const object of [deviceObject, userObject, callerObject]) object.free();
assert.equal(inMemory(deviceText), 0, "free() wipes the key");
assert.throws(() => deviceObject.exportKey(), "a freed object is gone");
track("key objects");

const blobOpened = client.unwrapKeys(backupKey, "alice", blob);
track("a last unwrapKeys");
assert.ok(blobOpened.length > 0);

console.log("web package: smoke test passed");
