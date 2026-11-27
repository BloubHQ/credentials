// Verifies the OpenPGP signatures the engine wrote (crates/engine/tests/schemes_srp_pgp.rs
// with CREDENTIALS_INTEROP_DIR set) with OpenPGP.js, an implementation independent of the
// engine: version 4 with RSA and with EdDSA, and version 6 with Ed25519.
// Usage: node openpgp.mjs <openpgp.mjs module path> <interop directory>
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const [modulePath, dir] = process.argv.slice(2);
const openpgp = await import(pathToFileURL(modulePath).href);
const data = await readFile(join(dir, "data.txt"));
let failed = 0;
for (const name of ["rsa", "eddsa", "v6"]) {
  try {
    const key = await openpgp.readKey({ binaryKey: await readFile(join(dir, `${name}.pub`)) });
    const signature = await openpgp.readSignature({
      armoredSignature: await readFile(join(dir, `${name}.asc`), "utf8"),
    });
    // The test signs at a fixed time (2027-01-15), so the check is made at that time.
    const date = signature.packets[0].created;
    const message = await openpgp.createMessage({ binary: data });
    const { signatures } = await openpgp.verify({
      message, signature, verificationKeys: key, expectSigned: true, format: "binary", date,
    });
    await signatures[0].verified;
    console.log(`${name}: good signature, key version ${key.keyPacket.version}`);
    // The same signature over other data must not verify.
    const other = await openpgp.createMessage({ binary: new Uint8Array([1, 2, 3]) });
    const bad = await openpgp.verify({ message: other, signature, verificationKeys: key, date });
    const refused = await bad.signatures[0].verified.then(() => false, () => true);
    if (!refused) throw new Error("a signature over other data verified");
    console.log(`${name}: refused over other data`);
  } catch (error) {
    failed += 1;
    console.log(`${name}: FAILED ${error.message}`);
  }
}
process.exit(failed === 0 ? 0 : 1);
