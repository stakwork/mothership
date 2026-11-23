/**
 * Verifier rules the fixtures don't pin: strict structure, expiry,
 * multisig thresholds, and that limits are per block (no narrowing).
 */

import { strict as assert } from "node:assert";
import { test } from "node:test";

import { attenuate, decodeToken, encodeToken, generateKey, signRoot, signRootMultisig, verify, VerifyError } from "../src/index.js";
import type { Caveats, Policy, Token } from "../src/index.js";

const NOW = new Date("2026-05-14T10:00:01Z");
const org = generateKey("ecdsa-secp256k1-sha256");
const person = generateKey();
const policy: Policy = { type: "single", key: org.pub };

const caveats = (over: Partial<Caveats> = {}): Caveats => ({
  run_id: "r1",
  iat: "2026-05-14T10:00:00Z",
  exp: "2026-05-14T11:00:00Z",
  nonce: "00112233445566778899aabbccddeeff",
  ...over,
});

function personToken(root: Partial<Caveats> = {}): Token {
  const block = signRoot("org_x", caveats({ run_id: "grant", user_id: "alice", ...root }), person.pub, org);
  return { v: 2, org_id: "org_x", blocks: [block], proof: Buffer.from(person.priv).toString("hex") };
}

const fails = (t: Token | string, code: string, p: Policy = policy, now = NOW) =>
  assert.throws(() => verify(t, p, now), (e: unknown) => e instanceof VerifyError && e.code === code);

test("a child wider than its parent still verifies: every block's limits apply", () => {
  const parent = attenuate(personToken(), caveats({ run_id: "run", max_cost_usd: 5, exp: "2026-05-14T10:30:00Z" }));
  const child = attenuate(parent, caveats({ run_id: "child", max_cost_usd: 100, max_steps: 7 }));
  const claims = verify(child, policy, NOW);
  assert.deepEqual(claims.chain.map((l) => [l.run_id, l.max_cost_usd, l.max_steps]), [
    ["grant", 0, 0],
    ["run", 5, 0],
    ["child", 100, 7],
  ]);
  assert.equal(claims.exp, "2026-05-14T10:30:00Z", "the earliest exp in the chain");
  assert.equal(claims.run_id, "child");
  assert.equal(claims.user_id, "alice");
});

test("attenuate leaves the parent token as it was", () => {
  const parent = personToken();
  const before = encodeToken(parent);
  attenuate(parent, caveats({ run_id: "run" }));
  assert.equal(encodeToken(parent), before);
  verify(parent, policy, NOW);
});

test("any expired block fails the token", () => {
  const t = attenuate(personToken(), caveats({ run_id: "run", exp: "2026-05-14T10:00:00Z" }));
  fails(t, "macaroon_expired");
});

test("user_id on a later block is malformed: only the org names a person", () => {
  fails(attenuate(personToken(), caveats({ user_id: "mallory" })), "macaroon_malformed");
});

test("an unknown caveat is malformed, not ignored", () => {
  const t = attenuate(personToken(), caveats({ run_id: "run" }));
  (t.blocks[1]!.caveats as unknown as Record<string, unknown>).max_tokens = 10;
  fails(t, "macaroon_malformed");
});

test("v1 tokens are refused", () => {
  const v1 = Buffer.from(JSON.stringify({ v: 1, org_id: "org_x", user_authorization: {}, invocation: {}, attenuations: [] })).toString("base64url");
  fails(v1, "macaroon_unsupported_version");
});

test("permitted_realms is what every block that sets realms allows", () => {
  const t = attenuate(personToken({ realms: { w1: {}, w2: { max_cost_usd: 3 } } }), caveats({ run_id: "run", realms: { w2: {}, w3: {} } }));
  assert.deepEqual(verify(t, policy, NOW).permitted_realms, ["w2"]);
  assert.equal(verify(personToken(), policy, NOW).permitted_realms, null);
});

test("multisig: below the threshold fails, at it verifies", () => {
  const keys = [generateKey("ecdsa-secp256k1-sha256"), generateKey(), generateKey("ecdsa-secp256k1-sha256")];
  const ms: Policy = { type: "multisig", threshold: 2, keys: keys.map((k) => k.pub) };
  const token = (signers: number[]): Token => ({
    v: 2,
    org_id: "org_x",
    blocks: [signRootMultisig("org_x", caveats({ run_id: "grant" }), person.pub, signers.map((i) => ({ ...keys[i]!, key_index: i })))],
    proof: Buffer.from(person.priv).toString("hex"),
  });
  verify(token([0, 1]), ms, NOW);
  fails(token([2]), "invalid_root_signature", ms);
  fails(token([2, 2]), "invalid_root_signature", ms);
});

test("a multisig signature past block 0 is malformed", () => {
  const t = attenuate(personToken(), caveats({ run_id: "run" }));
  t.blocks[1]!.sig = { alg: "multisig-v1", sigs: [] };
  fails(t, "macaroon_malformed");
});

test("the wire form round-trips", () => {
  const t = attenuate(personToken(), caveats({ run_id: "run", agent: "coder" }));
  assert.deepEqual(decodeToken(encodeToken(t)), t);
  assert.equal(verify(encodeToken(t), policy, NOW).agent_name, "coder");
});
