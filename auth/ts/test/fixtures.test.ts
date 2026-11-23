/**
 * Cross-language byte-equivalence test (TS side).
 *
 * Rebuilds every `auth/fixtures/NN-*.json` token from its `inputs`,
 * matches every `expected` value byte for byte, and checks every
 * tampered token fails with its code. The Go side runs the same checks
 * against the same files; if both pass, the implementations agree.
 */

import { strict as assert } from "node:assert";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  attenuate,
  blockHash,
  blockSigningBytes,
  bytesToHex,
  encodeToken,
  hexToBytes,
  jcs,
  keyPair,
  signRoot,
  signRootMultisig,
  verify,
  VerifyError,
} from "../src/index.js";
import type { Block, Caveats, Claims, KeyAlg, Policy, Token } from "../src/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(HERE, "..", "..", "fixtures");

interface KeyInput {
  alg: KeyAlg;
  priv_hex: string;
}

interface Fixture {
  description: string;
  inputs: {
    org_id: string;
    policy: Policy;
    org_keys: KeyInput[];
    participating_signers?: number[];
    root: { caveats: Caveats; holder: KeyInput };
    blocks: Array<{ caveats: Caveats; next: KeyInput }>;
    now: string;
  };
  expected: {
    blocks: Array<{ prev_hex: string; signing_bytes_hex: string; block_canonical_json: string }>;
    token_canonical_json: string;
    token_b64url: string;
    claims: Claims;
    tampered: Array<{ case: string; token_b64url: string; code: string }>;
  };
}

const kp = (k: KeyInput) => keyPair(k.alg, hexToBytes(k.priv_hex));

for (const file of readdirSync(FIXTURES_DIR).filter((f) => /^\d{2}-.*\.json$/.test(f)).sort()) {
  const fx: Fixture = JSON.parse(readFileSync(join(FIXTURES_DIR, file), "utf8"));
  const { inputs, expected } = fx;
  const now = new Date(inputs.now);

  test(`fixture ${file}: rebuilds byte for byte and verifies`, () => {
    const holder = kp(inputs.root.holder);
    const root: Block = inputs.participating_signers
      ? signRootMultisig(
          inputs.org_id,
          inputs.root.caveats,
          holder.pub,
          inputs.participating_signers.map((i) => ({ ...kp(inputs.org_keys[i]!), key_index: i })),
        )
      : signRoot(inputs.org_id, inputs.root.caveats, holder.pub, kp(inputs.org_keys[0]!));

    let token: Token = { v: 2, org_id: inputs.org_id, blocks: [root], proof: inputs.root.holder.priv_hex };
    for (const b of inputs.blocks) token = attenuate(token, b.caveats, kp(b.next));

    assert.equal(token.blocks.length, expected.blocks.length);
    token.blocks.forEach((b, i) => {
      const prev = i === 0 ? null : token.blocks[i - 1]!;
      const want = expected.blocks[i]!;
      assert.equal(prev ? blockHash(prev) : "", want.prev_hex, `block ${i} prev_hex`);
      assert.equal(bytesToHex(blockSigningBytes(inputs.org_id, prev, b.caveats, b.next_key)), want.signing_bytes_hex,
        `block ${i} signing_bytes_hex`);
      assert.equal(jcs(b), want.block_canonical_json, `block ${i} block_canonical_json`);
    });
    assert.equal(jcs(token), expected.token_canonical_json, "token_canonical_json");
    assert.equal(encodeToken(token), expected.token_b64url, "token_b64url");

    assert.deepEqual(verify(expected.token_b64url, inputs.policy, now), expected.claims);
  });

  for (const t of expected.tampered) {
    test(`fixture ${file}: ${t.case} → ${t.code}`, () => {
      assert.throws(
        () => verify(t.token_b64url, inputs.policy, now),
        (err: unknown) => err instanceof VerifyError && err.code === t.code,
      );
    });
  }
}
