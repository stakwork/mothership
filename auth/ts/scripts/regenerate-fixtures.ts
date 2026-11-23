/**
 * Regenerate `auth/fixtures/NN-*.json` and `keys.json` from fixed seed
 * keys. Run with:
 *
 *     npm run regenerate-fixtures
 *
 * The fixtures are the cross-language contract: the Go and TS tests
 * rebuild every token from `inputs`, match every `expected` value byte
 * for byte, and check every tampered token fails with its code. If a
 * spec change shifts the bytes, regenerate and commit the fixtures with
 * the change.
 *
 * Deterministic: Ed25519 signing is deterministic (RFC 8032) and ECDSA
 * uses RFC 6979 nonces, so anyone running this gets the same files.
 */

import { readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
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
import type { Block, Caveats, Claims, KeyAlg, KeyPair, Policy, Token } from "../src/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(HERE, "..", "..", "fixtures");

// ─── fixed seed keys (published: never use them for anything real) ────

const SEEDS = {
  org: "0000000000000000000000000000000000000000000000000000000000000001",
  org2: "0000000000000000000000000000000000000000000000000000000000000002",
  org3: "0000000000000000000000000000000000000000000000000000000000000003",
  orgEd25519: "3333333333333333333333333333333333333333333333333333333333333333",
  person: "1111111111111111111111111111111111111111111111111111111111111111",
  personSecp256k1: "000000000000000000000000000000000000000000000000000000000000000a",
  agent1: "2121212121212121212121212121212121212121212121212121212121212121",
  agent2: "2222222222222222222222222222222222222222222222222222222222222222",
  agent3: "2323232323232323232323232323232323232323232323232323232323232323",
  intruder: "9999999999999999999999999999999999999999999999999999999999999999",
} as const;

type SeedName = keyof typeof SEEDS;

const ALGS: Record<SeedName, KeyAlg> = {
  org: "ecdsa-secp256k1-sha256",
  org2: "ecdsa-secp256k1-sha256",
  org3: "ecdsa-secp256k1-sha256",
  orgEd25519: "ed25519",
  person: "ed25519",
  personSecp256k1: "ecdsa-secp256k1-sha256",
  agent1: "ed25519",
  agent2: "ed25519",
  agent3: "ed25519",
  intruder: "ed25519",
};

const key = (name: SeedName): KeyPair => keyPair(ALGS[name], hexToBytes(SEEDS[name]));
const keyInput = (name: SeedName) => ({ alg: ALGS[name], priv_hex: SEEDS[name] });

// ─── fixed times (verified at NOW: after every iat, before every exp) ─

const NOW = "2026-05-14T10:00:01Z";

function rootCaveats(over: Partial<Caveats> = {}): Caveats {
  return {
    run_id: "ua_01h8alicegrant000000000000",
    user_id: "u_alice",
    agents: ["coder", "repair-agent"],
    iat: "2026-05-14T09:00:00Z",
    exp: "2026-06-14T09:00:00Z",
    nonce: "9f4e1c8b2a3d4e5f6a7b8c9d0e1f2a3b",
    ...over,
  };
}

function agentCaveats(over: Partial<Caveats> = {}): Caveats {
  return {
    run_id: "r_01h8alpharootinvocation00",
    agent: "coder",
    max_cost_usd: 5,
    max_steps: 100,
    iat: "2026-05-14T10:00:00Z",
    exp: "2026-05-14T10:10:00Z",
    nonce: "7c2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c",
    ...over,
  };
}

const CHILD: Caveats = {
  run_id: "r_01h8alphachildlevel1run00",
  agent: "web-search",
  max_cost_usd: 2,
  max_steps: 40,
  iat: "2026-05-14T10:00:00Z",
  exp: "2026-05-14T10:02:00Z",
  nonce: "1e8d2c3b4a5f6e7d8c9b0a1f2e3d4c5b",
};

const GRANDCHILD: Caveats = {
  run_id: "r_01h8alphagrandchild2run00",
  agent: "browser",
  max_cost_usd: 0.5,
  max_steps: 10,
  iat: "2026-05-14T10:00:00Z",
  exp: "2026-05-14T10:01:30Z",
  nonce: "2f9e3d4c5b6a7f8e9d0c1b2a3f4e5d6c",
};

// ─── one fixture ──────────────────────────────────────────────────────

interface OrgSpec {
  /** Single key, or multisig: which policy keys exist and which sign. */
  keys: SeedName[];
  threshold?: number;
  signers?: number[];
}

interface FixtureSpec {
  file: string;
  description: string;
  org: OrgSpec;
  root: Caveats;
  holder: SeedName;
  /** Later blocks: each one's caveats and the key it names. */
  blocks: Array<{ caveats: Caveats; next: SeedName }>;
}

function policyOf(org: OrgSpec): Policy {
  if (org.keys.length === 1) return { type: "single", key: key(org.keys[0]!).pub };
  return { type: "multisig", threshold: org.threshold!, keys: org.keys.map((k) => key(k).pub) };
}

function rootBlock(orgId: string, org: OrgSpec, caveats: Caveats, holder: SeedName): Block {
  if (org.keys.length === 1) {
    const k = key(org.keys[0]!);
    return signRoot(orgId, caveats, key(holder).pub, k);
  }
  return signRootMultisig(
    orgId,
    caveats,
    key(holder).pub,
    org.signers!.map((i) => ({ ...key(org.keys[i]!), key_index: i })),
  );
}

function build(spec: FixtureSpec) {
  const orgId = "org_acme";
  const policy = policyOf(spec.org);
  let token: Token = {
    v: 2,
    org_id: orgId,
    blocks: [rootBlock(orgId, spec.org, spec.root, spec.holder)],
    proof: SEEDS[spec.holder],
  };
  for (const b of spec.blocks) token = attenuate(token, b.caveats, key(b.next));

  const now = new Date(NOW);
  const claims: Claims = verify(token, policy, now);

  const blocks = token.blocks.map((b, i) => {
    const prev = i === 0 ? null : token.blocks[i - 1]!;
    return {
      prev_hex: prev ? blockHash(prev) : "",
      signing_bytes_hex: bytesToHex(blockSigningBytes(orgId, prev, b.caveats, b.next_key)),
      block_canonical_json: jcs(b),
    };
  });

  return {
    description: spec.description,
    inputs: {
      org_id: orgId,
      policy,
      org_keys: spec.org.keys.map(keyInput),
      ...(spec.org.signers ? { participating_signers: spec.org.signers } : {}),
      root: { caveats: spec.root, holder: keyInput(spec.holder) },
      blocks: spec.blocks.map((b) => ({ caveats: b.caveats, next: keyInput(b.next) })),
      now: NOW,
    },
    expected: {
      blocks,
      token_canonical_json: jcs(token),
      token_b64url: encodeToken(token),
      claims,
      tampered: tamperedTokens(spec, token, policy),
    },
  };
}

/**
 * Tokens that must NOT verify, each with the code it fails with. The
 * point of v2: a holder cannot shorten its chain, reuse a block under a
 * different root, or edit a signed block.
 */
function tamperedTokens(spec: FixtureSpec, token: Token, policy: Policy) {
  const out: Array<{ case: string; token_b64url: string; code: string }> = [];
  const add = (name: string, t: Token) => out.push({ case: name, token_b64url: encodeToken(t), code: codeOf(t, policy) });

  // Every truncation, keeping the proof the holder has.
  for (let keep = token.blocks.length - 1; keep >= 1; keep--) {
    add(`drop the last ${token.blocks.length - keep} block(s)`, { ...token, blocks: token.blocks.slice(0, keep) });
  }
  // A proof that is some other key.
  add("proof from another key", { ...token, proof: SEEDS.intruder });
  // Block 0 edited after signing.
  add("block 0's caveats edited", {
    ...token,
    blocks: [{ ...token.blocks[0]!, caveats: { ...token.blocks[0]!.caveats, exp: "2099-01-01T00:00:00Z" } }, ...token.blocks.slice(1)],
  });
  if (token.blocks.length > 1) {
    // A later block edited after signing.
    const last = token.blocks.length - 1;
    add(`block ${last}'s caveats edited`, {
      ...token,
      blocks: token.blocks.map((b, i) => (i === last ? { ...b, caveats: { ...b.caveats, max_cost_usd: 1000 } } : b)),
    });
    // Block 1 moved under another block 0 the org signed for the same holder.
    const otherRoot = rootBlock(token.org_id, spec.org, { ...spec.root, nonce: "00000000000000000000000000000000" }, spec.holder);
    add("block 1 moved under another block 0", { ...token, blocks: [otherRoot, ...token.blocks.slice(1)] });
  }
  // A properly signed next block naming an agent block 0 does not allow.
  if (spec.root.agents && token.blocks.length === 1) {
    add("next block names an agent outside agents", attenuate(token, agentCaveats({ agent: "intruder" }), key("intruder")));
  }
  return out;
}

function codeOf(t: Token, policy: Policy): string {
  try {
    verify(t, policy, new Date(NOW));
  } catch (err) {
    if (err instanceof VerifyError) return err.code;
    throw err;
  }
  throw new Error("a tampered token verified");
}

// ─── the fixtures ─────────────────────────────────────────────────────

const SINGLE: OrgSpec = { keys: ["org"] };

const SPECS: FixtureSpec[] = [
  {
    file: "01-person.json",
    description: "block 0 only: the org hands the chain to a person's key; the proof is the person's private key",
    org: SINGLE,
    root: rootCaveats(),
    holder: "person",
    blocks: [],
  },
  {
    file: "02-person-to-agent.json",
    description: "the person hands an agent (coder) a run with a $5 / 100-step cap: a standing delegation",
    org: SINGLE,
    root: rootCaveats(),
    holder: "person",
    blocks: [{ caveats: agentCaveats(), next: "agent1" }],
  },
  {
    file: "03-one-sub-agent.json",
    description: "the agent spawns a sub-agent (web-search) with a $2 / 40-step cap and an earlier exp",
    org: SINGLE,
    root: rootCaveats(),
    holder: "person",
    blocks: [
      { caveats: agentCaveats(), next: "agent1" },
      { caveats: CHILD, next: "agent2" },
    ],
  },
  {
    file: "04-two-sub-agents.json",
    description: "two sub-agent levels: coder → web-search → browser ($0.50 / 10 steps)",
    org: SINGLE,
    root: rootCaveats(),
    holder: "person",
    blocks: [
      { caveats: agentCaveats(), next: "agent1" },
      { caveats: CHILD, next: "agent2" },
      { caveats: GRANDCHILD, next: "agent3" },
    ],
  },
  {
    file: "05-multisig-2of3.json",
    description: "a 2-of-3 multisig org signs block 0 (signers 0 and 2); the person hands an agent a run",
    org: { keys: ["org", "org2", "org3"], threshold: 2, signers: [0, 2] },
    root: rootCaveats({ run_id: "ua_01h8multisiggrant000000000", nonce: "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a" }),
    holder: "person",
    blocks: [{ caveats: agentCaveats({ run_id: "r_01h8multisigrun00000000000", nonce: "6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b" }), next: "agent1" }],
  },
  {
    file: "06-caps-on-root.json",
    description: "block 0 caps everything under the person's grant at $1000 (v1's max_total_usd); the agent's run at $5",
    org: SINGLE,
    root: rootCaveats({ run_id: "ua_01h8budgetgrant00000000000", max_cost_usd: 1000, nonce: "ab1234567890abcdef1234567890abcd" }),
    holder: "person",
    blocks: [{ caveats: agentCaveats({ run_id: "r_01h8budgetenveloperun0000", nonce: "cd1234567890abcdef1234567890abcd" }), next: "agent1" }],
  },
  {
    file: "07-multi-realm.json",
    description: "block 0 permits realms w1 ($50) and w2 ($30); the agent's run narrows to w1 at $10",
    org: SINGLE,
    root: rootCaveats({
      run_id: "ua_01h8multirealmgrant0000000",
      realms: { w1: { max_cost_usd: 50 }, w2: { max_cost_usd: 30 } },
      nonce: "e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1",
    }),
    holder: "person",
    blocks: [{
      caveats: agentCaveats({ run_id: "r_01h8multirealmrun000000000", realms: { w1: { max_cost_usd: 10 } }, nonce: "e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2" }),
      next: "agent1",
    }],
  },
  {
    file: "08-cross-realm-sub-agent.json",
    description: "the agent may spend on w1 and w2; it spawns a sub-agent for w2 only, at $1",
    org: SINGLE,
    root: rootCaveats({ run_id: "ua_01h8crossrealmgrant0000000", realms: { w1: {}, w2: {} }, nonce: "f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1" }),
    holder: "person",
    blocks: [
      { caveats: agentCaveats({ run_id: "r_01h8crossrealmrun000000000", nonce: "f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2" }), next: "agent1" },
      {
        caveats: { ...CHILD, run_id: "r_01h8crossrealmchild0000000", realms: { w2: { max_cost_usd: 1 } }, nonce: "f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3" },
        next: "agent2",
      },
    ],
  },
  {
    file: "09-mixed-algs.json",
    description: "an Ed25519 org key and a secp256k1 person key: block 1 is signed with ECDSA, the agent's key is Ed25519",
    org: { keys: ["orgEd25519"] },
    root: rootCaveats({ run_id: "ua_01h8mixedalgsgrant00000000", nonce: "a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9" }),
    holder: "personSecp256k1",
    blocks: [{ caveats: agentCaveats({ run_id: "r_01h8mixedalgsrun0000000000", nonce: "b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9" }), next: "agent1" }],
  },
];

// ─── write ────────────────────────────────────────────────────────────

for (const f of readdirSync(FIXTURES_DIR)) {
  if (/^\d{2}-.*\.json$/.test(f)) rmSync(join(FIXTURES_DIR, f));
}
for (const spec of SPECS) {
  writeFileSync(join(FIXTURES_DIR, spec.file), JSON.stringify(build(spec), null, 2) + "\n");
  console.log(`wrote ${spec.file}`);
}
writeFileSync(
  join(FIXTURES_DIR, "keys.json"),
  JSON.stringify(
    {
      description:
        "Fixed seed keys used by every fixture. Reproducible: anyone running scripts/regenerate-fixtures.ts gets the same values. NOT secret: published in the repo.",
      keys: Object.fromEntries(
        (Object.keys(SEEDS) as SeedName[]).map((n) => [n, { alg: ALGS[n], priv_hex: SEEDS[n], pub_hex: key(n).pub.key }]),
      ),
    },
    null,
    2,
  ) + "\n",
);
console.log("wrote keys.json");
