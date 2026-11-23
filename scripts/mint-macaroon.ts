/**
 * mint-macaroon.ts — mint a fresh v2 token for smoke tests.
 *
 * Companion to scripts/smoke-test-enforcement.sh. Run via:
 *
 *   cd auth/ts && node --import tsx ../../scripts/mint-macaroon.ts \
 *     --org-id org_smoke \
 *     --user-id u_alice \
 *     --agent coder \
 *     --run-id r_smoke_<unix> \
 *     --max-cost-usd 1.00 \
 *     --max-steps 50 \
 *     --ttl-seconds 600 \
 *     [--realms '{"w1":{"max_cost_usd":50}}']
 *
 * Prints the base64url token on stdout (one line, no trailing newline
 * cruft). Errors go to stderr.
 *
 * The token has two blocks (plans/phases/phase-13-signed-block-chain.md):
 * block 0, the org's grant to the person (an hour of life, the agent it
 * allows, and --realms when given), and block 1, the person's run for
 * the agent (--run-id, the caps, --ttl-seconds). The proof is a fresh
 * agent key, as an issuer would hand it to the agent.
 *
 * Why this lives in scripts/ instead of auth/ts/scripts/
 * --------------------------------------------------------------------
 * The mint helper is smoke-test support code, not a piece of the
 * cryptographic package. Keeping it next to the bash scripts that
 * invoke it means the pair moves together when either changes. The
 * auth/ts/scripts/ directory is reserved for fixture regeneration.
 *
 * Keys are NOT a flag
 * -------------------
 * We always sign with the fixture seed keys (`org` and `person` in
 * auth/fixtures/keys.json). Those values are deliberately published
 * test material. The smoke test registers the matching org pubkey
 * against `org_id` via /_plugin/trust before minting, so the gateway's
 * verifier accepts the signature.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { attenuate, bytesToHex, encodeToken, hexToBytes, keyPair, signRoot } from "../auth/ts/src/index.js";
import type { KeyAlg, RealmCap, Token } from "../auth/ts/src/index.js";

// ─── arg parsing ─────────────────────────────────────────────────────

interface Args {
  orgId: string;
  userId: string;
  agent: string;
  runId: string;
  maxCostUsd: number;
  maxSteps: number;
  ttlSeconds: number;
  /** Optional multi-swarm scoping: realm-id → cap, on block 0. */
  realms?: Record<string, RealmCap>;
}

function parseArgs(argv: string[]): Args {
  const required = new Set(["--org-id", "--user-id", "--agent", "--run-id"]);
  const out: Record<string, string> = {};
  for (let i = 0; i < argv.length; i += 2) {
    const flag = argv[i];
    const val = argv[i + 1];
    if (!flag || !flag.startsWith("--") || val === undefined) {
      die(`bad flag/value pair near argv[${i}]: ${flag} ${val}`);
    }
    out[flag] = val;
  }
  for (const r of required) {
    if (!out[r]) die(`missing required flag ${r}`);
  }
  // --realms is optional JSON, parsed up-front so a bad argument fails
  // fast rather than inside the signing path.
  let realms: Record<string, RealmCap> | undefined;
  if (out["--realms"]) {
    try {
      const parsed = JSON.parse(out["--realms"]);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        realms = parsed as Record<string, RealmCap>;
      } else {
        die("--realms must be a JSON object");
      }
    } catch (e) {
      die(`--realms is not valid JSON: ${String(e)}`);
    }
  }
  return {
    orgId: out["--org-id"]!,
    userId: out["--user-id"]!,
    agent: out["--agent"]!,
    runId: out["--run-id"]!,
    // Defaults match a typical smoke run: a sub-dollar cap that's
    // plenty for 20-token calls, 50 steps (we make ≤5), 10 minutes.
    maxCostUsd: out["--max-cost-usd"] ? Number(out["--max-cost-usd"]) : 1.0,
    maxSteps: out["--max-steps"] ? Number(out["--max-steps"]) : 50,
    ttlSeconds: out["--ttl-seconds"] ? Number(out["--ttl-seconds"]) : 600,
    realms,
  };
}

function die(msg: string): never {
  process.stderr.write(`mint-macaroon: ${msg}\n`);
  process.exit(2);
}

// ─── key material ────────────────────────────────────────────────────

interface KeysFile {
  keys: Record<string, { alg: KeyAlg; priv_hex: string; pub_hex: string }>;
}

function fixtureKey(keys: KeysFile, name: string) {
  const k = keys.keys[name];
  if (!k) die(`fixtures/keys.json has no key "${name}"`);
  return keyPair(k.alg, hexToBytes(k.priv_hex));
}

// ─── helpers ─────────────────────────────────────────────────────────

/** 16 random bytes → 32 hex chars. */
function randomNonceHex(): string {
  const buf = new Uint8Array(16);
  globalThis.crypto.getRandomValues(buf);
  return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** RFC 3339 UTC at second precision (matches fixtures). */
function rfc3339(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

// ─── main ────────────────────────────────────────────────────────────

function main() {
  const args = parseArgs(process.argv.slice(2));
  const here = dirname(fileURLToPath(import.meta.url));
  const keys = JSON.parse(readFileSync(join(here, "..", "auth", "fixtures", "keys.json"), "utf8")) as KeysFile;
  const org = fixtureKey(keys, "org");
  const person = fixtureKey(keys, "person");

  const now = new Date();
  const iat = rfc3339(now);

  // Block 0: the org's grant to the person, outliving the run.
  const root = signRoot(
    args.orgId,
    {
      run_id: `ua_${args.runId}`,
      user_id: args.userId,
      agents: [args.agent],
      ...(args.realms ? { realms: args.realms } : {}),
      iat,
      exp: rfc3339(new Date(now.getTime() + 60 * 60 * 1000)),
      nonce: randomNonceHex(),
    },
    person.pub,
    org,
  );
  const personToken: Token = { v: 2, org_id: args.orgId, blocks: [root], proof: bytesToHex(person.priv) };

  // Block 1: the person's run for the agent, signed with the person's
  // key; the proof becomes a fresh agent key.
  const token = attenuate(personToken, {
    run_id: args.runId,
    agent: args.agent,
    ...(args.maxCostUsd > 0 ? { max_cost_usd: args.maxCostUsd } : {}),
    ...(args.maxSteps > 0 ? { max_steps: args.maxSteps } : {}),
    iat,
    exp: rfc3339(new Date(now.getTime() + args.ttlSeconds * 1000)),
    nonce: randomNonceHex(),
  });

  // Single line, no trailing newline — the bash side does
  //   MACAROON=$(node --import tsx mint-macaroon.ts ...)
  // and any extra whitespace would land in the header.
  process.stdout.write(encodeToken(token));
}

main();
