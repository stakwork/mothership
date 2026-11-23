/**
 * Pure verifier, the TS mirror of `auth/go/verify.go`: a token (wire
 * form or parsed), the org's policy and a clock in; `Claims` out, or a
 * `VerifyError` with a machine-readable `code`. No I/O, no revocation
 * list: the gateway adds those.
 *
 * One loop: check each block's signature with the key the block before
 * it named (the org's policy for block 0), then check the proof is the
 * private half of the last key. Every block's limits apply; nothing is
 * compared between blocks except `agents` → `agent`.
 */

import { base64urlToBytes, bytesToHex, hexToBytes, utf8Bytes } from "./encoding.js";
import { jcs } from "./jcs.js";
import { KEY_ALGS, PUBKEY_BYTES, publicKeyBytes, verifyWith } from "./keys.js";
import { blockSigningBytes } from "./sign.js";
import type { Block, Caveats, ChainLayer, Claims, KeyAlg, Policy, PubKey, RealmCap, Sig, Token } from "./types.js";

export type VerifyErrorCode =
  | "macaroon_malformed"
  | "macaroon_unsupported_version"
  | "invalid_root_signature"
  | "invalid_block_signature"
  | "invalid_proof"
  | "macaroon_expired"
  | "agent_not_permitted";

/**
 * The longest chain a verifier accepts: block 0 plus 15 hops. Each block
 * costs a signature check and, at the gateway, its own Redis keys, so an
 * unbounded chain lets one request create thousands.
 */
export const MAX_BLOCKS = 16;

export class VerifyError extends Error {
  readonly code: VerifyErrorCode;
  constructor(code: VerifyErrorCode, message?: string) {
    super(message ?? code);
    this.code = code;
    this.name = "VerifyError";
  }
}

/**
 * Verify a token end to end.
 *
 * @param token  the base64url wire form or a parsed token
 * @param policy the org's key or multisig policy (from the trust registry)
 * @param now    the verifier's clock
 */
export function verify(token: string | Token, policy: Policy, now: Date): Claims {
  const t = typeof token === "string" ? decodeToken(token) : token;
  validateToken(t);

  let key: PubKey | null = null; // null = block 0, checked against the policy
  let prev: Block | null = null;
  for (const [i, block] of t.blocks.entries()) {
    const msg = blockSigningBytes(t.org_id, prev, block.caveats, block.next_key);
    if (key === null) {
      if (!verifyRoot(policy, msg, block.sig)) {
        throw new VerifyError("invalid_root_signature", "block 0's signature does not match the org's policy");
      }
    } else if (block.sig.alg !== key.alg || !("sig" in block.sig) || !verifyWith(key, msg, block.sig.sig)) {
      throw new VerifyError("invalid_block_signature", `block ${i}'s signature does not match block ${i - 1}'s next_key`);
    }
    if (date(block.caveats.exp) < now) {
      throw new VerifyError("macaroon_expired", `block ${i} expired at ${block.caveats.exp}`);
    }
    const allowed = prev?.caveats.agents;
    if (allowed && !(block.caveats.agent !== undefined && allowed.includes(block.caveats.agent))) {
      throw new VerifyError("agent_not_permitted",
        `block ${i}'s agent ${JSON.stringify(block.caveats.agent ?? null)} is not in block ${i - 1}'s agents`);
    }
    key = block.next_key;
    prev = block;
  }

  // The proof: only the holder of the last key's private half can show it.
  // A token with its last block dropped would need the private half of the
  // block before, which no holder downstream of it ever had.
  if (!key || !proofMatches(key, t.proof)) {
    throw new VerifyError("invalid_proof", "proof is not the private key of the last block's next_key");
  }

  return claimsOf(t);
}

// ─── signatures ───────────────────────────────────────────────────────

function verifyRoot(policy: Policy, msg: Uint8Array, sig: Sig): boolean {
  if (policy.type === "single") {
    return sig.alg === policy.key.alg && "sig" in sig && verifyWith(policy.key, msg, sig.sig);
  }
  if (sig.alg !== "multisig-v1") return false;
  const seen = new Set<number>();
  let valid = 0;
  for (const entry of sig.sigs) {
    if (seen.has(entry.key_index)) continue;
    seen.add(entry.key_index);
    const pk = policy.keys[entry.key_index];
    if (pk && entry.alg === pk.alg && verifyWith(pk, msg, entry.sig)) valid++;
  }
  return valid >= policy.threshold && policy.threshold > 0;
}

function proofMatches(key: PubKey, proofHex: string): boolean {
  try {
    const priv = hexToBytes(proofHex);
    if (priv.length !== 32) return false;
    return bytesToHex(publicKeyBytes(key.alg, priv)) === key.key.toLowerCase();
  } catch {
    return false;
  }
}

// ─── claims ───────────────────────────────────────────────────────────

function claimsOf(t: Token): Claims {
  const first = t.blocks[0]!.caveats;
  const last = t.blocks[t.blocks.length - 1]!.caveats;
  let agentName = "";
  const lineage: string[] = [];
  let exp = first.exp;
  let realms: Set<string> | null = null;
  const chain: ChainLayer[] = [];
  for (const { caveats: c } of t.blocks) {
    if (c.agent !== undefined) {
      agentName = c.agent;
      lineage.push(c.agent);
    }
    if (date(c.exp) < date(exp)) exp = c.exp;
    if (c.realms) {
      const keys = Object.keys(c.realms);
      realms = realms ? new Set(keys.filter((r) => realms!.has(r))) : new Set(keys);
    }
    chain.push({
      run_id: c.run_id,
      max_cost_usd: c.max_cost_usd ?? 0,
      max_steps: c.max_steps ?? 0,
      realms: c.realms ?? null,
      exp: c.exp,
    });
  }
  return {
    org_id: t.org_id,
    user_id: first.user_id ?? "",
    agent_name: agentName,
    lineage,
    run_id: last.run_id,
    iat: first.iat,
    exp,
    chain,
    nonces: t.blocks.map((b) => b.caveats.nonce),
    permitted_realms: realms ? [...realms].sort() : null,
  };
}

// ─── wire form ────────────────────────────────────────────────────────

export function decodeToken(b64url: string): Token {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(base64urlToBytes(b64url)));
  } catch {
    throw new VerifyError("macaroon_malformed", "base64url or JSON decode failed");
  }
  return parsed as Token;
}

/** `base64url(JCS(token))`, the form a token travels in. */
export function encodeToken(t: Token): string {
  return Buffer.from(utf8Bytes(jcs(t))).toString("base64url");
}

// ─── structure ────────────────────────────────────────────────────────
//
// Strict, and the same rules as the Go verifier: an unknown field or a
// null anywhere is malformed (a caveat this verifier does not know could
// be a limit it would silently skip), and an optional field that is
// present must be non-zero.

const CAVEAT_FIELDS: Record<keyof Caveats, true> = {
  run_id: true, nonce: true, iat: true, exp: true, user_id: true,
  agent: true, agents: true, max_cost_usd: true, max_steps: true, realms: true,
};

function validateToken(t: unknown): asserts t is Token {
  const o = object(t, "token");
  if (o.v !== 2) throw new VerifyError("macaroon_unsupported_version", `v=${String(o.v)}`);
  only(o, ["v", "org_id", "blocks", "proof"], "token");
  nonEmptyString(o.org_id, "org_id");
  hex(o.proof, "proof");
  if (!Array.isArray(o.blocks) || o.blocks.length === 0) malformed("blocks must be a non-empty array");
  if (o.blocks.length > MAX_BLOCKS) malformed(`too many blocks: ${o.blocks.length} (at most ${MAX_BLOCKS})`);
  o.blocks.forEach((b, i) => validateBlock(b, i));
}

function validateBlock(b: unknown, i: number): void {
  const o = object(b, `block ${i}`);
  only(o, ["caveats", "next_key", "sig"], `block ${i}`);
  validateCaveats(o.caveats, i);
  validatePubKey(o.next_key, `block ${i}.next_key`);
  validateSig(o.sig, i);
}

function validateCaveats(c: unknown, i: number): void {
  const where = `block ${i}.caveats`;
  const o = object(c, where);
  for (const k of Object.keys(o)) {
    if (!(k in CAVEAT_FIELDS)) malformed(`${where}: unknown field ${k}`);
  }
  for (const k of ["run_id", "nonce", "iat", "exp"] as const) nonEmptyString(o[k], `${where}.${k}`);
  date(o.iat as string);
  date(o.exp as string);
  if (o.user_id !== undefined) {
    if (i > 0) malformed(`${where}: user_id is only allowed on block 0`);
    nonEmptyString(o.user_id, `${where}.user_id`);
  }
  if (o.agent !== undefined) nonEmptyString(o.agent, `${where}.agent`);
  if (o.agents !== undefined) {
    if (!Array.isArray(o.agents) || o.agents.length === 0) malformed(`${where}.agents must be a non-empty array of names`);
    o.agents.forEach((a, j) => nonEmptyString(a, `${where}.agents[${j}]`));
  }
  if (o.max_cost_usd !== undefined) amount(o.max_cost_usd, `${where}.max_cost_usd`);
  if (o.max_steps !== undefined) {
    amount(o.max_steps, `${where}.max_steps`);
    if (!Number.isInteger(o.max_steps)) malformed(`${where}.max_steps must be a whole number`);
  }
  if (o.realms !== undefined) {
    const realms = object(o.realms, `${where}.realms`);
    if (Object.keys(realms).length === 0) malformed(`${where}.realms must name at least one realm`);
    for (const [r, cap] of Object.entries(realms)) {
      const rc = object(cap, `${where}.realms.${r}`) as RealmCap & Record<string, unknown>;
      only(rc, ["max_cost_usd"], `${where}.realms.${r}`);
      if (rc.max_cost_usd !== undefined) amount(rc.max_cost_usd, `${where}.realms.${r}.max_cost_usd`);
    }
  }
}

function validatePubKey(k: unknown, where: string): void {
  const o = object(k, where);
  only(o, ["alg", "key"], where);
  const alg = keyAlg(o.alg, `${where}.alg`);
  hex(o.key, `${where}.key`);
  if ((o.key as string).length !== PUBKEY_BYTES[alg] * 2) malformed(`${where}.key has the wrong length for ${alg}`);
}

function validateSig(s: unknown, i: number): void {
  const where = `block ${i}.sig`;
  const o = object(s, where);
  if (o.alg === "multisig-v1") {
    if (i > 0) malformed(`${where}: only block 0 can carry a multisig signature`);
    only(o, ["alg", "sigs"], where);
    if (!Array.isArray(o.sigs)) malformed(`${where}.sigs must be an array`);
    o.sigs.forEach((e, j) => {
      const so = object(e, `${where}.sigs[${j}]`);
      only(so, ["key_index", "alg", "sig"], `${where}.sigs[${j}]`);
      if (!Number.isInteger(so.key_index) || (so.key_index as number) < 0) malformed(`${where}.sigs[${j}].key_index`);
      keyAlg(so.alg, `${where}.sigs[${j}].alg`);
      hex(so.sig, `${where}.sigs[${j}].sig`);
    });
    return;
  }
  only(o, ["alg", "sig"], where);
  keyAlg(o.alg, `${where}.alg`);
  hex(o.sig, `${where}.sig`);
}

function object(v: unknown, where: string): Record<string, unknown> {
  if (v === null || typeof v !== "object" || Array.isArray(v)) malformed(`${where} must be an object`);
  return v as Record<string, unknown>;
}

function only(o: Record<string, unknown>, fields: string[], where: string): void {
  for (const k of Object.keys(o)) if (!fields.includes(k)) malformed(`${where}: unknown field ${k}`);
}

function nonEmptyString(v: unknown, where: string): void {
  if (typeof v !== "string" || v === "") malformed(`${where} must be a non-empty string`);
}

function hex(v: unknown, where: string): void {
  if (typeof v !== "string" || v.length === 0 || v.length % 2 !== 0 || !/^[0-9a-f]+$/.test(v)) {
    malformed(`${where} must be lowercase hex`);
  }
}

// An optional number that is present must be > 0: leave it out for "no
// cap". With that rule a valid token's JSON is exactly what the Go
// structs marshal to, so both verifiers rebuild the same signed bytes.
function amount(v: unknown, where: string): void {
  if (typeof v !== "number" || !Number.isFinite(v) || v <= 0) malformed(`${where} must be a number > 0 (omit it for no cap)`);
}

function keyAlg(v: unknown, where: string): KeyAlg {
  if (!KEY_ALGS.includes(v as KeyAlg)) malformed(`${where}: unsupported alg ${String(v)}`);
  return v as KeyAlg;
}

// RFC 3339, as Go's time.RFC3339 reads it: the two verifiers must agree.
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

function date(iso: string): Date {
  const d = new Date(iso);
  if (!RFC3339.test(iso) || Number.isNaN(d.getTime())) malformed(`invalid timestamp: ${iso}`);
  return d;
}

function malformed(detail: string): never {
  throw new VerifyError("macaroon_malformed", detail);
}
