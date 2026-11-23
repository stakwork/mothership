/**
 * Wire types for the v2 macaroon: a chain of signed blocks plus a
 * proof key. Spec: `plans/phases/phase-13-signed-block-chain.md`.
 *
 * All binary fields (keys, signatures, nonces, the proof) are
 * lowercase hex strings WITHOUT `0x`. All timestamps are RFC 3339 UTC.
 */

// ─── keys and signatures ──────────────────────────────────────────────

/** A single key's algorithm. Any block may use either. */
export type KeyAlg = "ed25519" | "ecdsa-secp256k1-sha256";

export type SigAlg = KeyAlg | "multisig-v1";

/**
 * A public key. `ed25519`: 32 bytes (64 hex). `ecdsa-secp256k1-sha256`:
 * 33-byte compressed point (66 hex).
 */
export interface PubKey {
  alg: KeyAlg;
  key: string;
}

/** One signature by one key: 64 bytes, hex (ECDSA as compact r||s, low-s). */
export interface SingleSig {
  alg: KeyAlg;
  sig: string;
}

/** An m-of-n org signature. Only block 0 can carry one. */
export interface MultisigV1Sig {
  alg: "multisig-v1";
  sigs: Array<{ key_index: number; alg: KeyAlg; sig: string }>;
}

export type Sig = SingleSig | MultisigV1Sig;

/** The org's trust-registry entry: what block 0's `sig` is checked against. */
export interface SinglePolicy {
  type: "single";
  key: PubKey;
}

export interface MultisigPolicy {
  type: "multisig";
  threshold: number;
  keys: PubKey[];
}

export type Policy = SinglePolicy | MultisigPolicy;

/** A key with its private half, as `generateKey` returns it. */
export interface KeyPair {
  alg: KeyAlg;
  /** 32 bytes: the Ed25519 seed or the secp256k1 scalar. */
  priv: Uint8Array;
  pub: PubKey;
}

// ─── the token ────────────────────────────────────────────────────────

/** A per-realm cap. `{}` permits the realm with no cap of its own. */
export interface RealmCap {
  max_cost_usd?: number;
}

/**
 * One shape on every block. Every field applies to the block it is on
 * and to everything under it; the gateway checks every block's limits,
 * so a child never needs to restate (or be compared with) its parent's.
 */
export interface Caveats {
  /** The key this block's spend, steps, meta and kill switch go under. */
  run_id: string;
  /** 128-bit random hex: the revocation handle. */
  nonce: string;
  iat: string;
  exp: string;
  /** The person the org hands the chain to. Block 0 only. */
  user_id?: string;
  /** The agent that holds this block's `next_key`. */
  agent?: string;
  /** When set, the next block's `agent` must be one of these. */
  agents?: string[];
  /** Cap on spend under this block. Absent: no cap (present must be > 0). */
  max_cost_usd?: number;
  /** Cap on calls under this block. Absent: no cap (present must be > 0). */
  max_steps?: number;
  /** When set, the gateway's realm must be a key; its cap applies too. */
  realms?: Record<string, RealmCap>;
}

export interface Block {
  caveats: Caveats;
  /** The key that signs the next block (and whose private half is the proof). */
  next_key: PubKey;
  /** Block 0: the org's policy. Later blocks: the previous block's `next_key`. */
  sig: Sig;
}

export interface Token {
  v: 2;
  org_id: string;
  blocks: Block[];
  /** Hex private key matching the last block's `next_key`. */
  proof: string;
}

// ─── verifier output ──────────────────────────────────────────────────

/** One block's limits, as the gateway enforces them. */
export interface ChainLayer {
  run_id: string;
  /** 0 = no cap. */
  max_cost_usd: number;
  /** 0 = no cap. */
  max_steps: number;
  realms: Record<string, RealmCap> | null;
  exp: string;
}

export interface Claims {
  org_id: string;
  /** Block 0's `user_id`, or "". */
  user_id: string;
  /** The innermost `agent`, or "". */
  agent_name: string;
  /** Every block's `agent`, outermost first (blocks without one skipped). */
  lineage: string[];
  /** The last block's `run_id`. */
  run_id: string;
  /** Block 0's `iat`: the `revoke_user_before` axis. */
  iat: string;
  /** The earliest `exp` in the chain. */
  exp: string;
  /** Every block, outermost first. */
  chain: ChainLayer[];
  /** Every block's nonce, outermost first. */
  nonces: string[];
  /**
   * The realms every block that sets `realms` allows, sorted; null when
   * no block sets `realms`. For logs: the gateway checks each block.
   */
  permitted_realms: string[] | null;
}
