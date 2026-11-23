/**
 * Building a chain. Block 0 is signed by the org; every later block by
 * the key the block before it named. `attenuate` is the one operation
 * an agent needs: it signs a block with the token's proof key, names a
 * fresh key, and hands that key's private half on as the new proof.
 */

import { sha256 } from "@noble/hashes/sha2";

import { bytesToHex, hexToBytes, utf8Bytes } from "./encoding.js";
import { jcs } from "./jcs.js";
import { generateKey, signWith } from "./keys.js";
import type { Block, Caveats, KeyAlg, KeyPair, MultisigV1Sig, PubKey, Token } from "./types.js";

/**
 * The bytes a block's signature covers:
 * `utf8(JCS({ org_id, prev, caveats, next_key }))`, where `prev` is ""
 * for block 0 and `blockHash` of the block before otherwise.
 */
export function blockSigningBytes(
  orgId: string,
  prev: Block | null,
  caveats: Caveats,
  nextKey: PubKey,
): Uint8Array {
  return utf8Bytes(jcs({ org_id: orgId, prev: prev ? blockHash(prev) : "", caveats, next_key: nextKey }));
}

/** `hex(sha256(utf8(JCS(block))))`: the whole block, signature included. */
export function blockHash(block: Block): string {
  return bytesToHex(sha256(utf8Bytes(jcs(block))));
}

/** One private key and its algorithm: what signs a block. */
export interface Signer {
  alg: KeyAlg;
  priv: Uint8Array;
}

/**
 * Block 0 under a single-key org: hands the chain to `holder`, usually a
 * person's key. The holder's private half becomes the token's proof.
 */
export function signRoot(orgId: string, caveats: Caveats, holder: PubKey, org: Signer): Block {
  const msg = blockSigningBytes(orgId, null, caveats, holder);
  return { caveats, next_key: holder, sig: { alg: org.alg, sig: bytesToHex(signWith(org.alg, org.priv, msg)) } };
}

/**
 * Block 0 under an m-of-n org. `signers` name their index in the
 * policy's `keys`; the threshold is checked when the token is verified.
 */
export function signRootMultisig(
  orgId: string,
  caveats: Caveats,
  holder: PubKey,
  signers: Array<Signer & { key_index: number }>,
): Block {
  const msg = blockSigningBytes(orgId, null, caveats, holder);
  const sigs = [...signers]
    .sort((a, b) => a.key_index - b.key_index)
    .map((s) => ({ key_index: s.key_index, alg: s.alg, sig: bytesToHex(signWith(s.alg, s.priv, msg)) }));
  const sig: MultisigV1Sig = { alg: "multisig-v1", sigs };
  return { caveats, next_key: holder, sig };
}

/**
 * Append one block. Signs it with `token.proof` (the key the last block
 * named), names `next` (a fresh Ed25519 key when omitted), and returns a
 * new token whose proof is `next`'s private key. The input token is not
 * changed, and nothing in the result lets its holder get it back.
 */
export function attenuate(token: Token, caveats: Caveats, next: KeyPair = generateKey()): Token {
  const last = token.blocks[token.blocks.length - 1];
  if (!last) throw new Error("attenuate: the token has no blocks");
  const msg = blockSigningBytes(token.org_id, last, caveats, next.pub);
  const sig = { alg: last.next_key.alg, sig: bytesToHex(signWith(last.next_key.alg, hexToBytes(token.proof), msg)) };
  return {
    v: 2,
    org_id: token.org_id,
    blocks: [...token.blocks, { caveats, next_key: next.pub, sig }],
    proof: bytesToHex(next.priv),
  };
}
