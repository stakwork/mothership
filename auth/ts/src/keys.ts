/**
 * Keys by algorithm: generate one, derive its public half, sign and
 * verify with it. Every block uses these, whichever `alg` its key has.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { secp256k1 } from "@noble/curves/secp256k1";

import { bytesToHex, hexToBytes } from "./encoding.js";
import {
  ecdsaPublicKey,
  ecdsaSign,
  ecdsaVerify,
  ed25519PublicKey,
  ed25519Sign,
  ed25519Verify,
} from "./sigs.js";
import type { KeyAlg, KeyPair, PubKey } from "./types.js";

export const KEY_ALGS: readonly KeyAlg[] = ["ed25519", "ecdsa-secp256k1-sha256"];

/** Public key length in bytes, by algorithm. */
export const PUBKEY_BYTES: Record<KeyAlg, number> = {
  ed25519: 32,
  "ecdsa-secp256k1-sha256": 33,
};

/** A fresh random key. Ed25519 unless asked otherwise. */
export function generateKey(alg: KeyAlg = "ed25519"): KeyPair {
  const priv =
    alg === "ed25519"
      ? ed25519.utils.randomPrivateKey()
      : secp256k1.utils.randomPrivateKey();
  return keyPair(alg, priv);
}

/** A key pair from a known private key (fixtures, stored keys). */
export function keyPair(alg: KeyAlg, priv: Uint8Array): KeyPair {
  return { alg, priv, pub: { alg, key: bytesToHex(publicKeyBytes(alg, priv)) } };
}

export function publicKeyBytes(alg: KeyAlg, priv: Uint8Array): Uint8Array {
  return alg === "ed25519" ? ed25519PublicKey(priv) : ecdsaPublicKey(priv);
}

/** Sign `msg` with a private key of the given algorithm (64-byte signature). */
export function signWith(alg: KeyAlg, priv: Uint8Array, msg: Uint8Array): Uint8Array {
  return alg === "ed25519" ? ed25519Sign(priv, msg) : ecdsaSign(priv, msg);
}

/** Verify a hex signature against a public key, by the key's algorithm. */
export function verifyWith(pub: PubKey, msg: Uint8Array, sigHex: string): boolean {
  let key: Uint8Array;
  let sig: Uint8Array;
  try {
    key = hexToBytes(pub.key);
    sig = hexToBytes(sigHex);
  } catch {
    return false;
  }
  if (key.length !== PUBKEY_BYTES[pub.alg] || sig.length !== 64) return false;
  return pub.alg === "ed25519" ? ed25519Verify(key, msg, sig) : ecdsaVerify(key, msg, sig);
}
