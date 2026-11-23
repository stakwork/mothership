/**
 * `gatekey` — macaroon v2 for cryptographic LLM governance: a chain of
 * signed blocks plus a proof key. Spec:
 * `plans/phases/phase-13-signed-block-chain.md`.
 */

export type {
  KeyAlg,
  SigAlg,
  PubKey,
  SingleSig,
  MultisigV1Sig,
  Sig,
  SinglePolicy,
  MultisigPolicy,
  Policy,
  KeyPair,
  RealmCap,
  Caveats,
  Block,
  Token,
  ChainLayer,
  Claims,
} from "./types.js";

// Encoding + canonicalization (exposed for advanced use + tests).
export {
  bytesToHex,
  hexToBytes,
  bytesToBase64url,
  base64urlToBytes,
  utf8Bytes,
} from "./encoding.js";

export { jcs, signingBytes } from "./jcs.js";

// Curve primitives (the transparency log signs with ECDSA directly).
export {
  ed25519Sign,
  ed25519Verify,
  ed25519PublicKey,
  ecdsaSign,
  ecdsaVerify,
  ecdsaPublicKey,
} from "./sigs.js";

// Keys by algorithm.
export { generateKey, keyPair, publicKeyBytes, signWith, verifyWith } from "./keys.js";

// Building a chain: the org's block 0, then `attenuate` for every hop after.
export {
  signRoot,
  signRootMultisig,
  attenuate,
  blockSigningBytes,
  blockHash,
} from "./sign.js";
export type { Signer } from "./sign.js";

// Verifier.
export { verify, decodeToken, encodeToken, VerifyError, MAX_BLOCKS } from "./verify.js";
export type { VerifyErrorCode } from "./verify.js";

// Transparency log (phase 12): Merkle verifiers + signed tree heads.
export type {
  TlogLeaf,
  SignedTreeHead,
  SignedTreeHeadUnsigned,
  TlogSthResponse,
  HashLike,
} from "./tlog/types.js";

export {
  emptyRoot,
  leafHash,
  nodeHash,
  leafBytes,
  hashLeaf,
  rootFromLeafHashes,
  rootFromLeaves,
  verifyInclusion,
  verifyConsistency,
  hashBytes,
  bytesEqual,
} from "./tlog/merkle.js";

export type { InclusionProofInput, ConsistencyProofInput } from "./tlog/merkle.js";

export { sthSigningBytes, signSth, verifySth } from "./tlog/sth.js";
