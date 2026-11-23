// Package macaroon signs and verifies the v2 macaroon defined in
// plans/phases/phase-13-signed-block-chain.md: a chain of blocks, each
// signed by the key the block before it named (the org's policy for
// block 0), plus a proof key, the private half of the last key, that
// makes the chain impossible to shorten.
//
// Pure means: no I/O, no Bifrost types, no ambient state.
//
//   - Verify (verify.go) takes the token (base64url), the org's policy
//     and the current time, and returns verified Claims or a
//     *VerifyError with a machine-readable Code.
//   - SignRoot / SignRootMultisig, Attenuate and EncodeToken (sign.go)
//     build a token: the org signs block 0 for a person's key, and
//     every later hop is one Attenuate.
//
// Adapters (internal/auth/) wrap the verifier with header extraction,
// trust-registry lookup, Redis-backed revocation and caps, and
// bifrost.Error shaping.
//
// Byte-equivalence with the TypeScript sibling (auth/ts/, npm
// `gatekey`) is enforced by auth/fixtures/: both sides rebuild every
// fixture, match every intermediate value, and check every tampered
// token fails with the same code.
package macaroon
