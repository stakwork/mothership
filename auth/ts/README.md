# gatekey

Macaroon signer, attenuator and verifier for cryptographic LLM
governance. An organization grants a person, the person grants an
agent, an agent grants a sub-agent — every LLM call carries the chain
of authority, and anyone with the org's public key can verify it
offline.

```
gatekey (v2: a signed block chain)
  block 0   signed by the org     → hands the chain to a person's key
  block 1   signed by the person  → hands a run to an agent's key
  block n   signed by block n-1's key → hands a narrower run to a sub-agent
  proof     the private key of the last block's key
```

Every hop is the same block type. The proof makes the chain
impossible to shorten: a holder can add a block, never remove one.
The wire format and signing input are pinned to a language-neutral
spec with fixtures, so a TS signer and a Go verifier (or any other
implementation) agree byte for byte.

## Install

```sh
npm install gatekey
```

Requires Node >= 20. Version 1.0.0 is the v2 token; 0.x is the v1
three-layer format and is not compatible.

## Quick start

### Mint a delegation

The custodial case: the issuer holds the org key and the person's key,
and produces a token an agent can use.

```ts
import { attenuate, bytesToHex, encodeToken, signRoot, type Token } from "gatekey";

const now = new Date();
const later = (s: number) => new Date(now.getTime() + s * 1000).toISOString();

// Block 0: the org grants a person. `user_id` only goes here.
const root = signRoot(
  "org_acme",
  {
    run_id: "grant_alice_01",
    user_id: "alice",
    agents: ["browser-agent", "pr-monitor"], // who alice may hand a run to
    max_cost_usd: 1000,                      // everything under this grant
    iat: now.toISOString(),
    exp: later(7 * 24 * 3600),
    nonce: randomNonceHex(),
  },
  alicePub,          // { alg: "ed25519", key: "<hex>" }
  orgKey,            // { alg: "ecdsa-secp256k1-sha256", priv: Uint8Array }
);
const alicesToken: Token = { v: 2, org_id: "org_acme", blocks: [root], proof: bytesToHex(alicePriv) };

// Block 1: alice hands one run to an agent. A fresh agent key is made
// for it, and its private half becomes the new proof.
const agentToken = attenuate(alicesToken, {
  run_id: "run_abc",
  agent: "browser-agent",
  max_cost_usd: 10,
  max_steps: 200,
  iat: now.toISOString(),
  exp: later(3600),
  nonce: randomNonceHex(),
});

const header = encodeToken(agentToken); // → `x-macaroon: <header>`
```

Alice's private key never leaves the issuer: the agent gets only its
own.

### Attenuate before spawning a sub-agent

The agent narrows the scope before handing control to a child. No
network call: one signature with the key it holds.

```ts
import { attenuate } from "gatekey";

const childToken = attenuate(agentToken, {
  run_id: "run_child_xyz",
  agent: "browser-agent.search",
  max_cost_usd: 2,
  max_steps: 50,
  iat: new Date().toISOString(),
  exp: new Date(Date.now() + 600 * 1000).toISOString(),
  nonce: randomNonceHex(),
});
// Hand `childToken` to the child. It cannot get `agentToken` back.
```

### Verify

```ts
import { verify, VerifyError } from "gatekey";

try {
  const claims = verify(header, policy, new Date());
  // claims.user_id, claims.agent_name, claims.run_id, claims.chain, ...
} catch (e) {
  if (e instanceof VerifyError) {
    // e.code: macaroon_malformed, macaroon_unsupported_version,
    // invalid_root_signature, invalid_block_signature, invalid_proof,
    // macaroon_expired, agent_not_permitted.
  }
  throw e;
}
```

The verifier is pure: no I/O, no clock except the one you hand it, no
revocation list. Wrap it with whatever transport and freshness checks
your environment needs.

## Concepts

- **Block** — `{ caveats, next_key, sig }`. `sig` is by the key the
  block before named (the org's policy for block 0) over
  `JCS({ org_id, prev, caveats, next_key })`, where `prev` is the hash
  of the whole block before. `next_key` signs the next block.
- **Caveats** — one shape on every block: `run_id`, `nonce`, `iat`,
  `exp` (required), and `user_id` (block 0 only), `agent`, `agents`,
  `max_cost_usd`, `max_steps`, `realms` (optional). An optional field
  that is present must be non-zero: leave it out for "no cap".
- **No narrowing** — every block's limits apply; the gateway checks
  all of them, and each block's counter includes everything under it.
  A child that claims more than its parent still stops at the
  parent's cap. The one cross-block rule: when a block sets `agents`,
  the next block's `agent` must be in it.
- **Proof** — the private key of the last `next_key`. `attenuate`
  replaces it, so nothing downstream ever holds an earlier one.
- **Keys** — Ed25519 or secp256k1 for any key (`generateKey(alg)`).
  An org may sign block 0 as an m-of-n `multisig-v1`.

`verify` returns `Claims`: `user_id`, `agent_name` (the innermost
`agent`), `run_id` (the last block's), `iat` (block 0's), `exp` (the
earliest), `chain` (every block's `run_id` and caps, outermost first),
`nonces`, and `permitted_realms`. Spec:
[`phase-13-signed-block-chain.md`](https://github.com/stakwork/mothership/blob/main/plans/phases/phase-13-signed-block-chain.md).

## API surface

| Export | Purpose |
|---|---|
| `signRoot`, `signRootMultisig` | Block 0: the org's grant. |
| `attenuate` | Append a block with the token's proof key; returns a new token with a new proof. |
| `generateKey`, `keyPair`, `publicKeyBytes`, `signWith`, `verifyWith` | Keys by algorithm. |
| `encodeToken`, `decodeToken` | Base64url transport encoding. |
| `verify`, `VerifyError` | Full end-to-end verifier. |
| `blockSigningBytes`, `blockHash`, `jcs`, `signingBytes` | Signing input and RFC 8785 canonicalization (advanced). |
| `ed25519Sign/Verify/PublicKey`, `ecdsaSign/Verify/PublicKey` | Raw primitives (advanced). |
| `bytesToHex`, `hexToBytes`, `bytesToBase64url`, `base64urlToBytes`, `utf8Bytes` | Encoding helpers. |
| `rootFromLeaves`, `rootFromLeafHashes`, `hashLeaf`, `leafHash`, `nodeHash`, `emptyRoot` | Transparency log: RFC 9162 Merkle tree hashing. |
| `verifyInclusion`, `verifyConsistency` | Transparency log: proof verifiers (RFC 9162 §2.1.3.2 / §2.1.4.2). |
| `verifySth`, `signSth`, `sthSigningBytes` | Transparency log: signed tree heads. |

Types: `Token`, `Block`, `Caveats`, `RealmCap`, `Claims`, `ChainLayer`,
`Policy`, `PubKey`, `KeyPair`, `Sig`. See `src/types.ts` for the wire
shape.

## Transparency log

Every accounted LLM call that passes through the gateway becomes a
leaf in an append-only Merkle log (RFC 9162 §2.1 hashing, the scheme
RFC 6962 introduced). The gateway serves a signed tree head plus the
leaves since the last one at `GET /_plugin/tlog/sth?since=N`; a
witness outside the swarm (Hive) verifies and countersigns it. Once a
head is witnessed, nothing below it can be edited or dropped without
the recomputed root disagreeing. Spec:
`plans/phases/phase-12-transparency-log.md`.

The witness check, end to end:

```ts
import { rootFromLeaves, verifySth, bytesToHex, type TlogSthResponse } from "gatekey";

const page: TlogSthResponse = await fetchSth(since); // your transport
if (!verifySth(page.sth, page.log_pubkey)) throw new Error("bad sth signature");

// A full replica recomputes the root over every leaf it holds plus
// the new page. Store leaves as their canonical JSON string so the
// recompute never depends on a JSON round-trip.
const allLeaves = [...storedCanonicalLeaves, ...page.leaves];
if (bytesToHex(rootFromLeaves(allLeaves)) !== page.sth.root_hash) {
  throw new Error("root does not reproduce from leaves");
}
// Only now: countersign `page.sth` with the org key and store head + leaves.
```

Light witnesses that hold only heads use `verifyConsistency` with the
served `consistency_proof`; per-call receipts (Part 2, later) verify
with `verifyInclusion`. Leaf and head shapes are `TlogLeaf` and
`SignedTreeHead`; the head signature is `ECDSA-secp256k1-SHA256` over
`JCS(sth \ sig)`.

## Wire format

```
base64url( JCS({
  v: 2,
  org_id: "...",
  blocks: [
    { caveats: { run_id, nonce, iat, exp,
                 user_id?, agent?, agents?, max_cost_usd?, max_steps?,
                 realms?: { [realm_id]: { max_cost_usd? } } },
      next_key: { alg, key },
      sig: { alg, sig } | { alg: "multisig-v1", sigs: [...] } },   // multisig: block 0 only
    ...
  ],
  proof: "<hex private key of the last next_key>"
}) )
```

All binary fields are lowercase hex (no `0x` prefix). All timestamps
are RFC 3339 UTC strings. Canonical JSON is RFC 8785 (JCS). An
unknown field or a `null` anywhere is malformed.

## Cross-language

A Go verifier and signer live in the same repository
([`mothership/auth/go/`](https://github.com/stakwork/mothership/tree/main/auth/go))
and share the test fixtures, so byte equivalence is enforced in CI.
For the transparency log the roles flip: the Go gateway is the
producer and generates `auth/fixtures/tlog-*.json`
(`go test ./internal/tlog -update`), and this package's test checks
them byte for byte. Attenuating in another language needs JCS,
SHA-256, Ed25519 (or secp256k1) and hex; the spec and fixtures are
the contract.

## License

MIT
