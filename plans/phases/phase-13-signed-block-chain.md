# Phase 13 — Signed block chain (macaroon v2)

> One block type for every hop (org → person, person → agent, agent →
> sub-agent), each signed by the key the block before it named, and a
> proof key that makes the chain impossible to shorten. Replaces the
> three-layer wire format of `phase-4-macaroon-shape.md` and the
> narrowing rules of `phase-11-symmetric-recursive-authorization.md`.
> A clean break: this repo accepts only v2. v1 stays where it is
> (stakgraph's gateway, `gatekey` 0.1.x, Hive and the swarms).

## Why

v1 can be unwrapped by whoever holds it. The token carries every
attenuation's HMAC, and link *i*'s HMAC depends only on the links
before it, so any prefix of the chain still verifies:

```
grandchild's own token (2 links): VERIFIES  run=…grandchild2run  max_cost_usd=0.5
pop last link  -> parent's token : VERIFIES  run=…childlevel1run  max_cost_usd=2
pop both links -> root invocation: VERIFIES  run=…rootinvocation  max_cost_usd=5
```

(fixture `03-two-attenuations.json`, gatekey's own `verify`). Sending
only the last HMAC would not fix it: link 0 is keyed with
`invocation.user_sig.sig`, which is in the token, so a holder can
recompute any link from public bytes. An HMAC chain needs a root key
the holder never sees, and here the root is a public signature.

What it costs today: strut gives a pod a "grant" (strut's standing
delegation plus one link with the pod's cap). The pod can drop the
link and spend under strut's 60-day delegation. Any sub-agent can run
at its parent's or the root's limits, under the parent's `run_id`,
and step around a kill or a revoke aimed at its own run, nonce or
agent name, since those disappear with its link.

## The idea

Every hop is the same act: whoever holds a key hands narrower limits
to a new key. So there is one block type:

```
block = { caveats, next_key, sig }   // sig by the previous block's next_key
token = { v: 2, org_id, blocks, proof }
                                     // proof = private key of the last next_key
```

- **Block 0** is signed by the org's policy from the trust registry
  (single key or multisig). It hands the chain to a person's key.
- **Every later block** is signed by the previous block's `next_key`.
- **`proof`** is the private key matching the last block's
  `next_key`. Whoever holds the token can append a block (sign it
  with the proof key, name a fresh key, hand on the fresh key's
  private half as the new proof). Nobody can remove one: the token
  of the block before would need *that* block's private key, which
  was replaced when the block was appended and is in no token the
  child sees.

This is biscuit's construction without biscuit's Datalog: the
caveats stay a fixed set of fields.

## Wire format

```json
{
  "v": 2,
  "org_id": "org_stadeum",
  "blocks": [
    {
      "caveats": {
        "run_id": "ua_9f2c…",
        "user_id": "alice",
        "agents": ["strut-agent"],
        "iat": "2026-11-22T10:00:00Z",
        "exp": "2027-01-21T10:00:00Z",
        "nonce": "4be1…32-hex…"
      },
      "next_key": { "alg": "ed25519", "key": "8b2…64-hex…" },
      "sig": { "alg": "ecdsa-secp256k1-sha256", "sig": "…128-hex…" }
    },
    {
      "caveats": {
        "run_id": "d3c1…",
        "agent": "strut-agent",
        "max_cost_usd": 20,
        "iat": "2026-11-22T10:00:00Z",
        "exp": "2027-01-21T10:00:00Z",
        "nonce": "a71f…"
      },
      "next_key": { "alg": "ed25519", "key": "…" },
      "sig": { "alg": "ed25519", "sig": "…" }
    }
  ],
  "proof": "…64-hex private key of the last next_key…"
}
```

Encoding is unchanged: binary fields are lowercase hex, timestamps
RFC 3339 UTC, the token travels as `base64url(JCS(token))`.

### Caveats

One shape on every block. Every field applies to the block it is on
and to everything under it.

| Field | Required | Meaning |
| --- | --- | --- |
| `run_id` | yes | The key this block's spend, steps, meta and kill switch go under (`cost:run:<run_id>` …). Block 0's is the person's grant; later blocks name a run. Two blocks may share one (strut's step links reuse the run's), and then they share one counter. |
| `nonce` | yes | 128-bit random hex. The revocation handle, as today. |
| `iat` | yes | Issue time. Block 0's is the `revoke_user_before` axis. |
| `exp` | yes | The block is invalid after this. |
| `user_id` | block 0 only | The person the org hands the chain to. Only the org may name a person; on any later block it is malformed. |
| `agent` | no | The agent that holds this block's `next_key`. The innermost one is the billed agent (`agent_name`); the list of them is the lineage. |
| `agents` | no | When set, the next block must name an `agent` from this list. The org uses it to say which agents a person may run. |
| `max_cost_usd` | no | Cap on spend under this block on this gateway. Absent or 0: no cap. |
| `max_steps` | no | Cap on calls under this block. Absent or 0: no cap. |
| `realms` | no | `{ realm_id: { max_cost_usd } }`. When set, this gateway's realm must be a key, and its cap (if > 0) applies to this block too. |

What is gone from v1: the separate `user_authorization`,
`invocation` and `attenuations`; `user_pubkey` (it is block 0's
`next_key`); the `budget` block (`max_total_usd` is block 0's
`max_cost_usd`, `realm_budgets` is `realms`, `max_per_invocation_usd`
is dropped, see open question 1); the HMAC.

### No narrowing check

v1 compared every child's limits with its parent's and rejected a
wider child. v2 drops the comparison: every block's limits apply, and
the gateway checks all of them. A child that claims $100 under a $5
parent still stops at $5, because the parent's counter includes every
descendant's spend; a child whose `exp` is later than its parent's
still dies with the parent, because every block's `exp` is checked.
So the effective limit is the tightest one in the chain, by
construction. This also ends v1's `max_steps: 0` trap (0 meant "no
cap", but a child's positive cap counted as wider than it).

### Keys and algorithms

`next_key` is `{ alg, key }` with `alg` either `ed25519` (32-byte key)
or `ecdsa-secp256k1-sha256` (33-byte compressed key). Any block can
use either, so a person can sign with a secp256k1 key and an org with
an Ed25519 one. A block's `sig` is checked with the previous block's
`next_key`, by that key's `alg`. Block 0's `sig` is checked against
the org's policy: `single` (any `alg`) or `multisig-v1`. Agents
default to fresh Ed25519 keys.

The trust registry stores the org key as hex. Its `alg` is read from
the length: 66 hex characters is secp256k1, 64 is Ed25519.

### Signing input

```
msg_i = utf8(JCS({ org_id, prev: prev_i, caveats: caveats_i, next_key: next_key_i }))
prev_0 = ""
prev_i = hex(sha256(utf8(JCS(blocks[i-1]))))     // the whole previous block, sig included
```

Ed25519 signs `msg_i` directly; ECDSA signs `sha256(msg_i)`, compact
`r||s`, low-s (as v1). `prev` binds each block to the exact block
before it, so a block signed by a long-lived key (a person's) cannot
be moved under another block 0 that names the same key.

## Verifying

```
key = org policy
for each block i:
    check sig_i over msg_i with key            → invalid_root_signature (i = 0)
                                                 invalid_block_signature (i > 0)
    check exp_i ≥ now                           → macaroon_expired
    if i > 0 and user_id set                    → macaroon_malformed
    if blocks[i-1].agents set and agent_i ∉ it  → agent_not_permitted
    key = next_key_i
check public(proof) == key                      → invalid_proof
```

Returns claims:

| Claim | From |
| --- | --- |
| `org_id`, `user_id` | the token, block 0 |
| `agent_name` | innermost `agent` ("" if none) |
| `run_id` | the last block's `run_id` |
| `iat` | block 0's `iat` (`revoke_user_before`) |
| `exp` | the earliest `exp` in the chain |
| `chain` | every block, outermost first: `run_id`, `max_cost_usd`, `max_steps`, `realms`, `exp` |
| `nonces` | every block's nonce, outermost first |
| `permitted_realms` | the realms every block that sets `realms` allows, sorted; null when none does |

`effective_caveats` and the `ua_*` claims are gone: the gateway reads
the chain.

## Gateway (`internal/auth`)

Block 0 becomes one more layer of the chain, so the person-level
path folds into the per-layer loop:

- **Accumulators** (`accumulator.go`): `cost:run` / `steps:run` /
  `meta:run` per distinct `run_id`, block 0 included. `cost:ua` is
  gone; a person's total is `cost:run:<block 0's run_id>`. In the
  operator UI the grant shows as the root of the run tree.
- **Cap walk** (`capwalk.go`): per layer, `cost:run ≥ max_cost_usd`
  (`run_cost_exceeded`), `cost:run ≥ realms[realm].max_cost_usd`
  (`realm_budget_exceeded`), `steps:run ≥ max_steps`
  (`run_step_exceeded`). The `ua_budget_exceeded` branch is gone.
- **Realm membership** (`enforcement.go`): the four cases of phase
  11, checked on every block that sets `realms`.
- **Revocations** (`revocation.go`): unchanged, over `nonces`;
  `revoke_user_before` compares block 0's `iat`; nonce 0 still
  reports `user_authorization_revoked`.
- **Kills**: unchanged, over every `run_id` and the innermost agent.
- **Org key** (`verifier.go`): `singleKeyPolicy` reads the `alg` from
  the key's length.

Redis keys, the admin API and the hooks keep their shapes.

## `gatekey` 1.0.0 (`auth/ts`) and the Go package (`auth/go`)

One verifier loop and one signer in each language, byte-identical on
the fixtures:

- `generateKey(alg?)` → `{ alg, priv, pub }` (Ed25519 by default).
- `mintRoot(orgId, caveats, holder: PubKey, orgSigner)` → block 0;
  `mintRootMultisig(…, signers)` for an m-of-n org.
- `attenuate(token, caveats, next?)` → a new token: signs a block
  with `token.proof`, names `next` (fresh Ed25519 when omitted), and
  carries `next`'s private key as the new proof.
- `verify(token, policy, now)` → claims; `encodeToken` /
  `decodeToken`.

A custodial issuer (Stadeum holds the org and person keys) mints
block 0 for the person's key, then attenuates
`{ blocks: [block0], proof: personPriv }` to a fresh key for strut.
The person's private key never leaves the issuer.

`gatekey` goes to 1.0.0 so Hive's `^0.1.1` can never resolve to it.

## Fixtures

`auth/fixtures/` is regenerated for v2 and keeps the Go ↔ TS
byte-equivalence test. Cases: one block (a person's own token);
person → agent; two sub-agent levels; a multisig org; caps on block
0; multi-realm; a cross-realm sub-agent; a person with a secp256k1
key. Each fixture also lists the tampered tokens that must fail:
every truncation, a swapped proof, a block moved under another root.

## Rollout

1. This PR: the format, both libraries, the gateway, the fixtures,
   `scripts/mint-macaroon.ts` and the smoke scripts. v1 code is
   deleted from this repo.
2. Publish `gatekey` 1.0.0 and release the image.
3. strut: `src/mothership.ts` appends signed blocks with the
   delegation's proof key and hands each child a new one; it keeps a
   v1 path picked by `v` while mcp on the swarms still runs strut
   against stakgraph's gateway. `/llm/delegations` reports `v`.
4. Stadeum: `mint.ts` mints v2; `ensureDelegation` re-mints when
   strut's copy is not v2; `stack/stadeum.yml` moves to
   `ghcr.io/stakwork/mothership`. That deploy is the cutover.

## Open questions (with the default this PR builds)

1. **`max_per_invocation_usd`.** No issuer sets it (Stadeum does
   not). Default: dropped. Bring it back as a block field ("each
   next block's `max_cost_usd` ≤ this") when an org needs to cap a
   person's single run below their total.
2. **Multisig past block 0.** A person's key as a 2-of-3 needs a
   proof a group can hold. Default: only the org's root signs with a
   policy; every `next_key` is a single key.
3. **Sealed tokens.** The proof travels to the gateway, so a token
   in a log can still be narrowed by whoever reads the log (never
   widened). A sealed form (the last key signs the chain, no private
   key on the wire) would stop that. Default: not now; it is
   additive.
4. **Error codes.** `invalid_user_authorization`,
   `invalid_invocation_signature`, `attenuation_invalid`,
   `attenuation_widened`, `invocation_violated` and
   `ua_per_invocation_exceeded` give way to `invalid_root_signature`,
   `invalid_block_signature`, `invalid_proof` and
   `agent_not_permitted`, and the gateway's `ua_budget_exceeded`
   goes with `cost:ua`. Default: rename. Stadeum's code matches on
   none of them; strut's only match is a test of v1 widening
   (`src/mothership.test.ts`), which its PR replaces.

## Work items

- [ ] `auth/ts`: types, signer, verifier, `generateKey`, tests,
      README; version 1.0.0.
- [ ] `auth/go`: the same, `fixtures_test.go` against the new
      fixtures, tamper tests.
- [ ] `auth/ts/scripts/regenerate-fixtures.ts` and `auth/fixtures/`.
- [ ] `internal/auth`: claims, accumulator, cap walk, membership,
      revocation, verifier; tests.
- [ ] `scripts/mint-macaroon.ts`, `scripts/smoke-test-*.sh`.
- [ ] Docs: `auth/README.md`, `auth/ts/README.md`,
      `auth/fixtures/README.md`; a superseded note at the top of
      phase 4 and phase 11.
