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
| `run_id` | yes | The key this block's spend, steps, meta and kill switch go under (`cost:run:<run_id>` …). Block 0's is the person's grant; later blocks name a run. Two blocks may share one (strut's step links reuse the run's), and then they share one counter. The gateway keys every later block's under block 0's (see "Gateway"), so a holder can only name runs inside its own grant. |
| `nonce` | yes | 128-bit random hex. The revocation handle, as today. |
| `iat` | yes | Issue time. Block 0's is the `revoke_user_before` axis. |
| `exp` | yes | The block is invalid after this. |
| `user_id` | block 0 only | The person the org hands the chain to. Only the org may name a person; on any later block it is malformed. |
| `agent` | no | The agent that holds this block's `next_key`. The innermost one is the billed agent (`agent_name`); the list of them is the lineage. |
| `agents` | no | A non-empty list. When set, the next block must name an `agent` from it. The org uses it to say which agents a person may run. |
| `max_cost_usd` | no | Cap on spend under this block on this gateway. Absent: no cap. |
| `max_steps` | no | Cap on calls under this block. Absent: no cap. |
| `realms` | no | `{ realm_id: { max_cost_usd? } }`, at least one realm. When set, this gateway's realm must be a key, and its cap (when given) applies to this block too. |

Two structure rules, the same in both verifiers. An unknown field or
a `null` anywhere is malformed: a caveat the verifier does not know
could be a limit it would silently skip. And an optional field that
is present must be non-zero (no `max_steps: 0`, no empty `agents`):
leave it out for "no limit". The second rule makes every valid
token's JSON exactly what the Go structs marshal to, so the Go
verifier rebuilds the signed bytes from parsed structs and agrees
with the TS signer byte for byte.

A token holds at most 16 blocks (`MaxBlocks` in Go, `MAX_BLOCKS` in
TS); a longer one is malformed. Each block costs a signature check
and, at the gateway, its own Redis keys, and without the limit only
the front end's header size bounds a chain.

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

The trust registry stores the org key as hex and now accepts a
32-byte Ed25519 key as well as a 33-byte compressed secp256k1 one.
The verifier reads the `alg` from the length: 64 hex characters is
Ed25519, 66 is secp256k1.

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
check the structure of the whole token         → macaroon_malformed
                                                 (v ≠ 2: macaroon_unsupported_version)
key = org policy
for each block i:
    check sig_i over msg_i with key            → invalid_root_signature (i = 0)
                                                 invalid_block_signature (i > 0)
    check exp_i ≥ now                           → macaroon_expired
    if blocks[i-1].agents set and agent_i ∉ it  → agent_not_permitted
    key = next_key_i
check public(proof) == key                      → invalid_proof
```

Returns claims:

| Claim | From |
| --- | --- |
| `org_id`, `user_id` | the token, block 0 |
| `agent_name` | innermost `agent` ("" if none) |
| `lineage` | every block's `agent`, outermost first |
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

- **Run ids** (`verifier.go`, `scopeRunIDs`): a later block's
  `run_id` is whatever its holder wrote, so the gateway keys it under
  block 0's, the one `run_id` the org signs: a block that names `r1`
  under the grant `ua_x` is counted, capped, killed and logged as
  `ua_x:r1`. Unscoped, any holder could name another person's grant
  or run and write to its counters (add spend and steps, shorten the
  TTL so a spent cap resets, rewrite its meta). A later block that
  restates the grant's own `run_id` keeps it. Block 0's `run_id` must
  not contain `:` (`macaroon_malformed`), or one grant's id could be
  the prefix of another's. The claims carry the scoped ids, so every
  bullet below, the admin API and the logs use them.
- **Accumulators** (`accumulator.go`): `cost:run` / `steps:run` /
  `meta:run` per distinct `run_id`, block 0 included. `cost:ua` is
  gone; a person's total is `cost:run:<block 0's run_id>`. In the
  operator UI the grant shows as the root of the run tree. A write
  never shortens a run key's TTL (`EXPIRE NX`, then `EXPIRE GT`;
  Redis 7): a block that names another run of the same grant with a
  short `exp` cannot expire that run's counter early.
- **Cap walk** (`capwalk.go`): per block, leaf first,
  `cost:run ≥ max_cost_usd` (`run_cost_exceeded`),
  `cost:run ≥ realms[realm].max_cost_usd` (`realm_budget_exceeded`),
  `steps:run ≥ max_steps` (`run_step_exceeded`). Blocks that share a
  `run_id` share its counter, and each one's caps apply (v1 skipped
  the inner one as a duplicate). The `ua_budget_exceeded` branch is
  gone.
- **Agent budgets** (`capwalk.go`, `accumulator.go`): `agent_budgets`
  are charged and checked for every agent in the lineage, as kills
  are (v1 used only the innermost agent). An agent's budget, and a
  `cap_usd` of 0 that stops it for good, cover its sub-agents, so
  appending a block under another name does not get around either.
  `cost:agent:<name>:<bucket>` therefore includes the spend of the
  agent's sub-agents.
- **Realm membership** (`enforcement.go`): the four cases of phase
  11, checked on every block that sets `realms`.
- **Revocations** (`revocation.go`): unchanged, over `nonces`;
  `revoke_user_before` compares block 0's `iat`; nonce 0 still
  reports `user_authorization_revoked`.
- **Kills**: over every `run_id` (as before) and every agent in the
  lineage (v1 checked only the innermost agent). Killing an agent
  stops its sub-agents, and a killed agent can't keep going by
  appending a block under another name.
- **Org key** (`verifier.go`, `internal/trust`): `singleKeyPolicy`
  reads the `alg` from the key's length; the registry accepts 32-byte
  Ed25519 keys.

Redis keys, the admin API and the hooks keep their shapes; the run
ids in them are the scoped ones.

## `gatekey` 1.0.0 (`auth/ts`) and the Go package (`auth/go`)

One verifier loop and one signer in each language, byte-identical on
the fixtures (Go names in brackets):

- `generateKey(alg?)` [`GenerateKey`] → `{ alg, priv, pub }`
  (Ed25519 by default); `keyPair(alg, priv)` [`KeyPairFromPrivate`].
- `signRoot(orgId, caveats, holder, orgKey)` [`SignRoot`] → block 0;
  `signRootMultisig(…, signers)` [`SignRootMultisig`] for an m-of-n
  org.
- `attenuate(token, caveats, next?)` [`Attenuate`] → a new token:
  signs a block with `token.proof`, names `next` (fresh Ed25519 when
  omitted in TS), and carries `next`'s private key as the new proof.
- `verify(token, policy, now)` [`Verify`] → claims;
  `encodeToken` / `decodeToken` [`EncodeToken`].

A custodial issuer (Stadeum holds the org and person keys) mints
block 0 for the person's key, then attenuates
`{ blocks: [block0], proof: personPriv }` to a fresh key for strut.
The person's private key never leaves the issuer.

`gatekey` goes to 1.0.0 so Hive's `^0.1.1` can never resolve to it.

## Fixtures

`auth/fixtures/` is regenerated for v2 and keeps the Go ↔ TS
byte-equivalence test, now with Go signing too. Cases: one block (a
person's own token); person → agent; one and two sub-agent levels; a
multisig org; caps on block 0; multi-realm; a cross-realm sub-agent;
an Ed25519 org with a secp256k1 person. Each fixture also lists the
tampered tokens that must fail, with their codes: every truncation
(`invalid_proof`), a foreign proof, an edited block 0 or last block,
a block moved under another root, an agent outside `agents`.

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
5. **Per-agent budgets.** Settled: every agent in the lineage is
   charged and checked (see "Gateway"). The first build left them on
   the innermost agent only, which let any holder append a block
   under another name and spend outside a budget or past a
   `cap_usd: 0`, and meant a budget on `strut-agent` never applied,
   since strut bills each call to the step's name.

## Work items

- [x] `auth/ts`: types, signer, verifier, `generateKey`, tests,
      README; version 1.0.0.
- [x] `auth/go`: the same, `fixtures_test.go` against the new
      fixtures, tamper tests.
- [x] `auth/ts/scripts/regenerate-fixtures.ts` and `auth/fixtures/`.
- [x] `internal/auth`: claims, accumulator, cap walk, membership,
      revocation, verifier; tests. `internal/trust`: Ed25519 org keys.
- [x] `scripts/mint-macaroon.ts`, `scripts/smoke-test-*.sh` (updated;
      not run against a live gateway in this PR).
- [x] Docs: `auth/README.md`, `auth/ts/README.md`,
      `auth/fixtures/README.md`; a superseded note at the top of
      phase 4 and phase 11.
