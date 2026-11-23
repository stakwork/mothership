# Macaroon test vectors

Language-neutral fixtures that pin down every byte of the v2 token
(`plans/phases/phase-13-signed-block-chain.md`). Every implementation
(Go, TS, polyglot) rebuilds each token from `inputs`, reproduces every
`expected` value, checks every tampered token fails with its code, and
fails if any byte differs.

## Files

```
keys.json                        the fixed seed keys used by all fixtures
01-person.json                   block 0 only: the org hands the chain to a person
02-person-to-agent.json          the person hands an agent a run: a standing delegation
03-one-sub-agent.json            the agent spawns a sub-agent
04-two-sub-agents.json           two sub-agent levels
05-multisig-2of3.json            a 2-of-3 multisig org signs block 0 (signers 0 and 2)
06-caps-on-root.json             block 0 caps everything under the person's grant
07-multi-realm.json              block 0 permits two realms; the run narrows to one
08-cross-realm-sub-agent.json    a sub-agent spawned for one realm
09-mixed-algs.json               an Ed25519 org key and a secp256k1 person key
```

## Transparency-log fixtures (`tlog-*.json`)

Two more files pin the phase-12 transparency log
(`plans/phases/phase-12-transparency-log.md`). For these the
roles flip: **Go is the producer.** `internal/tlog` generates
them with

```sh
go test ./internal/tlog -update
```

and `auth/ts/test/tlog.test.ts` checks them byte-for-byte.

```
tlog-00-rfc9162-vectors.json   raw-byte CT test leaves: leaf hashes, roots 0..8,
                               every inclusion proof, every consistency proof —
                               pinned by the Go test to the reference implementation
tlog-01-leaves.json            eight JSON leaves through the real log with a fixed
                               log key and clock: canonical bytes, hashes, roots,
                               every proof, and signed heads (empty + full) with
                               their exact signing input
```

`log_priv_hex` in `tlog-01` is a published test key; never use it for
anything real.

## Reproducibility

The `NN-*.json` files are **generated**, not hand-written. The source
of truth is `auth/ts/scripts/regenerate-fixtures.ts`. To regenerate:

```sh
cd auth/ts
npm install
npm run regenerate-fixtures
```

The seed private keys are fixed in the script, so the output is
deterministic: `@noble/curves` Ed25519 signing is deterministic by
RFC 8032 and its ECDSA uses RFC 6979 nonces; everything else is JCS
canonicalization and SHA-256. Anyone running the script gets
byte-identical files.

## Fixture shape

Each `NN-*.json` has three top-level keys: `description`, `inputs`,
`expected`.

### `inputs`

| Field | Notes |
| --- | --- |
| `org_id` | The token's `org_id`. |
| `policy` | The trust-registry policy a verifier would hold for this org. |
| `org_keys` | `[{ alg, priv_hex }]`: one key for a single-key org, the policy's keys in order for multisig. |
| `participating_signers` | Multisig only: the `key_index`es that sign block 0. |
| `root` | `{ caveats, holder: { alg, priv_hex } }`: block 0's caveats and the person's key it names. |
| `blocks` | `[{ caveats, next: { alg, priv_hex } }]`: each later block's caveats and the key it names, in order. |
| `now` | The verification time: after every `iat`, before every `exp`. |

### `expected`

| Field | What it pins down |
| --- | --- |
| `blocks[i].prev_hex` | `hex(sha256(JCS(block i-1)))`, or `""` for block 0. |
| `blocks[i].signing_bytes_hex` | UTF-8 bytes of `JCS({ org_id, prev, caveats, next_key })`: what block *i*'s signature covers. |
| `blocks[i].block_canonical_json` | JCS of block *i*, signature included. |
| `token_canonical_json` | JCS of the whole token. |
| `token_b64url` | base64url of the canonical token — the value that goes in `x-macaroon`. |
| `claims` | What the verifier returns at `inputs.now`. |
| `tampered` | `[{ case, token_b64url, code }]`: tokens that must fail, with the code each fails with — every truncation, a foreign proof, an edited block, a block moved under another root, an agent outside `agents`. |

## How implementations use this

Both the Go package (`auth/go/fixtures_test.go`) and the TS package
(`auth/ts/test/fixtures.test.ts`):

1. Sign block 0 with `org_keys` (or the multisig signers) for
   `root.holder`'s public key.
2. Start a token with that block and `root.holder` as the proof, then
   `attenuate` once per entry in `blocks` with its `next` key.
3. Assert every `expected` value matches byte for byte.
4. Verify `token_b64url` against `policy` at `now` and compare the
   claims.
5. Verify every `tampered` token and assert it fails with its `code`.

If both implementations pass, they agree on the wire format. If a
spec change shifts the bytes, regenerate the fixtures (the script is
the source of truth) and commit them alongside the spec change.
