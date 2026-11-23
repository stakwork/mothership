package macaroon

// Wire types for the v2 macaroon: a chain of signed blocks plus a proof
// key. Field names and JSON tags match auth/ts/src/types.ts and
// plans/phases/phase-13-signed-block-chain.md.
//
// All binary fields (keys, signatures, nonces, the proof) are lowercase
// hex WITHOUT 0x. All timestamps are RFC 3339 UTC.
//
// An optional field that is present must be non-zero (leave it out for
// "no limit"). That makes every valid token's JSON exactly what these
// structs marshal to, so Go can rebuild signing input from a parsed
// block and get the bytes the TS signer signed.

// ─── keys and signatures ──────────────────────────────────────────────

// SigAlg is the algorithm tag of a key or signature.
type SigAlg string

const (
	AlgEd25519              SigAlg = "ed25519"
	AlgEcdsaSecp256k1Sha256 SigAlg = "ecdsa-secp256k1-sha256"
	AlgMultisigV1           SigAlg = "multisig-v1"
)

// PubKey is one public key. Ed25519: 32 bytes. secp256k1: the 33-byte
// compressed point.
type PubKey struct {
	Alg SigAlg `json:"alg"`
	Key string `json:"key"`
}

// Sig is a block's signature: one key's (Alg + Sig), or an org's
// multisig-v1 envelope (Alg + Sigs, block 0 only).
type Sig struct {
	Alg  SigAlg   `json:"alg"`
	Sig  string   `json:"sig,omitempty"`
	Sigs []SubSig `json:"sigs,omitempty"`
}

// SubSig is one member's signature in a multisig-v1 envelope.
type SubSig struct {
	KeyIndex int    `json:"key_index"`
	Alg      SigAlg `json:"alg"`
	Sig      string `json:"sig"`
}

// PolicyType is the kind of trust-registry policy attached to an org.
type PolicyType string

const (
	PolicySingle   PolicyType = "single"
	PolicyMultisig PolicyType = "multisig"
)

// Policy is the org's trust-registry entry: what block 0's signature is
// checked against.
type Policy struct {
	Type      PolicyType `json:"type"`
	Key       *PubKey    `json:"key,omitempty"`       // single
	Threshold int        `json:"threshold,omitempty"` // multisig
	Keys      []PubKey   `json:"keys,omitempty"`      // multisig
}

// KeyPair is a key with its private half: the 32-byte Ed25519 seed or
// secp256k1 scalar.
type KeyPair struct {
	Alg  SigAlg
	Priv []byte
	Pub  PubKey
}

// ─── the token ────────────────────────────────────────────────────────

// RealmCap is one realm's cap. A zero MaxCostUSD (omitted) permits the
// realm with no cap of its own.
type RealmCap struct {
	MaxCostUSD float64 `json:"max_cost_usd,omitempty"`
}

// Caveats is the one shape every block carries. Every field applies to
// the block it is on and to everything under it.
type Caveats struct {
	RunID      string              `json:"run_id"`
	Nonce      string              `json:"nonce"`
	IAT        string              `json:"iat"`
	Exp        string              `json:"exp"`
	UserID     string              `json:"user_id,omitempty"`      // block 0 only
	Agent      string              `json:"agent,omitempty"`        // who holds this block's next_key
	Agents     []string            `json:"agents,omitempty"`       // the next block's agent must be one of these
	MaxCostUSD float64             `json:"max_cost_usd,omitempty"` // cap on spend under this block
	MaxSteps   int                 `json:"max_steps,omitempty"`    // cap on calls under this block
	Realms     map[string]RealmCap `json:"realms,omitempty"`       // when set, the gateway's realm must be a key
}

// Block is one hop: limits, the key that signs the next block, and the
// signature of the key the previous block named (the org's for block 0).
type Block struct {
	Caveats Caveats `json:"caveats"`
	NextKey PubKey  `json:"next_key"`
	Sig     Sig     `json:"sig"`
}

// Token is the whole macaroon. Proof is the hex private key matching
// the last block's NextKey.
type Token struct {
	V      int     `json:"v"`
	OrgID  string  `json:"org_id"`
	Blocks []Block `json:"blocks"`
	Proof  string  `json:"proof"`
}

// ─── verifier output ──────────────────────────────────────────────────

// ChainLayer is one block's limits as the gateway enforces them: spend
// and steps under RunID, the realm caps, the block's own expiry (the
// TTL axis for its Redis keys). Zero caps mean no cap.
type ChainLayer struct {
	RunID      string
	MaxCostUSD float64
	MaxSteps   int
	Realms     map[string]RealmCap // nil when the block sets no realms
	Exp        string
}

// Claims is what Verify returns. Adapters stamp it on their plugin
// context for the hooks.
type Claims struct {
	OrgID     string
	UserID    string       // block 0's user_id, or ""
	AgentName string       // the innermost agent, or ""
	Lineage   []string     // every block's agent, outermost first (blocks without one skipped)
	RunID     string       // the last block's run_id
	IAT       string       // block 0's iat: the revoke_user_before axis
	Exp       string       // the earliest exp in the chain
	Chain     []ChainLayer // every block, outermost first
	Nonces    []string     // every block's nonce, outermost first
	// PermittedRealms is the set of realms every block that sets
	// realms allows, sorted; nil when no block sets realms. For logs:
	// the gateway checks each block's realms itself.
	PermittedRealms []string
}
