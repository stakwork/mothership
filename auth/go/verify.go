package macaroon

// Pure verifier — Go mirror of auth/ts/src/verify.ts. A token, the
// org's policy and a clock in; Claims out, or a *VerifyError with a
// machine-readable Code. No I/O, no revocation: adapters
// (internal/auth/) add those.
//
// One loop: check each block's signature with the key the block before
// it named (the org's policy for block 0), then check the proof is the
// private half of the last key. Every block's limits apply; nothing is
// compared between blocks except agents → agent.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"time"
)

// MaxBlocks is the longest chain a verifier accepts: block 0 plus 15
// hops. Each block costs a signature check and, at the gateway, its own
// Redis keys, so an unbounded chain lets one request create thousands.
const MaxBlocks = 16

// Verify checks a base64url token (as carried in x-macaroon) against
// one org's policy.
func Verify(tokenB64 string, policy Policy, now time.Time) (*Claims, error) {
	raw, err := Base64urlToBytes(tokenB64)
	if err != nil {
		return nil, newError(ErrMacaroonMalformed, fmt.Sprintf("base64url: %v", err))
	}
	return VerifyJSON(raw, policy, now)
}

// VerifyJSON is Verify on the decoded JSON.
func VerifyJSON(raw []byte, policy Policy, now time.Time) (*Claims, error) {
	t, vErr := parseToken(raw)
	if vErr != nil {
		return nil, vErr
	}

	var key *PubKey // nil = block 0, checked against the policy
	var prev *Block
	for i := range t.Blocks {
		b := &t.Blocks[i]
		msg, err := BlockSigningBytes(t.OrgID, prev, b.Caveats, b.NextKey)
		if err != nil {
			return nil, newError(ErrMacaroonMalformed, err.Error())
		}
		if key == nil {
			if !verifyRoot(policy, msg, b.Sig) {
				return nil, newError(ErrInvalidRootSignature, "block 0's signature does not match the org's policy")
			}
		} else if b.Sig.Alg != key.Alg || !VerifyWith(*key, msg, b.Sig.Sig) {
			return nil, newError(ErrInvalidBlockSignature,
				fmt.Sprintf("block %d's signature does not match block %d's next_key", i, i-1))
		}
		if mustTime(b.Caveats.Exp).Before(now) {
			return nil, newError(ErrMacaroonExpired, fmt.Sprintf("block %d expired at %s", i, b.Caveats.Exp))
		}
		if prev != nil && prev.Caveats.Agents != nil && !contains(prev.Caveats.Agents, b.Caveats.Agent) {
			return nil, newError(ErrAgentNotPermitted,
				fmt.Sprintf("block %d's agent %q is not in block %d's agents", i, b.Caveats.Agent, i-1))
		}
		key = &b.NextKey
		prev = b
	}

	// The proof: only the holder of the last key's private half can show
	// it. A token with its last block dropped would need the private half
	// of the block before, which no holder downstream of it ever had.
	if !proofMatches(*key, t.Proof) {
		return nil, newError(ErrInvalidProof, "proof is not the private key of the last block's next_key")
	}
	return claimsOf(t), nil
}

// ─── signatures ───────────────────────────────────────────────────────

func verifyRoot(policy Policy, msg []byte, sig Sig) bool {
	switch policy.Type {
	case PolicySingle:
		return policy.Key != nil && sig.Alg == policy.Key.Alg && VerifyWith(*policy.Key, msg, sig.Sig)
	case PolicyMultisig:
		if sig.Alg != AlgMultisigV1 || policy.Threshold <= 0 {
			return false
		}
		seen := map[int]bool{}
		valid := 0
		for _, e := range sig.Sigs {
			if seen[e.KeyIndex] {
				continue
			}
			seen[e.KeyIndex] = true
			if e.KeyIndex < 0 || e.KeyIndex >= len(policy.Keys) {
				continue
			}
			pk := policy.Keys[e.KeyIndex]
			if e.Alg == pk.Alg && VerifyWith(pk, msg, e.Sig) {
				valid++
			}
		}
		return valid >= policy.Threshold
	}
	return false
}

func proofMatches(key PubKey, proofHex string) bool {
	priv, err := HexToBytes(proofHex)
	if err != nil || len(priv) != 32 {
		return false
	}
	pub, err := PublicKeyBytes(key.Alg, priv)
	return err == nil && BytesToHex(pub) == key.Key
}

// ─── claims ───────────────────────────────────────────────────────────

func claimsOf(t Token) *Claims {
	first := t.Blocks[0].Caveats
	last := t.Blocks[len(t.Blocks)-1].Caveats
	c := &Claims{
		OrgID:  t.OrgID,
		UserID: first.UserID,
		RunID:  last.RunID,
		IAT:    first.IAT,
		Exp:    first.Exp,
		Chain:  make([]ChainLayer, 0, len(t.Blocks)),
		Nonces: make([]string, 0, len(t.Blocks)),
	}
	var realms map[string]bool
	for _, b := range t.Blocks {
		cv := b.Caveats
		if cv.Agent != "" {
			c.AgentName = cv.Agent
			c.Lineage = append(c.Lineage, cv.Agent)
		}
		if mustTime(cv.Exp).Before(mustTime(c.Exp)) {
			c.Exp = cv.Exp
		}
		if cv.Realms != nil {
			next := map[string]bool{}
			for r := range cv.Realms {
				if realms == nil || realms[r] {
					next[r] = true
				}
			}
			realms = next
		}
		c.Chain = append(c.Chain, ChainLayer{
			RunID:      cv.RunID,
			MaxCostUSD: cv.MaxCostUSD,
			MaxSteps:   cv.MaxSteps,
			Realms:     cv.Realms,
			Exp:        cv.Exp,
		})
		c.Nonces = append(c.Nonces, cv.Nonce)
	}
	if realms != nil {
		c.PermittedRealms = make([]string, 0, len(realms))
		for r := range realms {
			c.PermittedRealms = append(c.PermittedRealms, r)
		}
		sort.Strings(c.PermittedRealms)
	}
	return c
}

// ─── structure ────────────────────────────────────────────────────────
//
// Strict, and the same rules as the TS verifier: an unknown field or a
// null anywhere is malformed (a caveat this verifier does not know could
// be a limit it would silently skip), and an optional field that is
// present must be non-zero. The second rule is what lets
// BlockSigningBytes rebuild the signed bytes from the parsed structs.

var (
	hexRe     = regexp.MustCompile(`^[0-9a-f]+$`)
	rfc3339Re = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$`)
)

type fields map[string]json.RawMessage

func malformed(format string, a ...any) *VerifyError {
	return newError(ErrMacaroonMalformed, fmt.Sprintf(format, a...))
}

func objectOf(raw json.RawMessage, where string) (fields, *VerifyError) {
	if t := bytes.TrimSpace(raw); len(t) == 0 || t[0] != '{' {
		return nil, malformed("%s must be an object", where)
	}
	var m fields
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, malformed("%s: %v", where, err)
	}
	for k, v := range m {
		if string(bytes.TrimSpace(v)) == "null" {
			return nil, malformed("%s.%s must not be null", where, k)
		}
	}
	return m, nil
}

func (m fields) only(where string, allowed ...string) *VerifyError {
	for k := range m {
		if !contains(allowed, k) {
			return malformed("%s: unknown field %s", where, k)
		}
	}
	return nil
}

func (m fields) str(key, where string) (string, bool, *VerifyError) {
	raw, ok := m[key]
	if !ok {
		return "", false, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil || s == "" {
		return "", true, malformed("%s.%s must be a non-empty string", where, key)
	}
	return s, true, nil
}

func (m fields) requiredStr(key, where string) (string, *VerifyError) {
	s, ok, err := m.str(key, where)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", malformed("%s.%s is required", where, key)
	}
	return s, nil
}

func (m fields) hex(key, where string) (string, *VerifyError) {
	s, err := m.requiredStr(key, where)
	if err != nil {
		return "", err
	}
	if len(s)%2 != 0 || !hexRe.MatchString(s) {
		return "", malformed("%s.%s must be lowercase hex", where, key)
	}
	return s, nil
}

// positive reads an optional number that must be > 0 when present.
func (m fields) positive(key, where string) (float64, *VerifyError) {
	raw, ok := m[key]
	if !ok {
		return 0, nil
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err != nil || !(f > 0) || math.IsInf(f, 0) {
		return 0, malformed("%s.%s must be a number > 0 (omit it for no cap)", where, key)
	}
	return f, nil
}

func keyAlg(s, where string) (SigAlg, *VerifyError) {
	alg := SigAlg(s)
	if _, ok := pubKeyBytes[alg]; !ok {
		return "", malformed("%s: unsupported alg %s", where, s)
	}
	return alg, nil
}

func parseToken(raw []byte) (Token, *VerifyError) {
	var t Token
	top, err := objectOf(raw, "token")
	if err != nil {
		return t, err
	}
	var v float64
	if json.Unmarshal(top["v"], &v) != nil || v != 2 {
		return t, newError(ErrMacaroonUnsupportedVersion, fmt.Sprintf("v=%s", string(top["v"])))
	}
	t.V = 2
	if err := top.only("token", "v", "org_id", "blocks", "proof"); err != nil {
		return t, err
	}
	if t.OrgID, err = top.requiredStr("org_id", "token"); err != nil {
		return t, err
	}
	if t.Proof, err = top.hex("proof", "token"); err != nil {
		return t, err
	}
	var blocks []json.RawMessage
	if json.Unmarshal(top["blocks"], &blocks) != nil || len(blocks) == 0 {
		return t, malformed("blocks must be a non-empty array")
	}
	if len(blocks) > MaxBlocks {
		return t, malformed("too many blocks: %d (at most %d)", len(blocks), MaxBlocks)
	}
	for i, rb := range blocks {
		b, err := parseBlock(rb, i)
		if err != nil {
			return t, err
		}
		t.Blocks = append(t.Blocks, b)
	}
	return t, nil
}

func parseBlock(raw json.RawMessage, i int) (Block, *VerifyError) {
	var b Block
	where := fmt.Sprintf("block %d", i)
	m, err := objectOf(raw, where)
	if err != nil {
		return b, err
	}
	if err := m.only(where, "caveats", "next_key", "sig"); err != nil {
		return b, err
	}
	if b.Caveats, err = parseCaveats(m["caveats"], i); err != nil {
		return b, err
	}
	if b.NextKey, err = parsePubKey(m["next_key"], where+".next_key"); err != nil {
		return b, err
	}
	if b.Sig, err = parseSig(m["sig"], i); err != nil {
		return b, err
	}
	return b, nil
}

func parseCaveats(raw json.RawMessage, i int) (Caveats, *VerifyError) {
	var c Caveats
	where := fmt.Sprintf("block %d.caveats", i)
	m, err := objectOf(raw, where)
	if err != nil {
		return c, err
	}
	if err := m.only(where, "run_id", "nonce", "iat", "exp", "user_id", "agent", "agents",
		"max_cost_usd", "max_steps", "realms"); err != nil {
		return c, err
	}
	for _, f := range []struct {
		key string
		dst *string
	}{{"run_id", &c.RunID}, {"nonce", &c.Nonce}, {"iat", &c.IAT}, {"exp", &c.Exp}} {
		if *f.dst, err = m.requiredStr(f.key, where); err != nil {
			return c, err
		}
	}
	for _, ts := range []string{c.IAT, c.Exp} {
		if _, perr := time.Parse(time.RFC3339, ts); perr != nil || !rfc3339Re.MatchString(ts) {
			return c, malformed("invalid timestamp: %s", ts)
		}
	}
	var ok bool
	if c.UserID, ok, err = m.str("user_id", where); err != nil {
		return c, err
	} else if ok && i > 0 {
		return c, malformed("%s: user_id is only allowed on block 0", where)
	}
	if c.Agent, _, err = m.str("agent", where); err != nil {
		return c, err
	}
	if raw, ok := m["agents"]; ok {
		if json.Unmarshal(raw, &c.Agents) != nil || len(c.Agents) == 0 {
			return c, malformed("%s.agents must be a non-empty array of names", where)
		}
		for _, a := range c.Agents {
			if a == "" {
				return c, malformed("%s.agents must not hold an empty name", where)
			}
		}
	}
	if c.MaxCostUSD, err = m.positive("max_cost_usd", where); err != nil {
		return c, err
	}
	steps, err := m.positive("max_steps", where)
	if err != nil {
		return c, err
	}
	if steps != math.Trunc(steps) || steps > math.MaxInt32 {
		return c, malformed("%s.max_steps must be a whole number", where)
	}
	c.MaxSteps = int(steps)
	if raw, ok := m["realms"]; ok {
		rm, err := objectOf(raw, where+".realms")
		if err != nil {
			return c, err
		}
		if len(rm) == 0 {
			return c, malformed("%s.realms must name at least one realm", where)
		}
		c.Realms = make(map[string]RealmCap, len(rm))
		for r, rraw := range rm {
			rw := where + ".realms." + r
			cm, err := objectOf(rraw, rw)
			if err != nil {
				return c, err
			}
			if err := cm.only(rw, "max_cost_usd"); err != nil {
				return c, err
			}
			cap, err := cm.positive("max_cost_usd", rw)
			if err != nil {
				return c, err
			}
			c.Realms[r] = RealmCap{MaxCostUSD: cap}
		}
	}
	return c, nil
}

func parsePubKey(raw json.RawMessage, where string) (PubKey, *VerifyError) {
	var k PubKey
	m, err := objectOf(raw, where)
	if err != nil {
		return k, err
	}
	if err := m.only(where, "alg", "key"); err != nil {
		return k, err
	}
	alg, err := m.requiredStr("alg", where)
	if err != nil {
		return k, err
	}
	if k.Alg, err = keyAlg(alg, where+".alg"); err != nil {
		return k, err
	}
	if k.Key, err = m.hex("key", where); err != nil {
		return k, err
	}
	if len(k.Key) != pubKeyBytes[k.Alg]*2 {
		return k, malformed("%s.key has the wrong length for %s", where, k.Alg)
	}
	return k, nil
}

func parseSig(raw json.RawMessage, i int) (Sig, *VerifyError) {
	var s Sig
	where := fmt.Sprintf("block %d.sig", i)
	m, err := objectOf(raw, where)
	if err != nil {
		return s, err
	}
	alg, err := m.requiredStr("alg", where)
	if err != nil {
		return s, err
	}
	if SigAlg(alg) == AlgMultisigV1 {
		if i > 0 {
			return s, malformed("%s: only block 0 can carry a multisig signature", where)
		}
		if err := m.only(where, "alg", "sigs"); err != nil {
			return s, err
		}
		s.Alg = AlgMultisigV1
		var subs []json.RawMessage
		if json.Unmarshal(m["sigs"], &subs) != nil || subs == nil {
			return s, malformed("%s.sigs must be an array", where)
		}
		for j, sraw := range subs {
			sw := fmt.Sprintf("%s.sigs[%d]", where, j)
			sm, err := objectOf(sraw, sw)
			if err != nil {
				return s, err
			}
			if err := sm.only(sw, "key_index", "alg", "sig"); err != nil {
				return s, err
			}
			var idx float64
			if json.Unmarshal(sm["key_index"], &idx) != nil || idx < 0 || idx != math.Trunc(idx) || idx > math.MaxInt32 {
				return s, malformed("%s.key_index must be a whole number ≥ 0", sw)
			}
			salg, err := sm.requiredStr("alg", sw)
			if err != nil {
				return s, err
			}
			sub := SubSig{KeyIndex: int(idx)}
			if sub.Alg, err = keyAlg(salg, sw+".alg"); err != nil {
				return s, err
			}
			if sub.Sig, err = sm.hex("sig", sw); err != nil {
				return s, err
			}
			s.Sigs = append(s.Sigs, sub)
		}
		return s, nil
	}
	if err := m.only(where, "alg", "sig"); err != nil {
		return s, err
	}
	if s.Alg, err = keyAlg(alg, where+".alg"); err != nil {
		return s, err
	}
	if s.Sig, err = m.hex("sig", where); err != nil {
		return s, err
	}
	return s, nil
}

// ─── helpers ──────────────────────────────────────────────────────────

// mustTime parses a timestamp parseToken already validated.
func mustTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
