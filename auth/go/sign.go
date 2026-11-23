package macaroon

// Building a chain — Go mirror of auth/ts/src/sign.ts. Block 0 is
// signed by the org; every later block by the key the block before it
// named. Attenuate is the one operation an agent needs.
//
// Ed25519 (RFC 8032) and ECDSA-secp256k1 (RFC 6979, low-s) are
// deterministic in both implementations, so a fixture signed in TS and
// re-signed here produces identical bytes.

import (
	"crypto/sha256"
	"fmt"
	"sort"
)

// signingInput is what a block's signature covers.
type signingInput struct {
	OrgID   string  `json:"org_id"`
	Prev    string  `json:"prev"`
	Caveats Caveats `json:"caveats"`
	NextKey PubKey  `json:"next_key"`
}

// BlockSigningBytes is utf8(JCS({org_id, prev, caveats, next_key})),
// where prev is "" for block 0 (prev == nil) and BlockHash of the block
// before otherwise.
func BlockSigningBytes(orgID string, prev *Block, c Caveats, next PubKey) ([]byte, error) {
	in := signingInput{OrgID: orgID, Caveats: c, NextKey: next}
	if prev != nil {
		h, err := BlockHash(*prev)
		if err != nil {
			return nil, err
		}
		in.Prev = h
	}
	return JCS(in)
}

// BlockHash is hex(sha256(JCS(block))): the whole block, signature
// included.
func BlockHash(b Block) (string, error) {
	canonical, err := JCS(b)
	if err != nil {
		return "", fmt.Errorf("block hash: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return BytesToHex(sum[:]), nil
}

// SignRoot makes block 0 under a single-key org: it hands the chain to
// holder, usually a person's key, whose private half is the proof of a
// token made of this block alone.
func SignRoot(orgID string, c Caveats, holder PubKey, org KeyPair) (Block, error) {
	msg, err := BlockSigningBytes(orgID, nil, c, holder)
	if err != nil {
		return Block{}, err
	}
	sig, err := SignWith(org.Alg, org.Priv, msg)
	if err != nil {
		return Block{}, fmt.Errorf("sign root: %w", err)
	}
	return Block{Caveats: c, NextKey: holder, Sig: Sig{Alg: org.Alg, Sig: BytesToHex(sig)}}, nil
}

// MultisigSigner is one participating org signer. KeyIndex is the
// signer's position in the policy's Keys.
type MultisigSigner struct {
	KeyIndex int
	Key      KeyPair
}

// SignRootMultisig makes block 0 under an m-of-n org. The threshold is
// checked when the token is verified.
func SignRootMultisig(orgID string, c Caveats, holder PubKey, signers []MultisigSigner) (Block, error) {
	msg, err := BlockSigningBytes(orgID, nil, c, holder)
	if err != nil {
		return Block{}, err
	}
	sorted := append([]MultisigSigner(nil), signers...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].KeyIndex < sorted[j].KeyIndex })
	subs := make([]SubSig, 0, len(sorted))
	for _, s := range sorted {
		sig, err := SignWith(s.Key.Alg, s.Key.Priv, msg)
		if err != nil {
			return Block{}, fmt.Errorf("sign root multisig[%d]: %w", s.KeyIndex, err)
		}
		subs = append(subs, SubSig{KeyIndex: s.KeyIndex, Alg: s.Key.Alg, Sig: BytesToHex(sig)})
	}
	return Block{Caveats: c, NextKey: holder, Sig: Sig{Alg: AlgMultisigV1, Sigs: subs}}, nil
}

// Attenuate appends one block: signed with t.Proof (the key the last
// block named), naming next, and returns a new token whose proof is
// next's private key. t is not changed.
func Attenuate(t Token, c Caveats, next KeyPair) (Token, error) {
	if len(t.Blocks) == 0 {
		return Token{}, fmt.Errorf("attenuate: the token has no blocks")
	}
	last := t.Blocks[len(t.Blocks)-1]
	msg, err := BlockSigningBytes(t.OrgID, &last, c, next.Pub)
	if err != nil {
		return Token{}, err
	}
	proof, err := HexToBytes(t.Proof)
	if err != nil {
		return Token{}, fmt.Errorf("attenuate: proof: %w", err)
	}
	sig, err := SignWith(last.NextKey.Alg, proof, msg)
	if err != nil {
		return Token{}, fmt.Errorf("attenuate: %w", err)
	}
	blocks := append(append([]Block(nil), t.Blocks...), Block{
		Caveats: c,
		NextKey: next.Pub,
		Sig:     Sig{Alg: last.NextKey.Alg, Sig: BytesToHex(sig)},
	})
	return Token{V: 2, OrgID: t.OrgID, Blocks: blocks, Proof: BytesToHex(next.Priv)}, nil
}

// EncodeToken is the wire form: base64url(JCS(token)), unpadded.
func EncodeToken(t Token) (string, error) {
	canonical, err := JCS(t)
	if err != nil {
		return "", fmt.Errorf("encode token: %w", err)
	}
	return BytesToBase64url(canonical), nil
}
