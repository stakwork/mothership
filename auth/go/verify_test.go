package macaroon_test

// Verifier rules the fixtures don't pin — the mirror of
// auth/ts/test/verify.test.ts.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	macaroon "github.com/stakwork/mothership/auth/go"
)

var testNow = time.Date(2026, 5, 14, 10, 0, 1, 0, time.UTC)

func caveats(runID string) macaroon.Caveats {
	return macaroon.Caveats{
		RunID: runID,
		IAT:   "2026-05-14T10:00:00Z",
		Exp:   "2026-05-14T11:00:00Z",
		Nonce: "00112233445566778899aabbccddeeff",
	}
}

func mustKey(t *testing.T, alg macaroon.SigAlg) macaroon.KeyPair {
	t.Helper()
	k, err := macaroon.GenerateKey(alg)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// personToken is block 0 alone: the org hands the chain to a person.
func personToken(t *testing.T) (macaroon.Token, macaroon.Policy) {
	t.Helper()
	org := mustKey(t, macaroon.AlgEcdsaSecp256k1Sha256)
	person := mustKey(t, macaroon.AlgEd25519)
	c := caveats("grant")
	c.UserID = "alice"
	root, err := macaroon.SignRoot("org_x", c, person.Pub, org)
	if err != nil {
		t.Fatal(err)
	}
	return macaroon.Token{V: 2, OrgID: "org_x", Blocks: []macaroon.Block{root}, Proof: macaroon.BytesToHex(person.Priv)},
		macaroon.Policy{Type: macaroon.PolicySingle, Key: &org.Pub}
}

func attenuate(t *testing.T, tok macaroon.Token, c macaroon.Caveats) macaroon.Token {
	t.Helper()
	out, err := macaroon.Attenuate(tok, c, mustKey(t, macaroon.AlgEd25519))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func encode(t *testing.T, tok macaroon.Token) string {
	t.Helper()
	s, err := macaroon.EncodeToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func wantCode(t *testing.T, b64 string, p macaroon.Policy, code macaroon.ErrorCode) {
	t.Helper()
	_, err := macaroon.Verify(b64, p, testNow)
	var ve *macaroon.VerifyError
	if !errors.As(err, &ve) || ve.Code != code {
		t.Fatalf("got %v, want %s", err, code)
	}
}

// editJSON decodes a token, lets f change it as plain JSON, re-encodes.
func editJSON(t *testing.T, b64 string, f func(m map[string]any)) string {
	t.Helper()
	raw, err := macaroon.Base64urlToBytes(b64)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(out)
}

func lastCaveats(m map[string]any) map[string]any {
	blocks := m["blocks"].([]any)
	return blocks[len(blocks)-1].(map[string]any)["caveats"].(map[string]any)
}

func TestWiderChildStillVerifies(t *testing.T) {
	tok, p := personToken(t)
	parent := caveats("run")
	parent.MaxCostUSD, parent.Exp = 5, "2026-05-14T10:30:00Z"
	child := caveats("child")
	child.MaxCostUSD, child.MaxSteps = 100, 7
	claims, err := macaroon.Verify(encode(t, attenuate(t, attenuate(t, tok, parent), child)), p, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(claims.Chain) != 3 || claims.Chain[1].MaxCostUSD != 5 || claims.Chain[2].MaxCostUSD != 100 || claims.Chain[2].MaxSteps != 7 {
		t.Fatalf("chain: %+v", claims.Chain)
	}
	if claims.Exp != "2026-05-14T10:30:00Z" || claims.RunID != "child" || claims.UserID != "alice" {
		t.Fatalf("claims: %+v", claims)
	}
}

func TestDroppingABlockFailsTheProof(t *testing.T) {
	tok, p := personToken(t)
	child := attenuate(t, attenuate(t, tok, caveats("run")), caveats("child"))
	child.Blocks = child.Blocks[:2]
	wantCode(t, encode(t, child), p, macaroon.ErrInvalidProof)
}

func TestExpiredBlockFails(t *testing.T) {
	tok, p := personToken(t)
	c := caveats("run")
	c.Exp = "2026-05-14T10:00:00Z"
	wantCode(t, encode(t, attenuate(t, tok, c)), p, macaroon.ErrMacaroonExpired)
}

func TestUserIDOnALaterBlockIsMalformed(t *testing.T) {
	tok, p := personToken(t)
	c := caveats("run")
	c.UserID = "mallory"
	wantCode(t, encode(t, attenuate(t, tok, c)), p, macaroon.ErrMacaroonMalformed)
}

func TestStructureRules(t *testing.T) {
	tok, p := personToken(t)
	b64 := encode(t, attenuate(t, tok, caveats("run")))
	for name, f := range map[string]func(m map[string]any){
		"unknown caveat":    func(m map[string]any) { lastCaveats(m)["max_tokens"] = 10 },
		"null caveat":       func(m map[string]any) { lastCaveats(m)["agent"] = nil },
		"zero cap":          func(m map[string]any) { lastCaveats(m)["max_steps"] = 0 },
		"empty agents":      func(m map[string]any) { lastCaveats(m)["agents"] = []any{} },
		"empty realms":      func(m map[string]any) { lastCaveats(m)["realms"] = map[string]any{} },
		"bad timestamp":     func(m map[string]any) { lastCaveats(m)["exp"] = "2026-05-14" },
		"unknown top field": func(m map[string]any) { m["extra"] = true },
	} {
		t.Run(name, func(t *testing.T) { wantCode(t, editJSON(t, b64, f), p, macaroon.ErrMacaroonMalformed) })
	}
}

func TestV1IsRefused(t *testing.T) {
	_, p := personToken(t)
	v1 := base64.RawURLEncoding.EncodeToString([]byte(`{"v":1,"org_id":"org_x","user_authorization":{},"invocation":{},"attenuations":[]}`))
	wantCode(t, v1, p, macaroon.ErrMacaroonUnsupportedVersion)
}

func TestAgentsLimitTheNextBlock(t *testing.T) {
	org := mustKey(t, macaroon.AlgEd25519)
	person := mustKey(t, macaroon.AlgEcdsaSecp256k1Sha256)
	c := caveats("grant")
	c.Agents = []string{"coder"}
	root, err := macaroon.SignRoot("org_x", c, person.Pub, org)
	if err != nil {
		t.Fatal(err)
	}
	tok := macaroon.Token{V: 2, OrgID: "org_x", Blocks: []macaroon.Block{root}, Proof: macaroon.BytesToHex(person.Priv)}
	p := macaroon.Policy{Type: macaroon.PolicySingle, Key: &org.Pub}

	ok := caveats("run")
	ok.Agent = "coder"
	sub := caveats("sub")
	sub.Agent = "anything" // agents only limits the very next block
	claims, err := macaroon.Verify(encode(t, attenuate(t, attenuate(t, tok, ok), sub)), p, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if claims.AgentName != "anything" {
		t.Fatalf("agent_name = %q", claims.AgentName)
	}
	bad := caveats("run")
	bad.Agent = "intruder"
	wantCode(t, encode(t, attenuate(t, tok, bad)), p, macaroon.ErrAgentNotPermitted)
}

func TestMultisigThreshold(t *testing.T) {
	keys := []macaroon.KeyPair{mustKey(t, macaroon.AlgEcdsaSecp256k1Sha256), mustKey(t, macaroon.AlgEd25519), mustKey(t, macaroon.AlgEcdsaSecp256k1Sha256)}
	p := macaroon.Policy{Type: macaroon.PolicyMultisig, Threshold: 2, Keys: []macaroon.PubKey{keys[0].Pub, keys[1].Pub, keys[2].Pub}}
	person := mustKey(t, macaroon.AlgEd25519)
	token := func(idx ...int) string {
		var signers []macaroon.MultisigSigner
		for _, i := range idx {
			signers = append(signers, macaroon.MultisigSigner{KeyIndex: i, Key: keys[i]})
		}
		root, err := macaroon.SignRootMultisig("org_x", caveats("grant"), person.Pub, signers)
		if err != nil {
			t.Fatal(err)
		}
		return encode(t, macaroon.Token{V: 2, OrgID: "org_x", Blocks: []macaroon.Block{root}, Proof: macaroon.BytesToHex(person.Priv)})
	}
	if _, err := macaroon.Verify(token(0, 1), p, testNow); err != nil {
		t.Fatal(err)
	}
	wantCode(t, token(2), p, macaroon.ErrInvalidRootSignature)
	wantCode(t, token(2, 2), p, macaroon.ErrInvalidRootSignature)
}

func TestAttenuateLeavesTheParent(t *testing.T) {
	tok, p := personToken(t)
	before := encode(t, tok)
	attenuate(t, tok, caveats("run"))
	if encode(t, tok) != before {
		t.Fatal("parent changed")
	}
	if _, err := macaroon.Verify(before, p, testNow); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(before, "ey") {
		t.Fatal("wire form is not base64url JSON")
	}
}
