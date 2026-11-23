package macaroon_test

// Cross-language byte-equivalence test (Go side), the mirror of
// auth/ts/test/fixtures.test.ts.
//
// Rebuilds every auth/fixtures/NN-*.json token from its inputs (Go signs
// too: Ed25519 and RFC 6979 ECDSA are deterministic), matches every
// expected value byte for byte, verifies the token to the recorded
// claims, and checks every tampered token fails with its code.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"testing"
	"time"

	macaroon "github.com/stakwork/mothership/auth/go"
)

const fixturesDir = "../fixtures"

type keyInput struct {
	Alg     macaroon.SigAlg `json:"alg"`
	PrivHex string          `json:"priv_hex"`
}

type fixture struct {
	Inputs struct {
		OrgID                string          `json:"org_id"`
		Policy               macaroon.Policy `json:"policy"`
		OrgKeys              []keyInput      `json:"org_keys"`
		ParticipatingSigners []int           `json:"participating_signers"`
		Root                 struct {
			Caveats macaroon.Caveats `json:"caveats"`
			Holder  keyInput         `json:"holder"`
		} `json:"root"`
		Blocks []struct {
			Caveats macaroon.Caveats `json:"caveats"`
			Next    keyInput         `json:"next"`
		} `json:"blocks"`
		Now string `json:"now"`
	} `json:"inputs"`
	Expected struct {
		Blocks []struct {
			PrevHex            string `json:"prev_hex"`
			SigningBytesHex    string `json:"signing_bytes_hex"`
			BlockCanonicalJSON string `json:"block_canonical_json"`
		} `json:"blocks"`
		TokenCanonicalJSON string `json:"token_canonical_json"`
		TokenB64url        string `json:"token_b64url"`
		Claims             struct {
			OrgID     string   `json:"org_id"`
			UserID    string   `json:"user_id"`
			AgentName string   `json:"agent_name"`
			Lineage   []string `json:"lineage"`
			RunID     string   `json:"run_id"`
			IAT       string   `json:"iat"`
			Exp       string   `json:"exp"`
			Chain     []struct {
				RunID      string                       `json:"run_id"`
				MaxCostUSD float64                      `json:"max_cost_usd"`
				MaxSteps   int                          `json:"max_steps"`
				Realms     map[string]macaroon.RealmCap `json:"realms"`
				Exp        string                       `json:"exp"`
			} `json:"chain"`
			Nonces          []string `json:"nonces"`
			PermittedRealms []string `json:"permitted_realms"`
		} `json:"claims"`
		Tampered []struct {
			Case        string `json:"case"`
			TokenB64url string `json:"token_b64url"`
			Code        string `json:"code"`
		} `json:"tampered"`
	} `json:"expected"`
}

func keyPair(t *testing.T, k keyInput) macaroon.KeyPair {
	t.Helper()
	priv, err := macaroon.HexToBytes(k.PrivHex)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := macaroon.KeyPairFromPrivate(k.Alg, priv)
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func TestFixtures(t *testing.T) {
	entries, err := os.ReadDir(fixturesDir)
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	re := regexp.MustCompile(`^\d{2}-.*\.json$`)
	var names []string
	for _, e := range entries {
		if re.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		t.Fatal("no fixtures found")
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) { runFixture(t, name) })
	}
}

func runFixture(t *testing.T, name string) {
	raw, err := os.ReadFile(filepath.Join(fixturesDir, name))
	if err != nil {
		t.Fatal(err)
	}
	var fx fixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parse: %v", err)
	}
	in, want := fx.Inputs, fx.Expected
	now, err := time.Parse(time.RFC3339, in.Now)
	if err != nil {
		t.Fatal(err)
	}

	// ─── rebuild ─────────────────────────────────────────────────
	holder := keyPair(t, in.Root.Holder)
	var root macaroon.Block
	if len(in.ParticipatingSigners) > 0 {
		var signers []macaroon.MultisigSigner
		for _, i := range in.ParticipatingSigners {
			signers = append(signers, macaroon.MultisigSigner{KeyIndex: i, Key: keyPair(t, in.OrgKeys[i])})
		}
		root, err = macaroon.SignRootMultisig(in.OrgID, in.Root.Caveats, holder.Pub, signers)
	} else {
		root, err = macaroon.SignRoot(in.OrgID, in.Root.Caveats, holder.Pub, keyPair(t, in.OrgKeys[0]))
	}
	if err != nil {
		t.Fatal(err)
	}
	tok := macaroon.Token{V: 2, OrgID: in.OrgID, Blocks: []macaroon.Block{root}, Proof: in.Root.Holder.PrivHex}
	for _, b := range in.Blocks {
		if tok, err = macaroon.Attenuate(tok, b.Caveats, keyPair(t, b.Next)); err != nil {
			t.Fatal(err)
		}
	}

	if len(tok.Blocks) != len(want.Blocks) {
		t.Fatalf("blocks: got %d, want %d", len(tok.Blocks), len(want.Blocks))
	}
	for i, b := range tok.Blocks {
		var prev *macaroon.Block
		prevHex := ""
		if i > 0 {
			prev = &tok.Blocks[i-1]
			if prevHex, err = macaroon.BlockHash(*prev); err != nil {
				t.Fatal(err)
			}
		}
		if prevHex != want.Blocks[i].PrevHex {
			t.Errorf("block %d prev_hex: got %s want %s", i, prevHex, want.Blocks[i].PrevHex)
		}
		msg, err := macaroon.BlockSigningBytes(in.OrgID, prev, b.Caveats, b.NextKey)
		if err != nil {
			t.Fatal(err)
		}
		if got := macaroon.BytesToHex(msg); got != want.Blocks[i].SigningBytesHex {
			t.Errorf("block %d signing_bytes_hex:\n got  %s\n want %s", i, got, want.Blocks[i].SigningBytesHex)
		}
		canonical, err := macaroon.JCS(b)
		if err != nil {
			t.Fatal(err)
		}
		if string(canonical) != want.Blocks[i].BlockCanonicalJSON {
			t.Errorf("block %d block_canonical_json:\n got  %s\n want %s", i, canonical, want.Blocks[i].BlockCanonicalJSON)
		}
	}
	canonical, err := macaroon.JCS(tok)
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != want.TokenCanonicalJSON {
		t.Errorf("token_canonical_json:\n got  %s\n want %s", canonical, want.TokenCanonicalJSON)
	}
	encoded, err := macaroon.EncodeToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	if encoded != want.TokenB64url {
		t.Errorf("token_b64url differs")
	}

	// ─── verify ──────────────────────────────────────────────────
	claims, err := macaroon.Verify(want.TokenB64url, in.Policy, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	wc := want.Claims
	if claims.OrgID != wc.OrgID || claims.UserID != wc.UserID || claims.AgentName != wc.AgentName ||
		claims.RunID != wc.RunID || claims.IAT != wc.IAT || claims.Exp != wc.Exp {
		t.Errorf("claims: got %+v, want %+v", claims, wc)
	}
	if len(claims.Lineage) != len(wc.Lineage) || (len(wc.Lineage) > 0 && !reflect.DeepEqual(claims.Lineage, wc.Lineage)) {
		t.Errorf("lineage: got %v want %v", claims.Lineage, wc.Lineage)
	}
	if !reflect.DeepEqual(claims.Nonces, wc.Nonces) {
		t.Errorf("nonces: got %v want %v", claims.Nonces, wc.Nonces)
	}
	if !reflect.DeepEqual(claims.PermittedRealms, wc.PermittedRealms) {
		t.Errorf("permitted_realms: got %v want %v", claims.PermittedRealms, wc.PermittedRealms)
	}
	if len(claims.Chain) != len(wc.Chain) {
		t.Fatalf("chain: got %d layers, want %d", len(claims.Chain), len(wc.Chain))
	}
	for i, l := range claims.Chain {
		w := wc.Chain[i]
		if l.RunID != w.RunID || l.MaxCostUSD != w.MaxCostUSD || l.MaxSteps != w.MaxSteps || l.Exp != w.Exp ||
			!reflect.DeepEqual(l.Realms, w.Realms) {
			t.Errorf("chain[%d]: got %+v want %+v", i, l, w)
		}
	}

	// ─── tampered tokens ─────────────────────────────────────────
	for _, tc := range want.Tampered {
		_, err := macaroon.Verify(tc.TokenB64url, in.Policy, now)
		var ve *macaroon.VerifyError
		if !errors.As(err, &ve) || string(ve.Code) != tc.Code {
			t.Errorf("%s: got %v, want %s", tc.Case, err, tc.Code)
		}
	}
}
