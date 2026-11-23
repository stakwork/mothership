package auth

// Test helpers shared across the auth package's unit tests.
//
// The strategy: we build real signed macaroons against a real (in-
// memory) trust registry and a real Redis (miniredis), and exercise
// the adapter through its public entry points. No mock fakes —
// brittleness from mock drift is exactly what the phase-4 doc warned
// against ("fixtures are the contract"). For the trust registry
// specifically we use trust.New() directly because the public
// surface is small enough that we don't gain anything from a fake.

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/redis/go-redis/v9"

	macaroon "github.com/stakwork/mothership/auth/go"
	"github.com/stakwork/mothership/internal/redisclient"
	"github.com/stakwork/mothership/internal/trust"
)

// Deterministic test keys. Reused across every test in this package
// so a failure's diagnostic strings stay comparable across runs.
const (
	testOrgPrivHex  = "0000000000000000000000000000000000000000000000000000000000000001"
	testUserPrivHex = "1111111111111111111111111111111111111111111111111111111111111111"
	testOrgID       = "org_test"
	testUserID      = "u_alice"
)

func testOrgPriv() []byte  { return mustHexBytes(testOrgPrivHex) }
func testUserPriv() []byte { return mustHexBytes(testUserPrivHex) }

func testOrgPubHex() string {
	p := secp256k1.PrivKeyFromBytes(testOrgPriv())
	return hex.EncodeToString(p.PubKey().SerializeCompressed())
}

func mustHexBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// newTestRegistry builds an in-memory trust registry populated with
// the deterministic test org. Helper because every test that hits
// the verifier needs this setup.
func newTestRegistry(t *testing.T) *trust.Registry {
	t.Helper()
	r := trust.New()
	o := trust.Org{
		OrgID:                 testOrgID,
		Pubkey:                testOrgPubHex(),
		IssuerURL:             "https://hive.test",
		RevocationPollSeconds: 60,
	}
	if err := r.Upsert(o, trust.SeedSourceAPI); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	return r
}

// newMiniRedis spins up miniredis and points redisclient at it.
// Returns the miniredis handle for direct state inspection. The
// cleanup hook closes the miniredis AND nils out the package
// client so the next test starts clean.
func newMiniRedis(t *testing.T) *miniredis.Miniredis {
	t.Helper()
	mr := miniredis.RunT(t)
	c := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	redisclient.SetClientForTest(c)
	t.Cleanup(func() {
		redisclient.SetClientForTest(nil)
		_ = c.Close()
	})
	return mr
}

// buildMacaroon assembles a fully-signed v2 token against the test
// keys: block 0 (the org's grant to the person) and block 1 (the
// person's run for an agent), proof = the agent key. Knobs let each
// test tweak the fields it cares about; everything else is fixed and
// minimal. The ua*/inv* names are kept from v1 for the two blocks.
type macaroonOptions struct {
	orgID  string
	userID string
	// Block 0: the org's grant to the person.
	grantRunID      string
	agents          []string // which agents the person may run
	grantMaxCostUSD float64  // v1's budget.max_total_usd
	realms          map[string]macaroon.RealmCap
	uaExp           time.Time
	uaIAT           time.Time
	uaNonce         string
	// Block 1: the person's run for an agent.
	agent      string
	runID      string
	maxCostUSD float64
	maxSteps   int
	invExp     time.Time
	invIAT     time.Time
	invNonce   string
	// signWithOrgPriv overrides the org private key — used in tests
	// that need to exercise the "signed by an untrusted key" path.
	signWithOrgPriv []byte
}

func defaultMacaroonOptions(now time.Time) macaroonOptions {
	return macaroonOptions{
		orgID:      testOrgID,
		userID:     testUserID,
		grantRunID: "ua_test_grant_000000000000",
		agents:     []string{"coder"},
		agent:      "coder",
		runID:      "r_test_run_000000000000000",
		maxCostUSD: 5.00,
		maxSteps:   100,
		uaIAT:      now.Add(-1 * time.Hour),
		uaExp:      now.Add(24 * time.Hour),
		invIAT:     now.Add(-1 * time.Minute),
		invExp:     now.Add(10 * time.Minute),
		uaNonce:    "aaaa000000000000000000000000aaaa",
		invNonce:   "bbbb000000000000000000000000bbbb",
	}
}

func buildMacaroon(t *testing.T, opts macaroonOptions) string {
	t.Helper()

	person, err := macaroon.KeyPairFromPrivate(macaroon.AlgEd25519, testUserPriv())
	if err != nil {
		t.Fatalf("person key: %v", err)
	}
	signKey := opts.signWithOrgPriv
	if signKey == nil {
		signKey = testOrgPriv()
	}
	org, err := macaroon.KeyPairFromPrivate(macaroon.AlgEcdsaSecp256k1Sha256, signKey)
	if err != nil {
		t.Fatalf("org key: %v", err)
	}

	root, err := macaroon.SignRoot(opts.orgID, macaroon.Caveats{
		RunID:      opts.grantRunID,
		UserID:     opts.userID,
		Agents:     opts.agents,
		MaxCostUSD: opts.grantMaxCostUSD,
		Realms:     opts.realms,
		IAT:        opts.uaIAT.UTC().Format(time.RFC3339),
		Exp:        opts.uaExp.UTC().Format(time.RFC3339),
		Nonce:      opts.uaNonce,
	}, person.Pub, org)
	if err != nil {
		t.Fatalf("sign block 0: %v", err)
	}

	agentKey, err := macaroon.GenerateKey(macaroon.AlgEd25519)
	if err != nil {
		t.Fatalf("agent key: %v", err)
	}
	tok, err := macaroon.Attenuate(
		macaroon.Token{V: 2, OrgID: opts.orgID, Blocks: []macaroon.Block{root}, Proof: macaroon.BytesToHex(person.Priv)},
		macaroon.Caveats{
			RunID:      opts.runID,
			Agent:      opts.agent,
			MaxCostUSD: opts.maxCostUSD,
			MaxSteps:   opts.maxSteps,
			IAT:        opts.invIAT.UTC().Format(time.RFC3339),
			Exp:        opts.invExp.UTC().Format(time.RFC3339),
			Nonce:      opts.invNonce,
		},
		agentKey,
	)
	if err != nil {
		t.Fatalf("sign block 1: %v", err)
	}
	encoded, err := macaroon.EncodeToken(tok)
	if err != nil {
		t.Fatalf("encode token: %v", err)
	}
	return encoded
}
