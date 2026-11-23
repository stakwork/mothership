package auth

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	macaroon "github.com/stakwork/mothership/auth/go"
	"github.com/stakwork/mothership/internal/trust"
)

func TestVerify_MissingHeader(t *testing.T) {
	reg := newTestRegistry(t)
	claims, err := Verify("", reg, time.Now())
	if claims != nil {
		t.Fatalf("expected nil claims, got %+v", claims)
	}
	if err == nil || err.Code != "macaroon_required" {
		t.Fatalf("want macaroon_required, got %+v", err)
	}
	if err.HTTPStatus != 401 {
		t.Fatalf("want 401, got %d", err.HTTPStatus)
	}
}

func TestVerify_MalformedBase64(t *testing.T) {
	reg := newTestRegistry(t)
	_, err := Verify("not-base64url!!!", reg, time.Now())
	if err == nil || err.Code != string(macaroon.ErrMacaroonMalformed) {
		t.Fatalf("want macaroon_malformed, got %+v", err)
	}
}

func TestVerify_MalformedJSON(t *testing.T) {
	reg := newTestRegistry(t)
	// Valid base64url that decodes to garbage JSON.
	_, err := Verify("aGVsbG8", reg, time.Now())
	if err == nil || err.Code != string(macaroon.ErrMacaroonMalformed) {
		t.Fatalf("want macaroon_malformed, got %+v", err)
	}
}

func TestVerify_UntrustedOrg(t *testing.T) {
	reg := trust.New() // empty registry — no orgs
	encoded := buildMacaroon(t, defaultMacaroonOptions(time.Now()))
	_, err := Verify(encoded, reg, time.Now())
	if err == nil || err.Code != "untrusted_org" {
		t.Fatalf("want untrusted_org, got %+v", err)
	}
}

func TestVerify_NilRegistry(t *testing.T) {
	encoded := buildMacaroon(t, defaultMacaroonOptions(time.Now()))
	_, err := Verify(encoded, nil, time.Now())
	if err == nil || err.Code != "trust_registry_unavailable" {
		t.Fatalf("want trust_registry_unavailable, got %+v", err)
	}
}

func TestVerify_Happy(t *testing.T) {
	reg := newTestRegistry(t)
	now := time.Now()
	encoded := buildMacaroon(t, defaultMacaroonOptions(now))
	claims, err := Verify(encoded, reg, now)
	if err != nil {
		t.Fatalf("verify: %+v", err)
	}
	if claims == nil {
		t.Fatal("nil claims on success")
	}
	if claims.OrgID != testOrgID || claims.UserID != testUserID {
		t.Fatalf("wrong claims: %+v", claims)
	}
	if claims.AgentName != "coder" {
		t.Fatalf("agent_name: %s", claims.AgentName)
	}
}

func TestVerify_WrongSigningKey_Rejected(t *testing.T) {
	reg := newTestRegistry(t)
	now := time.Now()
	opts := defaultMacaroonOptions(now)
	// Sign with a different secp256k1 key — registry will reject.
	opts.signWithOrgPriv = mustHexBytes("0000000000000000000000000000000000000000000000000000000000000002")
	encoded := buildMacaroon(t, opts)
	_, err := Verify(encoded, reg, now)
	if err == nil {
		t.Fatal("expected verification failure for wrong key")
	}
	if err.Code != string(macaroon.ErrInvalidRootSignature) {
		t.Fatalf("want invalid_root_signature, got %s", err.Code)
	}
}

func TestVerify_ExpiredUA(t *testing.T) {
	reg := newTestRegistry(t)
	now := time.Now()
	opts := defaultMacaroonOptions(now)
	opts.uaExp = now.Add(-1 * time.Hour) // already expired
	encoded := buildMacaroon(t, opts)
	_, err := Verify(encoded, reg, now)
	if err == nil {
		t.Fatal("expected expiry rejection")
	}
	if err.Code != string(macaroon.ErrMacaroonExpired) {
		t.Fatalf("want macaroon_expired, got %s", err.Code)
	}
}

func TestVerify_GraceKey_AcceptedWithinWindow(t *testing.T) {
	// Build a registry where org's active key is the wrong key,
	// but the test key sits in grace_pubkeys with a future deadline.
	reg := trust.New()
	otherPriv := mustHexBytes("0000000000000000000000000000000000000000000000000000000000000005")
	otherPub := hex.EncodeToString(secp256k1.PrivKeyFromBytes(otherPriv).PubKey().SerializeCompressed())

	o := trust.Org{
		OrgID:                 testOrgID,
		Pubkey:                otherPub,
		IssuerURL:             "https://hive.test",
		RevocationPollSeconds: 60,
		GracePubkeys:          []string{testOrgPubHex()},
		GraceUntil:            time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339),
	}
	if err := reg.Upsert(o, trust.SeedSourceAPI); err != nil {
		t.Fatalf("seed: %v", err)
	}

	now := time.Now()
	encoded := buildMacaroon(t, defaultMacaroonOptions(now))
	claims, err := Verify(encoded, reg, now)
	if err != nil {
		t.Fatalf("grace key should verify within window: %+v", err)
	}
	if claims == nil {
		t.Fatal("nil claims")
	}
}

func TestVerify_GraceKey_RejectedAfterWindow(t *testing.T) {
	reg := trust.New()
	otherPriv := mustHexBytes("0000000000000000000000000000000000000000000000000000000000000005")
	otherPub := hex.EncodeToString(secp256k1.PrivKeyFromBytes(otherPriv).PubKey().SerializeCompressed())

	o := trust.Org{
		OrgID:                 testOrgID,
		Pubkey:                otherPub,
		IssuerURL:             "https://hive.test",
		RevocationPollSeconds: 60,
		GracePubkeys:          []string{testOrgPubHex()},
		GraceUntil:            time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339), // expired
	}
	if err := reg.Upsert(o, trust.SeedSourceAPI); err != nil {
		t.Fatalf("seed: %v", err)
	}

	now := time.Now()
	encoded := buildMacaroon(t, defaultMacaroonOptions(now))
	_, err := Verify(encoded, reg, now)
	if err == nil {
		t.Fatal("expected rejection: grace window already expired")
	}
	if err.Code != string(macaroon.ErrInvalidRootSignature) {
		t.Fatalf("want invalid_root_signature, got %s", err.Code)
	}
}

func TestVerify_PeekOrgID_EmptyOrgID(t *testing.T) {
	// Hand-craft a base64url JSON with no org_id field.
	raw := []byte(`{"v":1}`)
	b64 := macaroon.BytesToBase64url(raw)
	_, err := Verify(b64, newTestRegistry(t), time.Now())
	if err == nil || !strings.Contains(err.Message, "org_id") {
		t.Fatalf("want org_id error, got %+v", err)
	}
}

func TestAdapterError_Error(t *testing.T) {
	// Sanity: the Error() string includes the code and message so a
	// log line is debuggable.
	e := &AdapterError{Code: "x", HTTPStatus: 401, Message: "y"}
	if got := e.Error(); !strings.Contains(got, "x") || !strings.Contains(got, "y") {
		t.Fatalf("Error() missing fields: %s", got)
	}
}

// An org can sign block 0 with an Ed25519 key: the registry stores 64
// hex characters and the verifier reads the algorithm from the length.
func TestVerify_Ed25519OrgKey(t *testing.T) {
	org, err := macaroon.KeyPairFromPrivate(macaroon.AlgEd25519, mustHexBytes(strings.Repeat("33", 32)))
	if err != nil {
		t.Fatal(err)
	}
	reg := trust.New()
	if err := reg.Upsert(trust.Org{OrgID: testOrgID, Pubkey: org.Pub.Key, IssuerURL: "https://hive.test"}, trust.SeedSourceAPI); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	now := time.Now()
	person, err := macaroon.KeyPairFromPrivate(macaroon.AlgEd25519, testUserPriv())
	if err != nil {
		t.Fatal(err)
	}
	root, err := macaroon.SignRoot(testOrgID, macaroon.Caveats{
		RunID: "ua_ed25519", UserID: testUserID,
		IAT: now.Add(-time.Minute).UTC().Format(time.RFC3339), Exp: now.Add(time.Hour).UTC().Format(time.RFC3339),
		Nonce: "cccc000000000000000000000000cccc",
	}, person.Pub, org)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := macaroon.EncodeToken(macaroon.Token{V: 2, OrgID: testOrgID, Blocks: []macaroon.Block{root}, Proof: macaroon.BytesToHex(person.Priv)})
	if err != nil {
		t.Fatal(err)
	}
	claims, vErr := Verify(encoded, reg, now)
	if vErr != nil {
		t.Fatalf("verify: %v", vErr)
	}
	if claims.UserID != testUserID || claims.RunID != "ua_ed25519" {
		t.Fatalf("claims: %+v", claims)
	}
}

// Every later block's run id is keyed under the grant's, so no holder
// can name a run outside its own grant.
func TestVerify_ScopesRunIDsToTheGrant(t *testing.T) {
	reg := newTestRegistry(t)
	now := time.Now()
	opts := defaultMacaroonOptions(now)
	sameAsGrant := appendBlock(t, buildMacaroon(t, opts), macaroon.Caveats{
		RunID: opts.grantRunID,
		IAT:   now.UTC().Format(time.RFC3339),
		Exp:   now.Add(time.Minute).UTC().Format(time.RFC3339),
		Nonce: "cccc000000000000000000000000cccc",
	})
	claims, err := Verify(sameAsGrant, reg, now)
	if err != nil {
		t.Fatalf("verify: %+v", err)
	}
	want := []string{opts.grantRunID, opts.grantRunID + ":" + opts.runID, opts.grantRunID}
	for i, l := range claims.Chain {
		if l.RunID != want[i] {
			t.Errorf("chain[%d].RunID = %q, want %q", i, l.RunID, want[i])
		}
	}
	if claims.RunID != opts.grantRunID {
		t.Errorf("RunID = %q, want the last block's", claims.RunID)
	}

	claims, err = Verify(buildMacaroon(t, opts), reg, now)
	if err != nil {
		t.Fatalf("verify: %+v", err)
	}
	if claims.RunID != opts.scopedRunID() {
		t.Errorf("RunID = %q, want %q", claims.RunID, opts.scopedRunID())
	}
}

// A grant id with the separator in it could be the prefix of another
// grant's, so the gateway refuses it.
func TestVerify_GrantRunIDWithSeparator_Malformed(t *testing.T) {
	reg := newTestRegistry(t)
	now := time.Now()
	opts := defaultMacaroonOptions(now)
	opts.grantRunID = "ua_bob:r_1"
	_, err := Verify(buildMacaroon(t, opts), reg, now)
	if err == nil || err.Code != string(macaroon.ErrMacaroonMalformed) || err.HTTPStatus != 401 {
		t.Fatalf("want macaroon_malformed 401, got %+v", err)
	}
}

// The v1 unwrap, through the adapter: a token with its last block
// dropped keeps a proof that no longer matches, and is refused.
func TestVerify_TruncatedTokenRefused(t *testing.T) {
	reg := newTestRegistry(t)
	now := time.Now()
	raw, err := macaroon.Base64urlToBytes(buildMacaroon(t, defaultMacaroonOptions(now)))
	if err != nil {
		t.Fatal(err)
	}
	var tok macaroon.Token
	if err := json.Unmarshal(raw, &tok); err != nil {
		t.Fatal(err)
	}
	tok.Blocks = tok.Blocks[:1]
	encoded, err := macaroon.EncodeToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	_, vErr := Verify(encoded, reg, now)
	if vErr == nil || vErr.Code != string(macaroon.ErrInvalidProof) {
		t.Fatalf("want invalid_proof, got %+v", vErr)
	}
}
