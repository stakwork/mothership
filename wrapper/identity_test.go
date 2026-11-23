package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testIdentity(t *testing.T) *identity {
	t.Helper()
	key, err := loadOrCreateSigningKey(filepath.Join(t.TempDir(), identityKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	return newIdentity("https://mothership.example.com", key, filepath.Join(t.TempDir(), "secrets", "token"))
}

// keyFromJWKS rebuilds the public key a relying party would, from the
// served key set alone.
func keyFromJWKS(t *testing.T, body []byte) (*ecdsa.PublicKey, jwk) {
	t.Helper()
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil || len(set.Keys) != 1 {
		t.Fatalf("key set %s: %v", body, err)
	}
	k := set.Keys[0]
	if k.Kty != "EC" || k.Crv != "P-256" || k.Alg != "ES256" || k.Use != "sig" || k.Kid == "" {
		t.Fatalf("jwk = %+v", k)
	}
	coord := func(s string) *big.Int {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil || len(b) != 32 {
			t.Fatalf("coordinate %q: %d bytes, %v", s, len(b), err)
		}
		return new(big.Int).SetBytes(b)
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: coord(k.X), Y: coord(k.Y)}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		t.Fatal("served key is not on P-256")
	}
	return pub, k
}

// verifyJWT checks an ES256 JWT against pub and returns its header and
// claims.
func verifyJWT(t *testing.T, token string, pub *ecdsa.PublicKey) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts", len(parts))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		t.Fatalf("signature: %d bytes, %v", len(sig), err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		t.Fatal("signature does not verify against the served key")
	}
	decode := func(seg string) map[string]any {
		raw, err := base64.RawURLEncoding.DecodeString(seg)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	return decode(parts[0]), decode(parts[1])
}

func TestIdentityFromEnvUnset(t *testing.T) {
	for _, v := range []string{"", "  "} {
		id, err := identityFromEnv(func(string) string { return v }, t.TempDir())
		if id != nil || err != nil {
			t.Fatalf("%q: id=%v err=%v, want nothing", v, id, err)
		}
	}
}

func TestParseIssuer(t *testing.T) {
	good := map[string]string{
		"https://mothership.acme.stakwork.ai":  "https://mothership.acme.stakwork.ai",
		"https://mothership.acme.stakwork.ai/": "https://mothership.acme.stakwork.ai",
		"https://example.com/tenant/a":         "https://example.com/tenant/a",
		"http://mothership.stadeum.localhost":  "http://mothership.stadeum.localhost",
	}
	for in, want := range good {
		if got, err := parseIssuer(in); err != nil || got != want {
			t.Errorf("parseIssuer(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"mothership.example.com", "ftp://example.com", "https://", "/relative",
		"https://u:p@example.com", "https://example.com?x=1", "https://example.com#f",
	} {
		if got, err := parseIssuer(in); err == nil {
			t.Errorf("parseIssuer(%q) = %q, want an error", in, got)
		}
	}
}

func TestSigningKeyMadeOnceAndKept(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity", "signing-key.pem")
	first, err := loadOrCreateSigningKey(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %o, want 600", perm)
	}
	again, err := loadOrCreateSigningKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Equal(again) {
		t.Fatal("second load made a new key instead of reading the first")
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file left behind: %v", err)
	}
}

func TestUnreadableSigningKeyIsNotReplaced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing-key.pem")
	garbage := []byte("not a key\n")
	if err := os.WriteFile(path, garbage, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateSigningKey(path); err == nil {
		t.Fatal("garbage accepted as a key")
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, garbage) {
		t.Fatal("an unreadable key file was overwritten")
	}
}

func TestTokenVerifiesAgainstServedKeySet(t *testing.T) {
	id := testIdentity(t)
	fixed := time.Unix(1_800_000_000, 0)
	id.now = func() time.Time { return fixed }

	pub, k := keyFromJWKS(t, id.jwks())
	if k.Kid != id.kid {
		t.Fatalf("served kid %q, signer kid %q", k.Kid, id.kid)
	}
	// RFC 7638, recomputed here from the served members alone.
	sum := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + k.X + `","y":"` + k.Y + `"}`))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); k.Kid != want {
		t.Fatalf("kid %q, RFC 7638 thumbprint %q", k.Kid, want)
	}

	tok, err := id.sign()
	if err != nil {
		t.Fatal(err)
	}
	header, claims := verifyJWT(t, tok, pub)
	if header["alg"] != "ES256" || header["typ"] != "JWT" || header["kid"] != id.kid {
		t.Errorf("header = %v", header)
	}
	want := map[string]any{
		"iss": "https://mothership.example.com",
		"sub": identitySubject,
		"aud": identityAudience,
		"iat": float64(fixed.Unix()),
		"exp": float64(fixed.Add(identityTokenLifetime).Unix()),
	}
	for name, v := range want {
		if claims[name] != v {
			t.Errorf("claim %s = %v, want %v", name, claims[name], v)
		}
	}
	jti, _ := claims["jti"].(string)
	if len(jti) < 20 {
		t.Errorf("jti %q too short to be unique", jti)
	}

	tok2, _ := id.sign()
	_, claims2 := verifyJWT(t, tok2, pub)
	if claims2["jti"] == jti {
		t.Error("two tokens share a jti; Anthropic accepts each jti once")
	}
}

func TestDiscoveryNamesTheKeySet(t *testing.T) {
	id := testIdentity(t)
	var doc map[string]any
	if err := json.Unmarshal(id.discovery(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["issuer"] != id.issuer || doc["jwks_uri"] != id.issuer+"/.well-known/mothership-jwks.json" {
		t.Fatalf("discovery = %v", doc)
	}
}

func TestWriteTokenReplacesTheFile(t *testing.T) {
	id := testIdentity(t)
	if err := id.writeToken(); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(id.tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(id.tokenPath)
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("token file mode = %o, want 600", perm)
	}
	if err := id.writeToken(); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(id.tokenPath)
	if bytes.Equal(first, second) {
		t.Fatal("token file did not change")
	}
	pub, _ := keyFromJWKS(t, id.jwks())
	verifyJWT(t, string(second), pub)
	if _, err := os.Stat(id.tokenPath + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file left behind: %v", err)
	}
}

func TestRunRotatesUntilCancelled(t *testing.T) {
	id := testIdentity(t)
	if err := id.writeToken(); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(id.tokenPath)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		id.run(ctx, log.New(io.Discard, "", 0), 10*time.Millisecond)
		close(done)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		now, _ := os.ReadFile(id.tokenPath)
		if len(now) > 0 && !bytes.Equal(now, before) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("token file never rotated")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("run did not stop on cancel")
	}
}

func TestWellKnownRoutes(t *testing.T) {
	id := testIdentity(t)
	var nextHit string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextHit = r.URL.Path
		w.WriteHeader(http.StatusTeapot)
	})
	h := id.wellKnown(next)

	for path, want := range map[string][]byte{
		"/.well-known/openid-configuration": id.discovery(),
		"/.well-known/mothership-jwks.json": id.jwks(),
	} {
		nextHit = ""
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), want) || nextHit != "" {
			t.Errorf("GET %s: %d %q (next saw %q)", path, rec.Code, rec.Body.String(), nextHit)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("GET %s: Content-Type %q", path, ct)
		}

		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}")))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s: %d, want 405", path, rec.Code)
		}
	}

	// /.well-known/jwks.json is bifrost's own (MCP OAuth), not the issuer's.
	for _, path := range []string{"/v1/messages", "/.well-known/jwks.json", "/.well-known/other", "/anthropic/v1/messages"} {
		nextHit = ""
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if nextHit != path || rec.Code != http.StatusTeapot {
			t.Errorf("GET %s: not handed on (next saw %q, code %d)", path, nextHit, rec.Code)
		}
	}
}
