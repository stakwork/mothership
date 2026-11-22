package main

// The gateway as its own OIDC issuer, so a provider that federates
// workload identity (Anthropic) trusts it with no static API key.
//
// With BIFROST_IDENTITY_ISSUER set to an https URL whose /.well-known/*
// reaches this listener, the wrapper:
//
//  1. keeps a P-256 signing key at <app-dir>/identity/signing-key.pem,
//     made on first boot (0600, in the data volume, so it survives
//     restarts and is in backups);
//  2. serves the public half at /.well-known/openid-configuration and
//     /.well-known/mothership-jwks.json on the public listener;
//  3. writes a freshly signed JWT to identityTokenPath before
//     bifrost-http starts, then every identityTokenInterval for the life
//     of the container.
//
// Bifrost does the rest. An Anthropic key whose anthropic_key_config has
// a workload_identity with identity_source {type: file, path:
// identityTokenPath} reads the file on each exchange, trades it at
// POST {base_url}/v1/oauth/token for a short-lived sk-ant-oat01 token,
// caches and refreshes that, and sends it as a bearer (bifrost core
// providers/anthropic/workloadidentity.go). Whoever manages the gateway
// (Stadeum) writes that key through Bifrost's API, as it writes a static
// one today, and registers the issuer with Anthropic.
//
// The JWT: header {alg ES256, typ JWT, kid}; claims iss, sub
// identitySubject, aud identityAudience, iat, exp (iat +
// identityTokenLifetime) and a random jti. The jti makes it single-use at
// Anthropic. Bifrost knows (hasJTIClaim): it keeps serving the token it
// has and looks at the file again every 5 s inside its 120 s refresh
// window until the file changes, so a 30 s rewrite always lands in time.
// 30 minutes of life gives access tokens of about an hour: Anthropic
// grants the lesser of the federation rule's lifetime and twice the
// assertion's remaining life.
//
// Unset, nothing here runs and /.well-known/* reaches bifrost-http as
// before. A key that cannot be loaded or made turns the issuer off for
// this boot (logged); the other providers keep working.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	envIdentityIssuer = "BIFROST_IDENTITY_ISSUER"

	// identityTokenPath is where the current identity token is written.
	// Bifrost reads identity token files only under /var/run/secrets or
	// /run/secrets unless BIFROST_OIDC_ALLOWED_CREDENTIAL_DIRS says
	// otherwise; the Dockerfile makes this directory, owned by app.
	identityTokenPath = "/run/secrets/mothership/anthropic-identity-token"

	// identityKeyFile is the signing key, under the app dir.
	identityKeyFile = "identity/signing-key.pem"

	identitySubject       = "mothership"
	identityAudience      = "https://api.anthropic.com"
	identityTokenLifetime = 30 * time.Minute
	identityTokenInterval = 30 * time.Second

	wellKnownDiscoveryPath = "/.well-known/openid-configuration"
	// Not /.well-known/jwks.json: bifrost-http registers that path for
	// its MCP OAuth server (handlers/mcpoauth2discovery.go, transports
	// v2.6.0; 404 unless MCP OAuth mode is on). The discovery document
	// names this one, which is all a relying party follows.
	wellKnownJWKSPath = "/.well-known/mothership-jwks.json"
)

// identity is the gateway's issuer: its URL, signing key and where its
// tokens go. now is a field so tests can pin the clock.
type identity struct {
	issuer    string
	key       *ecdsa.PrivateKey
	kid       string
	tokenPath string
	now       func() time.Time
}

// identityFromEnv returns the issuer BIFROST_IDENTITY_ISSUER asks for,
// loading or making its key under appDir; nil when the variable is unset
// or empty.
func identityFromEnv(getenv func(string) string, appDir string) (*identity, error) {
	raw := strings.TrimSpace(getenv(envIdentityIssuer))
	if raw == "" {
		return nil, nil
	}
	issuer, err := parseIssuer(raw)
	if err != nil {
		return nil, err
	}
	key, err := loadOrCreateSigningKey(filepath.Join(appDir, identityKeyFile))
	if err != nil {
		return nil, err
	}
	return newIdentity(issuer, key, identityTokenPath), nil
}

func newIdentity(issuer string, key *ecdsa.PrivateKey, tokenPath string) *identity {
	return &identity{
		issuer:    issuer,
		key:       key,
		kid:       jwkThumbprint(&key.PublicKey),
		tokenPath: tokenPath,
		now:       time.Now,
	}
}

// parseIssuer checks an issuer URL: http(s), a host, no user info, query
// or fragment. A trailing slash is dropped, since the issuer must match
// the JWT's iss byte for byte and the discovery URL is built on it.
func parseIssuer(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%s %q: %w", envIdentityIssuer, raw, err)
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", fmt.Errorf("%s %q: want an http(s) URL with a host, such as https://mothership.example.com", envIdentityIssuer, raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%s %q: an issuer has no user info, query or fragment", envIdentityIssuer, raw)
	}
	return strings.TrimRight(raw, "/"), nil
}

// loadOrCreateSigningKey reads the PKCS#8 P-256 key at path, or makes one
// there when the file does not exist. A file that exists but cannot be
// read as such a key is an error, never replaced: a new key would
// silently stop matching what was registered with the provider.
func loadOrCreateSigningKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		return parseSigningKey(path, data)
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("read signing key %s: %w", path, err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("make signing key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode signing key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("make %s: %w", filepath.Dir(path), err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := writeFileAtomicMode(path, pemBytes, 0o600); err != nil {
		return nil, fmt.Errorf("write signing key: %w", err)
	}
	return key, nil
}

func parseSigningKey(path string, data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("signing key %s: not a PEM PRIVATE KEY block", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("signing key %s: %w", path, err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("signing key %s: want an ECDSA P-256 key", path)
	}
	return key, nil
}

// jwk is the public key as a JSON Web Key (RFC 7517/7518).
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
}

// publicJWK returns the bare public key, coordinates as 32-byte big-endian
// base64url (RFC 7518 §6.2.1).
func publicJWK(pub *ecdsa.PublicKey) jwk {
	enc := base64.RawURLEncoding
	return jwk{
		Kty: "EC",
		Crv: "P-256",
		X:   enc.EncodeToString(pub.X.FillBytes(make([]byte, 32))),
		Y:   enc.EncodeToString(pub.Y.FillBytes(make([]byte, 32))),
	}
}

// jwkThumbprint is the key's RFC 7638 thumbprint: SHA-256 over the
// required members in lexicographic order, base64url. Used as the kid, so
// it changes exactly when the key does.
func jwkThumbprint(pub *ecdsa.PublicKey) string {
	k := publicJWK(pub)
	canonical := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`, k.Crv, k.Kty, k.X, k.Y)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// jwks is the key set served at wellKnownJWKSPath.
func (id *identity) jwks() []byte {
	k := publicJWK(&id.key.PublicKey)
	k.Use, k.Alg, k.Kid = "sig", "ES256", id.kid
	out, _ := json.Marshal(struct {
		Keys []jwk `json:"keys"`
	}{[]jwk{k}})
	return out
}

// discovery is the OpenID Provider metadata served at
// wellKnownDiscoveryPath: enough for a relying party to find and check
// the key set. This issuer only signs identity tokens for itself, so it
// has no authorization endpoint.
func (id *identity) discovery() []byte {
	out, _ := json.Marshal(map[string]any{
		"issuer":                                id.issuer,
		"jwks_uri":                              id.issuer + wellKnownJWKSPath,
		"response_types_supported":              []string{"id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"claims_supported":                      []string{"iss", "sub", "aud", "iat", "exp", "jti"},
	})
	return out
}

// sign returns a new identity token, ES256 over header.claims.
func (id *identity) sign() (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", fmt.Errorf("jti: %w", err)
	}
	now := id.now().UTC()
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": id.kid})
	claims, _ := json.Marshal(map[string]any{
		"iss": id.issuer,
		"sub": identitySubject,
		"aud": identityAudience,
		"iat": now.Unix(),
		"exp": now.Add(identityTokenLifetime).Unix(),
		"jti": base64.RawURLEncoding.EncodeToString(jti),
	})
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, id.key, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	// JWS ES256 is R || S, each 32 bytes big-endian (RFC 7518 §3.4), not ASN.1.
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return signingInput + "." + enc.EncodeToString(sig), nil
}

// writeToken signs a token and replaces the token file with it in one
// rename, so Bifrost never reads half a token.
func (id *identity) writeToken() error {
	token, err := id.sign()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(id.tokenPath), 0o700); err != nil {
		return fmt.Errorf("make %s: %w", filepath.Dir(id.tokenPath), err)
	}
	return writeFileAtomicMode(id.tokenPath, []byte(token+"\n"), 0o600)
}

// run rewrites the token file every interval until ctx ends. A failed
// write is logged once and again when it recovers; the previous token
// stays in the file meanwhile.
func (id *identity) run(ctx context.Context, logger *log.Logger, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	failing := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if err := id.writeToken(); err != nil {
			if !failing {
				logger.Printf("ERROR: identity token not rewritten (retrying every %s; the previous one stays): %v", interval, err)
			}
			failing = true
			continue
		}
		if failing {
			logger.Printf("identity token rewritten again")
			failing = false
		}
	}
}

// wellKnown serves the issuer's discovery document and key set, and hands
// every other request to next.
func (id *identity) wellKnown(next http.Handler) http.Handler {
	discovery, jwks := id.discovery(), id.jwks()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		switch r.URL.Path {
		case wellKnownDiscoveryPath:
			body = discovery
		case wellKnownJWKSPath:
			body = jwks
		default:
			next.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Relying parties cache the key set; Anthropic picks a change up
		// within a minute. Five minutes here is plenty for a key that
		// never changes on its own.
		w.Header().Set("Cache-Control", "public, max-age=300")
		if r.Method == http.MethodGet {
			_, _ = w.Write(body)
		}
	})
}
