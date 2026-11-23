package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	macaroon "github.com/stakwork/mothership/auth/go"
	"github.com/stakwork/mothership/internal/trust"
)

// HeaderName is the canonical HTTP header carrying the wire-format
// macaroon. Matches the swarm-side issuer and the phase-4 wire spec.
const HeaderName = "x-macaroon"

// ErrMissingMacaroon is returned by Verify when no x-macaroon header
// was supplied. Distinguished from a bad macaroon so the caller can
// pick the right reject reason ("macaroon_required" vs "invalid").
var ErrMissingMacaroon = &AdapterError{
	Code:       "macaroon_required",
	HTTPStatus: 401,
	Message:    "x-macaroon header is required",
}

// ErrUntrustedOrg is returned when the macaroon's org_id has no entry
// in the trust registry. Surfaced as 401 (not 403): from the
// verifier's perspective the caller is not authenticated, full stop —
// we have no public key to evaluate their claim of identity.
var ErrUntrustedOrg = &AdapterError{
	Code:       "untrusted_org",
	HTTPStatus: 401,
	Message:    "org is not in this swarm's trust registry",
}

// AdapterError is the adapter-shaped failure mode, with enough info
// for the LLMPre hook to turn it into a bifrost.Error. Wraps the
// pure verifier's *macaroon.VerifyError when applicable.
//
// Kept distinct from macaroon.VerifyError because the adapter has
// its own failure axes (missing header, untrusted org, Redis
// unavailable) that don't exist in the pure verifier.
type AdapterError struct {
	Code       string                // machine-readable, stable across versions
	HTTPStatus int                   // 401 (auth) or 402 (budget) — phase-6 vocab
	Message    string                // human-readable diagnostic for logs
	Cause      *macaroon.VerifyError // non-nil when the failure came from the pure verifier
}

func (e *AdapterError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (%v)", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Verify is the adapter's single entry point. Takes the wire-format
// macaroon (base64url string from the x-macaroon header), the trust
// registry to look up the org's policy in, and the current time;
// returns verified claims or an *AdapterError with a stable Code.
//
// Verify does NOT touch Redis. Revocation checks live in
// CheckRevocations (revocation.go) and run AFTER the signature
// verifies, so an unsigned-but-revoked macaroon still gets the right
// rejection reason ("invalid signature" beats "revoked"). The hook
// orchestration in enforcement.go composes the two.
func Verify(macaroonB64 string, registry *trust.Registry, now time.Time) (*macaroon.Claims, *AdapterError) {
	if macaroonB64 == "" {
		return nil, ErrMissingMacaroon
	}

	orgID, raw, err := peekOrgID(macaroonB64)
	if err != nil {
		return nil, &AdapterError{
			Code:       string(macaroon.ErrMacaroonMalformed),
			HTTPStatus: 401,
			Message:    fmt.Sprintf("malformed macaroon: %v", err),
		}
	}

	if registry == nil {
		// The plugin can be brought up in test setups without a
		// registry (admin server tests, fixture loaders). Refusing
		// here surfaces the misconfiguration clearly rather than
		// silently passing every macaroon as untrusted.
		return nil, &AdapterError{
			Code:       "trust_registry_unavailable",
			HTTPStatus: 401,
			Message:    "trust registry not configured",
		}
	}

	org, ok := registry.Get(orgID)
	if !ok {
		return nil, ErrUntrustedOrg
	}

	// Build a Policy per candidate key (active + any non-expired
	// grace keys) and try each. Phase-5 says: during the grace
	// window, accept signatures by either old or new key; after
	// grace_until, only the active key verifies.
	candidates := candidatePolicies(org, now)
	if len(candidates) == 0 {
		// Shouldn't happen — trust.Org.validate() rejects empty
		// active pubkeys at insert time — but defense in depth.
		return nil, ErrUntrustedOrg
	}

	var lastVerifyErr *macaroon.VerifyError
	for _, policy := range candidates {
		claims, vErr := macaroon.VerifyJSON(raw, policy, now)
		if vErr == nil {
			if err := scopeRunIDs(claims); err != nil {
				return nil, err
			}
			return claims, nil
		}
		var ve *macaroon.VerifyError
		if errors.As(vErr, &ve) {
			lastVerifyErr = ve
			// Only re-try with a different key when the failure was
			// signature-related; anything structural (malformed,
			// expired, a later block's signature, the proof) reproduces against
			// every key, so short-circuit those.
			if ve.Code != macaroon.ErrInvalidRootSignature {
				break
			}
			continue
		}
		// Non-VerifyError shouldn't happen; surface as a malformed
		// failure so the rejection reason stays specific.
		return nil, &AdapterError{
			Code:       "verify_internal_error",
			HTTPStatus: 401,
			Message:    vErr.Error(),
		}
	}

	if lastVerifyErr == nil {
		// Defensive: candidates was empty above; we already returned.
		return nil, ErrUntrustedOrg
	}
	return nil, &AdapterError{
		Code:       string(lastVerifyErr.Code),
		HTTPStatus: 401,
		Message:    lastVerifyErr.Detail,
		Cause:      lastVerifyErr,
	}
}

// runScopeSep joins the grant's run_id and a later block's.
const runScopeSep = ":"

// scopeRunIDs puts every later block's run id under block 0's: a block
// that names run "r1" under the grant "ua_x" is counted, capped, killed
// and logged as "ua_x:r1". Everything downstream reads the run ids off
// the claims, so this is the one place the gateway's run ids are made.
//
// Block 0 is the only block the org signs, so its run_id is the one
// name a holder cannot choose. A later block's is any string the holder
// likes: unscoped, it could name another person's grant or run and
// write to those counters (add spend and steps, shorten the TTL so a
// spent cap resets, rewrite the meta the operator UI shows).
//
// A later block that restates the grant's own run_id keeps it: that is
// the grant's counter, which every block under the grant feeds anyway.
// The grant's run_id must not contain the separator, or one grant's id
// could be the prefix of another's.
func scopeRunIDs(claims *macaroon.Claims) *AdapterError {
	if len(claims.Chain) == 0 {
		return nil
	}
	grant := claims.Chain[0].RunID
	if strings.Contains(grant, runScopeSep) {
		return &AdapterError{
			Code:       string(macaroon.ErrMacaroonMalformed),
			HTTPStatus: 401,
			Message:    fmt.Sprintf("block 0's run_id must not contain %q", runScopeSep),
		}
	}
	for i := 1; i < len(claims.Chain); i++ {
		if id := claims.Chain[i].RunID; id != grant {
			claims.Chain[i].RunID = grant + runScopeSep + id
		}
	}
	claims.RunID = claims.Chain[len(claims.Chain)-1].RunID
	return nil
}

// peekOrgID parses just enough of the wire-format macaroon to extract
// org_id for trust-registry lookup. The full strict verification
// happens later in macaroon.VerifyJSON; we accept any well-formed
// JSON with an org_id string here.
//
// Returns the org_id and the raw JSON bytes (so the caller doesn't
// have to base64-decode twice) on success.
func peekOrgID(b64 string) (string, []byte, error) {
	raw, err := macaroon.Base64urlToBytes(b64)
	if err != nil {
		return "", nil, fmt.Errorf("base64url: %w", err)
	}
	var probe struct {
		OrgID string `json:"org_id"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return "", nil, fmt.Errorf("parse json: %w", err)
	}
	if probe.OrgID == "" {
		return "", nil, errors.New("org_id is empty")
	}
	return probe.OrgID, raw, nil
}

// candidatePolicies expands a trust.Org into the list of pure-verifier
// policies we should try, active key first. Grace keys are only
// included while now < grace_until; after that they're treated as
// dropped even if the registry hasn't been re-written yet (the registry
// has no background sweeper — see trust.Registry.Rotate). The verifier
// is the authoritative deadline-checker.
func candidatePolicies(org trust.Org, now time.Time) []macaroon.Policy {
	policies := make([]macaroon.Policy, 0, 1+len(org.GracePubkeys))
	// Active key always first.
	policies = append(policies, singleKeyPolicy(org.Pubkey))

	if org.GraceUntil == "" || len(org.GracePubkeys) == 0 {
		return policies
	}
	deadline, err := time.Parse(time.RFC3339, org.GraceUntil)
	if err != nil || !now.Before(deadline) {
		return policies
	}
	for _, gp := range org.GracePubkeys {
		policies = append(policies, singleKeyPolicy(gp))
	}
	return policies
}

// singleKeyPolicy wraps the org's hex pubkey in the pure verifier's
// Policy envelope. The registry stores only the hex, so the algorithm
// comes from its length (phase 13): 64 hex characters is an Ed25519
// key, anything else is read as a compressed secp256k1 key (66), and
// a wrong length simply fails to verify. Multisig will land via the
// trust registry storing a Policy directly rather than just a Pubkey,
// at which point this helper becomes one branch of a switch.
func singleKeyPolicy(pubkeyHex string) macaroon.Policy {
	alg := macaroon.AlgEcdsaSecp256k1Sha256
	if len(pubkeyHex) == 64 {
		alg = macaroon.AlgEd25519
	}
	return macaroon.Policy{
		Type: macaroon.PolicySingle,
		Key:  &macaroon.PubKey{Alg: alg, Key: pubkeyHex},
	}
}
