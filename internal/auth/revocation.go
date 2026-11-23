package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	macaroon "github.com/stakwork/mothership/auth/go"
	"github.com/stakwork/mothership/internal/redisclient"
)

// Redis key sub-paths (the bifrost: prefix is added by
// redisclient.Key). The full key shapes are documented in
// plans/phases/phase-6-plugin-enforcement.md "Redis schema".
const (
	// revokePrefix + <nonce> tombstones a single layer of the
	// macaroon chain. Presence ⇒ macaroon rejected. TTL = layer.exp.
	revokePrefix = "revoke:"

	// revokeUserBeforePrefix + <user_id> stores an RFC 3339 UTC
	// timestamp. Any token whose block 0 (the org's grant to the
	// person) has an iat strictly before it is rejected (covers
	// org-level offboarding / user re-issuance).
	revokeUserBeforePrefix = "revoke_user_before:"

	// killRunPrefix + <run_id> is the per-run kill switch. Checked
	// for the leaf run AND every ancestor in the chain, so killing a
	// parent kills every descendant. TTL 1h (hot operational state).
	killRunPrefix = "kill:"

	// killAgentPrefix + <agent_name> halts every run whose chain names
	// that agent at any depth (Claims.Lineage), so killing an agent
	// kills its sub-agents too — and a killed agent can't step around
	// it by appending a block under another name. TTL 24h.
	killAgentPrefix = "kill:agent:"
)

// pipelineTimeout bounds a single revocation pipeline round-trip.
// Phase 6 expects sub-millisecond on a co-located Redis; 500 ms is
// our "something is wrong" cliff. Hooks are in the request hot path,
// so we'd rather fail-closed quickly than block.
const pipelineTimeout = 500 * time.Millisecond

// CheckRevocations runs the Redis revocation + kill-switch pipeline
// (phase-6 "Hot path" PIPELINE 1) against the claims produced by
// Verify. Returns nil on "all clear", or an *AdapterError describing
// which nonce / user-level rule / kill switch rejected. Revocations
// are 401s; kills are 402s (the macaroon is still valid — an
// operator chose to stop the run).
//
// Observability mode: when redisclient.Client() returns nil (no
// REDIS_URL configured, or startup ping failed), CheckRevocations
// returns nil — the adapter still verifies signatures and stamps
// claims, it just skips the Redis-backed authoritative-revocation
// step. This matches the phase-6 contract: "verify signatures and
// stamp claims" works without Redis; revocation enforcement is the
// piece that requires it.
//
// Redis errors: per phase-6 "Failure modes", fail-closed during
// PreHook. We surface a synthetic AdapterError with
// Code="revocation_check_unavailable" and HTTPStatus=401 so the
// caller can short-circuit. The caller is free to demote this to
// observability behavior under shadow mode — see enforcement.go.
func CheckRevocations(ctx context.Context, claims *macaroon.Claims) *AdapterError {
	rdb := redisclient.Client()
	if rdb == nil {
		// Observability mode is part of the contract; not an error.
		return nil
	}
	if claims == nil {
		return &AdapterError{
			Code:       "verify_internal_error",
			HTTPStatus: 401,
			Message:    "nil claims passed to revocation check",
		}
	}

	pctx, cancel := context.WithTimeout(ctx, pipelineTimeout)
	defer cancel()

	// PIPELINE 1 from phase-6 "Hot path" — every nonce EXISTS lookup
	// plus the user-level GET, all in one round-trip. Even if some
	// of the EXISTS returns 1 we still evaluate after the trip so
	// the failure reason is deterministic (we always check ua first,
	// then user-level, then inv, then atts).
	pipe := rdb.Pipeline()

	nonceCmds := make(map[string]*redis.IntCmd, len(claims.Nonces))
	for _, n := range claims.Nonces {
		if n == "" {
			continue
		}
		nonceCmds[n] = pipe.Exists(pctx, redisclient.Key(revokePrefix+n))
	}
	userBeforeCmd := pipe.Get(pctx, redisclient.Key(revokeUserBeforePrefix+claims.UserID))

	// Kill switches ride the same round-trip. One EXISTS per distinct
	// run_id in the chain (outermost first, so a parent kill reports
	// the parent's id), plus one per distinct agent in the lineage.
	runIDs := chainRunIDs(claims)
	killRunCmds := make([]*redis.IntCmd, len(runIDs))
	for i, id := range runIDs {
		killRunCmds[i] = pipe.Exists(pctx, redisclient.Key(killRunPrefix+id))
	}
	agents := chainAgents(claims)
	killAgentCmds := make([]*redis.IntCmd, len(agents))
	for i, a := range agents {
		killAgentCmds[i] = pipe.Exists(pctx, redisclient.Key(killAgentPrefix+a))
	}

	if _, err := pipe.Exec(pctx); err != nil && !errors.Is(err, redis.Nil) {
		// Exec returns the first non-Nil error; redis.Nil is the
		// expected sentinel when GET misses, so filter it out.
		return &AdapterError{
			Code:       "revocation_check_unavailable",
			HTTPStatus: 401,
			Message:    fmt.Sprintf("redis pipeline: %v", err),
		}
	}

	// Walk in a deterministic order matching the claims-side nonce
	// list: ua → inv → atts. Claims.Nonces is built in exactly that
	// order (see pure verifier verify.go) so iterating it here
	// gives the same priority.
	for i, n := range claims.Nonces {
		cmd, ok := nonceCmds[n]
		if !ok {
			continue
		}
		exists, err := cmd.Result()
		if err != nil {
			return &AdapterError{
				Code:       "revocation_check_unavailable",
				HTTPStatus: 401,
				Message:    fmt.Sprintf("redis exists %s: %v", redactNonce(n), err),
			}
		}
		if exists == 1 {
			return &AdapterError{
				Code:       revokeCodeFor(i),
				HTTPStatus: 401,
				Message:    fmt.Sprintf("nonce %s is revoked", redactNonce(n)),
			}
		}
	}

	// User-level revocation: compare block 0's iat (the org's grant
	// to the person) against the stored cutoff — not a later block's,
	// see "revoke_user_before" in the phase-6 schema.
	cutoffRaw, err := userBeforeCmd.Result()
	switch {
	case errors.Is(err, redis.Nil):
		// No user-level revocation set; happy path.
	case err != nil:
		return &AdapterError{
			Code:       "revocation_check_unavailable",
			HTTPStatus: 401,
			Message:    fmt.Sprintf("redis get user_before %s: %v", claims.UserID, err),
		}
	default:
		if cutoff, parseErr := time.Parse(time.RFC3339, cutoffRaw); parseErr == nil {
			uaIAT, parseErr2 := uaIATFromClaims(claims)
			if parseErr2 == nil && uaIAT.Before(cutoff) {
				return &AdapterError{
					Code:       "user_authorization_revoked",
					HTTPStatus: 401,
					Message: fmt.Sprintf("user %s authorization issued at %s is before revoke cutoff %s",
						claims.UserID, uaIAT.Format(time.RFC3339), cutoffRaw),
				}
			}
		}
		// A malformed cutoff string is logged at the call site; we
		// fail-open on garbage rather than blanket-reject every
		// macaroon for a user. The cutoff is operator-written and
		// shouldn't arrive malformed, but if it does the safer
		// behavior is to let the macaroon through (the layer-nonce
		// revocations above still apply).
	}

	// Kill switches, after revocation so a revoked-and-killed
	// macaroon reports the stronger (auth) reason. Per-run first,
	// then per-agent, matching phase-6 "Hot path" step 2.
	for i, cmd := range killRunCmds {
		exists, err := cmd.Result()
		if err != nil {
			return &AdapterError{
				Code:       "revocation_check_unavailable",
				HTTPStatus: 401,
				Message:    fmt.Sprintf("redis exists kill:%s: %v", runIDs[i], err),
			}
		}
		if exists == 1 {
			return &AdapterError{
				Code:       "run_killed",
				HTTPStatus: 402,
				Message:    fmt.Sprintf("run %s was killed by an operator", runIDs[i]),
			}
		}
	}
	for i, cmd := range killAgentCmds {
		exists, err := cmd.Result()
		if err != nil {
			return &AdapterError{
				Code:       "revocation_check_unavailable",
				HTTPStatus: 401,
				Message:    fmt.Sprintf("redis exists kill:agent:%s: %v", agents[i], err),
			}
		}
		if exists == 1 {
			return &AdapterError{
				Code:       "agent_killed",
				HTTPStatus: 402,
				Message:    fmt.Sprintf("agent %s was killed by an operator", agents[i]),
			}
		}
	}

	return nil
}

// chainAgents returns every distinct agent named in the chain,
// outermost first, falling back to Claims.AgentName for callers that
// only set the leaf.
func chainAgents(claims *macaroon.Claims) []string {
	out := make([]string, 0, len(claims.Lineage)+1)
	seen := map[string]bool{}
	for _, a := range append(append([]string(nil), claims.Lineage...), claims.AgentName) {
		if a != "" && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

// chainRunIDs returns every distinct run_id in the verified chain,
// outermost (block 0) first, leaf last. Falls back to Claims.RunID
// when the chain is empty so callers that only populate the leaf
// still get their kill checked.
func chainRunIDs(claims *macaroon.Claims) []string {
	ids := make([]string, 0, len(claims.Chain)+1)
	seen := make(map[string]bool, len(claims.Chain)+1)
	for _, layer := range claims.Chain {
		if layer.RunID == "" || seen[layer.RunID] {
			continue
		}
		seen[layer.RunID] = true
		ids = append(ids, layer.RunID)
	}
	if claims.RunID != "" && !seen[claims.RunID] {
		ids = append(ids, claims.RunID)
	}
	return ids
}

// revokeCodeFor maps the position of a revoked nonce in the
// Claims.Nonces slice to a specific failure code, so an operator
// reading a 401 can tell whether it was the org's grant to the person
// (block 0, issuance) or a later block that was revoked.
//
// Claims.Nonces order is fixed by the pure verifier: one per block,
// block 0 first.
func revokeCodeFor(i int) string {
	switch i {
	case 0:
		return "user_authorization_revoked"
	default:
		return "macaroon_revoked"
	}
}

// uaIATFromClaims pulls block 0's iat out of the verified claims —
// the phase-6 comparison axis for revoke_user_before (not a later
// block's: user-level revocation invalidates the org's grants to the
// person, and a run started after the cutoff under a re-issued grant
// is fine). The pure verifier surfaces it as Claims.IAT.
func uaIATFromClaims(claims *macaroon.Claims) (time.Time, error) {
	return time.Parse(time.RFC3339, claims.IAT)
}

// redactNonce shortens a 32-char hex nonce to its first 8 chars +
// "…" for logging. Nonces aren't secret per se — they're revocation
// handles — but a full nonce in a log line is noisy and the prefix
// is enough to correlate with the revocation that fired.
func redactNonce(n string) string {
	if len(n) <= 8 {
		return n
	}
	return n[:8] + "…"
}
