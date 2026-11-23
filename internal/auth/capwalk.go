package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	macaroon "github.com/stakwork/mothership/auth/go"
	"github.com/stakwork/mothership/internal/duration"
	"github.com/stakwork/mothership/internal/redisclient"
)

// The cap walk — phase-6 "Hot path" PIPELINE 2. Reads the
// accumulators PostLLMHook writes (accumulator.go) and compares them
// against every cap the verified macaroon and the plugin config
// declare. One pipelined Redis round-trip, then a fixed-order
// evaluation so the rejection reason is deterministic:
//
//  1. cost:run:<r>   >= layer.MaxCostUSD          every layer  → run_cost_exceeded
//  2. cost:run:<r>   >= layer.Realms[realm] cap   every layer  → realm_budget_exceeded
//  3. steps:run:<r>  >= layer.MaxSteps            every layer  → run_step_exceeded
//  4. cost:agent:<a>:<bucket> >= agent_budgets cap             → agent_cost_exceeded
//
// The walk covers every block, leaf first, then each ancestor up to
// block 0 (the person's grant): a child whose own $2 cap is untouched
// is still rejected when its parent's $5 is gone, because the parent's
// counter includes every descendant's spend. That is also why v2 has
// no narrowing check at verify time (phase 13): a child that claims
// more than its parent is stopped here by the parent's cap. Blocks
// that share a run_id share a counter and each one's caps apply.
//
// Comparisons use *past* spend — the call's own price isn't known
// before it runs — so a run can overshoot by up to one call's cost
// (times concurrency). Phase 6 "Pipelining and atomicity" accepts
// that. `>=` rather than `>` so a run that lands exactly on its cap
// is done.
//
// A cap of 0 means "no cap" for macaroon caveats (the field is
// optional at every layer). For agent_budgets it means the opposite:
// an entry with cap_usd 0 blocks the agent outright — that is how
// phase 6 says to stop an agent permanently (a kill:agent key only
// lasts 24h).
//
// Fail-closed on Redis errors (402 budget_check_unavailable); no-op
// in observability mode (Redis unconfigured), like CheckRevocations.

// capLayer is one block's caps, in walk order.
type capLayer struct {
	runID       string
	maxCostUSD  float64
	realmCapUSD float64
	maxSteps    int
}

// CheckCaps runs the cap walk. realmID is the swarm's own realm (from
// the trust registry; "" for single-swarm deployments), used to pick
// each block's per-realm cap out of its realms. Returns nil on "within
// every cap".
func CheckCaps(ctx context.Context, claims *macaroon.Claims, realmID string, now time.Time) *AdapterError {
	rdb := redisclient.Client()
	if rdb == nil {
		return nil
	}
	if claims == nil {
		return &AdapterError{
			Code:       "verify_internal_error",
			HTTPStatus: 401,
			Message:    "nil claims passed to cap walk",
		}
	}

	layers := capLayers(claims, realmID)
	agentBudget, agentConfigured := GetConfig().AgentBudgets[claims.AgentName]

	pctx, cancel := context.WithTimeout(ctx, pipelineTimeout)
	defer cancel()
	pipe := rdb.Pipeline()

	// One read per counter, however many blocks share it.
	costCmds := map[string]*redis.StringCmd{}
	stepCmds := map[string]*redis.StringCmd{}
	for _, l := range layers {
		if (l.maxCostUSD > 0 || l.realmCapUSD > 0) && costCmds[l.runID] == nil {
			costCmds[l.runID] = pipe.HGet(pctx, redisclient.Key(costRunPrefix+l.runID), "total")
		}
		if l.maxSteps > 0 && stepCmds[l.runID] == nil {
			stepCmds[l.runID] = pipe.HGet(pctx, redisclient.Key(stepsRunPrefix+l.runID), "total")
		}
	}
	var agentCmd *redis.StringCmd
	var agentBucket string
	if agentConfigured && agentBudget.CapUSD > 0 && agentBudget.Window != "" {
		if w, err := duration.Parse(agentBudget.Window); err == nil {
			agentBucket = w.BucketKey(now)
			agentCmd = pipe.HGet(pctx, redisclient.Key(costAgentPrefix+claims.AgentName+":"+agentBucket), "total")
		}
		// An unparseable window is logged by the accumulator on
		// every write; nothing to compare here, so no cap applies.
	}

	if _, err := pipe.Exec(pctx); err != nil && !errors.Is(err, redis.Nil) {
		return budgetUnavailable(fmt.Sprintf("redis pipeline: %v", err))
	}

	spent := map[string]float64{}
	for id, cmd := range costCmds {
		v, err := hashFloat(cmd)
		if err != nil {
			return budgetUnavailable(fmt.Sprintf("cost:run:%s: %v", id, err))
		}
		spent[id] = v
	}

	// 1. Per-run cost, leaf first.
	for _, l := range layers {
		if l.maxCostUSD > 0 && spent[l.runID] >= l.maxCostUSD {
			return &AdapterError{
				Code:       "run_cost_exceeded",
				HTTPStatus: 402,
				Message:    fmt.Sprintf("run %s spent $%.4f of its $%.2f cap", l.runID, spent[l.runID], l.maxCostUSD),
			}
		}
	}

	// 2. Per-realm cost, leaf first.
	for _, l := range layers {
		if l.realmCapUSD > 0 && spent[l.runID] >= l.realmCapUSD {
			return &AdapterError{
				Code:       "realm_budget_exceeded",
				HTTPStatus: 402,
				Message: fmt.Sprintf("run %s spent $%.4f of its $%.2f cap for realm %s",
					l.runID, spent[l.runID], l.realmCapUSD, realmID),
			}
		}
	}

	// 3. Per-run steps, same walk.
	for _, l := range layers {
		cmd := stepCmds[l.runID]
		if l.maxSteps <= 0 || cmd == nil {
			continue
		}
		steps, err := hashInt(cmd)
		if err != nil {
			return budgetUnavailable(fmt.Sprintf("steps:run:%s: %v", l.runID, err))
		}
		if steps >= int64(l.maxSteps) {
			return &AdapterError{
				Code:       "run_step_exceeded",
				HTTPStatus: 402,
				Message:    fmt.Sprintf("run %s used %d of its %d steps", l.runID, steps, l.maxSteps),
			}
		}
	}

	// 4. Per-agent windowed budget.
	if agentConfigured && agentBudget.CapUSD <= 0 {
		return &AdapterError{
			Code:       "agent_cost_exceeded",
			HTTPStatus: 402,
			Message:    fmt.Sprintf("agent %s has a $0 budget (blocked by operator config)", claims.AgentName),
		}
	}
	if agentCmd != nil {
		spent, err := hashFloat(agentCmd)
		if err != nil {
			return budgetUnavailable(fmt.Sprintf("cost:agent:%s: %v", claims.AgentName, err))
		}
		if spent >= agentBudget.CapUSD {
			return &AdapterError{
				Code:       "agent_cost_exceeded",
				HTTPStatus: 402,
				Message: fmt.Sprintf("agent %s spent $%.4f of its $%.2f/%s cap (bucket %s)",
					claims.AgentName, spent, agentBudget.CapUSD, agentBudget.Window, agentBucket),
			}
		}
	}

	return nil
}

// capLayers returns every block's caps in walk order: leaf first, then
// each ancestor out to block 0. Claims.Chain is outermost-first. Blocks
// that share a run_id are all kept: each one's caps apply to the
// shared counter.
func capLayers(claims *macaroon.Claims, realmID string) []capLayer {
	out := make([]capLayer, 0, len(claims.Chain))
	for i := len(claims.Chain) - 1; i >= 0; i-- {
		l := claims.Chain[i]
		if l.RunID == "" {
			continue
		}
		var realmCap float64
		if realmID != "" {
			realmCap = l.Realms[realmID].MaxCostUSD
		}
		out = append(out, capLayer{runID: l.RunID, maxCostUSD: l.MaxCostUSD, realmCapUSD: realmCap, maxSteps: l.MaxSteps})
	}
	return out
}

func budgetUnavailable(detail string) *AdapterError {
	return &AdapterError{
		Code:       "budget_check_unavailable",
		HTTPStatus: 402,
		Message:    detail,
	}
}

// hashFloat / hashInt read an HGET result, treating a missing key or
// field (redis.Nil) as zero — a run that has never spent is at $0.
func hashFloat(cmd *redis.StringCmd) (float64, error) {
	v, err := cmd.Float64()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	return v, err
}

func hashInt(cmd *redis.StringCmd) (int64, error) {
	v, err := cmd.Int64()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	return v, err
}
