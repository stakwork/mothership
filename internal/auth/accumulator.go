package auth

import (
	"context"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	macaroon "github.com/stakwork/mothership/auth/go"
	"github.com/stakwork/mothership/internal/duration"
	"github.com/stakwork/mothership/internal/pluginlog"
	"github.com/stakwork/mothership/internal/redisclient"
)

// Redis key sub-paths for the phase-6 accumulators (the bifrost:
// prefix is added by redisclient.Key). Shapes per
// plans/phases/phase-6-plugin-enforcement.md "Redis schema".
const (
	costRunPrefix   = "cost:run:"   // HASH { total: float }
	stepsRunPrefix  = "steps:run:"  // HASH { total: int }
	toolsRunPrefix  = "tools:run:"  // LIST, capped at toolHistoryLen
	costAgentPrefix = "cost:agent:" // HASH { total: float }, key + ":" + bucket

	// metaRunPrefix + <run_id> is the run's static shape as the
	// macaroon chain declared it: the caps the cap walk compares
	// against, the layer's expiry, and the parent run (the next
	// layer outward, "" for block 0). Written alongside the
	// accumulators so the operator UI can render "spent $X of $Y" and
	// walk ancestors without a macaroon in hand (phase 9 "cap
	// meters"). `agent` / `user` are only stamped by the run's own
	// calls (the leaf layer) — an ancestor's agent isn't in the
	// child's chain. HASH { max_cost_usd, max_steps, exp, parent,
	// agent, user }; same TTL axis as cost:run.
	metaRunPrefix = "meta:run:"

	// runsUserPrefix + <user_id> indexes the runs a user has driven
	// through this gateway, for /_plugin/users/:id/quota's in-flight
	// list (phase 7). ZSET member = leaf run_id, score = that layer's
	// exp (unix seconds) so readers can prune expired runs by score.
	// The key itself lives runsUserTTL past the last write.
	runsUserPrefix = "runs:user:"
)

// runsUserTTL is the per-user run index's key expiry, refreshed on
// every write. Matches the 7d ceiling on the per-run keys: after a
// week of silence there is no run state left to point at anyway.
const runsUserTTL = 7 * 24 * time.Hour

// toolHistoryLen is the tool-loop detection window: tools:run keeps
// the last N tool names (LPUSH + LTRIM 0 N-1).
const toolHistoryLen = 10

// ApplyToLLMPost is the canonical "call from PostLLMHook" entry
// point for the phase-6 accumulator writes. It walks the verified
// chain and issues one pipelined Redis round-trip:
//
//   - HINCRBYFLOAT cost:run:<r> / HINCRBY steps:run:<r> + EXPIRE,
//     for every distinct run_id in the chain (leaf + ancestors, block
//     0 included) — killing or capping a parent must see descendant
//     spend, and block 0's counter is the person's total under their
//     grant (phase 13; v1 kept that in a separate cost:ua key).
//   - HINCRBYFLOAT cost:agent:<agent>:<bucket> + EXPIRE, for every
//     agent in the lineage that has a configured windowed budget: an
//     agent's budget counts its sub-agents' spend too.
//   - LPUSH/LTRIM tools:run:<leaf> + EXPIRE when the response
//     contained tool calls.
//   - HSET meta:run:<r> (caps, exp, parent link; agent + user on the
//     leaf) + EXPIRE for every layer, so the operator UI can render
//     cap meters and walk ancestors from Redis alone.
//   - ZADD runs:user:<user> <leaf exp> <leaf run_id> + EXPIRE, the
//     per-user in-flight run index behind /_plugin/users/:id/quota.
//
// Fire-and-forget per the phase-6 failure-mode contract: accounting
// fails open. The pipeline runs on a goroutine with its own timeout;
// errors log loudly and are never surfaced to the caller — a Redis
// outage must not block or fail the response. The resulting drift is
// bounded by outage duration × call rate and is reconciled against
// logs.db (which Bifrost's own logging plugin writes after us).
//
// No-op when claims is nil (shadow mode without a verified macaroon)
// or Redis is unconfigured (observability mode).
func ApplyToLLMPost(claims *macaroon.Claims, costUSD float64, toolNames []string) {
	if claims == nil || redisclient.Client() == nil {
		return
	}
	inflight.Add(1)
	go func() {
		defer inflight.Done()
		ctx, cancel := context.WithTimeout(context.Background(), pipelineTimeout)
		defer cancel()
		if err := accumulate(ctx, claims, costUSD, toolNames, time.Now().UTC()); err != nil {
			pluginlog.Warnf(
				"auth: accumulator pipeline failed (spend uncounted this call) run_id=%s agent=%s cost=%.4f: %v",
				claims.RunID, claims.AgentName, costUSD, err,
			)
		}
	}()
}

// inflight counts the accumulator pipelines ApplyToLLMPost has started
// and not finished. Nothing in production waits on it.
var inflight sync.WaitGroup

// WaitForAccumulatorsForTest blocks until every pipeline ApplyToLLMPost
// started has finished. A test calls it before reading the
// accumulators, since the pipeline's commands land one at a time
// (cost:run is visible before steps:run), and before closing the
// Redis client: a pipeline still in flight then fails, and its
// warning lands in whatever the next test does with stderr.
func WaitForAccumulatorsForTest() {
	inflight.Wait()
}

// accumulate is the synchronous pipeline body. Split from
// ApplyToLLMPost so tests can run it deterministically against
// miniredis without racing the goroutine.
//
// Every command is individually idempotent on its own value
// (HINCRBYFLOAT is commutative, LPUSH+LTRIM is bounded, EXPIRE is
// set-not-add and a run's TTL only ever grows), so the pipeline needs
// no transaction — out-of-order or partially-applied writes converge
// to the same state. See phase-6 "Pipelining and atomicity".
func accumulate(
	ctx context.Context,
	claims *macaroon.Claims,
	costUSD float64,
	toolNames []string,
	now time.Time,
) error {
	rdb := redisclient.Client()
	if rdb == nil {
		return nil
	}
	pipe := rdb.Pipeline()

	// Per-run accumulators: every distinct run_id in the chain,
	// outermost first. Each layer's keys get that layer's own TTL
	// axis (clamp(layer.exp - now + 1h, 1h, 7d)) — an ancestor's
	// accumulator must outlive the short-lived leaf that wrote it.
	// TTL refreshes on every write, so an actively-spending run
	// keeps its keys alive for its whole lifetime. A write never
	// shortens it (keepAlive): a block that names another run of the
	// same grant with a short exp must not expire that run's counter
	// early and so reset its cap.
	//
	// The same pass stamps meta:run:<id> for each layer: caps, exp
	// and the parent link (the previous distinct layer). Idempotent —
	// a layer's caveats never change for a given run_id, so re-HSET
	// on every call just refreshes the value. The leaf additionally
	// records its agent and user, which is what the per-user run
	// index and the quota view key on.
	layers := chainLayers(claims)
	leafTTL := runKeyTTL(parseRFC3339(claims.Exp), now)
	parent := ""
	for i, layer := range layers {
		ttl := runKeyTTL(parseRFC3339(layer.Exp), now)
		costKey := redisclient.Key(costRunPrefix + layer.RunID)
		stepsKey := redisclient.Key(stepsRunPrefix + layer.RunID)
		metaKey := redisclient.Key(metaRunPrefix + layer.RunID)
		pipe.HIncrByFloat(ctx, costKey, "total", costUSD)
		pipe.HIncrBy(ctx, stepsKey, "total", 1)
		keepAlive(ctx, pipe, costKey, ttl)
		keepAlive(ctx, pipe, stepsKey, ttl)

		meta := []any{
			"max_cost_usd", layer.MaxCostUSD,
			"max_steps", layer.MaxSteps,
			"exp", layer.Exp,
			"parent", parent,
		}
		if i == len(layers)-1 {
			meta = append(meta, "agent", claims.AgentName, "user", claims.UserID)
		}
		pipe.HSet(ctx, metaKey, meta...)
		keepAlive(ctx, pipe, metaKey, ttl)
		parent = layer.RunID
	}

	// Per-user run index (leaf only). Score is the leaf's exp so a
	// reader can drop runs whose macaroon has lapsed without a
	// second lookup; a missing / unparseable exp scores as "now +
	// key TTL" so the run still shows up until its state expires.
	if n := len(layers); n > 0 && claims.UserID != "" {
		leaf := layers[n-1]
		score := parseRFC3339(leaf.Exp)
		if score.IsZero() {
			score = now.Add(leafTTL)
		}
		userKey := redisclient.Key(runsUserPrefix + claims.UserID)
		pipe.ZAdd(ctx, userKey, redis.Z{Score: float64(score.Unix()), Member: leaf.RunID})
		pipe.Expire(ctx, userKey, runsUserTTL)
	}

	// Per-agent windowed buckets — one for every agent in the lineage
	// the operator configured a budget for, so the cap walk can hold a
	// sub-agent to its parent agent's budget. The bucket key is
	// computed from THIS write's clock ("bucket by the time of the
	// write" — see phase-6 "Bucket boundary mid-call"), never carried
	// over from PreHook.
	budgets := GetConfig().AgentBudgets
	for _, name := range chainAgents(claims) {
		b, ok := budgets[name]
		if !ok || b.CapUSD <= 0 || b.Window == "" {
			continue
		}
		w, err := duration.Parse(b.Window)
		if err != nil {
			pluginlog.Warnf("auth: accumulator agent=%s: unrecognized window %q", name, b.Window)
			continue
		}
		agentKey := redisclient.Key(costAgentPrefix + name + ":" + w.BucketKey(now))
		pipe.HIncrByFloat(ctx, agentKey, "total", costUSD)
		pipe.Expire(ctx, agentKey, w.TTL())
	}

	// Tool-loop history on the leaf run only.
	if len(toolNames) > 0 && claims.RunID != "" {
		toolsKey := redisclient.Key(toolsRunPrefix + claims.RunID)
		for _, name := range toolNames {
			pipe.LPush(ctx, toolsKey, name)
		}
		pipe.LTrim(ctx, toolsKey, 0, toolHistoryLen-1)
		pipe.Expire(ctx, toolsKey, leafTTL)
	}

	_, err := pipe.Exec(ctx)
	return err
}

// keepAlive gives key a TTL of ttl unless it already has a longer one.
// EXPIRE GT alone would never set a TTL on a new key (no TTL counts as
// infinite), so NX sets the first one and GT lengthens it after that.
// Both options need Redis 7.
func keepAlive(ctx context.Context, pipe redis.Pipeliner, key string, ttl time.Duration) {
	pipe.ExpireNX(ctx, key, ttl)
	pipe.ExpireGT(ctx, key, ttl)
}

// chainLayers returns the chain's distinct run layers outermost-first
// (block 0, then each block inward; the last element is the leaf).
// Two blocks may share a run_id (strut's step links reuse the run's);
// they share one counter, so the run is written once, with the
// outermost block's caps on its meta.
func chainLayers(claims *macaroon.Claims) []macaroon.ChainLayer {
	out := make([]macaroon.ChainLayer, 0, len(claims.Chain))
	seen := make(map[string]bool, len(claims.Chain))
	for _, l := range claims.Chain {
		if l.RunID == "" || seen[l.RunID] {
			continue
		}
		seen[l.RunID] = true
		out = append(out, l)
	}
	return out
}
