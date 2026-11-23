package auth

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	macaroon "github.com/stakwork/mothership/auth/go"
)

// chainClaims builds a verified-claims shape with one layer per run
// id, exps spaced so per-layer TTLs differ.
func chainClaims(runIDs []string, exps []string) *macaroon.Claims {
	chain := make([]macaroon.ChainLayer, len(runIDs))
	for i := range runIDs {
		chain[i] = macaroon.ChainLayer{
			RunID:      runIDs[i],
			MaxCostUSD: 5,
			MaxSteps:   100,
			Exp:        exps[i],
		}
	}
	leaf := len(runIDs) - 1
	earliest := exps[0]
	for _, e := range exps {
		if e < earliest {
			earliest = e
		}
	}
	return &macaroon.Claims{
		OrgID:     "org_acme",
		UserID:    testUserID,
		AgentName: "coder",
		RunID:     runIDs[leaf],
		Exp:       earliest,
		Chain:     chain,
		Nonces:    []string{"aaaa000000000000000000000000aaaa", "bbbb000000000000000000000000bbbb"},
		IAT:       "2026-05-14T09:00:00Z",
	}
}

func testNow() time.Time {
	return time.Date(2026, 5, 14, 10, 5, 0, 0, time.UTC)
}

func TestAccumulate_PerRunChainWalk(t *testing.T) {
	mr := newMiniRedis(t)
	claims := chainClaims(
		[]string{"r_parent", "r_child"},
		[]string{"2026-05-14T18:00:00Z", "2026-05-14T10:30:00Z"},
	)

	if err := accumulate(context.Background(), claims, 0.42, nil, testNow()); err != nil {
		t.Fatal(err)
	}

	for _, r := range []string{"r_parent", "r_child"} {
		if got := mr.HGet("bifrost:cost:run:"+r, "total"); got != "0.42" {
			t.Errorf("cost:run:%s total = %q, want 0.42", r, got)
		}
		if got := mr.HGet("bifrost:steps:run:"+r, "total"); got != "1" {
			t.Errorf("steps:run:%s total = %q, want 1", r, got)
		}
	}

	// Second call accumulates.
	if err := accumulate(context.Background(), claims, 0.08, nil, testNow()); err != nil {
		t.Fatal(err)
	}
	if got := mr.HGet("bifrost:cost:run:r_parent", "total"); got != "0.5" {
		t.Errorf("after second call cost:run:r_parent = %q, want 0.5", got)
	}
	if got := mr.HGet("bifrost:steps:run:r_child", "total"); got != "2" {
		t.Errorf("after second call steps:run:r_child = %q, want 2", got)
	}
}

func TestAccumulate_PerLayerTTL(t *testing.T) {
	mr := newMiniRedis(t)
	// Parent exp 8h out, leaf exp 25m out. Parent keys must get the
	// longer TTL (exp-now+1h), leaf keys the 1h floor + 25m.
	claims := chainClaims(
		[]string{"r_parent", "r_child"},
		[]string{"2026-05-14T18:05:00Z", "2026-05-14T10:30:00Z"},
	)
	if err := accumulate(context.Background(), claims, 0.01, nil, testNow()); err != nil {
		t.Fatal(err)
	}

	parentTTL := mr.TTL("bifrost:cost:run:r_parent")
	childTTL := mr.TTL("bifrost:cost:run:r_child")
	if want := 9 * time.Hour; parentTTL != want { // 8h remaining + 1h grace
		t.Errorf("parent TTL = %s, want %s", parentTTL, want)
	}
	if want := 85 * time.Minute; childTTL != want { // 25m remaining + 1h grace
		t.Errorf("child TTL = %s, want %s", childTTL, want)
	}
}

func TestAccumulate_DuplicateRunIDsWrittenOnce(t *testing.T) {
	mr := newMiniRedis(t)
	// An attenuation that narrows caps but keeps the parent's run_id
	// must not double-count the call.
	claims := chainClaims(
		[]string{"r_same", "r_same"},
		[]string{"2026-05-14T18:00:00Z", "2026-05-14T12:00:00Z"},
	)
	if err := accumulate(context.Background(), claims, 0.10, nil, testNow()); err != nil {
		t.Fatal(err)
	}
	if got := mr.HGet("bifrost:cost:run:r_same", "total"); got != "0.1" {
		t.Errorf("cost:run:r_same = %q, want 0.1 (single write)", got)
	}
	if got := mr.HGet("bifrost:steps:run:r_same", "total"); got != "1" {
		t.Errorf("steps:run:r_same = %q, want 1 (single write)", got)
	}
}

// Block 0 (the person's grant) is one more layer: its counter is the
// person's total, written like any run's (v1 kept a separate cost:ua).
func TestAccumulate_GrantIsALayer(t *testing.T) {
	mr := newMiniRedis(t)
	claims := chainClaims(
		[]string{"ua_grant", "r_1"},
		[]string{"2026-06-14T09:00:00Z", "2026-05-14T11:00:00Z"},
	)
	if err := accumulate(context.Background(), claims, 0.25, nil, testNow()); err != nil {
		t.Fatal(err)
	}
	if got := mr.HGet("bifrost:cost:run:ua_grant", "total"); got != "0.25" {
		t.Errorf("cost:run:ua_grant = %q, want 0.25", got)
	}
	// A month out → clamped to the 7d ceiling.
	if got, want := mr.TTL("bifrost:cost:run:ua_grant"), 7*24*time.Hour; got != want {
		t.Errorf("cost:run:ua_grant TTL = %s, want %s", got, want)
	}
	if got := hgetall(mr, "bifrost:meta:run:r_1")["parent"]; got != "ua_grant" {
		t.Errorf("meta:run:r_1 parent = %q, want ua_grant", got)
	}
	for _, k := range mr.Keys() {
		if len(k) >= len("bifrost:cost:ua:") && k[:len("bifrost:cost:ua:")] == "bifrost:cost:ua:" {
			t.Fatalf("v1 key written: %s", k)
		}
	}
}

func TestAccumulate_AgentBucket_OnlyWhenConfigured(t *testing.T) {
	mr := newMiniRedis(t)
	claims := chainClaims([]string{"r_1"}, []string{"2026-05-14T11:00:00Z"})

	// No configured budget for "coder" → no agent key.
	SetConfigForTest(Config{})
	t.Cleanup(func() { SetConfigForTest(Config{}) })
	if err := accumulate(context.Background(), claims, 0.30, nil, testNow()); err != nil {
		t.Fatal(err)
	}
	// cost:run + steps:run + meta:run + runs:user — no cost:agent.
	if keys := mr.Keys(); len(keys) != 4 || mr.Exists("bifrost:cost:agent:coder:2026-05-14") {
		t.Fatalf("unexpected keys without agent budget: %v", keys)
	}

	// Configured 1d budget → write to the UTC day bucket with 48h TTL.
	SetConfigForTest(Config{AgentBudgets: map[string]AgentBudget{
		"coder": {CapUSD: 500, Window: "1d"},
	}})
	if err := accumulate(context.Background(), claims, 0.30, nil, testNow()); err != nil {
		t.Fatal(err)
	}
	key := "bifrost:cost:agent:coder:2026-05-14"
	if got := mr.HGet(key, "total"); got != "0.3" {
		t.Errorf("%s total = %q, want 0.3", key, got)
	}
	if got, want := mr.TTL(key), 48*time.Hour; got != want {
		t.Errorf("agent bucket TTL = %s, want %s", got, want)
	}
}

func TestAccumulate_ToolHistory_CappedAtTen(t *testing.T) {
	mr := newMiniRedis(t)
	claims := chainClaims([]string{"r_1"}, []string{"2026-05-14T11:00:00Z"})

	for i := 0; i < 6; i++ {
		if err := accumulate(context.Background(), claims, 0, []string{"grep", "read"}, testNow()); err != nil {
			t.Fatal(err)
		}
	}
	list, err := mr.List("bifrost:tools:run:r_1")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != toolHistoryLen {
		t.Fatalf("tools list length = %d, want %d (LTRIM cap)", len(list), toolHistoryLen)
	}
	// Most recent push is at the head.
	if list[0] != "read" {
		t.Errorf("tools head = %q, want most-recent \"read\"", list[0])
	}
}

func TestAccumulate_ZeroCostStillCountsStep(t *testing.T) {
	mr := newMiniRedis(t)
	claims := chainClaims([]string{"r_1"}, []string{"2026-05-14T11:00:00Z"})

	// Errored call: cost 0, but the step must still increment (phase-6
	// PostLLMHook step 1).
	if err := accumulate(context.Background(), claims, 0, nil, testNow()); err != nil {
		t.Fatal(err)
	}
	if got := mr.HGet("bifrost:steps:run:r_1", "total"); got != "1" {
		t.Errorf("steps after zero-cost call = %q, want 1", got)
	}
	if got := mr.HGet("bifrost:cost:run:r_1", "total"); got != "0" {
		t.Errorf("cost after zero-cost call = %q, want 0", got)
	}
}

func TestApplyToLLMPost_NilClaimsOrNoRedis_NoOp(t *testing.T) {
	// Nil claims: must not panic, must not write.
	mr := newMiniRedis(t)
	ApplyToLLMPost(nil, 1.0, nil)
	time.Sleep(20 * time.Millisecond) // would-be goroutine window
	if keys := mr.Keys(); len(keys) != 0 {
		t.Fatalf("nil claims wrote keys: %v", keys)
	}
}

func TestAccumulate_RunMetaAndUserIndex(t *testing.T) {
	mr := newMiniRedis(t)
	claims := chainClaims(
		[]string{"r_parent", "r_child"},
		[]string{"2026-05-14T18:00:00Z", "2026-05-14T10:30:00Z"},
	)
	claims.Chain[0].MaxCostUSD = 20
	claims.Chain[0].MaxSteps = 500
	claims.Chain[1].MaxCostUSD = 2.5
	claims.Chain[1].MaxSteps = 40

	if err := accumulate(context.Background(), claims, 0.10, nil, testNow()); err != nil {
		t.Fatal(err)
	}

	// Leaf: caps, exp, parent link, and — only here — agent/user.
	leaf := hgetall(mr, "bifrost:meta:run:r_child")
	want := map[string]string{
		"max_cost_usd": "2.5", "max_steps": "40",
		"exp": "2026-05-14T10:30:00Z", "parent": "r_parent",
		"agent": "coder", "user": testUserID,
	}
	for k, v := range want {
		if leaf[k] != v {
			t.Errorf("meta:run:r_child[%s] = %q, want %q", k, leaf[k], v)
		}
	}

	// Ancestor: its own caps, no parent (invocation), and no agent —
	// the child's chain doesn't know what agent the parent runs as.
	par := hgetall(mr, "bifrost:meta:run:r_parent")
	if par["max_cost_usd"] != "20" || par["max_steps"] != "500" || par["parent"] != "" {
		t.Errorf("meta:run:r_parent = %v", par)
	}
	if _, ok := par["agent"]; ok {
		t.Errorf("ancestor meta must not carry the leaf's agent: %v", par)
	}

	// Meta shares the accumulator's TTL axis per layer.
	if got, want := mr.TTL("bifrost:meta:run:r_child"), mr.TTL("bifrost:cost:run:r_child"); got != want {
		t.Errorf("meta:run:r_child ttl %v != cost:run ttl %v", got, want)
	}

	// Per-user index: leaf run scored by its exp, key TTL'd at 7d.
	members, err := mr.ZMembers("bifrost:runs:user:" + testUserID)
	if err != nil || len(members) != 1 || members[0] != "r_child" {
		t.Fatalf("runs:user members = %v (%v)", members, err)
	}
	score, err := mr.ZScore("bifrost:runs:user:"+testUserID, "r_child")
	if err != nil || int64(score) != parseRFC3339("2026-05-14T10:30:00Z").Unix() {
		t.Errorf("runs:user score = %v (%v)", score, err)
	}
	if got := mr.TTL("bifrost:runs:user:" + testUserID); got != runsUserTTL {
		t.Errorf("runs:user ttl = %v, want %v", got, runsUserTTL)
	}
}

func TestGetRunState_ReadsMeta_And_ListUserRuns(t *testing.T) {
	mr := newMiniRedis(t)
	claims := chainClaims(
		[]string{"r_parent", "r_child"},
		[]string{"2026-05-14T18:00:00Z", "2026-05-14T10:30:00Z"},
	)
	if err := accumulate(context.Background(), claims, 0.4, nil, testNow()); err != nil {
		t.Fatal(err)
	}

	st, err := GetRunState(context.Background(), "r_child")
	if err != nil {
		t.Fatal(err)
	}
	if !st.HasMeta || st.MaxCostUSD != 5 || st.MaxSteps != 100 || st.Parent != "r_parent" ||
		st.AgentName != "coder" || st.UserID != testUserID || st.Exp != "2026-05-14T10:30:00Z" {
		t.Errorf("run state: %+v", st)
	}
	par, err := GetRunState(context.Background(), "r_parent")
	if err != nil {
		t.Fatal(err)
	}
	if !par.HasMeta || par.Parent != "" || par.AgentName != "" || par.CostUSD != 0.4 {
		t.Errorf("parent state: %+v", par)
	}

	// Never-seen run: no meta, zero caps.
	none, err := GetRunState(context.Background(), "r_never")
	if err != nil || none.HasMeta {
		t.Errorf("unknown run: %+v (%v)", none, err)
	}

	// Index lists the leaf while its exp is in the future ...
	ids, err := ListUserRuns(context.Background(), testUserID, testNow(), 10)
	if err != nil || len(ids) != 1 || ids[0] != "r_child" {
		t.Fatalf("ListUserRuns = %v (%v)", ids, err)
	}
	// ... prunes it once the exp has passed ...
	ids, err = ListUserRuns(context.Background(), testUserID, testNow().Add(2*time.Hour), 10)
	if err != nil || len(ids) != 0 {
		t.Fatalf("ListUserRuns after exp = %v (%v)", ids, err)
	}
	if members, _ := mr.ZMembers("bifrost:runs:user:" + testUserID); len(members) != 0 {
		t.Errorf("expired member not pruned: %v", members)
	}
	// ... and an unknown user is an empty list, not an error.
	ids, err = ListUserRuns(context.Background(), "u_nobody", testNow(), 10)
	if err != nil || ids == nil || len(ids) != 0 {
		t.Fatalf("ListUserRuns unknown user = %v (%v)", ids, err)
	}
}

// hgetall is the HGETALL miniredis doesn't expose on its handle.
func hgetall(mr *miniredis.Miniredis, key string) map[string]string {
	out := map[string]string{}
	keys, _ := mr.HKeys(key)
	for _, k := range keys {
		out[k] = mr.HGet(key, k)
	}
	return out
}
