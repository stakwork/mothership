package hooks

import (
	"context"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

func routeCtx(route string) *schemas.BifrostContext {
	ctx := schemas.NewBifrostContext(context.Background(), time.Time{})
	if route != "" {
		ctx.SetValue(schemas.BifrostContextKeyIntegrationType, route)
	}
	return ctx
}

func chatReq(provider schemas.ModelProvider, model string) *schemas.BifrostRequest {
	return &schemas.BifrostRequest{
		RequestType: schemas.ChatCompletionRequest,
		ChatRequest: &schemas.BifrostChatRequest{Provider: provider, Model: model},
	}
}

func TestRequestPreServesABareModelOnItsRoutesProvider(t *testing.T) {
	cases := []struct {
		route string
		model string
		want  schemas.ModelProvider
	}{
		{"genai", "gemini-4-argon", schemas.Gemini},
		{"anthropic", "claude-sonnet-5-5", schemas.Anthropic},
		{"openai", "gpt-5.6-luna", schemas.OpenAI},
		// An org prefix that is no provider stays on the route's provider.
		{"openai", "moonshotai/kimi-k3", schemas.OpenAI},
	}
	for _, c := range cases {
		req := chatReq("", c.model)
		if err := RequestPre(routeCtx(c.route), req); err != nil {
			t.Fatalf("%s %s: %v", c.route, c.model, err)
		}
		provider, model, fallbacks := req.GetRequestFields()
		if provider != c.want || model != c.model || len(fallbacks) != 0 {
			t.Errorf("%s %s: got provider=%q model=%q fallbacks=%v, want provider=%q and the model unchanged",
				c.route, c.model, provider, model, fallbacks, c.want)
		}
	}
}

func TestRequestPreLeavesANamedProviderAlone(t *testing.T) {
	// `gemini/gemini-4-argon` on the OpenAI route: Bifrost split the
	// prefix into the provider before any hook runs.
	req := chatReq(schemas.Gemini, "gemini-4-argon")
	if err := RequestPre(routeCtx("openai"), req); err != nil {
		t.Fatal(err)
	}
	if provider, _, _ := req.GetRequestFields(); provider != schemas.Gemini {
		t.Fatalf("provider = %q, want gemini", provider)
	}
}

func TestRequestPreLeavesBifrostsOwnRoutesAndModelLessCallsAlone(t *testing.T) {
	// Bifrost's own /v1 routes carry no integration type.
	req := chatReq("", "gemini-4-argon")
	if err := RequestPre(routeCtx(""), req); err != nil {
		t.Fatal(err)
	}
	if provider, _, _ := req.GetRequestFields(); provider != "" {
		t.Fatalf("/v1: provider = %q, want it left for Bifrost", provider)
	}
	// A model list has no model to route.
	list := &schemas.BifrostRequest{RequestType: schemas.ListModelsRequest, ListModelsRequest: &schemas.BifrostListModelsRequest{}}
	if err := RequestPre(routeCtx("openai"), list); err != nil {
		t.Fatal(err)
	}
	if list.ListModelsRequest.Provider != "" {
		t.Fatalf("list models: provider = %q, want empty", list.ListModelsRequest.Provider)
	}
}
