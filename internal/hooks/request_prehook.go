package hooks

import (
	"github.com/maximhq/bifrost/core/schemas"

	"github.com/stakwork/mothership/internal/pluginlog"
)

// routeProviders maps each drop-in route the gateway serves (Bifrost's
// integration type) to the provider it speaks for. A model with no
// "<provider>/" prefix on that route is that provider's model.
var routeProviders = map[string]schemas.ModelProvider{
	"openai":    schemas.OpenAI,
	"anthropic": schemas.Anthropic,
	"genai":     schemas.Gemini,
}

// RequestPre is the body of PreRequestHook: a model with no provider
// prefix is served by the provider of the route it came in on, and by
// no other.
//
// Bifrost leaves such a request's provider empty and lets its
// model-catalog resolver choose one. The resolver picks the route's
// provider when its catalog lists the model, and adds every other
// provider whose catalog lists it as automatic fallbacks: OpenRouter
// lists almost every model, and a custom provider with no model list
// (`openrouter-images`, or any key-less one) claims them all. So a
// Gemini call that Gemini refused (a 429, a 503, a retired model) was
// retried on OpenRouter, and a model Gemini does not list went to
// `openrouter-images` first. The caller sees OpenRouter's error, or
// OpenRouter's answer, for a call it sent to Gemini.
//
// Setting the provider here, before Bifrost's own routing plugins
// (this plugin is placed pre_builtin), means governance and the
// resolver both leave the request alone. A prefixed model
// (`gemini/gemini-4-argon` on the OpenAI route) already names its
// provider and is not touched. Bifrost's own routes (`/v1/*`) have no
// provider of their own and are left to Bifrost.
func RequestPre(ctx *schemas.BifrostContext, req *schemas.BifrostRequest) error {
	provider, model, _ := req.GetRequestFields()
	if provider != "" || model == "" {
		return nil
	}
	route, _ := ctx.Value(schemas.BifrostContextKeyIntegrationType).(string)
	pinned, ok := routeProviders[route]
	if !ok {
		return nil
	}
	req.SetProvider(pinned)
	pluginlog.Logf("route: model=%s has no provider prefix; the %s route serves it with provider=%s", model, route, pinned)
	return nil
}
