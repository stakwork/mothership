/**
 * route-e2e.ts — a model with no provider prefix is served by its route's
 * provider and by no other, through the real gateway image.
 *
 * Run (Docker up, `npm install` done in auth/ts):
 *
 *   make docker-build
 *   cd auth/ts && node --import tsx ../../scripts/route-e2e.ts
 *
 * IMAGE picks another image (default stakgraph-gateway:dev); KEEP=1 leaves
 * the containers up. Exits non-zero when any check fails. It needs no
 * provider key and makes no provider call.
 *
 * What it starts: redis and the gateway with macaroons and budgets
 * enforced, as on a Stadeum box, and a virtual key shaped like the one
 * stadeum-ui gives each person before an admin picks models: every
 * provider the gateway has, `allowed_models: ["*"]`.
 *
 * What it proves, for each route (`/genai` → gemini, `/anthropic` →
 * anthropic, `/openai` → openai): a bare model id is attempted on the
 * route's provider only. Every attempt Bifrost logs for the request (the
 * request's row and its fallbacks' rows, by parent_request_id) names that
 * provider, and none names openrouter or openrouter-images. No key is set,
 * so the route's provider refuses each call, which is what makes Bifrost
 * try fallbacks: without the plugin's PreRequestHook, its model-catalog
 * resolver retries the call on OpenRouter and on `openrouter-images` (a
 * provider with no model list claims every model), and sends a model the
 * route's provider does not list to `openrouter-images` first.
 *
 * A prefixed model (`gemini/<id>` on the OpenAI route) is checked too: it
 * names its provider, and stays there.
 */

import { execFileSync, spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const IMAGE = process.env.IMAGE ?? "stakgraph-gateway:dev";
const KEEP = process.env.KEEP === "1";
const NAME = `route-e2e-${process.pid}`;
const ADMIN_USER = "admin";
const ADMIN_PASS = "e2e-admin-password";
const TOKEN = "e2e-provisioning-token";
const ORG_ID = "org_e2e";
// Fixture org pubkey #0, the key mint-macaroon.ts signs with.
const ORG_PUBKEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const TS_DIR = join(SCRIPT_DIR, "../auth/ts");
const MINT = join(SCRIPT_DIR, "mint-macaroon.ts");

const failures: string[] = [];
function check(name: string, ok: boolean, detail = "") {
  console.log(`  ${ok ? "ok  " : "FAIL"} ${name}${detail ? `  (${detail})` : ""}`);
  if (!ok) failures.push(name);
}
function section(title: string) {
  console.log(`\n=== ${title} ===`);
}

function docker(...args: string[]): string {
  return execFileSync("docker", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}
function containerLogs(name: string): string {
  const r = spawnSync("docker", ["logs", name], { encoding: "utf8" });
  return `${r.stdout}${r.stderr}`;
}

let GW = "";
const basic = `Basic ${Buffer.from(`${ADMIN_USER}:${ADMIN_PASS}`).toString("base64")}`;

async function http(method: string, path: string, headers: Record<string, string>, body?: unknown) {
  const res = await fetch(`${GW}${path}`, {
    method,
    headers: { ...headers, ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json: any;
  try {
    json = JSON.parse(text);
  } catch {
    json = undefined;
  }
  return { status: res.status, text, json, requestId: res.headers.get("x-bifrost-request-id") ?? "" };
}
const admin = (m: string, p: string, b?: unknown) => http(m, p, { Authorization: basic }, b);
const plugin = (m: string, p: string, b?: unknown) => http(m, p, { Authorization: `Bearer ${TOKEN}` }, b);

async function waitHealthy() {
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    try {
      const [a, b] = await Promise.all([fetch(`${GW}/health`), fetch(`${GW}/_plugin/health`)]);
      if (a.ok && b.ok) return;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`gateway not healthy in 90s:\n${containerLogs(`${NAME}-gw`).split("\n").slice(-40).join("\n")}`);
}

let runSeq = 0;
function mint(): string {
  const runId = `r_route_${process.pid}_${++runSeq}`;
  return execFileSync(
    process.execPath,
    ["--import", "tsx", MINT, "--org-id", ORG_ID, "--user-id", "u_e2e", "--agent", "coder",
      "--run-id", runId, "--max-cost-usd", "1", "--max-steps", "50"],
    { cwd: TS_DIR, encoding: "utf8" },
  ).trim();
}

// One request per route, in that route's own wire format.
function send(route: "genai" | "anthropic" | "openai", model: string, vk: string) {
  const mac = { "x-macaroon": mint() };
  if (route === "genai") {
    return http("POST", `/genai/v1beta/models/${model}:generateContent`, { "x-goog-api-key": vk, ...mac },
      { contents: [{ role: "user", parts: [{ text: "hi" }] }] });
  }
  if (route === "anthropic") {
    return http("POST", "/anthropic/v1/messages", { "x-api-key": vk, "anthropic-version": "2023-06-01", ...mac },
      { model, max_tokens: 16, messages: [{ role: "user", content: "hi" }] });
  }
  return http("POST", "/openai/v1/chat/completions", { Authorization: `Bearer ${vk}`, ...mac },
    { model, messages: [{ role: "user", content: "hi" }] });
}

interface Attempt {
  provider: string;
  fallback_index: number;
}

// Every attempt Bifrost logged for the request: its own row and each
// fallback's (parent_request_id). Rows are written on a goroutine.
async function attempts(requestId: string): Promise<Attempt[]> {
  const deadline = Date.now() + 10_000;
  let rows: any[] = [];
  for (;;) {
    const r = await admin("GET", "/api/logs?limit=200&order=desc");
    rows = (r.json?.logs ?? []).filter((x: any) => x.id === requestId || x.parent_request_id === requestId);
    if (rows.some((x) => x.id === requestId) || Date.now() > deadline) break;
    await new Promise((res) => setTimeout(res, 250));
  }
  // Let late fallback rows land.
  await new Promise((res) => setTimeout(res, 1000));
  const r = await admin("GET", "/api/logs?limit=200&order=desc");
  rows = (r.json?.logs ?? []).filter((x: any) => x.id === requestId || x.parent_request_id === requestId);
  return rows
    .map((x) => ({ provider: String(x.provider), fallback_index: Number(x.fallback_index ?? 0) }))
    .sort((a, b) => a.fallback_index - b.fallback_index);
}

async function main() {
  try {
    section(`start redis + ${IMAGE}`);
    docker("network", "create", NAME);
    docker("run", "-d", "--name", `${NAME}-redis`, "--network", NAME, "--network-alias", "redis", "redis:7-alpine");
    docker(
      "run", "-d", "--name", `${NAME}-gw`, "--network", NAME,
      "-p", "127.0.0.1::8181",
      "-e", `BIFROST_ADMIN_USER=${ADMIN_USER}`, "-e", `BIFROST_ADMIN_PASS=${ADMIN_PASS}`,
      "-e", `BIFROST_PROVISIONING_TOKEN=${TOKEN}`,
      "-e", "BIFROST_PLUGIN_REDIS_URL=redis://redis:6379/0",
      "-e", "BIFROST_PLUGIN_ENFORCE_MACAROONS=true",
      "-e", "BIFROST_PLUGIN_ENFORCE_BUDGETS=true",
      "-e", "BIFROST_PLUGIN_PRICING_URL=off",
      IMAGE,
    );
    GW = `http://${docker("port", `${NAME}-gw`, "8181").split("\n")[0]}`;
    await waitHealthy();
    console.log(`  gateway at ${GW}`);

    const trust = await plugin("POST", "/_plugin/trust", {
      org_id: ORG_ID, pubkey: ORG_PUBKEY, issuer_url: "", revocation_poll_seconds: 60,
    });
    check("org registered in the trust registry", trust.status === 200, trust.text);

    section("a person's virtual key, as stadeum-ui makes it");
    const providers: string[] = ((await admin("GET", "/api/providers")).json?.providers ?? []).map((p: any) => p.name);
    check("the gateway holds openrouter and openrouter-images", providers.includes("openrouter") && providers.includes("openrouter-images"), providers.join(","));
    const customer = await admin("POST", "/api/governance/customers", { name: `${NAME}-org`, budget: { max_limit: 100, reset_duration: "1d" } });
    const vkRes = await admin("POST", "/api/governance/virtual-keys", {
      name: `${NAME}-person`,
      customer_id: customer.json?.customer?.id,
      provider_configs: providers.map((provider) => ({ provider, allowed_models: ["*"], key_ids: ["*"] })),
    });
    const vk: string = vkRes.json?.virtual_key?.value ?? "";
    check("virtual key made", vk.startsWith("sk-bf-"), vkRes.text.slice(0, 200));

    section("a bare model stays on its route's provider");
    const cases: Array<{ route: "genai" | "anthropic" | "openai"; model: string; want: string }> = [
      { route: "genai", model: "gemini-4-argon", want: "gemini" },
      // A model the provider does not list: Bifrost sent it to openrouter-images first.
      { route: "genai", model: "gemini-0-no-such-model", want: "gemini" },
      { route: "anthropic", model: "claude-sonnet-5-5", want: "anthropic" },
      { route: "openai", model: "gpt-5.6-luna", want: "openai" },
      // The prefix names the provider on the OpenAI route.
      { route: "openai", model: "gemini/gemini-4-argon", want: "gemini" },
    ];
    for (const c of cases) {
      const res = await send(c.route, c.model, vk);
      const seen = res.requestId ? await attempts(res.requestId) : [];
      const where = seen.map((a) => `${a.fallback_index}:${a.provider}`).join(" ") || "no logged attempt";
      const strays = seen.filter((a) => a.provider !== c.want);
      check(`/${c.route} ${c.model} → ${c.want} only`, res.requestId !== "" && strays.length === 0,
        `HTTP ${res.status}; attempts ${where}`);
    }
  } finally {
    if (!KEEP) {
      spawnSync("docker", ["rm", "-f", `${NAME}-gw`, `${NAME}-redis`], { stdio: "ignore" });
      spawnSync("docker", ["network", "rm", NAME], { stdio: "ignore" });
    } else {
      console.log(`\nKEEP=1: containers ${NAME}-gw and ${NAME}-redis left up at ${GW}`);
    }
  }
  console.log(failures.length ? `\n${failures.length} check(s) FAILED:\n  ${failures.join("\n  ")}` : "\nall checks passed");
  process.exit(failures.length ? 1 : 0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
