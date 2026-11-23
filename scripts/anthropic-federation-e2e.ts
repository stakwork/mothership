/**
 * anthropic-federation-e2e.ts — the gateway as its own OIDC issuer, through
 * the real image, against a fake Anthropic that checks what the real one
 * would.
 *
 * Run (Docker up, `npm install` done in auth/ts):
 *
 *   make docker-build
 *   cd auth/ts && node --import tsx ../../scripts/anthropic-federation-e2e.ts
 *
 * IMAGE picks another image (default stakgraph-gateway:dev); KEEP=1 leaves
 * the containers up. Takes about a minute (it waits out one token rotation).
 * Exits non-zero when any check fails.
 *
 * What it starts: redis; a fake Anthropic in a node container; and the
 * gateway with BIFROST_IDENTITY_ISSUER set, in the fake's network namespace,
 * so it reaches the fake on 127.0.0.1:9999 (Bifrost sends an identity token
 * over plain http to a loopback host only). The fake owns the namespace, so
 * it stays up while the gateway restarts, as Anthropic would. The fake's token endpoint
 * fetches the gateway's key set from its discovery document and verifies
 * each assertion as Anthropic does: ES256 signature, iss, aud, exp, and a jti
 * it has not seen before. Its /v1/messages accepts only a bearer it minted.
 *
 * What it proves:
 *   1. /.well-known/openid-configuration names the issuer and a key set the
 *      gateway serves, unauthenticated, with one ES256 key.
 *   2. The token file Bifrost reads holds a JWT that verifies against that
 *      key set, with the documented claims, and is rewritten on schedule.
 *   3. An Anthropic key written through Bifrost's API with
 *      anthropic_key_config.workload_identity (as Stadeum writes one) makes a
 *      /anthropic/v1/messages call work with no API key anywhere: one
 *      exchange carrying the rule, organization and service account, then
 *      the minted token as a bearer. A second call reuses it.
 *   4. The signing key (so the kid Anthropic was given) survives a restart,
 *      and the exchanges Bifrost makes while it boots (it lists the key's
 *      models) are accepted: the wrapper serves the issuer's documents
 *      before bifrost-http starts.
 */

import { execFileSync, spawnSync } from "node:child_process";
import { createPublicKey, verify, type JsonWebKey } from "node:crypto";

const IMAGE = process.env.IMAGE ?? "stakgraph-gateway:dev";
const KEEP = process.env.KEEP === "1";
const NAME = `fed-e2e-${process.pid}`;
const ADMIN_USER = "admin";
const ADMIN_PASS = "e2e-admin-password";
const TOKEN = "e2e-provisioning-token";
const ISSUER = "https://mothership.e2e.test";
const TOKEN_FILE = "/run/secrets/mothership/anthropic-identity-token";
const FAKE_PORT = 9999;
const FEDERATION = {
  federation_rule_id: "fdrl_e2e",
  organization_id: "00000000-0000-4000-8000-00000000e2e0",
  service_account_id: "svac_e2e",
};

// ─── checks ──────────────────────────────────────────────────────────

const failures: string[] = [];
function check(name: string, ok: boolean, detail = "") {
  console.log(`  ${ok ? "ok  " : "FAIL"} ${name}${detail ? `  (${detail})` : ""}`);
  if (!ok) failures.push(name);
}
function section(title: string) {
  console.log(`\n=== ${title} ===`);
}

// ─── the fake Anthropic (runs in its own container) ─────────────────

const FAKE = String.raw`
import { createServer } from "node:http";
import { createPublicKey, verify } from "node:crypto";

const seen = { exchanges: [], messages: [], models: [] };
const usedJti = new Set();
const minted = new Set();
let n = 0;

const read = (req) => new Promise((ok) => { let s = ""; req.on("data", (c) => (s += c)); req.on("end", () => ok(s)); });
const b64 = (s) => Buffer.from(s, "base64url");
const send = (res, code, body) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };

// What Anthropic checks on an assertion, with the key found the way it
// finds it: the discovery document at {iss}/.well-known/openid-configuration.
// The issuer's host is not resolvable here, so its origin is swapped for the
// gateway's listener; the path is the issuer's own.
async function checkAssertion(assertion) {
  const [h, p, s] = assertion.split(".");
  const header = JSON.parse(b64(h)); const claims = JSON.parse(b64(p));
  const local = (u) => u.replace(new URL(claims.iss).origin, "http://127.0.0.1:8181");
  const disc = await (await fetch(local(claims.iss) + "/.well-known/openid-configuration")).json();
  if (disc.issuer !== claims.iss) return "discovery issuer " + disc.issuer + " != iss " + claims.iss;
  const jwks = await (await fetch(local(disc.jwks_uri))).json();
  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  if (!jwk) return "no key with kid " + header.kid;
  if (header.alg !== "ES256") return "alg " + header.alg;
  const key = createPublicKey({ key: jwk, format: "jwk" });
  if (!verify("sha256", Buffer.from(h + "." + p), { key, dsaEncoding: "ieee-p1363" }, b64(s))) return "bad signature";
  const now = Math.floor(Date.now() / 1000);
  if (claims.aud !== "https://api.anthropic.com") return "aud " + claims.aud;
  if (!(claims.exp > now)) return "expired";
  if (!(claims.iat <= now + 60)) return "iat in the future";
  if (!claims.jti || usedJti.has(claims.jti)) return "jti missing or reused";
  usedJti.add(claims.jti);
  return null;
}

createServer(async (req, res) => {
  const body = await read(req);
  if (req.method === "GET" && req.url === "/_seen") return send(res, 200, seen);
  if (req.method === "POST" && req.url === "/v1/oauth/token") {
    const j = JSON.parse(body || "{}");
    const problem = j.grant_type !== "urn:ietf:params:oauth:grant-type:jwt-bearer"
      ? "grant_type " + j.grant_type : await checkAssertion(String(j.assertion ?? "")).catch((e) => String(e));
    seen.exchanges.push({ problem, beta: String(req.headers["anthropic-beta"] ?? ""),
      federation_rule_id: j.federation_rule_id, organization_id: j.organization_id,
      service_account_id: j.service_account_id, claims: j.assertion ? JSON.parse(b64(j.assertion.split(".")[1])) : null });
    if (problem) return send(res, 401, { type: "error", error: { type: "authentication_error", message: problem } });
    const token = "sk-ant-oat01-e2e-" + ++n;
    minted.add(token);
    return send(res, 200, { access_token: token, token_type: "Bearer", expires_in: 3600 });
  }
  if (req.method === "GET" && req.url?.startsWith("/v1/models")) {
    const auth = String(req.headers.authorization ?? "");
    seen.models.push({ auth });
    if (!minted.has(auth.replace(/^Bearer /, ""))) return send(res, 401, { type: "error", error: { type: "authentication_error", message: "unknown token" } });
    return send(res, 200, { data: [{ type: "model", id: "claude-e2e", display_name: "Claude E2E", created_at: "2026-01-01T00:00:00Z" }],
      has_more: false, first_id: "claude-e2e", last_id: "claude-e2e" });
  }
  if (req.method === "POST" && req.url?.startsWith("/v1/messages")) {
    const auth = String(req.headers.authorization ?? "");
    seen.messages.push({ auth, xApiKey: String(req.headers["x-api-key"] ?? ""), beta: String(req.headers["anthropic-beta"] ?? "") });
    if (!minted.has(auth.replace(/^Bearer /, ""))) return send(res, 401, { type: "error", error: { type: "authentication_error", message: "unknown token" } });
    const j = JSON.parse(body);
    return send(res, 200, { id: "msg_e2e", type: "message", role: "assistant", model: j.model,
      content: [{ type: "text", text: "hello" }], stop_reason: "end_turn", stop_sequence: null,
      usage: { input_tokens: 10, output_tokens: 5 } });
  }
  send(res, 404, { type: "error", error: { type: "not_found_error", message: req.method + " " + req.url } });
}).listen(${FAKE_PORT}, "0.0.0.0");
`;

// ─── docker and http ─────────────────────────────────────────────────

function docker(...args: string[]): string {
  return execFileSync("docker", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}
function containerLogs(name: string): string {
  const r = spawnSync("docker", ["logs", name], { encoding: "utf8" });
  return `${r.stdout}${r.stderr}`;
}

let GW = "";
let FAKE_URL = "";
const basic = `Basic ${Buffer.from(`${ADMIN_USER}:${ADMIN_PASS}`).toString("base64")}`;

async function http(method: string, url: string, headers: Record<string, string> = {}, body?: unknown) {
  const res = await fetch(url, {
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
  return { status: res.status, text, json, headers: res.headers };
}
const admin = (m: string, p: string, b?: unknown) => http(m, `${GW}${p}`, { Authorization: basic }, b);

async function locate() {
  GW = `http://${docker("port", `${NAME}-fake`, "8181").split("\n")[0]}`;
  FAKE_URL = `http://${docker("port", `${NAME}-fake`, String(FAKE_PORT)).split("\n")[0]}`;
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    try {
      const [a, b] = await Promise.all([fetch(`${GW}/health`), fetch(`${GW}/_plugin/health`)]);
      if (a.ok && b.ok) return;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`gateway not healthy in 120s:\n${containerLogs(`${NAME}-gw`).split("\n").slice(-40).join("\n")}`);
}


async function fakeSeen(): Promise<{ exchanges: any[]; messages: any[]; models: any[] }> {
  return (await http("GET", `${FAKE_URL}/_seen`)).json;
}

function b64json(seg: string) {
  return JSON.parse(Buffer.from(seg, "base64url").toString("utf8"));
}

// Verifies a JWT against a served key set, as a relying party would.
function verifyAgainst(token: string, jwks: { keys: (JsonWebKey & { kid: string })[] }) {
  const [h, p, s] = token.trim().split(".");
  const header = b64json(h);
  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  if (!jwk) return { ok: false, header, claims: undefined as any };
  const key = createPublicKey({ key: jwk, format: "jwk" });
  const ok = verify("sha256", Buffer.from(`${h}.${p}`), { key, dsaEncoding: "ieee-p1363" }, Buffer.from(s, "base64url"));
  return { ok, header, claims: b64json(p) };
}

const tokenFile = () => docker("exec", `${NAME}-gw`, "cat", TOKEN_FILE);

async function messages(vk: string, model = "claude-e2e") {
  return http("POST", `${GW}/anthropic/v1/messages`, { "x-bf-vk": vk }, {
    model, max_tokens: 16, messages: [{ role: "user", content: "hi" }],
  });
}

// ─── the run ─────────────────────────────────────────────────────────

async function main() {
  try {
    section(`start redis + ${IMAGE} (issuer ${ISSUER}) + fake Anthropic`);
    docker("network", "create", NAME);
    docker("volume", "create", `${NAME}-data`);
    docker("run", "-d", "--name", `${NAME}-redis`, "--network", NAME, "--network-alias", "redis", "redis:7-alpine");
    // The fake owns the network namespace and publishes both ports; the
    // gateway joins it (and reaches redis through the fake's network).
    docker("run", "-d", "--name", `${NAME}-fake`, "--network", NAME,
      "-p", "127.0.0.1::8181", "-p", `127.0.0.1::${FAKE_PORT}`,
      "node:24-alpine", "node", "--input-type=module", "-e", FAKE);
    docker(
      "run", "-d", "--name", `${NAME}-gw`, "--network", `container:${NAME}-fake`,
      "-v", `${NAME}-data:/app/data`,
      "-e", `BIFROST_ADMIN_USER=${ADMIN_USER}`, "-e", `BIFROST_ADMIN_PASS=${ADMIN_PASS}`,
      "-e", `BIFROST_PROVISIONING_TOKEN=${TOKEN}`,
      "-e", "BIFROST_PLUGIN_REDIS_URL=redis://redis:6379/0",
      "-e", "BIFROST_PLUGIN_ENFORCE_MACAROONS=false",
      "-e", "BIFROST_PLUGIN_PRICING_URL=off",
      "-e", `BIFROST_IDENTITY_ISSUER=${ISSUER}`,
      IMAGE,
    );
    await locate();
    console.log(`  gateway at ${GW}, fake Anthropic at ${FAKE_URL} (127.0.0.1:${FAKE_PORT} inside)`);
    const bootLog = containerLogs(`${NAME}-gw`);
    check("boot log names the issuer", bootLog.includes(`identity issuer on: iss=${ISSUER}`),
      bootLog.split("\n").find((l) => l.includes("identity issuer")) ?? "no identity issuer line");

    section("1. discovery and key set, unauthenticated");
    const disc = await http("GET", `${GW}/.well-known/openid-configuration`);
    check("discovery 200", disc.status === 200, `${disc.status} ${disc.text.slice(0, 200)}`);
    check("discovery issuer", disc.json?.issuer === ISSUER, disc.json?.issuer);
    const jwksPath = String(disc.json?.jwks_uri ?? "").replace(ISSUER, "");
    check("jwks_uri is on the issuer", String(disc.json?.jwks_uri).startsWith(`${ISSUER}/`), disc.json?.jwks_uri);
    const jwks = await http("GET", `${GW}${jwksPath}`);
    const keys = jwks.json?.keys ?? [];
    check("one ES256 P-256 key", jwks.status === 200 && keys.length === 1 && keys[0].alg === "ES256" && keys[0].crv === "P-256",
      jwks.text.slice(0, 200));
    check("key set has no private part", keys.length === 1 && !("d" in keys[0]));
    const kid = keys[0]?.kid;

    section("2. the token file Bifrost reads");
    const t1 = tokenFile();
    const v1 = verifyAgainst(t1, jwks.json);
    check("token verifies against the served key", v1.ok, `kid ${v1.header?.kid}`);
    check("claims iss/sub/aud", v1.claims?.iss === ISSUER && v1.claims?.sub === "mothership" && v1.claims?.aud === "https://api.anthropic.com",
      JSON.stringify(v1.claims));
    check("lives 30 minutes, has a jti", v1.claims?.exp - v1.claims?.iat === 1800 && typeof v1.claims?.jti === "string",
      `exp-iat=${v1.claims?.exp - v1.claims?.iat}`);
    console.log("  waiting for one rotation (30 s)…");
    await new Promise((r) => setTimeout(r, 32_000));
    const t2 = tokenFile();
    const v2 = verifyAgainst(t2, jwks.json);
    check("rewritten with a new jti", t2 !== t1 && v2.ok && v2.claims?.jti !== v1.claims?.jti);

    section("3. a federated Anthropic key, written as Stadeum writes one");
    const prov = await admin("GET", "/api/providers/anthropic");
    check("GET /api/providers/anthropic", prov.status === 200, `${prov.status} ${prov.text.slice(0, 200)}`);
    const put = await admin("PUT", "/api/providers/anthropic", {
      ...prov.json,
      network_config: {
        ...(prov.json?.network_config ?? {}),
        base_url: `http://127.0.0.1:${FAKE_PORT}`,
        allow_private_network: true,
      },
    });
    check("base_url pointed at the fake", put.status === 200, `${put.status} ${put.text.slice(0, 300)}`);
    const keyList = await admin("GET", "/api/providers/anthropic/keys");
    const slot = (keyList.json?.keys ?? keyList.json ?? [])[0];
    check("the seed's anthropic key slot exists", !!slot?.id, keyList.text.slice(0, 200));
    const wrote = await admin("PUT", `/api/providers/anthropic/keys/${slot?.id}`, {
      name: slot?.name ?? "anthropic-key-1",
      value: "",
      models: ["*"],
      weight: 1,
      anthropic_key_config: {
        workload_identity: { ...FEDERATION, identity_source: { type: "file", path: TOKEN_FILE } },
      },
    });
    check("key written with workload_identity", wrote.status === 200, `${wrote.status} ${wrote.text.slice(0, 300)}`);

    const customer = await admin("POST", "/api/governance/customers", { name: NAME });
    const vk = await admin("POST", "/api/governance/virtual-keys", {
      name: NAME,
      customer_id: customer.json?.customer?.id,
      provider_configs: [{ provider: "anthropic", allowed_models: ["*"], key_ids: ["*"] }],
    });
    const VK = vk.json?.virtual_key?.value ?? "";
    check("virtual key for anthropic", !!VK, `${vk.status} ${vk.text.slice(0, 200)}`);

    const m1 = await messages(VK);
    check("POST /anthropic/v1/messages 200", m1.status === 200, m1.status === 200 ? "" : m1.text.slice(0, 400));
    let seen = await fakeSeen();
    // Bifrost lists the key's models when the key is written; that call
    // is federated too, and the exchange it made is the one messages use.
    check("model listing used the minted bearer",
      seen.models.length > 0 && seen.models.every((m: any) => m.auth === "Bearer sk-ant-oat01-e2e-1"), JSON.stringify(seen.models));
    const ex = seen.exchanges[0];
    check("exactly one exchange", seen.exchanges.length === 1, `${seen.exchanges.length}`);
    check("exchange accepted by the fake's checks", !!ex && ex.problem === null, ex?.problem ?? "none");
    check("exchange carries rule/org/service account",
      ex?.federation_rule_id === FEDERATION.federation_rule_id && ex?.organization_id === FEDERATION.organization_id &&
        ex?.service_account_id === FEDERATION.service_account_id,
      JSON.stringify(ex && { r: ex.federation_rule_id, o: ex.organization_id, s: ex.service_account_id }));
    check("exchange sends the federation beta", String(ex?.beta).includes("oidc-federation"), ex?.beta);
    const msg = seen.messages[seen.messages.length - 1];
    check("messages call sent the minted bearer, no x-api-key",
      msg?.auth === "Bearer sk-ant-oat01-e2e-1" && msg?.xApiKey === "", JSON.stringify(msg));

    const m2 = await messages(VK);
    seen = await fakeSeen();
    check("second call reuses the token (no new exchange)", m2.status === 200 && seen.exchanges.length === 1,
      `${m2.status}, ${seen.exchanges.length} exchanges`);

    section("4. the signing key survives a restart");
    const before = (await fakeSeen()).exchanges.length;
    docker("restart", `${NAME}-gw`);
    await locate();
    const jwks2 = await http("GET", `${GW}${jwksPath}`);
    check("same kid after restart", jwks2.json?.keys?.[0]?.kid === kid, `${kid} → ${jwks2.json?.keys?.[0]?.kid}`);
    const v3 = verifyAgainst(tokenFile(), jwks.json);
    check("new token verifies against the key from before", v3.ok);
    // Bifrost exchanged while it booted (listing the key's models) and the
    // fake checked those assertions against the issuer's documents: they
    // must have been served before bifrost-http was ready.
    seen = await fakeSeen();
    const bootExchanges = seen.exchanges.slice(before);
    check("exchanges during boot were accepted", bootExchanges.length >= 1 && bootExchanges.every((e: any) => e.problem === null),
      JSON.stringify(bootExchanges.map((e: any) => e.problem)));
    const m3 = await messages(VK);
    check("a call after restart works, models listed at boot", m3.status === 200, m3.status === 200 ? "" : m3.text.slice(0, 300));
  } finally {
    if (KEEP) {
      console.log(`\nKEEP=1: containers ${NAME}-{gw,fake,redis} left up; gateway at ${GW}`);
    } else {
      for (const c of ["gw", "fake", "redis"]) spawnSync("docker", ["rm", "-f", `${NAME}-${c}`], { stdio: "ignore" });
      spawnSync("docker", ["volume", "rm", `${NAME}-data`], { stdio: "ignore" });
      spawnSync("docker", ["network", "rm", NAME], { stdio: "ignore" });
    }
  }
  console.log(failures.length ? `\n${failures.length} check(s) FAILED:\n  ${failures.join("\n  ")}` : "\nall checks passed");
  process.exit(failures.length ? 1 : 0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
