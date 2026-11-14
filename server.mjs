// server.mjs — Proof Gatekeeper agent (Manda 1) for Agent Games / zkVerify.
// Listens on port 3000 (the Cloudflare tunnel targets http://localhost:3000).
//
// Flow per task POST:
//   1. Verify HMAC (header x-agent-games-signature over the raw body) with
//      AGENT_SECRET — if the secret is not set yet (pre-registration) the
//      server accepts and warns; once set, a bad/missing signature is 401.
//   2. Decide APPROVE/REJECT with the 7 trap types (decide.mjs).
//   3. Generate the agent's own Groth16 proof with the gatekeeper circuit
//      (prove.mjs) and verify it locally before answering.
//   4. Best-effort Kurier submit (only if KURIER_API_KEY is set; the jobId
//      is logged, NOT awaited for Finalized — that can exceed the 60s window).
//   5. Respond { decision, reason_code, proof, public_signals }, signed with
//      x-agent-games-signature over the raw response body.
// Preflight: any request that is not a task (empty body, or a JSON object
// without task fields, or path /preflight) gets { ok: true, protocolVersion: "v1" }.
//
// Env:
//   PORT            default 3000 (MUST stay 3000 — the tunnel targets it)
//   AGENT_SECRET    HMAC secret issued once at agent registration (required in prod)
//   KURIER_API_KEY  optional — Kurier mainnet API key (request from Horizen Labs)
//   KURIER_API_URL  default https://api.kurier.xyz/api/v1
//   KURIER_CHAIN_ID default 0 (UNVERIFIED — see kurier.mjs)
//   SIGNATURE_ENCODING hex|base64, default hex (UNVERIFIED — preflight will confirm)
//   HOST            default 127.0.0.1
//
// Run:  node server.mjs   (Node 22)
//   ~/workspace/tools/node-v22.23.4-linux-x64/bin/node server.mjs
import http from "node:http";
import { createHmac, timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { decide, GATEKEEPER_VK_HASH } from "./decide.mjs";
import { prove } from "./prove.mjs";
import { submitProof } from "./kurier.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "127.0.0.1";
const AGENT_SECRET = process.env.AGENT_SECRET || "";
const KURIER_API_KEY = process.env.KURIER_API_KEY || "";
const KURIER_API_URL = process.env.KURIER_API_URL || "https://api.kurier.xyz/api/v1";
const KURIER_CHAIN_ID = Number(process.env.KURIER_CHAIN_ID || 0);
const SIG_ENCODING = (process.env.SIGNATURE_ENCODING || "hex").toLowerCase();
const RESPONSE_DEADLINE_MS = 55_000; // platform window is 60s; keep margin

const DATA_DIR = path.join(__dirname, "data");
const LOG_DIR = path.join(__dirname, "logs");
const SEEN_FILE = path.join(DATA_DIR, "seen-proof-tx.json");
const LOG_FILE = path.join(LOG_DIR, "gatekeeper.log");
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(LOG_DIR, { recursive: true });

// ---- seen proof_tx store (PROOF_REUSED detection, persistent) ----
let seenProofTx = new Set();
try {
  const raw = JSON.parse(fs.readFileSync(SEEN_FILE, "utf8"));
  if (Array.isArray(raw)) seenProofTx = new Set(raw.map(String));
} catch { /* first run: empty */ }
function persistSeen() {
  const arr = [...seenProofTx].slice(-10000);
  fs.writeFileSync(SEEN_FILE + ".tmp", JSON.stringify(arr));
  fs.renameSync(SEEN_FILE + ".tmp", SEEN_FILE);
}

// ---- logging (never logs AGENT_SECRET or any key material) ----
function logEvent(obj) {
  const line = JSON.stringify({ ts: new Date().toISOString(), ...obj });
  fs.appendFileSync(LOG_FILE, line + "\n");
  console.log(line);
}

// ---- HMAC helpers ----
function signBody(secret, body) {
  return createHmac("sha256", secret).update(body).digest(SIG_ENCODING);
}
function verifySignature(secret, body, signature) {
  if (!signature) return false;
  try {
    const expected = signBody(secret, body);
    const a = Buffer.from(expected, SIG_ENCODING === "base64" ? "base64" : "utf8");
    const b = Buffer.from(signature, SIG_ENCODING === "base64" ? "base64" : "utf8");
    return a.length === b.length && timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  const headers = { "content-type": "application/json" };
  if (AGENT_SECRET) headers["x-agent-games-signature"] = signBody(AGENT_SECRET, body);
  res.writeHead(status, headers);
  res.end(body);
  return body;
}

function readRawBody(req, limit = 1_000_000) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > limit) reject(new Error("body too large"));
      else chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

// A parsed body is a task if it (or its .task/.data wrapper) carries task fields.
const TASK_KEYS = ["taskId", "task_id", "minimum", "publicBalance", "public_balance", "recipient", "amount", "proofTx", "proof_tx"];
function unwrapTask(body) {
  if (!body || typeof body !== "object") return null;
  for (const wrapper of ["task", "data", "payload"]) {
    const inner = body[wrapper];
    if (inner && typeof inner === "object" && TASK_KEYS.some((k) => k in inner)) return inner;
  }
  return TASK_KEYS.some((k) => k in body) ? body : null;
}
function isPreflight(req, rawBody, parsed) {
  if (req.url === "/preflight" || req.url === "/agent/preflight") return true;
  if (!rawBody || rawBody.length === 0) return true;
  if (!parsed || typeof parsed !== "object") return true;
  if (parsed.type === "preflight" || parsed.kind === "preflight" || parsed.action === "preflight") return true;
  return unwrapTask(parsed) === null;
}

async function handleTask(task, reqId) {
  const t0 = Date.now();
  const result = decide(task, seenProofTx);
  const proofTx = result.fields.proofTx !== undefined ? String(result.fields.proofTx) : null;

  let proofData = null;
  let proveMs = null;
  let proveError = null;
  try {
    const p = await prove(result);
    proofData = { proof: p.proof, public_signals: p.publicSignals };
    proveMs = p.proveMs;
  } catch (e) {
    // Proving failed: the decision and the circuit disagree, or inputs are
    // malformed. Fail closed: keep the REJECT verdict (if it was APPROVE,
    // flip to REJECT — a proof we cannot generate must not be approved),
    // answer without a proof, and log loudly.
    proveError = String(e && e.message ? e.message : e).slice(0, 300);
    if (result.decision === "APPROVE") {
      result.decision = "REJECT";
      result.reason_code = "THRESHOLD_MISMATCH";
    }
  }

  // Record the proof_tx as seen (reuse check for later tasks).
  if (proofTx) {
    seenProofTx.add(proofTx);
    persistSeen();
  }

  // Best-effort Kurier submit (never blocks the response past the deadline).
  let kurierJobId = null;
  let kurierError = null;
  if (KURIER_API_KEY && proofData) {
    try {
      const remaining = RESPONSE_DEADLINE_MS - (Date.now() - t0) - 5000;
      if (remaining > 2000) {
        const r = await submitProof({
          proof: proofData.proof,
          publicSignals: proofData.public_signals,
          vkHash: GATEKEEPER_VK_HASH,
          apiKey: KURIER_API_KEY,
          apiUrl: KURIER_API_URL,
          chainId: KURIER_CHAIN_ID,
          timeoutMs: Math.min(15000, remaining),
        });
        kurierJobId = r.jobId;
      }
    } catch (e) {
      kurierError = String(e && e.message ? e.message : e).slice(0, 200);
    }
  }

  const totalMs = Date.now() - t0;
  logEvent({
    type: "task",
    reqId,
    taskId: result.fields.taskId !== undefined ? String(result.fields.taskId) : null,
    decision: result.decision,
    reason_code: result.reason_code,
    circuitDecision: result.circuitDecision,
    proofTxReuse: result.proofTxReuse,
    proveMs,
    totalMs,
    kurierJobId,
    kurierError,
    proveError,
    proofTxPrefix: proofTx ? proofTx.slice(0, 18) : null,
  });

  return {
    decision: result.decision,
    reason_code: result.reason_code,
    proof: proofData ? proofData.proof : null,
    public_signals: proofData ? proofData.public_signals : null,
  };
}

const server = http.createServer(async (req, res) => {
  const reqId = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  try {
    if (req.method === "GET" && (req.url === "/" || req.url === "/health")) {
      sendJson(res, 200, {
        ok: true,
        service: "gatekeeper-manda1",
        protocolVersion: "v1",
        track: "Proof Gatekeeper",
        agent: "manda1",
        hmac: AGENT_SECRET ? "configured" : "NOT SET (dev mode)",
        kurier: KURIER_API_KEY ? "configured" : "not configured",
        seenProofTx: seenProofTx.size,
      });
      return;
    }

    if (req.method !== "POST") {
      sendJson(res, 405, { error: "method not allowed" });
      return;
    }

    const rawBody = await readRawBody(req);

    // HMAC verification on the raw body (when a secret is configured).
    if (AGENT_SECRET) {
      const sig = req.headers["x-agent-games-signature"];
      if (!verifySignature(AGENT_SECRET, rawBody, sig)) {
        logEvent({ type: "auth_fail", reqId, url: req.url });
        sendJson(res, 401, { error: "invalid signature" });
        return;
      }
    } else {
      logEvent({ type: "auth_warn", reqId, note: "AGENT_SECRET not set — accepting unsigned (dev mode)" });
    }

    let parsed = null;
    try {
      parsed = rawBody.length ? JSON.parse(rawBody.toString("utf8")) : null;
    } catch {
      sendJson(res, 400, { error: "invalid json" });
      return;
    }

    if (isPreflight(req, rawBody, parsed)) {
      logEvent({ type: "preflight", reqId, url: req.url });
      sendJson(res, 200, { ok: true, protocolVersion: "v1" });
      return;
    }

    const task = unwrapTask(parsed);
    if (!task) {
      sendJson(res, 400, { error: "no task found in body" });
      return;
    }

    // Log the raw envelope shape (field names only) — the first live practice
    // task confirms the exact wire format; the values stay in the log file.
    logEvent({ type: "envelope", reqId, keys: Object.keys(task), taskId: task.taskId ?? task.task_id ?? null });
    const response = await handleTask(task, reqId);
    sendJson(res, 200, response);
  } catch (e) {
    logEvent({ type: "error", reqId, error: String(e && e.message ? e.message : e).slice(0, 300) });
    try {
      sendJson(res, 500, { error: "internal error" });
    } catch { /* socket already gone */ }
  }
});

server.listen(PORT, HOST, () => {
  console.log(`gatekeeper-manda1 listening on http://${HOST}:${PORT} (tunnel target http://localhost:3000)`);
  console.log(`hmac: ${AGENT_SECRET ? "configured" : "NOT SET (dev mode — will accept unsigned)"} | kurier: ${KURIER_API_KEY ? "configured" : "not configured (proofs returned locally only)"}`);
  logEvent({ type: "startup", port: PORT, host: HOST, hmac: !!AGENT_SECRET, kurier: !!KURIER_API_KEY });
});
