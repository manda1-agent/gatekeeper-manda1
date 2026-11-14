// test-e2e.mjs — end-to-end test: spawn server.mjs on port 3000, POST
// sample tasks, verify response shape, HMAC signature, proof validity,
// and timing. Run: node test-e2e.mjs
import { spawn } from "node:child_process";
import { createHmac } from "node:crypto";
import * as snarkjs from "snarkjs";

const NODE = "/home/hatch/workspace/tools/node-v22.23.4-linux-x64/bin/node";
const SECRET = "test-secret-do-not-use-in-prod";
const BASE = "http://127.0.0.1:3000";
const VK = await snarkjs.zKey.exportVerificationKey(
  new URL("../circuits/gatekeeper_final.zkey", import.meta.url).pathname
);
const GATEKEEPER_VK_HASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const ADDR = "0xDe42dE42dE42dE42dE42dE42dE42dE42dE429f01";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function hmac(body) {
  return createHmac("sha256", SECRET).update(body).digest("hex");
}
async function post(path, bodyObj, { sign = true, rawBody = null } = {}) {
  const body = rawBody !== null ? rawBody : JSON.stringify(bodyObj ?? {});
  const headers = { "content-type": "application/json" };
  if (sign) headers["x-agent-games-signature"] = hmac(body);
  const t0 = Date.now();
  const res = await fetch(BASE + path, { method: "POST", headers, body });
  const text = await res.text();
  return { status: res.status, ms: Date.now() - t0, text, sig: res.headers.get("x-agent-games-signature"), json: (() => { try { return JSON.parse(text); } catch { return null; } })() };
}

let pass = 0, fail = 0;
const check = (name, ok, extra = "") => {
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${extra ? " | " + extra : ""}`);
  ok ? pass++ : fail++;
};

const server = spawn(NODE, ["server.mjs"], {
  cwd: import.meta.dirname,
  env: { ...process.env, PORT: "3000", AGENT_SECRET: SECRET },
  stdio: ["ignore", "pipe", "pipe"],
});
server.stdout.on("data", (d) => process.stdout.write("[server] " + d));
server.stderr.on("data", (d) => process.stdout.write("[server:err] " + d));

// wait for health
let up = false;
for (let i = 0; i < 30; i++) {
  try {
    const r = await fetch(BASE + "/health");
    if (r.ok) { up = true; break; }
  } catch { /* not up yet */ }
  await sleep(500);
}
check("server starts on :3000", up);

const validTask = {
  taskId: "gk_e2e1", minimum: "1000", publicBalance: "1460",
  recipient: ADDR, conditionRecipient: ADDR, amount: "100", maxTransfer: "1000",
  expiryBlock: "1000", currentBlock: "500",
  registeredVkHash: GATEKEEPER_VK_HASH, proofVkHash: GATEKEEPER_VK_HASH,
  proofTx: "0xe2e-valid-1",
};
const thresholdTask = { ...validTask, taskId: "gk_e2e2", publicBalance: "500", proofTx: "0xe2e-thr-1" };

try {
  // 1. preflight (empty body)
  const pre = await post("/", null, { rawBody: "" });
  check("preflight empty body -> {ok:true, protocolVersion:v1}", pre.status === 200 && pre.json?.ok === true && pre.json?.protocolVersion === "v1", `HTTP ${pre.status} ${pre.ms}ms`);

  // 2. valid task -> APPROVE + proof that verifies locally + signed response
  const t1 = await post("/", validTask);
  const okShape = t1.status === 200 && t1.json?.decision === "APPROVE" && t1.json?.reason_code === "VALID_CONDITION"
    && t1.json?.proof && Array.isArray(t1.json?.public_signals) && t1.json.public_signals.length === 13;
  check("valid task -> APPROVE + proof + 13 public signals", okShape, `HTTP ${t1.status} ${t1.ms}ms`);
  let proofOk = false;
  if (t1.json?.proof && t1.json?.public_signals) {
    proofOk = await snarkjs.groth16.verify(VK, t1.json.public_signals, t1.json.proof);
    // public signals must match the task: [11]=decision 1, [12]=taskId, [4]=balance
    const ps = t1.json.public_signals;
    const match = ps[11] === "1" && ps[4] === "1460" && ps[3] === "1000";
    check("returned proof verifies against platform VK + signals match task", proofOk && match, `verify=${proofOk} ps[11]=${ps[11]} ps[4]=${ps[4]}`);
  } else {
    check("returned proof verifies against platform VK + signals match task", false, "no proof in response");
  }
  // response signature valid?
  if (t1.text && t1.sig) {
    const expectSig = createHmac("sha256", SECRET).update(t1.text).digest("hex");
    check("response carries valid x-agent-games-signature", t1.sig === expectSig);
  } else {
    check("response carries valid x-agent-games-signature", false, "no signature header");
  }
  check("valid task answered well under 60s", t1.ms < 60000, `${t1.ms}ms`);

  // 3. threshold task -> REJECT + proof for decision 0 (also verifies)
  const t2 = await post("/", thresholdTask);
  const ok2 = t2.status === 200 && t2.json?.decision === "REJECT" && t2.json?.reason_code === "THRESHOLD_MISMATCH" && t2.json?.proof;
  check("threshold task -> REJECT/THRESHOLD_MISMATCH + proof", ok2, `HTTP ${t2.status} ${t2.ms}ms`);
  if (t2.json?.proof) {
    const v2 = await snarkjs.groth16.verify(VK, t2.json.public_signals, t2.json.proof);
    check("reject proof verifies (decision 0 in signals)", v2 && t2.json.public_signals[11] === "0", `verify=${v2} ps[11]=${t2.json.public_signals[11]}`);
  }

  // 4. same proofTx again -> PROOF_REUSED
  const t3 = await post("/", validTask);
  check("reused proofTx -> REJECT/PROOF_REUSED", t3.status === 200 && t3.json?.decision === "REJECT" && t3.json?.reason_code === "PROOF_REUSED", `HTTP ${t3.status} got ${t3.json?.decision}/${t3.json?.reason_code}`);

  // 5. bad signature -> 401
  const t4 = await post("/", validTask, { sign: false });
  check("unsigned request -> 401", t4.status === 401, `HTTP ${t4.status}`);

  // 6. preflight via {type:"preflight"}
  const t5 = await post("/", { type: "preflight" });
  check("preflight JSON -> {ok:true}", t5.status === 200 && t5.json?.ok === true, `HTTP ${t5.status}`);
} finally {
  server.kill("SIGTERM");
  await sleep(500);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
