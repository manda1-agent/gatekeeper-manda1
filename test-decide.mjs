// test-decide.mjs — decision-logic tests: one synthetic task per trap type
// plus boundary cases. Run: node test-decide.mjs
import { decide, GATEKEEPER_VK_HASH } from "./decide.mjs";

const ADDR = "0xDe42dE42dE42dE42dE42dE42dE42dE42dE429f01";
const ADDR2 = "0x7a01c4b27a01c4b27a01c4b27a01c4b27a01c4b2";
const VK_OTHER = "0x1111111111111111111111111111111111111111111111111111111111111111";

function baseTask(overrides = {}) {
  return {
    taskId: "gk_9d1",
    minimum: "1000",
    publicBalance: "1460",
    recipient: ADDR,
    conditionRecipient: ADDR,
    amount: "100",
    maxTransfer: "1000",
    expiryBlock: "1000",
    currentBlock: "500",
    registeredVkHash: GATEKEEPER_VK_HASH,
    proofVkHash: GATEKEEPER_VK_HASH,
    proofTx: "0xabc123",
    ...overrides,
  };
}

const seen = new Set();
const cases = [
  { name: "VALID_CONDITION -> APPROVE", task: baseTask({ proofTx: "0xvalid1" }), want: ["APPROVE", "VALID_CONDITION", 1] },
  { name: "VK_SUBSTITUTION -> REJECT", task: baseTask({ proofTx: "0xvk1", proofVkHash: VK_OTHER }), want: ["REJECT", "VK_SUBSTITUTION", 0] },
  { name: "THRESHOLD_MISMATCH -> REJECT", task: baseTask({ proofTx: "0xth1", publicBalance: "500" }), want: ["REJECT", "THRESHOLD_MISMATCH", 0] },
  { name: "RECIPIENT_MISMATCH -> REJECT", task: baseTask({ proofTx: "0xrc1", recipient: ADDR2 }), want: ["REJECT", "RECIPIENT_MISMATCH", 0] },
  { name: "AMOUNT_OVERFLOW -> REJECT", task: baseTask({ proofTx: "0xam1", amount: "5000" }), want: ["REJECT", "AMOUNT_OVERFLOW", 0] },
  { name: "EXPIRED_CONDITION -> REJECT", task: baseTask({ proofTx: "0xex1", currentBlock: "1500" }), want: ["REJECT", "EXPIRED_CONDITION", 0] },
  // boundaries (circuit-verified): balance==minimum OK, amount==max OK,
  // current==expiry EXPIRED (strict <).
  { name: "boundary balance==minimum -> APPROVE", task: baseTask({ proofTx: "0xb1", publicBalance: "1000" }), want: ["APPROVE", "VALID_CONDITION", 1] },
  { name: "boundary amount==max -> APPROVE", task: baseTask({ proofTx: "0xb2", amount: "1000" }), want: ["APPROVE", "VALID_CONDITION", 1] },
  { name: "boundary current==expiry -> REJECT EXPIRED", task: baseTask({ proofTx: "0xb3", currentBlock: "1000" }), want: ["REJECT", "EXPIRED_CONDITION", 0] },
  { name: "boundary current==expiry-1 -> APPROVE", task: baseTask({ proofTx: "0xb4", currentBlock: "999" }), want: ["APPROVE", "VALID_CONDITION", 1] },
  // snake_case envelope form
  { name: "snake_case fields -> APPROVE", task: { task_id: "gk_9d2", minimum: "1000", public_balance: "1460", recipient: ADDR, condition_recipient: ADDR, amount: "100", max_transfer: "1000", expiry_block: "1000", current_block: "500", registered_vk: GATEKEEPER_VK_HASH, proof_vk: GATEKEEPER_VK_HASH, proof_tx: "0xsnake1" }, want: ["APPROVE", "VALID_CONDITION", 1] },
  // missing fields fail closed
  { name: "missing publicBalance -> REJECT THRESHOLD", task: baseTask({ proofTx: "0xm1", publicBalance: undefined }), want: ["REJECT", "THRESHOLD_MISMATCH", 0] },
];

let pass = 0;
let fail = 0;
for (const c of cases) {
  const r = decide(c.task, seen);
  const got = [r.decision, r.reason_code, r.circuitDecision];
  const ok = got[0] === c.want[0] && got[1] === c.want[1] && got[2] === c.want[2];
  console.log(`${ok ? "PASS" : "FAIL"} ${c.name} | got ${got.join("/")} want ${c.want.join("/")}`);
  ok ? pass++ : fail++;
  if (c.task.proofTx) seen.add(String(c.task.proofTx));
  if (c.task.proof_tx) seen.add(String(c.task.proof_tx));
}

// PROOF_REUSED: same proofTx as an earlier task, all other checks pass.
// Verdict must be REJECT/PROOF_REUSED, but circuitDecision must be 1
// (the circuit cannot prove 0 when the 5 on-circuit checks pass).
const reused = decide(baseTask({ proofTx: "0xvalid1" }), seen);
const reuseOk = reused.decision === "REJECT" && reused.reason_code === "PROOF_REUSED" && reused.circuitDecision === 1;
console.log(`${reuseOk ? "PASS" : "FAIL"} PROOF_REUSED -> REJECT (circuitDecision stays 1) | got ${reused.decision}/${reused.reason_code}/circuit=${reused.circuitDecision}`);
reuseOk ? pass++ : fail++;

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
