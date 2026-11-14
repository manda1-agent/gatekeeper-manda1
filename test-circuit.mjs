// Reverse-engineer gatekeeper circuit semantics via fullProve.
// Hypothesis: decision must equal 1 iff ALL checks pass:
//   publicBalance >= minimum, recipient == conditionRecipient,
//   amount <= maxTransfer, currentBlock <= expiryBlock,
//   registeredVkHash == proofVkHash.
// Encodings tried: addresses as BigInt, vkHash as BigInt(hex) (auto mod p),
// taskId as small int, salt as arbitrary int.
import * as snarkjs from "snarkjs";
import fs from "node:fs";

const WASM = "/home/hatch/workspace/agent-games-zkverify/circuits/gatekeeper.wasm";
const ZKEY = "/home/hatch/workspace/agent-games-zkverify/circuits/gatekeeper_final.zkey";
const VK = JSON.parse(fs.readFileSync("/tmp/ag2/gk-vk.json", "utf8"));

const VK_HASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const ADDR = "0xDe42dE42dE42dE42dE42dE42dE42dE42dE429f01";
const ADDR2 = "0x7a01c4b27a01c4b27a01c4b27a01c4b27a01c4b2";

const base = {
  decision: 1,
  taskId: 1,
  minimum: 1000,
  publicBalance: 1460,
  recipient: BigInt(ADDR).toString(),
  conditionRecipient: BigInt(ADDR).toString(),
  amount: 100,
  maxTransfer: 1000,
  expiryBlock: 1000,
  currentBlock: 500,
  salt: 42,
  registeredVkHash: BigInt(VK_HASH).toString(),
  proofVkHash: BigInt(VK_HASH).toString(),
};

async function attempt(name, input, expectOk) {
  const t0 = Date.now();
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    const ms = Date.now() - t0;
    const ok = await snarkjs.groth16.verify(VK, publicSignals, proof);
    console.log(`${expectOk ? "PASS?" : "UNEXPECTED-PASS"} ${name} | prove ${ms}ms | verify=${ok} | pubSignals=${JSON.stringify(publicSignals)}`);
    return { ok: true, ms, publicSignals };
  } catch (e) {
    const ms = Date.now() - t0;
    console.log(`${expectOk ? "UNEXPECTED-FAIL" : "EXPECTED-FAIL"} ${name} | ${ms}ms | ${String(e.message || e).slice(0, 160)}`);
    return { ok: false, ms };
  }
}

console.log("== circuit semantics probe ==\n");
const r0 = await attempt("A: all checks pass, decision=1 (expect prove OK)", { ...base }, true);
await attempt("B: all checks pass, decision=0 (expect FAIL if decision enforced)", { ...base, decision: 0 }, false);
await attempt("C: balance<minimum, decision=1 (expect FAIL)", { ...base, publicBalance: 500 }, false);
await attempt("D: balance<minimum, decision=0 (expect OK = correct reject)", { ...base, publicBalance: 500, decision: 0 }, true);
await attempt("E: recipient mismatch, decision=1 (expect FAIL)", { ...base, recipient: BigInt(ADDR2).toString() }, false);
await attempt("F: recipient mismatch, decision=0 (expect OK)", { ...base, recipient: BigInt(ADDR2).toString(), decision: 0 }, true);
await attempt("G: amount>max, decision=1 (expect FAIL)", { ...base, amount: 5000 }, false);
await attempt("H: expired (current>expiry), decision=1 (expect FAIL)", { ...base, currentBlock: 1500 }, false);
await attempt("I: vkHash mismatch, decision=1 (expect FAIL)", { ...base, proofVkHash: BigInt("0x" + "11".repeat(32)).toString() }, false);
await attempt("J: vkHash mismatch, decision=0 (expect OK)", { ...base, proofVkHash: BigInt("0x" + "11".repeat(32)).toString(), decision: 0 }, true);
await attempt("K: taskId=2513 (other value), all pass, decision=1", { ...base, taskId: 2513 }, true);
await attempt("L: salt=999999, all pass, decision=1", { ...base, salt: 999999 }, true);
await attempt("M: edge balance==minimum, decision=1 (expect OK)", { ...base, publicBalance: 1000 }, true);
await attempt("N: edge amount==max, decision=1 (expect OK)", { ...base, amount: 1000 }, true);
await attempt("O: edge current==expiry, decision=1 (expect OK)", { ...base, currentBlock: 1000 }, true);
console.log("\ndone");
