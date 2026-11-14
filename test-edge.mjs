// Edge-case semantics: boundary equality + commitment-hash scope.
// Logs to file as it goes (survives hangs).
import * as snarkjs from "snarkjs";
import fs from "node:fs";

const WASM = "/home/hatch/workspace/agent-games-zkverify/circuits/gatekeeper.wasm";
const ZKEY = "/home/hatch/workspace/agent-games-zkverify/circuits/gatekeeper_final.zkey";
const VK = JSON.parse(fs.readFileSync("/tmp/ag2/gk-vk.json", "utf8"));
const LOG = "/tmp/ag2/edge-test.log";
fs.writeFileSync(LOG, "");
const log = (s) => { fs.appendFileSync(LOG, s + "\n"); console.log(s); };

const VK_HASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const ADDR = "0xDe42dE42dE42dE42dE42dE42dE42dE42dE429f01";
const base = {
  decision: 1, taskId: 1, minimum: 1000, publicBalance: 1460,
  recipient: BigInt(ADDR).toString(), conditionRecipient: BigInt(ADDR).toString(),
  amount: 100, maxTransfer: 1000, expiryBlock: 1000, currentBlock: 500, salt: 42,
  registeredVkHash: BigInt(VK_HASH).toString(), proofVkHash: BigInt(VK_HASH).toString(),
};

async function attempt(name, input, expectOk) {
  const t0 = Date.now();
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    const ms = Date.now() - t0;
    const ok = await snarkjs.groth16.verify(VK, publicSignals, proof);
    log(`${expectOk ? "PASS?" : "UNEXPECTED-PASS"} ${name} | prove ${ms}ms | verify=${ok} | pub0=${publicSignals[0]} | pub11=${publicSignals[11]} pub12=${publicSignals[12]}`);
    return publicSignals;
  } catch (e) {
    log(`${expectOk ? "UNEXPECTED-FAIL" : "EXPECTED-FAIL"} ${name} | ${Date.now() - t0}ms | ${String(e.message || e).slice(0, 120)}`);
    return null;
  }
}

log("== edge cases ==");
const pA = await attempt("M: balance==minimum, decision=1", { ...base, publicBalance: 1000 }, true);
const pN = await attempt("N: amount==max, decision=1", { ...base, amount: 1000 }, true);
const pO = await attempt("O: current==expiry, decision=1", { ...base, currentBlock: 1000 }, true);
// commitment scope: change ONLY minimum -> does pub0 change?
const pP = await attempt("P: minimum=2000 (other fields same), decision=1, balance 2460", { ...base, minimum: 2000, publicBalance: 2460 }, true);
log("pub0 A vs P (minimum changed): " + (pA && pP ? (pA[0] === pP[0] ? "SAME -> hash covers only taskId+salt" : "DIFFERENT -> hash covers more") : "n/a"));
log("done");
