// prove.mjs — encode a task into gatekeeper circuit inputs and generate
// a Groth16 proof with snarkjs (BN128).
//
// Circuit inputs (13 total; found by probing the wasm's input-signal table):
//   decision, taskId, minimum, publicBalance, recipient, conditionRecipient,
//   amount, maxTransfer, expiryBlock, currentBlock, salt (PRIVATE),
//   registeredVkHash, proofVkHash.
// Public signals returned by the circuit, in order:
//   [0] commitment = Poseidon([salt, taskId])   (verified against 3 vectors)
//   [1] registeredVkHash   [2] proofVkHash      [3] minimum
//   [4] publicBalance      [5] expiryBlock      [6] currentBlock
//   [7] recipient          [8] conditionRecipient
//   [9] amount             [10] maxTransfer
//   [11] decision          [12] taskId
// Encodings: addresses as BigInt(address); vk hashes as BigInt("0x...") —
// snarkjs reduces mod p automatically (the platform vkHash 0x6b79... is
// 256-bit and exceeds the field prime, so mod-p reduction matters).
import * as snarkjs from "snarkjs";
import { randomBytes, createHash } from "node:crypto";
import { FIELD_PRIME } from "./decide.mjs";

const WASM = new URL("../circuits/gatekeeper.wasm", import.meta.url).pathname;
const ZKEY = new URL("../circuits/gatekeeper_final.zkey", import.meta.url).pathname;

let vkCache = null;
export async function getVerificationKey() {
  if (!vkCache) vkCache = await snarkjs.zKey.exportVerificationKey(ZKEY);
  return vkCache;
}

// taskId -> field element.
// - number / numeric string -> itself.
// - "0x..." hex -> BigInt.
// - "gk_<hex>" (the dashboard display form) -> the hex suffix as int.
// - any other string -> sha256(string) mod p (FALLBACK, unverified:
//   the real envelope's taskId format is only confirmed once a live
//   practice task is observed; the raw envelope is logged for that).
export function encodeTaskId(raw) {
  if (raw === undefined || raw === null) throw new Error("taskId missing");
  if (typeof raw === "bigint") return raw;
  if (typeof raw === "number") return BigInt(Math.trunc(raw));
  if (typeof raw === "string") {
    const s = raw.trim();
    if (/^\d+$/.test(s)) return BigInt(s);
    if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
    const m = s.match(/^gk_([0-9a-fA-F]+)$/i);
    if (m) return BigInt("0x" + m[1]);
    const h = createHash("sha256").update(s).digest();
    return BigInt("0x" + h.toString("hex")) % FIELD_PRIME;
  }
  throw new Error(`unsupported taskId type: ${typeof raw}`);
}

// Fresh random salt per task (private input; makes each proof unique and
// binds it to this task via commitment = Poseidon([salt, taskId])).
export function freshSalt() {
  return BigInt("0x" + randomBytes(16).toString("hex"));
}

// Build the circuit input object from a decide() result.
// `decision` here is the CIRCUIT decision (0/1), which for a PROOF_REUSED
// task with otherwise-passing checks is 1 even though the verdict is REJECT
// (the circuit cannot prove a 0 when all 5 checks pass — see README).
export function buildCircuitInput(decisionResult, { salt } = {}) {
  const f = decisionResult.fields;
  const taskId = encodeTaskId(f.taskId);
  const usedSalt = salt !== undefined ? BigInt(salt) : freshSalt();
  const input = {
    decision: decisionResult.circuitDecision,
    taskId: taskId.toString(),
    minimum: f.minimum.toString(),
    publicBalance: f.publicBalance.toString(),
    recipient: BigInt(f.recipient).toString(),
    conditionRecipient: BigInt(f.conditionRecipient).toString(),
    amount: f.amount.toString(),
    maxTransfer: f.maxTransfer.toString(),
    expiryBlock: f.expiryBlock.toString(),
    currentBlock: f.currentBlock.toString(),
    salt: usedSalt.toString(),
    registeredVkHash: BigInt(f.registeredVkHash).toString(),
    proofVkHash: BigInt(f.proofVkHash).toString(),
  };
  return { input, salt: usedSalt, taskId };
}

// Generate the proof and verify it locally before returning.
// Returns { proof, publicSignals, proveMs, verifyOk }.
// Throws if proving fails (e.g. decision/input mismatch) or local verify fails.
export async function prove(decisionResult, opts = {}) {
  const t0 = Date.now();
  const { input, salt, taskId } = buildCircuitInput(decisionResult, opts);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  const proveMs = Date.now() - t0;
  const vk = await getVerificationKey();
  const verifyOk = await snarkjs.groth16.verify(vk, publicSignals, proof);
  if (!verifyOk) throw new Error("local proof verification failed");
  return { proof, publicSignals, proveMs, verifyOk, salt, taskId };
}
