// decide.mjs — pure decision logic for the Proof Gatekeeper (Manda 1).
// Implements the 7 documented trap types. FAIL CLOSED: any check whose
// inputs are missing/unparseable fails with that check's reason code.
//
// Circuit-verified decision rule (reverse-engineered from the real
// gatekeeper circuit, GatekeeperEvaluation_79, line 102):
//   APPROVE (decision=1)  iff  publicBalance >= minimum
//                          AND recipient == conditionRecipient
//                          AND amount <= maxTransfer
//                          AND currentBlock < expiryBlock   (STRICT: equal == expired)
//                          AND registeredVkHash == proofVkHash
//   otherwise REJECT (decision=0).
// PROOF_REUSED is checked OFF-circuit (the circuit has no proofTx input):
// a reused proof_tx is always REJECT, even when the 5 on-circuit checks
// pass. In that case the proof is generated with the circuit-expected
// decision (see prove.mjs) — the verdict REJECT comes from the reuse
// check the platform itself can also see from proof_tx.

export const REASONS = {
  VALID_CONDITION: "VALID_CONDITION",
  VK_SUBSTITUTION: "VK_SUBSTITUTION",
  THRESHOLD_MISMATCH: "THRESHOLD_MISMATCH",
  PROOF_REUSED: "PROOF_REUSED",
  EXPIRED_CONDITION: "EXPIRED_CONDITION",
  RECIPIENT_MISMATCH: "RECIPIENT_MISMATCH",
  AMOUNT_OVERFLOW: "AMOUNT_OVERFLOW",
};

const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Pick the first defined (not null/undefined) value from a list of keys.
function pick(obj, keys) {
  for (const k of keys) {
    if (obj && obj[k] !== undefined && obj[k] !== null) return obj[k];
  }
  return undefined;
}

function toBigInt(v) {
  if (v === undefined || v === null) return undefined;
  try {
    if (typeof v === "bigint") return v;
    if (typeof v === "number") return BigInt(Math.trunc(v));
    if (typeof v === "string") {
      const s = v.trim();
      if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
      if (/^-?\d+$/.test(s)) return BigInt(s);
      return undefined;
    }
    return undefined;
  } catch {
    return undefined;
  }
}

// Normalize a VK value to a comparable hash string (lowercase hex, no 0x).
// - "0x..." hash string -> the hex itself.
// - full VK object -> sha256 of canonical JSON (FALLBACK, unverified:
//   the platform's vkHash is NOT keccak256 of the vk.json/zkey/wasm, so
//   if the envelope ever carries full VK objects this derivation may not
//   match the platform's. Prefer envelopes that carry hash strings.)
import { createHash } from "node:crypto";
export function normalizeVkHash(v) {
  if (v === undefined || v === null) return undefined;
  if (typeof v === "string") {
    const s = v.trim().toLowerCase();
    if (s.startsWith("0x")) return s;
    if (/^[0-9a-f]{64}$/.test(s)) return "0x" + s;
    return s; // some other string form; compare as-is
  }
  if (typeof v === "object") {
    const canon = JSON.stringify(v, Object.keys(v).sort());
    return "0x" + createHash("sha256").update(canon).digest("hex");
  }
  return undefined;
}

function normalizeAddress(a) {
  if (typeof a !== "string") return undefined;
  return a.trim().toLowerCase();
}

// The platform's published gatekeeper verification-key hash
// (GET /api/circuit-info -> gatekeeper.vkHash).
export const GATEKEEPER_VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

/**
 * Decide a task.
 * @param {object} task - raw task envelope (camelCase or snake_case).
 * @param {Set<string>} seenProofTx - proof_tx values already processed.
 * @returns {{
 *   decision: "APPROVE"|"REJECT",
 *   reason_code: string,
 *   circuitDecision: 0|1,      // decision the circuit expects (proof is built with this)
 *   checks: object,            // per-check booleans (false = failed / unknown)
 *   fields: object,            // normalized fields used
 *   proofTxReuse: boolean
 * }}
 */
export function decide(task, seenProofTx = new Set()) {
  const fields = {
    taskId: pick(task, ["taskId", "task_id", "id"]),
    minimum: toBigInt(pick(task, ["minimum"])),
    publicBalance: toBigInt(pick(task, ["publicBalance", "public_balance", "balance"])),
    recipient: normalizeAddress(pick(task, ["recipient"])),
    conditionRecipient: normalizeAddress(
      pick(task, ["conditionRecipient", "condition_recipient"])
    ),
    amount: toBigInt(pick(task, ["amount"])),
    maxTransfer: toBigInt(pick(task, ["maxTransfer", "max_transfer"])),
    expiryBlock: toBigInt(pick(task, ["expiryBlock", "expiry_block"])),
    currentBlock: toBigInt(pick(task, ["currentBlock", "current_block"])),
    registeredVkHash: normalizeVkHash(
      pick(task, ["registeredVkHash", "registered_vk_hash", "registeredVk", "registered_vk"])
    ),
    proofVkHash: normalizeVkHash(
      pick(task, ["proofVkHash", "proof_vk_hash", "proofVk", "proof_vk"])
    ),
    proofTx: pick(task, ["proofTx", "proof_tx", "proofTxHash", "proof_tx_hash"]),
  };

  // 1. VK substitution — registered VK must equal the proof's VK.
  const vkOk =
    fields.registeredVkHash !== undefined &&
    fields.proofVkHash !== undefined &&
    fields.registeredVkHash === fields.proofVkHash;
  // 2. Threshold — balance must cover the minimum (inclusive).
  const thresholdOk =
    fields.minimum !== undefined &&
    fields.publicBalance !== undefined &&
    fields.publicBalance >= fields.minimum;
  // 3. Recipient — must match the condition's recipient exactly.
  const recipientOk =
    fields.recipient !== undefined &&
    fields.conditionRecipient !== undefined &&
    fields.recipient === fields.conditionRecipient;
  // 4. Amount — must not exceed the max transfer (inclusive).
  const amountOk =
    fields.amount !== undefined &&
    fields.maxTransfer !== undefined &&
    fields.amount <= fields.maxTransfer;
  // 5. Expiry — current block must be STRICTLY before the expiry block.
  const expiryOk =
    fields.expiryBlock !== undefined &&
    fields.currentBlock !== undefined &&
    fields.currentBlock < fields.expiryBlock;

  const checks = { vkOk, thresholdOk, recipientOk, amountOk, expiryOk };
  const circuitDecision = vkOk && thresholdOk && recipientOk && amountOk && expiryOk ? 1 : 0;

  // 6. Proof reuse (off-circuit): a proof_tx seen before is a reject.
  const proofTxReuse =
    fields.proofTx !== undefined &&
    fields.proofTx !== null &&
    seenProofTx.has(String(fields.proofTx));

  let decision = "APPROVE";
  let reason_code = REASONS.VALID_CONDITION;
  if (!vkOk) {
    decision = "REJECT";
    reason_code = REASONS.VK_SUBSTITUTION;
  } else if (!thresholdOk) {
    decision = "REJECT";
    reason_code = REASONS.THRESHOLD_MISMATCH;
  } else if (!recipientOk) {
    decision = "REJECT";
    reason_code = REASONS.RECIPIENT_MISMATCH;
  } else if (!amountOk) {
    decision = "REJECT";
    reason_code = REASONS.AMOUNT_OVERFLOW;
  } else if (!expiryOk) {
    decision = "REJECT";
    reason_code = REASONS.EXPIRED_CONDITION;
  } else if (proofTxReuse) {
    decision = "REJECT";
    reason_code = REASONS.PROOF_REUSED;
  }

  return { decision, reason_code, circuitDecision, checks, fields, proofTxReuse };
}

export { FIELD_PRIME };
