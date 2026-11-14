// kurier.mjs — submit a Groth16 proof to zkVerify via Kurier (REST).
// Docs: https://docs.zkverify.io/overview/getting-started/kurier
//   Mainnet: https://api.kurier.xyz/api/v1
//   Testnet: https://api-testnet.kurier.xyz/api/v1
//   POST /register-vk/{API_KEY}   { proofType: "groth16",
//                                   proofOptions: { library: "snarkjs", curve: "bn128" },
//                                   vk }
//   POST /submit-proof/{API_KEY}  { proofType: "groth16", vkRegistered: true,
//                                   chainId, proofData: { proof, publicSignals, vk } }
//   GET  /job-status/{API_KEY}/{jobId}  -> status Queued|Valid|Submitted|
//        IncludedInBlock|Finalized (or Failed).
//
// The Agent Games platform already registered the gatekeeper VK (its vkHash
// is published on /api/circuit-info), so we submit with vkRegistered: true
// and vk = the published vkHash — no register-vk call needed.
// NOTE: chainId semantics for the game are UNVERIFIED (the docs example
// uses 11155111 Sepolia; zkVerifyJS uses domainId 0). Default 0, override
// with KURIER_CHAIN_ID. Kurier submission is BEST-EFFORT inside the 60s
// response window: we POST and return the jobId, but we do NOT wait for
// Finalized (that can take longer than the window). The platform verifies
// the proof itself from the response.

const DEFAULT_API_URL = "https://api.kurier.xyz/api/v1";

async function fetchWithTimeout(url, options, timeoutMs) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}

// Submit the proof. Returns { jobId } on success, throws on failure.
// `proof` = snarkjs proof object, `publicSignals` = array of decimal strings.
export async function submitProof({ proof, publicSignals, vkHash, apiKey, apiUrl, chainId = 0, timeoutMs = 15000 }) {
  const base = (apiUrl || DEFAULT_API_URL).replace(/\/$/, "");
  const res = await fetchWithTimeout(
    `${base}/submit-proof/${apiKey}`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        proofType: "groth16",
        vkRegistered: true,
        chainId,
        proofData: { proof, publicSignals, vk: vkHash },
      }),
    },
    timeoutMs
  );
  const text = await res.text();
  if (!res.ok) throw new Error(`kurier submit-proof HTTP ${res.status}: ${text.slice(0, 200)}`);
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(`kurier submit-proof non-JSON: ${text.slice(0, 200)}`);
  }
  if (!data.jobId) throw new Error(`kurier submit-proof no jobId: ${text.slice(0, 200)}`);
  return { jobId: data.jobId, raw: data };
}

export async function getJobStatus({ apiKey, jobId, apiUrl, timeoutMs = 10000 }) {
  const base = (apiUrl || DEFAULT_API_URL).replace(/\/$/, "");
  const res = await fetchWithTimeout(`${base}/job-status/${apiKey}/${jobId}`, {}, timeoutMs);
  const text = await res.text();
  if (!res.ok) throw new Error(`kurier job-status HTTP ${res.status}: ${text.slice(0, 200)}`);
  return JSON.parse(text);
}

export { DEFAULT_API_URL };
