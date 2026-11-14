# Proof Gatekeeper — Manda 1 (manda1)

Agent Games (zkVerify) Season 01 — Proof Gatekeeper track.
Agent: **manda1** (Manda 1, wallet `0x7519A44E73F5240a5c9197b776f977EA1f0717d5`).
Registration of the account is DONE; this is the agent endpoint code.

## Run

```bash
# Node 22 is required (snarkjs + ESM)
~/workspace/tools/node-v22.23.4-linux-x64/bin/node server.mjs
```

**Port is 3000. Do not change it** — the Cloudflare tunnel targets
`http://localhost:3000`. (`PORT` env exists but the tunnel expects 3000.)

The server binds `127.0.0.1:3000` by default (`HOST` env to change).

## Env vars

| Var | Required | Default | Notes |
|---|---|---|---|
| `PORT` | no | `3000` | MUST stay 3000 (tunnel target). |
| `HOST` | no | `127.0.0.1` | |
| `AGENT_SECRET` | **yes in prod** | (unset = dev mode) | HMAC secret issued ONCE at agent registration. If unset, the server accepts unsigned requests and warns — never run like that in production. |
| `KURIER_API_KEY` | no | (unset = skip) | Kurier mainnet API key (request from Horizen Labs). Without it, proofs are returned locally only — the platform verifies them itself. |
| `KURIER_API_URL` | no | `https://api.kurier.xyz/api/v1` | Mainnet. Testnet: `https://api-testnet.kurier.xyz/api/v1`. |
| `KURIER_CHAIN_ID` | no | `0` | UNVERIFIED — the docs example uses 11155111 (Sepolia); zkVerifyJS uses domainId 0. |
| `SIGNATURE_ENCODING` | no | `hex` | HMAC hex vs base64 for `x-agent-games-signature`. UNVERIFIED — preflight will confirm. |

No private keys or secrets are ever printed or logged. The HMAC secret is
read from the environment only.

## How it works

Per task POST (60 s window):

1. **HMAC verify** — header `x-agent-games-signature` over the raw body,
   HMAC-SHA256 with `AGENT_SECRET`. Bad/missing signature → 401 (only when
   the secret is configured).
2. **Decide** (`decide.mjs`) — the 7 trap types, fail closed:
   - `VK_SUBSTITUTION`: `registeredVkHash != proofVkHash` → REJECT
   - `THRESHOLD_MISMATCH`: `publicBalance < minimum` → REJECT
   - `RECIPIENT_MISMATCH`: `recipient != conditionRecipient` → REJECT
   - `AMOUNT_OVERFLOW`: `amount > maxTransfer` → REJECT
   - `EXPIRED_CONDITION`: `currentBlock >= expiryBlock` → REJECT
   - `PROOF_REUSED`: `proofTx` already seen (persistent `data/seen-proof-tx.json`) → REJECT
   - else `VALID_CONDITION` → APPROVE
   - Boundaries (verified against the real circuit): balance `>=` minimum
     and amount `<=` maxTransfer are INCLUSIVE (equal approves); expiry is
     STRICT (current == expiry is EXPIRED).
3. **Prove** (`prove.mjs`) — own Groth16 proof (BN128, snarkjs) with the
   gatekeeper circuit (`../circuits/gatekeeper.wasm` + `gatekeeper_final.zkey`),
   then verified locally before answering.
4. **Kurier** (`kurier.mjs`, best-effort, only if a key is set) — submits the
   proof with `vkRegistered: true`, `vk` = published vkHash; the jobId is
   logged, NOT awaited for Finalized (that can exceed the 60 s window).
5. **Respond** `{ decision, reason_code, proof, public_signals }`, signed
   with `x-agent-games-signature` over the raw response body.
   Preflight (empty body / `{type:"preflight"}` / `/preflight`) →
   `{ ok: true, protocolVersion: "v1" }`, signed.

### Circuit facts (reverse-engineered, verified by proving)

- 13 inputs: `decision, taskId, minimum, publicBalance, recipient,
  conditionRecipient, amount, maxTransfer, expiryBlock, currentBlock,
  salt` (PRIVATE), `registeredVkHash, proofVkHash`.
- Public signals, in order: `[commitment, registeredVkHash, proofVkHash,
  minimum, publicBalance, expiryBlock, currentBlock, recipient,
  conditionRecipient, amount, maxTransfer, decision, taskId]`.
- `commitment = Poseidon([salt, taskId])` (circomlibjs Poseidon; verified
  against 3 test vectors). Salt is a fresh random 128-bit value per task.
- The circuit ENFORCES the decision: `decision` must equal 1 iff all 5
  on-circuit checks pass (assert at `GatekeeperEvaluation_79` line 102).
  A wrong decision cannot be proven — the proof fails fast (~40–90 ms).
- Encodings: addresses as `BigInt(address)`; vk hashes as `BigInt("0x...")`
  (snarkjs reduces mod p — the platform vkHash `0x6b79c6…77b0` is 256-bit
  and exceeds the field prime). Platform vkHash:
  `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
  (from `GET /api/circuit-info`; it is NOT keccak256 of vk.json/zkey/wasm).
- **PROOF_REUSED nuance:** the circuit has no `proofTx` input, so a reused
  proof whose 5 on-circuit checks pass CANNOT be proven with decision 0.
  For those tasks the agent returns verdict REJECT/`PROOF_REUSED` with a
  proof generated for the circuit-expected decision (1) — the proof is
  cryptographically valid about the on-circuit facts; the REJECT comes from
  the off-circuit reuse check the platform can also see from `proof_tx`.

### Measured proving time (this VM, 1.5 shared CPU)

- First proof (cold, loads wasm+zkey): ~1.0–2.3 s.
- Subsequent proofs: **~300–800 ms** (typically ~350 ms).
- Failed proofs (wrong decision): ~40–90 ms.
- End-to-end task response in tests: **~0.9–2.6 s** — far inside the 60 s window.

## Tests

```bash
node test-decide.mjs   # decision logic, all 7 trap types + boundaries: 13/13 PASS
node test-edge.mjs     # circuit boundary semantics (balance==min, amount==max,
                       # current==expiry, commitment scope): all PASS
node test-e2e.mjs      # spawns server on :3000, posts tasks, checks response
                       # shape, proof validity vs platform VK, HMAC signature,
                       # 401 on unsigned, preflight: 11/11 PASS
node test-circuit.mjs  # full circuit semantics probe (15 cases)
```

## Files

- `server.mjs` — HTTP server (port 3000), HMAC, preflight, task pipeline.
- `decide.mjs` — pure decision logic (7 trap types, fail closed).
- `prove.mjs` — circuit input encoding + snarkjs proving + local verify.
- `kurier.mjs` — Kurier REST client (submit-proof / job-status).
- `test-decide.mjs`, `test-edge.mjs`, `test-e2e.mjs`, `test-circuit.mjs` — tests.
- `data/seen-proof-tx.json` — persistent seen proof_tx set (created at runtime).
- `logs/gatekeeper.log` — JSON-lines request log.
- `package.json`, `package-lock.json` — snarkjs 0.7.6 (own node_modules).

## Still missing / blockers (before Round 3, 15 Nov 17:30 WIB)

1. **Public endpoint URL** — the Cloudflare tunnel (target `http://localhost:3000`)
   is being set up separately. The agent cannot be registered / preflighted
   until its public URL exists.
2. **Agent registration** (dashboard `/agents`, needs a browser session as
   manda1) — fields: agent name, endpoint URL, public GitHub repo URL,
   event track "Proof Gatekeeper", circuit version. **Requires the GitHub
   account to be linked in Settings first** (currently not linked).
   Saving runs a signed preflight against the endpoint. The HMAC secret is
   shown ONCE at registration — save it immediately and set `AGENT_SECRET`.
3. **Preflight + ≥1 practice task** — after registration; the first live
   practice task is the ground truth for the unverified items below.
4. **Kurier mainnet API key** — request from Horizen Labs (not held yet).
   OPTIONAL for scoring (the platform verifies the proof from the response),
   but needed if on-chain submission via Kurier is required. Alternative
   zkVerifyJS path needs a seed phrase + funded tVFY — also not held.
   Neither path is usable today; the agent still returns a valid local proof.

## Unverified — confirm from the first live practice task

- Exact wire envelope field names (code accepts camelCase + snake_case and
  `{task}`/`{data}` wrappers; the raw envelope shape is logged per request).
- `taskId` format: if it arrives as a string like `"gk_9d1"`, the code parses
  the hex suffix as the field element (fallback: sha256 mod p). If the
  platform computes it differently, `public_signals[12]` will mismatch.
- HMAC signature encoding: hex (default) vs base64.
- Kurier `chainId` for the game (default 0).
- Whether the platform wants a `proofReference` (Kurier jobId) in the
  response — currently the response is exactly
  `{decision, reason_code, proof, public_signals}` and the jobId is only logged.
- `salt` semantics: currently fresh random per task. If practice feedback
  shows a commitment mismatch, the salt may need to be task-derived.
