# Defensive Hardening Guide for Cloud-Verified Licensing Schemes

> This document targets **licensing-system developers** and maps hardening measures to each attack surface in [methodology.md](methodology.md). Recommended reading order: understand the attack methodology first, then implement defenses in priority order.

---

## 1. Threat Recap: Why Licensing Schemes Get Broken

The methodology's conclusion is worth internalizing: **the residual attack surface after "packer + TLS + server adjudication" lands squarely on the licensing system's critical path** —

| Attack Surface | Stage | Why It Works |
|----------------|-------|--------------|
| Session keys resident in client memory | Ⅲ | The client needs them to decrypt responses; plaintext presence is highly likely |
| How the client trusts response content | Ⅳ | Without application-layer signatures, a successful decryption tends to be treated as trusted |
| DNS-layer routing can be rewritten locally | Ⅱ | Clients typically trust the system resolver; some implementations even ship a direct-IP fallback |

Hardening measures below are ordered by **priority**.

---

## 2. P0 Hardening: Protocol Layer (root-cause mitigation)

### 2.1 Response Signing (the highest-value single measure)

**Problem**: some mainstream cloud-licensing platforms encrypt responses but do not sign them — anyone holding the session key can, in principle, construct responses in a valid form.

**Solution**:

```text
Server signs:   sign = Ed25519_Sign(server_private_key, response_body)
Client verifies: assert Ed25519_Verify(built_in_public_key, response_body, sign) == valid
```

Points:

- Use **asymmetric signatures**, not HMAC — the client embeds only a public key, so an attacker without the signing key generally cannot construct valid signatures even with full session-key control
- The signature should cover **every response field** (including expiry, timeleft, status codes) to leave minimal rewrite room
- Consider embedding the public key in obfuscated form + runtime self-integrity checks (raises the cost of static replacement)
- Ed25519 over RSA: shorter signatures, faster verification, fewer opportunities for parameter misconfiguration

**Effect**: Stage Ⅳ forgery largely fails under this threat model — field rewriting typically breaks verification.

### 2.2 Server-Side Authoritative Decisions + No Delegation of Adjudication

**Problem**: shipping `expiry`/`timeleft` as client-parseable fields hands part of the adjudication to a machine the attacker controls.

**Solution**:

- Adjudicate subscription status server-side: the response carries only a **short-lived access credential** (e.g., a session token valid 1–24 hours), not long-term validity claims
- Clients renew by re-verifying online (usually cheap in online mode)
- If offline grace periods are required: grace credentials also need **signatures + anti-rollback counters** (see 2.3)

### 2.3 Anti-Rollback

**Problem**: locally cached authorization state can be rolled back to a historical legitimate state (clock tampering / response replay).

**Solution**:

- Embed a **monotonically increasing timestamp** under the response signature; the client rejects timestamps older than its local record
- Store the "latest seen timestamp" encrypted and bound to a hardware fingerprint
- Server-side: bind sessions to device fingerprints; challenge re-verification / apply risk controls when fingerprints change abruptly

---

## 3. P1 Hardening: Transport Layer (raise attack cost)

### 3.1 Certificate Pinning Done Right

**Problem**: some clients implement pinning but ship two common defects — **fail-open fallbacks** (e.g., direct-IP connections) or pinning applied to only some domains.

**Solution**:

- Pin certificates/public keys for **every domain** of the verification API
- On failure, **fail closed**: abort with a network-error message — treat "skip validation" and "hardcoded-IP direct" fallback paths with great caution
  - ⚠️ **Hardcoded-IP fallbacks are doubly harmful**: they bypass enterprise/security DNS-layer controls AND expose a bypass point to attackers (Stage Ⅱ's T3 experiment weaponizes exactly this indicator)
- Pin **public keys** rather than certificates (certs rotate; keys are stable) and pre-configure backup pins
- Set expectations honestly: pinning does not stop a fully in-control local attacker (binary modification is theoretically possible); its value is **closing the pure network-layer route**, pushing attackers toward costlier memory/binary routes

### 3.2 Anti-Replay on Verification Requests

- Requests carry a client-generated random nonce; the response signature covers it → captured historical responses are difficult to replay
- Tie the nonce into session-key derivation to reduce request-response splice attacks

---

## 4. P1 Hardening: Client Memory (raise attack cost)

### 4.1 Session-Key Lifecycle Management

**Problem**: session keys may persist in heap memory in plaintext for long periods; a cross-process read suffices to extract them (most commercial packers do not defend this path by default).

**Solution**:

- **Wipe after use**: `SecureZeroMemory` key buffers immediately after decryption; guard against compiler elision (`volatile` / `SecureZeroMemory`)
- **Short lifetime**: fresh keys per verification round; avoid long-lived session keys
- **Key wrapping**: keep keys wrapped at rest (e.g., XOR with a random mask); unwrap transiently and re-wrap immediately
- **CNG protection**: use Windows CNG `BCryptImportKey` with process-protected key features so keys live as OS-managed opaque handles

### 4.2 Handle Sensitive Response Data the Same Way

The decrypted response JSON (with authorization state) also resides in memory:

- Destroy the raw JSON buffer promptly after parsing
- Keep authorization state as a signed+encrypted compact structure rather than long-lived plaintext strings
- Reduce residency of plaintext protocol keywords (raises the cost of keyword scanning) — but recognize this is **cost-raising, not curative**, and should not be the primary defense

### 4.3 A Correct Understanding of Anti-Debug

- VMP-class anti-debug targets: debuggers, hooks, patches, self-memory writes
- **Cross-process reads (OpenProcess + ReadProcessMemory) are usually outside default defenses** — this is mostly a design boundary, not a defect
- Optional targeted measures: kernel callbacks (`ObRegisterCallbacks`) to strip `PROCESS_VM_READ` from external processes (requires driver signing; typically only for high-value targets); a user-mode alternative is periodic handle-table self-checks (`SystemHandleInformation`) to detect suspicious openers
- **Calibrate expectations**: these measures mainly raise cost. With P0 protocol hardening in place, the memory route's payoff drops sharply; without it, memory-layer countermeasures mostly buy time

---

## 5. P2 Hardening: Infrastructure

### 5.1 Taming Distribution-CDN Rate Limiting

A real-world failure pattern: token-bucket rate limiting plus idle timeouts on the CDN can make **legitimate users** fail repeatedly when downloading large components (throughput decays exponentially to KB/s level).

- Serve large artifacts via a dedicated channel: Range support / chunked parallel download / independent rate policies
- Verify artifact integrity (hash manifests + signatures), decoupled from the verification channel
- Monitor distribution success rates; distinguish "credential problems" from "distribution problems" (avoid flagging legitimate users as pirates)

### 5.2 Single Instance & Session Consistency

- Single-instance lock (named mutex) + cleanup hints for lingering processes
- Server-side session binding to device fingerprints; invalidate old sessions on anomalous concurrency

---

## 6. Priority Matrix

| Priority | Measure | Defends Against | Cost |
|----------|---------|-----------------|------|
| **P0** | Ed25519 response signatures | Ⅳ (forgery) | Low |
| **P0** | Server-side adjudication + short-lived credentials | Ⅲ+Ⅳ (holistic) | Medium |
| **P0** | Anti-rollback (signed timestamps + counters) | Offline state rollback | Low |
| **P1** | Full pinning coverage + fail-closed + minimal fallbacks | Ⅱ (MITM) | Low |
| **P1** | Request-nonce anti-replay | Ⅱ (replay) | Low |
| **P1** | Key wipe-after-use + wrapped residency | Ⅲ (memory extraction) | Medium |
| **P2** | Distribution-CDN remediation | Availability (not security) | Medium |
| **P2** | Handle stripping / self-checks (kernel) | Ⅲ (escalation) | High (high-value targets only) |

**Bottom line: do the three P0 items first — response signing, short-lived credentials, anti-rollback. Together they sharply shrink the payoff of Stages Ⅲ+Ⅳ, typically at person-day-level cost. Packers and memory countermeasures are decorations on the wall; the protocol layer is the foundation.**

---

*This document is a de-identified research artifact. Read [DISCLAIMER.md](../DISCLAIMER.md) before use.*
