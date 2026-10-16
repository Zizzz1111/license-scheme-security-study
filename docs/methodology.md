# A General Security Assessment Methodology for Cloud-Verified Licensing Schemes

> This document describes a systematic **five-stage methodology** for assessing desktop software that combines **cloud-verified subscription licensing with commercial code-virtualization protection**. The entire document is de-identified and does not involve any specific commercial product. The companion defensive guidance is in [defense.md](defense.md).
>
> **Prerequisite**: you are assessing software you own, or you hold written authorization. Otherwise stop here and read [DISCLAIMER.md](../DISCLAIMER.md).

---

## Table of Contents

- [0. Concepts & Threat Model](#0-concepts--threat-model)
- [Stage Ⅰ: Reconnaissance](#stage-ⅰ-reconnaissance)
- [Stage Ⅱ: Network-Layer Classification](#stage-ⅱ-network-layer-classification)
- [Stage Ⅲ: In-Memory Material Location](#stage-ⅲ-in-memory-material-location)
- [Stage Ⅳ: Protocol Forgery Verification](#stage-ⅳ-protocol-forgery-verification)
- [Stage Ⅴ: Steady-State Ops & Reporting](#stage-ⅴ-steady-state-ops--reporting)
- [Appendix A: Decision Quick Reference](#appendix-a-decision-quick-reference)
- [Appendix B: Common Pitfalls & Lessons](#appendix-b-common-pitfalls--lessons)
- [Appendix C: Diagnosing CDN-Side Outages](#appendix-c-diagnosing-cdn-side-outages)

---

## 0. Concepts & Threat Model

### 0.1 What Is Cloud-Verified Licensing (CVL)

Desktop licensing has evolved through three generations:

| Generation | Representative Form | Security Model |
|------------|--------------------|----------------|
| 1st | Offline serial numbers / registration codes | Pure client-side validation, algorithm embedded in the binary |
| 2nd | Local license file + hardware fingerprint | Client-side validation + machine binding |
| 3rd (this study) | **Cloud-verified subscription (CVL)** | Client connects to a remote verification API; the server adjudicates subscription status |

A typical CVL protocol structure (representative of mainstream cloud-licensing platforms):

```
Client                                Verification Server
  │ ① generate random session key K_aes (32B)
  │ ② generate random IV
  │ ③ RSA-encrypt(K_aes) ──────────────→ │
  │ ④ license key + device id + req type │
  │                                      │ server adjudicates subscription
  │ ←────────────── AES-CBC(K_aes, IV)   │
  │     encrypted JSON response           │
  │     (expiry / timeleft / status …)    │
  │ ⑤ client decrypts → parses → allow/deny
```

**Key observation**: `K_aes` is generated client-side and transported under RSA, so it is generally infeasible to derive from network traffic alone; however, it needs to exist in plaintext in client memory (to decrypt the response) — this constitutes one of the core attack surfaces of this methodology.

### 0.2 Threat Model

**Attacker capabilities** (assessor / malicious user):

- Owns a legitimate copy of the target software and a Windows environment with administrator rights
- Controls the local network stack (hosts editing, local proxying)
- Can perform **cross-process read-only** operations on target processes (OpenProcess + ReadProcessMemory)
- Does NOT have: kernel privileges, target source code, server-side access

**Defender assets**:

- Client binary hardened by a commercial code-virtualization protector (VMP-class)
- TLS-encrypted verification channel
- Remote verification server (adjudication logic not exposed)

**Core question**: given the combination of "packer + TLS + server-side adjudication," where does the actual security boundary sit?

### 0.3 Core Observations

```
Commercial packers primarily protect 「code」 — not 「data」.
TLS primarily protects 「transport」 — not 「endpoints」.
Server-side adjudication protects 「logic」 — but the client's trust anchor is local.

The residual attack surface after all three layers:
  ① session keys resident in client memory (data layer)
  ② how the client trusts the response (trust layer)
  ③ client-side parsing logic (integrity layer; packers mainly raise cost)

If ① and ② both fail (stages Ⅲ + Ⅳ of this methodology), the licensing
scheme typically suffers a significant security gap, and the gap correlates
weakly with packer strength.
```

---

## Stage Ⅰ: Reconnaissance

**Goal**: map the verification topology without touching the binary.

### 1.1 Network Connection Profiling

Observe outbound connections while the target logs in / verifies:

```powershell
# Admin PowerShell; poll rapidly at the moment "Login" is clicked
while ($true) {
    Get-NetTCPConnection -State Established |
        Where-Object { $_.OwningProcess -eq (Get-Process -Name "<target>" -ErrorAction SilentlyContinue).Id } |
        Format-Table RemoteAddress, RemotePort, OwningProcess
    Start-Sleep -Milliseconds 200
}
```

Points:

- Verification connections are often **transient** (torn down shortly after login), so high-frequency polling is needed to catch them
- Record both RemoteAddress (server IP) and port; the port type determines the toolchain
- Use `Resolve-DnsName` to cross-check domain names and CDN attribution per IP (Cloudflare proxy vs. origin-direct, judging by response characteristics)

### 1.2 Traffic Capture

- Toolchain: Wireshark + Npcap (NIC-level mirroring; no proxy involved, transparent to the target)
- Scenario design: capture one session each for a **wrong-key scenario** and a **valid-key scenario**, then diff the requests
- Analysis goals:
  - Transport layer of the verification protocol (HTTPS / custom TCP / UDP)
  - Byte shape of request-response (is ciphertext length 16-byte aligned → AES-family signature)
  - Any fixed-IP direct connection before handshakes (bypasses DNS → hardcoded-IP indicator)

### 1.3 Binary Triage (optional; qualitative only, no deep analysis)

```powershell
# Inspect section characteristics to identify packer type (look only, do not touch)
# VMP-class packer indicators: unusual sections such as .vmp0/.vmp1; string tables largely blind
```

Deliverable: a **verification topology map** (domains/IPs/ports/protocol/CDN attribution/packer type/transience).

> **De-identification reminder**: all outputs of this stage (IPs, domains, fingerprints) are sensitive intel and should be removed from any published report, keeping only the topology description.

---

## Stage Ⅱ: Network-Layer Classification

**Goal**: assess MITM feasibility. This is commonly the **fork in the road** for the whole methodology.

### 2.1 Building the MITM Environment

The standard environment has three parts:

**① Hosts hijack** (point verification domains to localhost):

```
127.0.0.1  auth.example-domain.com
::1        auth.example-domain.com   ← dual-stack entries are needed
```

> ⚠️ **Dual-stack point**: modern Windows clients commonly prefer IPv6. With only IPv4 entries, the client may reach the real server directly over IPv6 and your proxy stays fully transparent — the most common "I hijacked it but see no traffic" failure.

**② Local reverse proxy** (mitmproxy as the example):

```bash
mitmdump --mode reverse:https://<real CDN IP>:443 \
         --listen-port 443 \
         --set ssl_insecure=true \
         --set keep_host_header=true \
         -s recon_addon.py
```

Why each key parameter matters:

| Parameter | Purpose | Consequence if Missing |
|-----------|---------|------------------------|
| `reverse:https://<real CDN IP>` | Upstream connects **by IP**, not by name | The proxy re-resolves the hijacked domain → back to localhost → **request loop** |
| `keep_host_header=true` | Preserve the client's original Host header | CDN routes by Host; loss commonly breaks routing |
| SNI passthrough (no overwrite) | CDN routes by client SNI | SNI mismatched with cert/Host → handshake likely refused |

**③ Trust preparation**: install the proxy CA into the system trust store (`certutil -addstore -f Root <ca.cer>`).

### 2.2 Classification Test Matrix

Run three experiments in order:

| Test | Action | If It Succeeds | If It Fails |
|------|--------|----------------|-------------|
| **T1 Baseline connectivity** | Hosts hijack + proxy running; can the target complete verification? | Proceed to T2 | Debug SNI/Host/dual-stack config |
| **T2 Certificate trust** | CA installed; observe the TLS handshake | No pinning observed → **MITM route usually viable** | **Pinning indicator** → MITM route obstructed |
| **T3 Direct-IP fallback** | Point every known domain to a black hole; verification still succeeds | No fallback observed | **Hardcoded-IP fallback** → DNS-layer hijack largely defeated |

### 2.3 Decision Logic

```
T1 ✓ T2 ✓ ──→ MITM route viable: proceed directly to Stage Ⅳ (skip Stage Ⅲ)
T2 ✗ (pinning) ──→ MITM route obstructed; go to Stage Ⅲ (memory route)
T3 ✗ (fallback) ──→ network-layer route largely defeated; go to Stage Ⅲ (memory route)
```

> **Key experience**: pinning typically manifests as "handshake fails even with the CA installed." Distinguish config-caused failures (SNI/Host — usually fixable) from binding-caused failures (persists across config permutations). Run multiple controlled rounds before concluding.
>
> **Second key experience**: even when every MITM attempt fails, if **legitimate verification still succeeds**, that alone is high-value intel — the client has a DNS-independent path that bypasses all your interception points. The network layer is usually no longer the viable battlefield.

---

## Stage Ⅲ: In-Memory Material Location

**Goal**: locate session key material in the target's process memory. This is the attack surface whose **correlation with packer strength is weak**.

### 3.1 Rationale

The CVL protocol structure strongly implies the key is in memory:

1. The client needs `K_aes` to decrypt the server response → at response time, `K_aes` plaintext is highly likely resident in memory
2. The decrypted JSON response (expiry and friends) also resides in memory briefly or persistently
3. VMP-class anti-debug focuses on: debugger attachment, API hooks, code patches, self-memory writes — **cross-process reads (PROCESS_VM_READ) are usually outside default defenses** (varies by product and configuration; test it — see 3.3)

### 3.2 Prerequisite: Access-Permission Self-Check (strongly recommended, do not skip)

Before scanning, confirm the cross-process reading baseline — otherwise you can burn hours on "zero hits" without knowing why. Probe logic:

```python
# For each target process, test 4 access-mask levels
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_QUERY_INFORMATION          = 0x0400
PROCESS_VM_READ                    = 0x0010

# Control-group design (key!):
#   explorer.exe  → same-integrity process; usually all OK → validates your own elevation chain
#   winlogon.exe  → usually denied without SeDebugPrivilege → validates the control's validity
#   target        → per-mask testing localizes the denial level
```

**Interpretation table**:

| Observation | Likely Root Cause | Action |
|-------------|-------------------|--------|
| explorer all OK, target all OK | Environment normal | Scan away |
| explorer all OK; target QUERY_LIMITED OK but VM_READ denied | Target may **strip handle rights** (kernel-callback protection) | Memory route obstructed for this process; consider alternate processes (e.g., a host process the target injects into) |
| explorer all OK; target fully denied | DACL restriction / protected process (PPL) | Needs elevated context, or accept the boundary |
| explorer also abnormal | Your own elevation chain is broken | Fix elevation (UAC / SeDebugPrivilege) |

> **Engineering lesson**: the scanner should log every `OpenProcess` failure together with GetLastError to a file. Console-only output vanishes when the window closes — you may misdiagnose "never read a single byte" as "insufficient keyword coverage."

### 3.3 Memory-Region Traversal

```python
# The core trio (public Windows APIs)
kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
kernel32.VirtualQueryEx(hproc, addr, byref(mbi), sizeof(mbi))   # enumerate regions
kernel32.ReadProcessMemory(hproc, base, buf, size, byref(got))  # read
```

Filters (reduce noise, control runtime):

- `State == MEM_COMMIT`
- `Protect` excludes `PAGE_NOACCESS(0x01)` and other unreadable protections
- `Type`: prefer `MEM_PRIVATE` (heap-resident dynamic data — high-yield area for key material)
- Cap per-region size (e.g., 256MB) so anomalous reservations do not stall the scan

### 3.4 Keyword Layer (fast recon)

First scan for **plaintext protocol keywords** to locate where responses reside:

- Field names: common CVL fields such as `expiry`, `timeleft`, `subscription`, `session`, `success`
- Encodings: **both ASCII and UTF-16LE** (Windows programs use wide characters heavily)
- Dump hit regions wholesale (±128/256 bytes of context) for manual protocol-structure analysis

### 3.5 Key Location: Ciphertext Trial-Decryption Self-Verification (core technique)

Directly scanning for raw key bytes is unreliable: keys may exist only as expanded round-key schedules with the original form already released — an AES-256 key typically expands into a 240-byte, 15-round schedule upon initialization in mainstream crypto libraries. The steadier approach is **reverse verification**:

```
Known: response ciphertext C (captured in Stage Ⅱ, or via the local proxy)
       the expected plaintext shape (JSON characteristics, e.g., "expiry")

Scan:  all 64-hex strings in process memory (high-probability key-material form)
Verify: for each candidate material M, enumerate key/IV derivation combos K,
        trial-decrypt the first 64 bytes of C:
        if AES-CBC(unpad(decrypt(derive_key(M), derive_iv(V), C))) exhibits
        valid JSON characteristics → M is highly likely the session key material
        (the criterion "decrypts into semantically correct plaintext" is
         self-verifying; no false positives were observed in this study's runs)
```

Derivation-combination reference space (common derivations):

- key: first 32 bytes of material as-is / first 32 hex chars of `SHA256(material)`
- IV: first 16 hex chars of `SHA256(request IV)` / first or last 16 raw bytes of the request IV / first or last 16 ASCII bytes of the request IV

> **Engineering points**:
> - Two-pass progression: aligned fast scan first, then full slow scan
> - Dump hits immediately (material + process + timestamp), because session keys are **typically regenerated per login** and are not reproducible
> - Set a scan budget guard (e.g., 600MB) so huge reserved regions do not exhaust memory
> - Poll design: the target may not have logged in yet; poll every ~15s and watch for process-list changes

### 3.6 Stage Deliverables

- Session key material (or the finding "handle rights stripped")
- Plaintext protocol samples (full request/response JSON)
- Protocol-structure documentation (field names/types/semantics)

---

## Stage Ⅳ: Protocol Forgery Verification

**Goal**: examine the client's trust model — does it unconditionally trust the decrypted response?

> ⚠️ This stage is the endpoint of the proof of concept, intended to **confirm the flaw exists** and size the risk, as grounds for defensive design.

### 4.1 Core Principle of Forgery: Byte-for-Byte Fidelity

When rewriting the response ciphertext, **everything except the target field value should match the original response byte-for-byte**:

- All field names, order, and JSON structure unchanged
- All field data types preserved exactly (string `"3650"` vs. numeric `3650` are usually not equivalent to client parsing; type drift commonly causes parse failures or crashes)
- Ciphertext length stays a multiple of 16 (AES-CBC block requirement); adjust padding accordingly
- Cipher, key derivation, and IV derivation identical to the original protocol

Any fidelity breach may cause client-side parse failure or a crash — in practice the clearest feedback signal of "alignment succeeded or not."

### 4.2 Placement

Mount the rewrite plugin on the MITM proxy from Stage Ⅱ:

```
response → decrypt with session key → locate expiry/timeleft → rewrite target value
         → re-encrypt (same key/iv derivation) → return to client
```

Where MITM is not viable (Stage Ⅱ obstructed), this stage degrades to an **offline proof of concept**: reproduce the "decrypt-rewrite-re-encrypt" principle in a self-contained lab (see examples/04, 05), demonstrating the generality of the client-trust-model flaw.

### 4.3 Acceptance Ladder

| Rung | What It Verifies | Notes |
|------|------------------|-------|
| L1 | Protocol capture works | Plaintext request/response reliably obtained |
| L2 | Baseline confirmed | Without intervention, wrong credentials are properly rejected |
| L3 | Forgery accepted | With interception, a wrong credential receives a forged long-validity response (protocol-level verification) |
| L4 | Full-chain verification | Confirmed at the business-side observation point (e.g., remaining time shown in-app) |

---

## Stage Ⅴ: Steady-State Ops & Reporting

### 5.1 Reproducibility

- **Environment snapshots**: full steps and restore scripts for hosts edits, proxy config, CA installation (a one-click restore script is as important as the deploy script)
- **Port conflicts**: a lingering proxy process may hold port 443 (Windows error 10048); the restore script should include process cleanup
- **Isolation**: run all experiments in an isolated environment to avoid polluting daily-use system state

### 5.2 Reporting & Disclosure

Follow responsible disclosure:

1. Submit a vulnerability report to the vendor (forgery feasibility, evidence of key residency, impact assessment)
2. Provide remediation guidance (reference [defense.md](defense.md))
3. Fully de-identify public write-ups (to the standard of this document)

---

## Appendix A: Decision Quick Reference

```
Q: Cannot capture verification traffic?
  → Check whether proxy/booster apps are closed (tunneled traffic is largely useless for capture)
  → Check hosts dual-stack (IPv4 + IPv6)
  → Verification connections are transient: poll rapidly at login time

Q: MITM handshake failing?
  → Check SNI and Host header config first (such failures are usually fixable)
  → CA installed yet still failing = pinning indicator (config rarely fixes it)
  → All domains black-holed yet legit verification succeeds = hardcoded-IP fallback indicator

Q: Memory scan zero hits?
  → First thing: check whether OpenProcess ever succeeded (log it!)
  → err=5 access denied: run the permission self-check probe (3.2 interpretation table)
  → OpenProcess OK but zero hits: widen keyword encodings (UTF-16) / switch to trial-decryption

Q: Forged response crashes the target?
  → Field-type infidelity (most common) / JSON structure drift / length not a multiple of 16
  → Diff byte-for-byte against the original response

Q: Stuck at one flow stage regardless of key validity?
  → Rule out vendor-side outages first (Appendix C); avoid wasted effort on a correct route
```

## Appendix B: Common Pitfalls & Lessons

1. **Hosts hijack + domain-based upstream = request loop**: the upstream should connect to the real CDN IP
2. **IPv4-only hijack is usually no hijack**: IPv6 direct escape is common
3. **SNI and Host headers are the CDN's routing keys**: wrong SNI tends to refuse the handshake; wrong Host tends to misroute
4. **Diagnostics must be persisted**: console output disappears when the window closes
5. **Byte-for-byte fidelity for forged responses**: field types, structure, and encodings should all match
6. **Cross-process READ is usually outside packer defenses — but "readable" must be tested**: run the permission probe first; do not assume
7. **Minimize toolchain dependencies**: prefer the proxy's built-in libraries; missing external deps commonly cause silent plugin-load failures
8. **Single-instance locks**: multiple instances / lingering processes may cause session conflicts and unresponsive buttons; clean up processes before experiments
9. **Key shape varies**: raw keys may already be expanded into round-key schedules and released; trial-decryption is usually more reliable than scanning for raw keys
10. **Streaming download APIs**: pass callbacks rather than file objects to proxy streaming, or you may end up with 0-byte files

## Appendix C: Diagnosing CDN-Side Outages

**Scenario**: even valid credentials consistently fail at the same flow stage. Rule out vendor-side outage before blaming your own method.

**Indicator chain**:

1. The CDN rate-limits small files loosely but token-bucket-limits the target file: throughput decays exponentially from normal to KB/s-level
2. CDN idle timeouts kill slow streams: connections dropped mid-download by the server
3. The target file lacks Range support: parallel chunked acceleration is generally infeasible
4. Corroboration: the old artifact is gone (request returns not-found), and the new artifact's upload time matches the outage onset

**Method**: plot a time-throughput curve (pcap or proxy logs) and cross-validate artifact age with fingerprints (PE TimeDateStamp, compiler fingerprints).

**Conclusion template**: when the indicators line up, the outage is most likely a vendor-side distribution-infrastructure problem (usually affecting all users) and weakly related to the assessor's actions; a sensible posture is low-frequency retries while waiting for the fix, plus a local cache-and-serve mechanism in the assessment framework as mitigation.

---

*This document is a de-identified research artifact. All covered topics have public-discussion precedent in security literature. Read [DISCLAIMER.md](../DISCLAIMER.md) before use.*
