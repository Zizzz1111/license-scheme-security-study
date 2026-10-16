# Network-Layer Assessment Lab Setup Guide (Educational)

> This guide describes a standard method for building a controlled network environment to assess CVL licensing schemes. **Use it only against software you own or an authorized lab environment.** It contains no real product's domains, IPs, or configuration.

---

## 0. Lab Topology

```
┌──────────────────────────────────────────────────────┐
│  Assessment machine (Windows, admin rights)          │
│                                                      │
│  [App under test] ──→ hosts redirect ──→ [proxy:443] │
│                                             │        │
│                                        upstream direct│
│                                             ↓        │
│                              [mock / licensed server]│
└──────────────────────────────────────────────────────┘
```

Three components: hosts redirection, a local reverse proxy, and traffic capture.

---

## 1. Pre-Checks

1. **Close proxy/booster applications** — they tunnel-encrypt traffic twice, making captures largely useless for analysis
2. Confirm no lingering proxy process holds port 443:
   ```powershell
   Get-NetTCPConnection -LocalPort 443 -ErrorAction SilentlyContinue
   ```
3. Install the proxy tool (mitmproxy as the example): the portable build is enough, no installer needed

---

## 2. Hosts Redirection (dual-stack point)

Edit `C:\Windows\System32\drivers\etc\hosts`:

```
127.0.0.1  your-lab-server.local
::1        your-lab-server.local    ← add the IPv6 entry as well
```

**Why dual-stack**: modern Windows clients prefer IPv6 (AAAA records) when resolving. With only an IPv4 entry, the client may reach the real server directly over IPv6 and your proxy stays fully transparent — the classic "I hijacked it but see no traffic" setup failure.

Flush the DNS cache after editing:

```powershell
ipconfig /flushdns
```

---

## 3. Local Reverse Proxy

```bash
mitmdump --mode reverse:https://<your upstream>:443 \
         --listen-port 443 \
         --set ssl_insecure=true \
         --set keep_host_header=true \
         -s 03_protocol_recon_addon.py
```

Why each key parameter matters:

| Parameter | Rationale | Consequence if Missing |
|-----------|-----------|------------------------|
| Upstream by **IP**, not domain | If you write a domain, the proxy itself resolves it — and that domain is hijacked to 127.0.0.1 → the proxy sends traffic back to itself → **request loop** | The app commonly hangs |
| `keep_host_header=true` | Upstreams (especially CDNs) route by the Host header | Routing commonly fails; upstream refuses |
| SNI passthrough | CDNs select certificates/backends by client SNI; overwriting SNI tends to mismatch cert/Host | TLS handshake likely refused |

**CA trust chain**: on first run, mitmproxy generates a CA in `%USERPROFILE%\.mitmproxy\`. Install it into the system trust store:

```powershell
certutil -addstore -f Root "$env:USERPROFILE\.mitmproxy\mitmproxy-ca-cert.cer"
```

> Note: installing the CA only solves "the client trusts your proxy certificate." If the app under test implements certificate pinning, the CA alone usually does not enable MITM — exactly what Stage Ⅱ of the methodology classifies. See `docs/methodology.md`.

---

## 4. Traffic Capture (passive mirroring, no proxy)

Mirror the transient verification connections at the NIC level (Wireshark + Npcap):

1. After installing Npcap, open Wireshark and start capture on the active adapter
2. Suggested display filters: `tcp.port == 443`, or filter by the known verification-server address
3. **Capture while clicking "Login" in the app under test** — verification connections are often sub-second and transient
4. Scenario design: capture a separate pcap per scenario — wrong-credential vs. valid-credential

Analysis points:

- Is the response length a multiple of 16 bytes (AES-CBC indicator)
- Any fixed-IP connection bypassing DNS (Stage Ⅱ's T3 fallback detection)
- Request-response timing structure (which request triggers which response)

---

## 5. Environment Restore

Symmetric cleanup after experiments (as important as setup):

```powershell
# 1. Kill lingering proxy processes (otherwise port 443 stays occupied, error 10048)
Get-Process mitmdump -ErrorAction SilentlyContinue | Stop-Process -Force

# 2. Remove lab entries from hosts (admin notepad, or a filter script)
# 3. Flush DNS
ipconfig /flushdns
# 4. (Optional) remove the lab CA:
# certutil -delstore Root mitmproxy
```

We recommend packaging setup and restore as one-click scripts each, so the environment can be reproduced and zeroed out quickly.

---

## 6. Compliance Reminders

- This lab may point only to **your own test server** or an **authorized assessment target**
- Captured pcaps and logs may contain license credentials and other sensitive data — never push them to a public repo (this repo's `.gitignore` excludes `*.pcap*`)
- See the root-level [DISCLAIMER.md](../DISCLAIMER.md)
