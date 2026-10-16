"""
03_protocol_recon_addon.py — mitmproxy protocol recon plugin (logging only, no rewriting)
==========================================================================================

Use with the lab in 01_traffic_capture_lab.md:
  mitmdump --mode reverse:https://<upstream>:443 --listen-port 443 \\
           --set ssl_insecure=true --set keep_host_header=true \\
           -s 03_protocol_recon_addon.py

Features (passive recon only):
  - Full request/response metadata logging (method, URL, status, type, length)
  - Ciphertext signature stats (16-byte alignment → AES-family protocol indicator)
  - TLS handshake logging (SNI collection, for methodology Stage Ⅱ classification)
  - Large response bodies streamed to dump/ (>20KB or binary-looking)

⚠️ This plugin only logs; it contains no rewriting logic.
   The forgery concept demo lives in 05_forge_concept_demo.py (self-contained).
   For authorized assessment environments only. See DISCLAIMER.md.
"""

import os
from datetime import datetime

from mitmproxy import http

BASE = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE, "recon_traffic.log")
DUMP_DIR = os.path.join(BASE, "dump")
os.makedirs(DUMP_DIR, exist_ok=True)


def log(msg: str) -> None:
    """Dual-write: console + log file.

    Engineering lesson: persist diagnostics. Recon notes that only print
    to console vanish with the window, leaving later analysis without a
    chain of evidence.
    """
    line = f"[{datetime.now():%H:%M:%S}] [recon] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def looks_binary(body: bytes) -> bool:
    """Does the payload look binary (a NUL byte in the first 4KB)?"""
    return b"\x00" in body[:4096]


class ReconAddon:
    # ---------- TLS layer ----------

    def tls_clienthello(self, data):
        """Log the client SNI — classification evidence for methodology Stage Ⅱ.

        Compatibility note: the data object's attribute names vary across
        mitmproxy versions; read defensively so the plugin does not crash on load.
        """
        try:
            sni = (getattr(data, "sni", None)
                   or getattr(data, "client_sni", None)
                   or "<no-sni>")
            log(f"TLS ClientHello: SNI={sni}")
        except Exception:
            pass

    def tls_failed_server(self, data):
        """Upstream TLS handshake failure — one possible pinning indicator."""
        log("!! upstream TLS handshake failed — if this persists with the CA"
            " installed, lean toward certificate pinning (methodology Stage Ⅱ, T2)")

    # ---------- HTTP layer ----------

    def request(self, flow: http.HTTPFlow) -> None:
        r = flow.request
        log(f"--> {r.method} {r.pretty_host}{r.path} "
            f"(Host={r.headers.get('Host', '?')})")
        body = r.raw_content or b""
        if body:
            align = "16B-aligned" if len(body) % 16 == 0 else "unaligned"
            log(f"    body={len(body)}B {align} "
                f"ct={r.headers.get('Content-Type', '-')}")

    def response(self, flow: http.HTTPFlow) -> None:
        r = flow.response
        if r is None:
            return
        body = r.raw_content or b""
        align = "16B-aligned" if len(body) % 16 == 0 else "unaligned"
        log(f"<-- {r.status_code} len={len(body)}B {align} "
            f"ct={r.headers.get('Content-Type', '-')}")

        # Large / binary-looking → dump wholesale for offline analysis
        if len(body) > 20_000 or looks_binary(body):
            name = datetime.now().strftime("resp_%H%M%S_%f")[:-3] + ".bin"
            path = os.path.join(DUMP_DIR, name)
            with open(path, "wb") as f:
                f.write(body)
            log(f"    dumped: {name} ({len(body)}B)")


addons = [ReconAddon()]
