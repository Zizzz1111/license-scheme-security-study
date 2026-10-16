"""
05_forge_concept_demo.py — Self-contained lab: response forgery concept demo
=============================================================================

Demonstrates the core principle behind the "encrypted-but-unsigned response"
weakness class in CVL protocols:
  decrypt → rewrite fields → re-encrypt; the client typically cannot tell
  the response was replaced.

This script simulates methodology Stages Ⅲ + Ⅳ end-to-end (operating only
on the local mock data produced by script 04; no network access, no real
products involved):

  [Stage Ⅲ mock] read key material from demo_material.txt
                 (in reality this step is the trial-decryption scan in
                  02_memory_scanner.py)
                 → trial-decryption self-verification: confirm the material
                   really decrypts into valid JSON
  [Stage Ⅳ mock] decrypt the full response → rewrite expiry/timeleft → re-encrypt
                 → write the forged ciphertext and diff plaintexts

Key teaching point: the **byte-for-byte fidelity principle**
  Everything except the target field value — field names, order, data
  types — should strictly match the original response.
  (In this teaching data, timeleft is numeric — writing the string "3650"
   would be a type-fidelity breach, which in real targets commonly triggers
   parse failures. This demo keeps strict fidelity.)

Dependency: pip install cryptography
⚠️ See DISCLAIMER.md. Educational use only.
"""

import hashlib
import json
import os
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BASE = os.path.dirname(os.path.abspath(__file__))
MATERIAL_PATH = os.path.join(BASE, "demo_material.txt")
RESPONSE_PATH = os.path.join(BASE, "demo_response.hex")

FORGED_PATH = os.path.join(BASE, "forged_response.hex")


def derive(material: bytes):
    """Key/IV derivation, identical to the generator in script 04."""
    key = hashlib.sha256(material).digest()[:32]
    iv = hashlib.sha256(material[:16]).digest()[:16]
    return key, iv


def pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    n = block - len(data) % block
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes):
    if not data or len(data) % 16:
        return None
    n = data[-1]
    if 1 <= n <= 16 and data[-n:] == bytes([n]) * n:
        return data[:-n]
    return None


def aes_cbc(key: bytes, iv: bytes, data: bytes, encrypt=False):
    try:
        c = Cipher(algorithms.AES(key), modes.CBC(iv))
        op = c.encryptor() if encrypt else c.decryptor()
        return op.update(data) + op.finalize()
    except Exception:
        return None


def try_decrypt(material: bytes, cipher: bytes):
    """Trial-decryption self-verification hook (same convention as scanner 02).

    Criterion: the plaintext fragment carries authorization-field signatures
    → the candidate material is treated as the key.
    (First 64B = 4 AES blocks, usually enough to cover the opening fields of
     the response JSON.)
    """
    if len(material) < 32 or len(cipher) < 32:
        return None
    key, iv = derive(material)
    pt = aes_cbc(key, iv, cipher[:64])
    if pt is None:
        return None
    if b'"status"' in pt or b"expiry" in pt:
        return (key, iv)
    return None


def main() -> None:
    print("=" * 60)
    print(" CVL response forgery concept demo (local self-contained data)")
    print("=" * 60)

    # ---- Load lab data ----
    material = open(MATERIAL_PATH, "rb").read().strip()
    cipher_hex = open(RESPONSE_PATH, "rb").read().decode().strip()
    cipher = bytes.fromhex(cipher_hex)
    print(f"\n[0] loaded mock data: material {len(material)}B, ciphertext {len(cipher)}B")

    # ---- Stage Ⅲ mock: key verification (in reality: memory scan + trial decryption) ----
    print("\n[1] Stage Ⅲ mock — trial-decryption self-verification:")
    hit = try_decrypt(material, cipher)
    if not hit:
        print("    verification failed: the material does not decrypt into a valid protocol"
              " plaintext. Run generator 04 first.")
        return
    key, iv = hit
    print(f"    material verified (64B trial decryption → JSON signature hit)")
    print(f"    derived key = SHA256(material)[:32] = {key.hex()[:32]}...")

    # ---- Decrypt the full response ----
    pt = pkcs7_unpad(aes_cbc(key, iv, cipher))
    if pt is None:
        print("    padding check failed (ciphertext/key mismatch)")
        return
    original = json.loads(pt.decode())
    print(f"\n[2] original response plaintext:\n    {pt.decode()}")

    # ---- Stage Ⅳ mock: byte-for-byte faithful rewrite ----
    print("\n[3] Stage Ⅳ mock — rewrite validity (byte-for-byte fidelity):")
    forged = dict(original)  # preserve field order (Python dicts are ordered)
    new_days = 3650
    forged["timeleft"] = new_days                       # numeric → numeric (type fidelity)
    forged["expiry"] = (datetime.now() + timedelta(days=new_days)).strftime(
        "%Y-%m-%d %H:%M:%S")                            # string → string
    forged_pt = json.dumps(forged, separators=(",", ":")).encode()

    # Diff demo: show which fields changed
    print(f"    original: {json.dumps(original, separators=(',', ':'))}")
    print(f"    forged:   {forged_pt.decode()}")
    diff_fields = [k for k in original if original[k] != forged[k]]
    print(f"    changed fields: {diff_fields}"
          f" (the other {len(original) - len(diff_fields)} fields are byte-for-byte faithful)")

    # ---- Re-encrypt ----
    ct = aes_cbc(key, iv, pkcs7_pad(forged_pt), encrypt=True)
    with open(FORGED_PATH, "wb") as f:
        f.write(ct.hex().encode())
    print(f"\n[4] forged ciphertext written to forged_response.hex"
          f" ({len(ct)}B, 16B-aligned: {len(ct) % 16 == 0})")

    # ---- Teaching summary ----
    print("\n" + "=" * 60)
    print(" Takeaways")
    print("=" * 60)
    print("""
 Nothing here touches any real product: the protocol structure (encrypted
 authorization responses) plus the trust-model weakness (unsigned → a
 successful decryption tends to be trusted) are common across CVL schemes.

 Defender's view (see docs/defense.md, P0 hardening):
   if the server signs responses with Ed25519 and the client verifies,
   step [3]'s rewrite typically fails verification — the forgery route
   largely collapses under that defense.

 This is the structural risk of "encrypted but unsigned responses":
   encryption provides confidentiality; it does not by itself provide
   integrity.
""")
    print("=" * 60)


if __name__ == "__main__":
    main()
