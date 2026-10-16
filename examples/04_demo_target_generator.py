"""
04_demo_target_generator.py — Self-contained lab: mock server ciphertext generator
===================================================================================

Generates a **fully local** mock CVL (cloud-verified licensing) protocol
dataset for 05_forge_concept_demo.py to demonstrate the complete
"decrypt → rewrite → re-encrypt" principle.

This script plays the role of an imaginary verification server:
  1. Randomly generate session key material (mock client session key)
  2. Build an authorization response JSON (status / expiry / timeleft fields)
  3. AES-256-CBC encrypt (PKCS#7 padding), output hex ciphertext

Protocol convention (kept consistent with the trial-decryption hook in
02_memory_scanner.py and with script 05):
  key = SHA256(material)[:32]          # material is a 64-hex ASCII string
  iv  = SHA256(material[:16])[:16]
  response plaintext = JSON

Output files (in this directory):
  demo_material.txt   ← 64-hex key material (mock "material resident in client memory")
  demo_response.hex   ← encrypted mock response ciphertext

⚠️ Purely local teaching data. No network access, no real services.
   See DISCLAIMER.md.
"""

import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BASE = os.path.dirname(os.path.abspath(__file__))
MATERIAL_PATH = os.path.join(BASE, "demo_material.txt")
RESPONSE_PATH = os.path.join(BASE, "demo_response.hex")


def pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    n = block - len(data) % block
    return data + bytes([n]) * n


def derive(material: bytes):
    """Protocol-convention key/IV derivation (simplified for teaching)."""
    key = hashlib.sha256(material).digest()[:32]
    iv = hashlib.sha256(material[:16]).digest()[:16]
    return key, iv


def main() -> None:
    # 1. Mock client random session key material (64 hex chars = 256-bit entropy)
    material = secrets.token_hex(32).encode()  # 64 bytes ASCII hex

    # 2. Build a mock authorization response (field layout follows generic CVL shapes)
    now = datetime.now()
    response = {
        "status": "success",
        "username": "lab_user",
        "expiry": (now + timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S"),
        "timeleft": 365,           # numeric type (mind type fidelity!)
        "subscription": "premium",
        "sessionid": secrets.token_hex(8),
    }
    plaintext = json.dumps(response, separators=(",", ":")).encode()

    # 3. AES-256-CBC encryption
    key, iv = derive(material)
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = enc.update(pkcs7_pad(plaintext)) + enc.finalize()

    # 4. Persist
    with open(MATERIAL_PATH, "wb") as f:
        f.write(material)
    with open(RESPONSE_PATH, "wb") as f:
        f.write(ciphertext.hex().encode())

    print("=" * 56)
    print(" Self-contained lab data generated")
    print("=" * 56)
    print(f"  session key material : {material.decode()}")
    print(f"  (mock material resident in client memory → demo_material.txt)")
    print()
    print(f"  response plaintext   : {plaintext.decode()}")
    print(f"  plaintext length     : {len(plaintext)}B -> ciphertext {len(ciphertext)}B (PKCS#7)")
    print(f"  ciphertext written to: demo_response.hex")
    print()
    print(" Next step: python 05_forge_concept_demo.py")
    print(" (it will simulate the full 'memory-scan for key + protocol rewrite' flow)")
    print("=" * 56)


if __name__ == "__main__":
    main()
