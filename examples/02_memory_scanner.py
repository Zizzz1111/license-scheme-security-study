"""
02_memory_scanner.py — Generic cross-process memory scanner (educational)
==========================================================================

Demonstrates read-only cross-process memory traversal via public Windows APIs:
  OpenProcess → VirtualQueryEx → ReadProcessMemory → pattern matching

Intended educational uses:
  - CTF memory-forensics practice
  - Memory-safety assessment of licensing schemes (with the trial-decryption
    self-verification framework)
  - Learning how debuggers / forensic tools work internally

⚠️ Use only against processes you own or targets with written authorization.
   See DISCLAIMER.md at the repository root.

Usage:
  python 02_memory_scanner.py <pid> --hex <hex pattern>
  python 02_memory_scanner.py <pid> --ascii <text pattern>
  python 02_memory_scanner.py <pid> --probe          # access self-check probe
  python 02_memory_scanner.py <pid> --selftest-cipher <cipher_hex> --try-key
      # Trial-decryption mode: feed every 64-hex material in memory as a key
      # candidate into your verification hook (see try_decrypt_hook); report hits
"""

import argparse
import ctypes
import ctypes.wintypes as wt
import re
import sys

# ---------------- Windows API bindings ----------------

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

kernel32.OpenProcess.restype = ctypes.c_void_p
kernel32.OpenProcess.argtypes = (ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32)
kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.VirtualQueryEx.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t)
kernel32.ReadProcessMemory.restype = ctypes.c_int
kernel32.ReadProcessMemory.argtypes = (
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t))
kernel32.CloseHandle.restype = ctypes.c_int
kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
PAGE_NOACCESS = 0x01

# Scan guardrails
MAX_REGION_SIZE = 0x10000000        # 256MB per-region cap
MAX_TOTAL_READ = 600 * 1024 * 1024  # 600MB total budget
MAX_ADDR = 0x7FFFFFFEFFFF           # user-space address ceiling


class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
    """64-bit memory region info structure for VirtualQueryEx"""
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64),
        ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", ctypes.c_uint32),
        ("_pad1", ctypes.c_uint32),
        ("RegionSize", ctypes.c_uint64),
        ("State", ctypes.c_uint32),
        ("Protect", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
        ("_pad2", ctypes.c_uint32),
    ]


def log(msg: str) -> None:
    """Teaching note: persist all diagnostics (this demo prints; real projects
    should also write to a log file).

    Lesson: console-only diagnostics vanish when the window closes — a
    "zero-hit" scan without knowing whether OpenProcess ever succeeded makes
    it hard to distinguish "wrong keywords" from "never read a single byte".
    """
    print(f"[scanner] {msg}", flush=True)


# ---------------- Access self-check probe ----------------

def enable_debug_privilege() -> bool:
    """Enable SeDebugPrivilege (admins commonly hold it in a disabled state).

    Returns True on success; False with GetLastError==1300 means the token
    does not hold the privilege (typically requires a SYSTEM context).
    """
    TOKEN_ADJUST_PRIVILEGES = 0x0020
    TOKEN_QUERY = 0x0008
    SE_DEBUG_NAME = "SeDebugPrivilege"

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", ctypes.c_uint32), ("HighPart", ctypes.c_int32)]

    class LUID_AND_ATTR(ctypes.Structure):
        _fields_ = [("Luid", LUID), ("Attributes", ctypes.c_uint32)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", ctypes.c_uint32),
                    ("Privileges", LUID_AND_ATTR * 1)]

    luid = LUID()
    if not advapi32.LookupPrivilegeValueW(None, SE_DEBUG_NAME, ctypes.byref(luid)):
        log(f"LookupPrivilegeValue failed err={ctypes.get_last_error()}")
        return False

    htok = wt.HANDLE()
    if not kernel32.OpenProcessToken(kernel32.GetCurrentProcess(),
                                     TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                     ctypes.byref(htok)):
        return False
    try:
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = 2  # SE_PRIVILEGE_ENABLED
        if not advapi32.AdjustTokenPrivileges(htok, False, ctypes.byref(tp), 0, None, None):
            log(f"AdjustTokenPrivileges failed err={ctypes.get_last_error()}")
            return False
        if ctypes.get_last_error() == 1300:  # ERROR_NOT_ALL_ASSIGNED
            log("SeDebugPrivilege not granted (token does not hold the privilege)")
            return False
        return True
    finally:
        kernel32.CloseHandle(htok)


def probe_access(pid: int) -> dict:
    """Test four access-mask levels against one PID; return per-level results."""
    masks = {
        "QUERY_LIMITED": PROCESS_QUERY_LIMITED_INFORMATION,
        "QUERY": PROCESS_QUERY_INFORMATION,
        "VM_READ": PROCESS_VM_READ,
        "QUERY|VM_READ": PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
    }
    result = {}
    for name, mask in masks.items():
        h = kernel32.OpenProcess(mask, False, pid)
        result[name] = (bool(h), ctypes.get_last_error())
        if h:
            kernel32.CloseHandle(h)
    return result


def print_probe_verdict(pid: int, r: dict) -> None:
    """Interpretation table — see docs/methodology.md §3.2"""
    log(f"PID {pid} access-probe results:")
    for name, (ok, err) in r.items():
        log(f"  {name:<14} {'OK' if ok else f'DENY err={err}'}")

    ql_ok = r["QUERY_LIMITED"][0]
    vm_ok = r["VM_READ"][0]
    if ql_ok and vm_ok:
        log("Verdict: access normal; scanning can proceed.")
    elif ql_ok and not vm_ok:
        log("Verdict: QUERY works but VM_READ denied → the target may strip handle"
            " rights (kernel-callback protection) or apply a DACL. The memory route"
            " is likely obstructed for this process.")
    elif not ql_ok:
        log("Verdict: all masks denied → check your own elevation chain (admin?),"
            " or the target is a protected process (PPL). Recommend probing"
            " explorer.exe as a control: if explorer is denied too, the problem"
            " is more likely your environment.")
    log("Tip: control-experiment design — run the same probe against a same-user"
        " process (e.g., explorer.exe); all-OK there usually validates your own"
        " elevation chain and rules out environment factors.")


# ---------------- Memory traversal ----------------

def iter_regions(hproc):
    """Enumerate committed readable regions; yield (base, data) streams."""
    addr = 0
    total = 0
    while addr < MAX_ADDR:
        mbi = MEMORY_BASIC_INFORMATION64()
        if not kernel32.VirtualQueryEx(hproc, ctypes.c_void_p(addr),
                                       ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        region_ok = (
            mbi.State == MEM_COMMIT
            and mbi.Protect not in (0, PAGE_NOACCESS)
            and mbi.RegionSize < MAX_REGION_SIZE
        )
        if region_ok:
            if total + mbi.RegionSize > MAX_TOTAL_READ:
                log(f"Total read budget {MAX_TOTAL_READ >> 20}MB reached; stopping early (guardrail)")
                break
            buf = (ctypes.c_char * mbi.RegionSize)()
            got = ctypes.c_size_t()
            if kernel32.ReadProcessMemory(hproc, ctypes.c_void_p(mbi.BaseAddress),
                                          buf, mbi.RegionSize, ctypes.byref(got)):
                data = buf.raw[:got.value]
                total += len(data)
                yield mbi.BaseAddress, data
        addr = mbi.BaseAddress + mbi.RegionSize
    log(f"Traversal done, {total >> 10}KB read in total")


def scan(hproc, pattern: bytes) -> int:
    """Scan for a byte pattern; report hit addresses with context. Return hits."""
    hits = 0
    rx = re.compile(re.escape(pattern))
    for base, data in iter_regions(hproc):
        for m in rx.finditer(data):
            off = m.start()
            ctx_lo = max(0, off - 64)
            ctx_hi = min(len(data), off + len(pattern) + 64)
            log(f"hit @ 0x{base + off:X} context: {data[ctx_lo:ctx_hi]!r}")
            hits += 1
            if hits >= 64:
                log("64 hits reached; stopping (anti-spam)")
                return hits
    return hits


# ---------------- Trial-decryption self-verification framework ----------------

def try_decrypt_hook(candidate_material: bytes, cipher: bytes) -> bool:
    """Trial-decryption verification hook — implement per your target protocol.

    Teaching example protocol (matches 04_demo_target_generator.py output):
      key = SHA256(material)[:32]  ← same convention as the generator
      iv  = SHA256(material[:16])[:16]
      Plaintext should be valid JSON containing an "expiry" field

    This hook is the injection point of the methodology's "ciphertext
    trial-decryption self-verification": the criterion "decrypts into
    semantically correct plaintext" is self-verifying by protocol semantics.
    """
    import hashlib
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    if len(candidate_material) < 32:
        return False
    key = hashlib.sha256(candidate_material).digest()[:32]
    iv = hashlib.sha256(candidate_material[:16]).digest()[:16]
    ct = cipher[:64]  # first 64 bytes (4 AES blocks) usually suffice for JSON signatures
    if len(ct) < 32:
        return False
    try:
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        pt = dec.update(ct) + dec.finalize()
    except Exception:
        return False
    # Semantic test: plaintext should contain JSON authorization field signatures
    return b"expiry" in pt or b"status" in pt or b"success" in pt


HEX64 = re.compile(rb"[0-9a-fA-F]{64}")


def selftest_cipher_scan(pid: int, cipher_hex: str) -> None:
    """Trial-decryption mode: walk all 64-hex materials in memory into the hook."""
    cipher = bytes.fromhex(cipher_hex)
    if not cipher:
        log("cipher is empty")
        return
    seen = set()
    tried = 0
    hproc = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not hproc:
        log(f"OpenProcess failed err={ctypes.get_last_error()} — run --probe first!")
        return
    try:
        for base, data in iter_regions(hproc):
            for m in HEX64.finditer(data):
                mat = m.group()
                if mat in seen:
                    continue
                seen.add(mat)
                tried += 1
                if try_decrypt_hook(mat, cipher):
                    log(f"★ key material hit @ 0x{base + m.start():X} = {mat.decode()}")
                    log(f"  {tried} candidates trial-decrypted before the hit (criterion: protocol-semantics signature).")
                    return
        log(f"Trial-decryption done: none of {tried} candidates hit."
            " (If the key should exist: check whether the derivation formula matches"
            " the hook, or whether the key is stored in a non-hex form)")
    finally:
        kernel32.CloseHandle(hproc)


# ---------------- Entry ----------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Generic cross-process memory scanner (educational)")
    ap.add_argument("pid", type=int)
    ap.add_argument("--hex", dest="hexpat", help="hex byte pattern")
    ap.add_argument("--ascii", dest="asciipat", help="ASCII text pattern")
    ap.add_argument("--probe", action="store_true", help="access self-check probe")
    ap.add_argument("--selftest-cipher", dest="cipher", help="trial-decryption mode (hex)")
    ap.add_argument("--try-key", action="store_true", help="used with --selftest-cipher")
    args = ap.parse_args()

    log("Enabling SeDebugPrivilege ...")
    enable_debug_privilege()

    if args.probe:
        print_probe_verdict(args.pid, probe_access(args.pid))
        return

    if args.cipher:
        selftest_cipher_scan(args.pid, args.cipher)
        return

    pattern = None
    if args.hexpat:
        pattern = bytes.fromhex(args.hexpat)
    elif args.asciipat:
        pattern = args.asciipat.encode()
    if not pattern:
        ap.error("one of --hex / --ascii / --probe / --selftest-cipher is required")

    hproc = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, args.pid)
    if not hproc:
        log(f"OpenProcess failed err={ctypes.get_last_error()} — run --probe first!")
        sys.exit(1)
    try:
        n = scan(hproc, pattern)
        log(f"{n} hit(s) in total")
    finally:
        kernel32.CloseHandle(hproc)


if __name__ == "__main__":
    main()
