#!/usr/bin/env python3
import json
import os
import re
import struct
import sys
import hashlib
import hmac
from multiprocessing import Pool
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


PBKDF2_ITERS = 4096
XTS_KEY_LEN = 32
MAC_LEN = 6
USER_BLOCK_LEN = 24
MASTER_CONST_LEN = 16

def derive_xts_key(master_const: bytes, user_block: bytes, mac: bytes) -> bytes:
    ikm = hmac.new(master_const, user_block, hashlib.sha256).digest()
    return hashlib.pbkdf2_hmac("sha256", ikm, mac, PBKDF2_ITERS, dklen=XTS_KEY_LEN)


_UNIT = 0x80

def _xts_op(data: bytes, key: bytes, flash_address: int, decrypt: bool) -> bytes:
    pad_left = flash_address % _UNIT
    data = (b"\x00" * pad_left) + data
    pad_right = (-len(data)) % _UNIT
    data = data + (b"\x00" * pad_right)
    addr = flash_address - pad_left
    out_chunks = []
    backend = default_backend()
    for off in range(0, len(data), _UNIT):
        block = data[off : off + _UNIT]
        tweak = struct.pack("<I", addr) + b"\x00" * 12
        cipher = Cipher(algorithms.AES(key), modes.XTS(tweak), backend=backend)
        op = cipher.decryptor() if decrypt else cipher.encryptor()
        out_chunks.append(op.update(block[::-1])[::-1])
        addr += _UNIT
    result = b"".join(out_chunks)
    if pad_right: result = result[:-pad_right]
    if pad_left: result = result[pad_left:]
    return result

def decrypt_region(ciphertext: bytes, key: bytes, flash_address: int) -> bytes:
    return _xts_op(ciphertext, key, flash_address, decrypt=True)


def _find_rodata_elf(data: bytes) -> tuple:
    """Extract .rodata offset and size from stripped ELF"""
    _SHDR_SIZE = 40
    e_shoff = struct.unpack_from("<I", data, 32)[0]
    e_shnum = struct.unpack_from("<H", data, 48)[0]
    e_shstrndx = struct.unpack_from("<H", data, 50)[0]
    
    strtab_shdr_off = e_shoff + e_shstrndx * _SHDR_SIZE
    strtab_off = struct.unpack_from("<I", data, strtab_shdr_off + 16)[0]
    strtab_size = struct.unpack_from("<I", data, strtab_shdr_off + 20)[0]
    strtab = data[strtab_off:strtab_off + strtab_size]

    for i in range(e_shnum):
        shdr_off = e_shoff + i * _SHDR_SIZE
        sh_name_idx = struct.unpack_from("<I", data, shdr_off)[0]
        name = strtab[sh_name_idx:strtab.index(b"\x00", sh_name_idx)].decode("ascii", errors="replace")
        if name == ".rodata":
            sh_offset = struct.unpack_from("<I", data, shdr_off + 16)[0]
            sh_size = struct.unpack_from("<I", data, shdr_off + 20)[0]
            return sh_offset, sh_size
    raise ValueError("No .rodata section found in ELF")

def find_master_const_candidates(firmware: bytes, candidate_len: int = 16) -> list:
    """Find all 16-byte arrays in .rodata"""
    try:
        if firmware[:4] == b"\x7fELF":
            rodata_off, rodata_size = _find_rodata_elf(firmware)
        else:
            raise ValueError("Not an ELF")
    except Exception as e:
        print(f"[*] Warning: Could not parse ELF section headers ({e}). Scanning entire file...")
        rodata_off = 0
        rodata_size = len(firmware)

    candidates = []
    section = firmware[rodata_off:rodata_off + rodata_size]
    for i in range(0, len(section) - candidate_len + 1, 1):
        chunk = section[i:i + candidate_len]
        if chunk == b"\x00" * candidate_len or chunk == b"\xff" * candidate_len:
            continue
        candidates.append((rodata_off + i, chunk))
    return candidates

# ==============================================================================
# MAIN SOLVER CONSTANTS & HELPERS
# ==============================================================================
HEX_RE = re.compile(r"[0-9a-fA-F]{2}")
FLAG_RE = re.compile(rb"V1T\{[^}]{1,200}\}")

# Ignore decoy flags
DECOY_FLAGS = {
    b"V1T{not_the_real_flag_nice_try}",
    b"V1T{test_flag_ignore}",
}

# Standard ESP32 Partition Table config (Offset moved to 0xA000 due to large Bootloader)
PT_OFFSET = 0xA000
PT_ENTRY_SIZE = 32
PT_MAGIC = 0xAA
PT_MD5_MAGIC = 0xEB

def hex_field(summary: dict, *names: str, expected_len: int) -> bytes:
    """Extract hex data from efuse_summary.json"""
    for name in names:
        entry = summary.get(name)
        if not entry: continue
        value = entry["value"] if isinstance(entry, dict) else entry
        if "??" in str(value): continue
        pairs = HEX_RE.findall(value)
        if len(pairs) >= expected_len:
            return bytes(int(p, 16) for p in pairs[:expected_len])
    raise ValueError(f"Could not find {expected_len} hex bytes for {names}")

def parse_partition_table(flash: bytes, xts_key: bytes) -> list[dict]:
    """Decrypt and extract ESP32 partition table structure"""
    pt_raw = flash[PT_OFFSET:PT_OFFSET + 0x1000]
    pt_plain = decrypt_region(pt_raw, xts_key, PT_OFFSET)
    partitions = []
    
    for i in range(0, len(pt_plain), PT_ENTRY_SIZE):
        entry = pt_plain[i:i + PT_ENTRY_SIZE]
        if len(entry) < PT_ENTRY_SIZE: break
        
        magic = entry[0]
        if magic == PT_MD5_MAGIC or magic == 0xFF: break
        if magic != PT_MAGIC: continue
        
        ptype, subtype = entry[1], entry[2]
        offset, size = struct.unpack_from("<II", entry, 4)
        name = entry[12:28].split(b"\x00")[0].decode("ascii", errors="replace")
        partitions.append({
            "name": name, "type": ptype, "subtype": subtype,
            "offset": offset, "size": size,
        })
    return partitions

def try_decrypt_flag(flash: bytes, xts_key: bytes, offset: int, size: int) -> bytes | None:
    """Decrypt partition and search for the real flag string"""
    ct = flash[offset:offset + size]
    if len(ct) != size: return None
    pt = decrypt_region(ct, xts_key, offset)
    m = FLAG_RE.search(pt)
    if m and m.group(0) not in DECOY_FLAGS:
        return m.group(0)
    return None


def init_worker(_flash, _user_block, _mac):
    global g_flash, g_user_block, g_mac
    g_flash, g_user_block, g_mac = _flash, _user_block, _mac

def check_candidate(arg):
    idx, off, cand = arg
    xts_key = derive_xts_key(cand, g_user_block, g_mac)
    try:
        parts = parse_partition_table(g_flash, xts_key)
    except Exception:
        return None
        
    for p in parts:
        if p["name"] == "flagdata" or p["subtype"] == 0x40:
            flag = try_decrypt_flag(g_flash, xts_key, p["offset"], p["size"])
            if flag:
                return (cand, idx, off, xts_key, flag)
    return None


def main():
    challenge_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    
   
    
    # 1. Read eFuse
    efuse_path = os.path.join(challenge_dir, "efuse_summary.json")
    if not os.path.exists(efuse_path):
        efuse_path = os.path.join(challenge_dir, "efuse_sum.json")
    
    print(f"[*] Reading eFuse configuration from {os.path.basename(efuse_path)}...")
    with open(efuse_path) as f:
        content = f.read()
        summary = json.loads(content[content.find("{"):])
    
    mac = hex_field(summary, "MAC", "MAC_FACTORY", expected_len=MAC_LEN)
    user_block = hex_field(summary, "BLOCK_USR_DATA", "USER_DATA", expected_len=USER_BLOCK_LEN)
    print(f"    [+] MAC Address    : {mac.hex()}")
    print(f"    [+] BLOCK_USR_DATA : {user_block.hex()}")
    
    # 2. Read Flash
    print("[*] Reading encrypted Flash memory...")
    with open(os.path.join(challenge_dir, "flash_dump.bin"), "rb") as f:
        flash = f.read()
    print(f"    [+] Flash size     : {len(flash) // 1024 // 1024} MiB")

    # 3. Analyze Firmware
    print("[*] Analyzing leaked_debug_firmware.bin to find MASTER_CONST...")
    with open(os.path.join(challenge_dir, "leaked_debug_firmware.bin"), "rb") as f:
        leaked = f.read()
        
    candidates = find_master_const_candidates(leaked)
    print(f"    [+] Found {len(candidates)} suspicious 16-byte arrays in .rodata!")

    # 4. Brute-force
    print("[*] Spawning Multiprocessing pool for brute-forcing...")
    print("    [!] This may take a few seconds depending on your CPU...")
    with Pool(initializer=init_worker, initargs=(flash, user_block, mac)) as pool:
        args = [(idx, off, cand) for idx, (off, cand) in enumerate(candidates)]
        for res in pool.imap_unordered(check_candidate, args, chunksize=500):
            if res is not None:
                cand, idx, off, xts_key, flag = res
                print("\n[+] SUCCESS! Found the correct MASTER_CONST!")
                print(f"    -> Candidate # : {idx}")
                print(f"    -> Offset      : 0x{off:x}")
                print(f"    -> Value       : {cand.hex()}")
                print(f"    -> XTS Key     : {xts_key.hex()}")
                print(f"[*] FLAG IS: {flag.decode()}")
                return

    print("[-] Failed. No valid key found.")

if __name__ == "__main__":
    main()
