#  Writeup — V1T CTF 2026: *XTS-AES*

- `efuse_sum.json`: A dump of the microcontroller's eFuse registers.
- `flash_dump.bin`: A full 4MB raw dump of the encrypted Flash memory.
- `leaked_debug_firmware.bin`: A stripped ELF firmware binary.
---

## Step 1: Initial Analysis

First, if we run the `strings` command on `flash_dump.bin` to blindly search for the flag, we won't find the real `V1T{...}` (or we will only find unencrypted decoy flags):

```bash
strings flash_dump.bin | grep 'V1T{'
```
The output only reveals a decoy: `V1T{not_the_real_flag_nice_try}`. The real flag resides in a partition that is heavily encrypted.

Next, examining the `efuse_sum.json` file reveals three critical pieces of information:
1. **Flash Encryption is enabled** (The `SPI_BOOT_CRYPT_CNT` bit is set).
2. The **MAC address** of the device:
   ```json
   "MAC": { "raw_value": "0xc8362f13cfd0", "value": "d0:cf:13:2f:36:c8" }
   ```
3. A **custom data block (BLOCK_USR_DATA)**:
   ```json
   "BLOCK_USR_DATA": { "raw_value": "0xeed822f54024e490e59ca5e670784a5daa1f04fd077873530000000000000000" }
   ```

Because the hardware AES-XTS key (stored in `BLOCK_KEY0`) is read-protected, we cannot extract it directly. We must figure out exactly how V1T Labs *derived* that key.

---

## Step 2: Reverse Engineering the Firmware

Open `leaked_debug_firmware.bin` using a reverse engineering tool (like Ghidra or IDA Pro) configured for the Xtensa architecture. Analyzing the assembly code reveals V1T Labs' custom Key Derivation Function (KDF):

1. **HMAC-SHA256 Step**: 
   - The function hashes the first 24 bytes of `BLOCK_USR_DATA` using a 16-byte secret key (let's call it `MASTER_CONST`). 
   - `IKM = HMAC-SHA256(key=MASTER_CONST, message=BLOCK_USR_DATA[0:24])`

2. **PBKDF2 Step**:
   - The result (`IKM`) is used as the password, and the `MAC` address is used as the salt. The algorithm runs for 4096 iterations.
   - `AES_XTS_KEY = PBKDF2(password=IKM, salt=MAC, iterations=4096, key_len=32)`

The catch: **The `MASTER_CONST` (16 bytes) is statically embedded inside the firmware's `.rodata` section.** However, the developers intentionally added around 4 decoy 16-byte arrays. With the ELF file stripped of symbols, it is impossible to visually distinguish the real `MASTER_CONST` from the decoys.

---

## Step 3: Brute-Force Extraction Strategy

Instead of manually tracing assembly xrefs to figure out which array is the decoy, we can write a Python script to take the known eFuse data and **brute-force every 16-byte chunk** in the firmware's `.rodata` section.

For each 16-byte chunk:
1. Feed it into the KDF (`HMAC-SHA256` -> `PBKDF2`) to generate a candidate `AES-XTS` key.
2. Use this candidate key to decrypt the **Partition Table** (located at offset `0xA000` in `flash_dump.bin`).
3. If decryption succeeds (i.e., it yields a valid ESP32 partition table containing the string `flagdata`), we know we have found the correct key.
4. Finally, jump to the offset of the `flagdata` partition, decrypt it using AES-XTS, and extract the real flag.

---

## Step 4: Running the Exploit

Using a Python script (with `multiprocessing` to speed up the brute-force process by checking tens of thousands of chunks in parallel), we run the solver:

```text
python3 test_solve.py
[*] Reading eFuse configuration from efuse_sum.json...
    [+] MAC Address    : d0cf132f36c8
    [+] BLOCK_USR_DATA : eed822f54024e490e59ca5e670784a5daa1f04fd07787353
[*] Reading encrypted Flash memory...
    [+] Flash size     : 4 MiB
[*] Analyzing leaked_debug_firmware.bin to find MASTER_CONST...
[*] Warning: Could not parse ELF section headers (No .rodata section found in ELF). Scanning entire file...
    [+] Found 170104 suspicious 16-byte arrays in .rodata!
[*] Spawning Multiprocessing pool for brute-forcing...
    [!] This may take a few seconds depending on your CPU...

[+] SUCCESS! Found the correct MASTER_CONST!
    -> Candidate # : 35796
    -> Offset      : 0x9b90
    -> Value       : 855780fc45bce8878d68f0040630cdbb
    -> XTS Key     : 3c0c3d36a5f470de0bb31bffb7cf4e1f2cc68b04868d0482c408a218976797ce
[*] FLAG IS: V1T{7h15_5h1d_k1nd4_h4rd_1kn0w}

```

