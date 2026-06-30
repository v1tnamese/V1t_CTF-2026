# Writeup - V1T CTF 2026: *10X54*

```bash
┌──(kali㉿kali)-[]
└─$ strings ducktricks.bin | grep -i esp32
ESP32-S3
esp32s3
```

## 1. Preparing
ESP32-S3 firmware images use the Xtensa 32-bit (little-endian) architecture. They also start with a specific magic byte (`0xE9`) and contain a custom segment header structure. 
If we just throw the raw `.bin` into Ghidra, the memory mapping (IRAM for instructions, DROM for data) will be completely messed up.

To fix this, I used `esptool`'s `elf2image` (or an ESP32 ELF extraction tool) to convert the `.bin` back into a standard ELF file, which Ghidra can parse and map correctly. 

Once converted, I imported the ELF into Ghidra, selected the Xtensa architecture, and ran the auto-analysis.

## 2. Navigating the Firmware and Finding the Logic
Since this is an Arduino/ESP-IDF based binary, the `app_main` or `setup`/`loop` functions are the entry points. I started by searching for interesting strings in the DROM section.

Found several suspicious string references and followed them to a large function that looked like the main state machine of the challenge.

Looking at the memory references in this function, the author left a massive minefield of variables:
- `FAKE_FLAG_0`, `FAKE_FLAG_1`, `FAKE_FLAG_2`
- `DECOY_A` through `DECOY_E` (all 38 bytes long)
- `ENC_A` (12 bytes), `ENC_B` (13 bytes), `ENC_C` (13 bytes)
- An array of 8 large 32-bit constants (`LCG_PARAMS`) containing troll values like `0xCAFEBABE`, `0xDEADC0DE`.

To filter out the noise, I traced the execution flow of the function that actually prints the flag (`output_flag`). I noticed that it exclusively uses `ENC_A`, `ENC_B`, and `ENC_C`. It uses `memcpy` to concatenate these three fragments into a single 38-byte array, completely ignoring the `DECOY` arrays and `FAKE_FLAG`s!

## 3. Reversing the Key 
Analyzed the key generation function (`derive_key`). The decompiled code looked like a classic Linear Congruential Generator (LCG):
```c
state = (state * mul + add) & 0xFFFFFFFF;
```

The function takes a seed (state), a multiplier (`mul`), and an adder (`add`). 
Tracing back the arguments passed to this function:
1. **The Seed:** It is constructed by combining two 16-bit variables: `s_lfsr_hi` (`0xFDD0`) and `s_lfsr_lo` (`0x9456`), resulting in a 32-bit target seed of `0xFDD09456`.
2. **The LCG Parameters:** The function reads from the `LCG_PARAMS` array. Despite the array having 8 entries with famous constants (like the glibc LCG multiplier), the code only accesses index `0` and index `1`:
   - Multiplier (`LCG_PARAMS[0]`): `0x6C62272E`
   - Adder (`LCG_PARAMS[1]`): `0x07354A6B`

## 4. The Decryption Algorithm
The final step was the decryption routine. The function iterates over the 38-byte concatenated `ENC_TOTAL` array and applies a double-layered XOR:
1. It XORs the byte with its own index (`i & 0xFF`).
2. It XORs the result with the derived 16-byte key (cycling through the key using `i % 16`).

## 5. The Solver
With all the parameters extracted from static analysis, there was no need to emulate the firmware or mess with physical boards. I wrote a simple Python script to replicate the math and extract the flag.

```python
#!/usr/bin/env python3
import struct

LFSR_HI = 0xFDD0
LFSR_LO = 0x9456
LCG_MUL = 0x6C62272E 
LCG_ADD = 0x07354A6B 

ENC_A = bytes([0x2C, 0x80, 0x4A, 0xA3, 0xAC, 0x36, 0xC1, 0x42, 0x1D, 0x11, 0xF6, 0x81])
ENC_B = bytes([0xA2, 0x0C, 0x8D, 0xD1, 0x02, 0xFE, 0x79, 0x80, 0xC0, 0x3F, 0x8A, 0x33, 0x61])
ENC_C = bytes([0x54, 0xE6, 0x91, 0xB6, 0x5A, 0xDA, 0xE1, 0x05, 0xFD, 0x73, 0x99, 0xF0, 0x2D])

ENC_TOTAL = ENC_A + ENC_B + ENC_C

def derive_key(state, mul, add):
    key = []
    for _ in range(16):
        state = (state * mul + add) & 0xFFFFFFFF
        key.append((state >> 24) & 0xFF)
    return bytes(key)

def decrypt_flag(enc, key):
    return bytes([enc[i] ^ (i & 0xFF) ^ key[i % 16] for i in range(len(enc))])

def main():
    lfsr_target = (LFSR_HI << 16) | LFSR_LO
    key = derive_key(lfsr_target, LCG_MUL, LCG_ADD)
    flag = decrypt_flag(ENC_TOTAL, key)
    print(f"[+] REAL FLAG: {flag.decode('ascii')}")

if __name__ == "__main__":
    main()
```


```bash
┌──(kali㉿kali)-[]
└─$ python3 solve.py
[+] REAL FLAG: V1T{LF5R_1s_tr4sh_wH0_n33ds_p4sS_lMa0}
```

**Flag: V1T{LF5R_1s_tr4sh_wH0_n33ds_p4sS_lMa0}**
