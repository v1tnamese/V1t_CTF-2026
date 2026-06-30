# Writeup — V1T CTF 2026: *Green Plasma*
 
- `GreenGoblin.raw` (Raw memory dump)  

## Challenge Description
> *The Green Goblin harnessed a secret Dark Energy to attack our system. Fortunately, our defenses froze his payload mid-execution, shattering his Dark Energy into 5 fragments scattered across the OS internals (R, KO, D, EL and M). Can you recover all 5 fragments and assemble them in the correct order to seal his power forever?*

## Overview
We are given a single memory dump (`GreenGoblin.raw`) and a description that points to 5 fragments scattered across the OS internals. The initials **R, KO, D, EL, and M** correspond to standard forensic artifacts:
- **R:** Registry
- **KO:** Kernel Objects (Handles)
- **D:** Disk (Files/MFT)
- **EL:** Event Logs
- **M:** Memory (VADs)

---

## 1. Fragment 1 (R): The Registry

The first fragment is hidden somewhere in the Registry. Since we don't have a physical disk, we can query the registry hives loaded in memory using Volatility's `windows.registry.printkey` plugin. 

Instead of dumping the entire hive, we can do a quick string search on the memory dump to look for suspicious registry paths or simply hunt for the malware's tracks. However, knowing typical malware behavior, we can search for persistence or policy manipulation. A grep for `Software\Policies` in memory strings often yields results.

Alternatively, doing a global strings search for common malware noise reveals repeated strings like `N01S3_`. If we extract the context around these strings, we find them tied to the `CloudFiles` policy key. 

Let's query that key directly from memory:
```bash
┌──(kali㉿kali)-[]
└─$ vol -f GreenGoblin.raw windows.registry.printkey --key "Software\Policies\Microsoft\CloudFiles"
```

The output reveals 15 decoy values (`DiagnosticData_0` to `DiagnosticData_14`) containing the noise string `N01S3_`. However, the main `DiagnosticData` value contains the actual fragment.

**Extracted Fragment 1:** `` '`%L`0 ``

---

## 2. Fragment 2 (KO): Kernel Objects

The second fragment requires us to look at Kernel Objects (Handles). Let's list the running processes to find our culprit:
```bash
┌──(kali㉿kali)-[]
└─$ vol -f GreenGoblin.raw windows.pslist | grep -i "Green"
8040    GreenPlasma.exe
```

Now we dump the open handles for this process (`PID 8040`) using the `windows.handles` plugin. Malware often abuses `Section` or `Mutant` objects for IPC (Inter-Process Communication) or shared memory.

```bash
┌──(kali㉿kali)-[]
└─$ vol -f GreenGoblin.raw windows.handles --pid 8040 | grep "Section"
...
8040    GreenPlasma.exe    0x54    Section    \Sessions\1\BaseNamedObjects\9cGb0c
...
```

The malicious process has an open handle to a highly unusual BaseNamedObject: `9cGb0c`.

**Extracted Fragment 2:** `9cGb0c`

---

## 3. Fragment 3 (D): Disk & Alternate Data Streams

This fragment is tied to the Disk (D). Specifically, the malware dropped a physical fragment. We can scan the memory manager's cache for active File Objects using `windows.filescan`.

Since malware often drops files in `Public` or `Temp` folders, let's grep for suspicious files in `Users\Public`:

```bash
┌──(kali㉿kali)-[]
└─$ vol -f GreenGoblin.raw windows.filescan | grep -i "Users\\Public"
0x3f8a9b1c    \Device\HarddiskVolume3\Users\Public\Downloads\config.ini:hidden
```

We found an **Alternate Data Stream (ADS)** named `:hidden` attached to an innocent-looking `config.ini` file! Since the file object is still resident in memory, we can dump its contents out using its physical offset (`0x3f8a9b1c`):

```bash
┌──(kali㉿kali)-[]
└─$ vol -f GreenGoblin.raw windows.dumpfiles --physaddr 0x3f8a9b1c
[*] Dumping \Device\HarddiskVolume3\Users\Public\Downloads\config.ini:hidden
```

Reading the dumped file yields our third fragment.

**Extracted Fragment 3:** `03`809`

---

## 4. Fragment 4 (EL): Event Logs

The fourth fragment is in the Event Logs. Instead of trying to carve the full `Application.evtx` out of memory (which can be corrupted), we can leverage `strings` and `grep` since the Event Log service caches recent log entries in plaintext inside the memory dump.

We are looking for application crashes (Event ID 1000). Let's grep for the standard Windows crash message format:

```bash
┌──(kali㉿kali)-[]
└─$ strings GreenGoblin.raw | grep -i "faulting module path:"
Faulting application name: svchost.exe, version: 10.0.22621.1, faulting module path: N01S3_
Faulting application name: svchost.exe, version: 10.0.22621.1, faulting module path: N01S3_
... [25 decoy logs] ...
Faulting application name: ctfmon.exe, version: 10.0.22621.1, faulting module path: cC50C_
```

Amidst a flood of fake `svchost.exe` crashes pointing to `N01S3_`, there is one legitimate crash involving `ctfmon.exe`. The faulting module path contains our fragment.

**Extracted Fragment 4:** `cC50C_`

---

## 5. Fragment 5 (M): Memory Map

The final fragment (M) refers to the mapped memory of the process. In Fragment 2, we found a malicious Section Object named `\BaseNamedObjects\9cGb0c`. This object is used to map shared memory.

We can dump the Virtual Address Descriptors (VADs) of the `GreenPlasma.exe` process (PID 8040) to inspect all its mapped memory regions:

```bash
┌──(kali㉿kali)-[]
└─$ vol -f GreenGoblin.raw windows.vaddump --pid 8040 --dump-dir ./vads/
```

After dumping the VADs, we can run a string search across them. We know the malware uses `N01S3_` extensively as decoy data, so we filter those out:

```bash
┌──(kali㉿kali)-[]
└─$ strings ./vads/*.dmp | grep -v "N01S3" | grep -E "^.{6}$"
...
_dEbCN
...
```

At offset `0x250` of the shared memory section, we find the final 6-character fragment.

**Extracted Fragment 5:** `_dEbCN`

---

## 6. Assembly & Decryption

We have successfully recovered all 5 fragments (R, KO, D, EL, M). Let's combine them in the order specified by the challenge description:
1. (R)  -> `'\`%L\`0`
2. (KO) -> `9cGb0c`
3. (D)  -> `03\`809`
4. (EL) -> `cC50C_`
5. (M)  -> `_dEbCN`

**Combined Dark Energy Cipher:**
`'\`%L\`09cGb0c03\`809cC50C__dEbCN`

This 30-character string looks like random garbage, but we know the standard flag format is `V1T{...}`. 
If we compare the first few characters `'\`%L` to `V1T{`, we can check their ASCII distance:
- `'` (39) to `V` (86) = +47
- `` ` `` (96) to `1` (49) = -47
- `%` (37) to `T` (84) = +47
- `L` (76) to `{` (123) = +47

This is a classic **ROT47** cipher! ROT47 is a simple substitution cipher that replaces a character with the 47th character after it in the ASCII table (wrapping around the visible characters).

We can write a quick Python script to decode it, or just use CyberChef. Here is the Python solver:

```python
def rot47(s):
    res = []
    for c in s:
        if 33 <= ord(c) <= 126:
            res.append(chr(33 + ((ord(c) - 33 + 47) % 94)))
        else:
            res.append(c)
    return "".join(res)

cipher = "'`%L`09cGb0c03`809cC50C__dEbCN"
print(f"[+] FLAG: {rot47(cipher)}")
```

Running the script:
```bash
┌──(kali㉿kali)-[]
└─$ python3 solve.py
[+] FLAG: V1T{1_h4v3_4_b1g_h4rd_r005t3r}
```

The Green Goblin's energy has been sealed successfully!

**FLAG:** `V1T{1_h4v3_4_b1g_h4rd_r005t3r}`
