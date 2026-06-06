---
name: elf-static-triage
description: >
  Use for Linux ELF static triage: executables, shared objects (.so),
  loadable kernel modules (.ko), bots, miners, backdoors, rootkits,
  IoT malware. Covers x86_64, ARM, MIPS, and other architectures.
  Reads pre-generated artifacts only. Does not execute the sample.
---

## Goal

Determine ELF type, architecture, likely malware class, and
Linux-specific behaviors. Establish capability clusters, recover
IOCs, and identify persistence and evasion mechanisms from static
artifacts alone.

---

## Artifact resolution rule

Check for each artifact file before running any tool. If it exists
and is non-empty, read it. If absent, run the tool and save output
to the path shown. Never run a tool twice on the same sample.

Artifact paths for ELF use the same `artifacts/pe_elf/` directory
as PE analysis — this is correct, the triage script writes both
there. ELF-specific outputs (readelf, nm) are in the same folder.

```bash
mkdir -p artifacts/pe_elf artifacts/decompiled
```

---

## Step 0 — Determine ELF type before anything else

Read `artifacts/metadata/file.txt` first. ELF type determines
the analysis path.

| file output | ELF type | Analysis path |
|---|---|---|
| `ELF ... executable` | ET_EXEC / ET_DYN PIE | Standard executable path |
| `ELF ... shared object` | ET_DYN | Shared object — check for LD_PRELOAD rootkit |
| `ELF ... relocatable` | ET_REL | Kernel module (.ko) — LKM rootkit path |
| `ELF ... core file` | ET_CORE | Memory dump — not a malware binary |
| Architecture: ARM / MIPS / PPC | IoT / embedded | Cross-arch — note, affects tool output |

If file reports "data" or non-ELF on a suspected ELF: possible
packing or corruption — note and proceed with strings triage.

---

## Read order and what to extract

### 1. `artifacts/metadata/file.txt`
- Confirm: ELF type, architecture (x86_64, i386, ARM, MIPS, etc.),
  endianness, 32 vs 64-bit, dynamically vs statically linked,
  stripped vs not stripped.
- Statically linked + stripped: high-confidence packing or
  deliberate analysis resistance — reduced symbol visibility.
- Architecture mismatch with host: IoT or cross-compiled malware.

### 2. `artifacts/metadata/exiftool.txt`
- Extract: compiler/linker version, build ID, any embedded paths.
- GCC version fingerprints build environment.
- Embedded absolute paths (e.g. `/home/user/project/`) leak
  development environment details — useful for clustering.

### 3. `artifacts/hashes/`
- Record SHA256 as primary sample identifier.
- Reference anchor only — no behavioral inference from hashes.

### 4. `artifacts/pe_elf/readelf_header.txt`
- If absent: `readelf -h sample/<file> > artifacts/pe_elf/readelf_header.txt`
- Extract: ELF type (ET_EXEC/ET_DYN/ET_REL), machine architecture,
  entry point address, number of sections and segments.
- ET_REL confirms kernel module — switch to LKM path.

### 5. `artifacts/pe_elf/readelf_sections.txt`
- If absent: `readelf -S sample/<file> > artifacts/pe_elf/readelf_sections.txt`
- Per section: name, type, flags, size, entropy (if available).
- High entropy sections: compressed or encrypted payload.
- Missing standard sections (`.text`, `.data`, `.bss`): packed or
  manually constructed binary.
- Unusual section names: packer or builder artifact.
- Executable + writable section: self-modifying code.
- Run additionally for full section details:
  ```bash
  readelf -l sample/<file> > artifacts/pe_elf/readelf_segments.txt
  ```

### 6. `artifacts/pe_elf/rabin2_info.txt`
- If absent: `rabin2 -I sample/<file> > artifacts/pe_elf/rabin2_info.txt`
- Extract: canary, PIC/PIE, RELRO, NX, stripped status, language,
  compiler, and linked libraries.
- No canary + No RELRO + No NX: older or deliberately hardened-off
  binary — common in IoT malware.
- PIE disabled on a shared object: unusual, flag it.

### 7. `artifacts/pe_elf/rabin2_imports.txt`
- If absent: `rabin2 -i sample/<file> > artifacts/pe_elf/rabin2_imports.txt`
- Group by library — capability clusters.
- High-signal import combinations:

  | Import pattern | Implication |
  |---|---|
  | `socket` + `connect` + `send`/`recv` | Network C2 or bot |
  | `fork` + `execve`/`system`/`popen` | Process spawning, command execution |
  | `dlopen` + `dlsym` | Dynamic library loading, possible rootkit |
  | `ptrace` | Anti-debug or process injection |
  | `mmap` + `mprotect` + `memcpy` | Shellcode injection, self-unpacking |
  | `curl_easy_*` / `libcurl` | HTTP C2 or downloader |
  | `IRC`-related strings in imports | IRC bot |
  | `crypto`/`openssl` imports | Encrypted C2 or miner |
  | `init_module` / `finit_module` | Loads kernel module (dropper) |
  | `setuid` + `setgid` | Privilege escalation attempt |
  | No imports / very few | Statically linked or packed |

### 8. `artifacts/pe_elf/readelf_sections.txt` — dynamic section
- Run additionally:
  ```bash
  readelf -d sample/<file> > artifacts/pe_elf/readelf_dynamic.txt
  ```
- Check: `NEEDED` entries (linked shared libraries), `RPATH`/`RUNPATH`
  (library search paths — unusual values indicate hijacking),
  `INTERP` (dynamic linker path — non-standard path is suspicious).

### 9. Symbol table — `artifacts/pe_elf/symbols.txt`
- If absent:
  ```bash
  readelf -s sample/<file> > artifacts/pe_elf/symbols.txt
  nm sample/<file> 2>/dev/null >> artifacts/pe_elf/symbols.txt
  ```
- Stripped binary: symbol table empty — note as analysis gap.
- Unstripped: function names reveal capability directly.
  Look for: `backdoor`, `rootkit`, `inject`, `hide_*`, `hook_*`,
  `encrypt_*`, `decrypt_*`, `download_*`, `persist_*`, `xor_*`.
- Exported symbols in shared objects: what the .so exposes —
  if it exports `read`/`write`/`open`/`stat`/`getdents`: LD_PRELOAD
  syscall hook rootkit pattern.

### 10. `artifacts/strings/strings_ascii.txt` and `strings_utf16le.txt`
- Primary IOC and behavior recovery source.
- Extract by category:

  **Network/C2:**
  - IP addresses, domains, URLs, IRC server strings (`irc.`, `#channel`).
  - User-agent strings, HTTP method strings.
  - Port numbers in context (`:4444`, `:1337`, `:6667` for IRC).
  - XMR/BTC wallet addresses (miner indicator).
  - Mining pool strings (`pool.`, `stratum+tcp://`, `xmrig`).

  **Filesystem/Persistence:**
  - `/etc/cron*`, `/etc/init.d/`, `/lib/systemd/system/` paths.
  - `/etc/ld.so.preload` — LD_PRELOAD rootkit persistence path.
  - `/lib/modules/` — kernel module installation path.
  - `/tmp/`, `/var/tmp/`, `/dev/shm/` — execution from temp paths.
  - `.bashrc`, `.bash_profile`, `.profile` — user persistence.
  - `authorized_keys` — SSH persistence.
  - `chattr +i` — immutable file attribute (anti-removal).

  **Evasion/Anti-analysis:**
  - `/proc/` path reads — process hiding or anti-debug checks.
  - `ptrace` in strings: anti-debug.
  - `LD_PRELOAD` in strings: rootkit injection vector.
  - `unlink`/`remove` of self after execution — self-deletion.
  - `/proc/net/` reads — network connection hiding.

  **Execution:**
  - Shell commands: `bash -i`, `sh -c`, `/bin/sh`.
  - `wget`/`curl` + URL: downloader.
  - `chmod +x` + path: dropper pattern.
  - `crontab -e`, `crontab -l`: cron persistence.
  - `systemctl enable`: service persistence.

### 11. `artifacts/yara/`
- Family, botnet variant, miner, and rootkit hits.
- Known family hit: corroborate with strings and imports.
- UPX/packer YARA hit: treat all capability findings as provisional.
- YARA silent + very few strings: likely packed — note explicitly.

### 12. `artifacts/capa/capa.txt` (if present)
- CAPA supports ELF with Linux-specific rules.
- Extract capability blocks and ATT&CK technique IDs.
- Treat as hypothesis-generating — corroborate with imports and strings.
- CAPA minimal output on non-trivial binary: packing signal.

### 13. `artifacts/decompiled/ghidra_decomp.txt` (if present)
- Pre-generated via Ghidra headless, top functions by size.
- Same reliability caveats as PE: packed binary output is stub only.
- For ELF, look additionally for:
  - Syscall invocations via `int 0x80` / `syscall` instruction
    (statically linked binaries often use direct syscalls).
  - ftrace hook registration patterns (LKM rootkits).
  - `/proc` filesystem manipulation (hiding PIDs, connections).
  - String decryption routines (XOR, RC4 over embedded config).
  - C2 beacon construction (URL assembly, HTTP header building).

---

## ELF type-specific paths

### Shared object (.so) — LD_PRELOAD rootkit indicators
Trigger: file reports `shared object` OR exports override standard
libc functions (`read`, `write`, `open`, `stat`, `getdents64`,
`readdir`, `opendir`, `fopen`, `unlink`).

- Check exported symbols for libc function overrides — these
  intercept syscalls to hide files, processes, or network connections.
- Look for `/etc/ld.so.preload` path in strings — rootkit writes
  itself here for persistence.
- `getdents`/`getdents64` override: hides files from `ls`.
- `readdir` override: hides directory entries.
- `open`/`fopen` override: intercepts file reads (log tampering).
- `stat`/`lstat` override: hides file metadata.
- `write` override: intercepts output (credential harvesting).

### Kernel module (.ko) — LKM rootkit indicators
Trigger: file reports `relocatable` (ET_REL).

- `init_module` and `cleanup_module` are standard exports — present
  in all LKMs, not malicious alone.
- Malicious indicators:
  - Syscall table patching: `sys_call_table` in strings or symbols.
  - ftrace hooks: `ftrace_ops`, `ftrace_hook` in symbols.
  - `/proc` entry creation to expose C2 channel or config.
  - `hidden` / `hide_*` function names in symbol table.
  - `kill` syscall hook (used for signal-based C2 — PUMAKIT pattern).
  - `rmdir` syscall hook (privilege escalation via syscall abuse).
  - No legitimate module description or author strings.
- Check with:
  ```bash
  readelf -s sample/<file> | grep -i "hook\|hide\|patch\|proc\|sys_call"
  modinfo sample/<file>   # module metadata — license, author, description
  ```

### IoT / cross-compiled (ARM, MIPS, PPC)
Trigger: file reports non-x86 architecture.

- Ghidra handles ARM and MIPS — decompiled output still useful.
- rabin2 and readelf work cross-architecture.
- `strings` output is the primary analysis path when disassembly
  is unavailable.
- Mirai/Gafgyt/Bashlite family indicators: hardcoded C2 IPs,
  `/bot`, `/bins/`, `busybox` commands, DDoS method strings
  (`UDP`, `TCP`, `HTTP`, `STOMP`, `VSE`).
- Scanner strings: `masscan`, port ranges, credential lists
  (`root:root`, `admin:admin`, `default` credential pairs).
- Architecture-specific packed UPX: `upx -d` safe unpacking
  may be possible — recommend to operator.

---

## Correlation thresholds

| Claim | Minimum corroboration |
|---|---|
| Packed/stripped | 2 of: YARA packer hit, high section entropy, no/few imports, no symbols |
| Network bot/backdoor | socket+connect imports + C2 IP/domain in strings |
| Cryptominer | Mining pool strings + crypto library imports or wallet address |
| Downloader/dropper | curl/wget imports or strings + URL + chmod/exec pattern |
| LD_PRELOAD rootkit | .so type + libc function exports (getdents/open/stat) + ld.so.preload path in strings |
| LKM rootkit | ET_REL type + syscall table or ftrace hook strings/symbols |
| Persistence | Cron/systemd/init path strings + write/install behavior in imports |
| Anti-debug | ptrace import + /proc/self checks in strings |
| Family attribution | YARA hit + import pattern + strings all consistent |

---

## Stop and recommend dynamic analysis when

- Binary is packed or encrypted and static decoding is inconclusive.
- C2 config is generated or decrypted at runtime.
- Architecture requires emulation for meaningful analysis
  (MIPS/ARM with no Ghidra output available).
- LKM rootkit hooks syscalls — full behavior only visible under
  active kernel loading.
- LD_PRELOAD .so behavior requires a host process to inject into.
- Miner pool address or C2 is dynamically resolved (DGA or
  runtime-computed).

---

## Tool reference

```bash
# ELF structure
readelf -h sample/<file>   > artifacts/pe_elf/readelf_header.txt
readelf -S sample/<file>   > artifacts/pe_elf/readelf_sections.txt
readelf -l sample/<file>   > artifacts/pe_elf/readelf_segments.txt
readelf -d sample/<file>   > artifacts/pe_elf/readelf_dynamic.txt
readelf -s sample/<file>   > artifacts/pe_elf/symbols.txt
nm sample/<file> 2>/dev/null >> artifacts/pe_elf/symbols.txt

# Imports and info
rabin2 -I sample/<file>    > artifacts/pe_elf/rabin2_info.txt
rabin2 -i sample/<file>    > artifacts/pe_elf/rabin2_imports.txt
rabin2 -S sample/<file>    > artifacts/pe_elf/rabin2_sections.txt

# Kernel module metadata
modinfo sample/<file>      > artifacts/pe_elf/modinfo.txt

# Symbol search for rootkit indicators
readelf -s sample/<file> | grep -iE "hook|hide|patch|proc|sys_call|ftrace"

# Strings
strings -a -n 6 sample/<file>     > artifacts/strings/strings_ascii.txt
strings -a -el -n 6 sample/<file> > artifacts/strings/strings_utf16le.txt

# UPX detection (recommend to operator only — do not unpack automatically)
upx -t sample/<file>

# Targeted disassembly (read-only)
r2 -A -q -c "aaa; pdf @ entry0" sample/<file>
r2 -A -q -c "aaa; axt sym.imp.connect" sample/<file>
```

Never execute the sample. Never load a kernel module. Never run
`ldd` against a potentially malicious binary on the analysis host.

---

## Output format

1. **ELF profile** — type, architecture, linking, stripped, size, SHA256
2. **Packing assessment** — packed/likely packed/not packed + evidence
3. **ELF type classification** — executable / shared object / kernel module
4. **Capability assessment** — what the binary likely does, per
   corroborated cluster
5. **Malware class/family** — bot/miner/backdoor/rootkit/dropper/wiper,
   only if YARA + imports + strings agree
6. **Rootkit indicators** — LD_PRELOAD or LKM, specific hooks identified
7. **Persistence mechanisms** — cron/systemd/ld.so.preload/authorized_keys
8. **IOCs** — IPs, domains, wallet addresses, file paths, pool URLs
9. **ATT&CK mapping** — from CAPA output; flag any without corroboration
10. **Confidence per claim** — high/medium/low with cited evidence
11. **Gaps** — stripped binary, packed, cross-arch limitations
12. **Next static steps** — specific commands if targeted verification
    is warranted
13. **Dynamic analysis recommendation** — yes/no with rationale
