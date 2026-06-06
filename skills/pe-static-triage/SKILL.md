---
name: pe-static-triage
description: >
  Windows PE static triage: EXE, DLL, SYS, loaders, droppers, packed
  binaries. Reads pre-generated artifacts only. Does not execute the
  sample or invoke tools unless explicitly instructed by the operator.
---

## Goal

Determine what the PE binary likely does, how confident the assessment
is, what evidence supports it, and what static work remains before
dynamic analysis is warranted.

---

## Read order and what to extract

Work through artifacts in this order. Track signal and absence of
signal equally — gaps are findings.

### 1. `artifacts/metadata/file.txt`
- Confirm: PE32 vs PE32+, architecture, subsystem (GUI/console/native),
  DLL vs EXE vs SYS.
- Note packer strings, overlay indicators, or "data" classification
  (high-confidence packed if file reports non-PE type).

### 2. `artifacts/metadata/exiftool.txt`
- Extract: compile timestamp (note if zeroed or epoch — likely spoofed),
  rich header hash (fingerprints compiler/linker, useful for clustering),
  linker version, code size, image version, and any embedded version
  info strings (CompanyName, ProductName, OriginalFilename).
- OriginalFilename mismatch with actual filename: masquerading indicator.
- Rich header absent: stripped or non-MSVC compiler.

### 3. `artifacts/hashes/`
- Record SHA256 as primary sample identifier.
- No inference from hashes alone — reference anchors for threat intel.

### 4. `artifacts/capa/capa.txt`
- Running with `-vv`: extract capability blocks, ATT&CK technique IDs,
  and the evidence lines (matched bytes, strings, API sequences).
- Treat capabilities as hypotheses — CAPA matches patterns, not behavior.
- Capabilities with thin evidence (single weak match, generic rule):
  flag as low-confidence, require corroboration.
- CAPA output minimal on a non-trivial binary: high-confidence packing
  signal — note explicitly.

### 5. `artifacts/yara/`
- Note family, packer, and tooling hits.
- Packer rule fires (UPX, MPRESS, Themida, Enigma, etc.): treat all
  capability findings as provisional until unpacking is done.
- YARA silent + CAPA weak: strong combined packing indicator.
- Family match: do not treat as confirmed attribution without
  corroborating imports and strings.

### 6. `artifacts/floss/floss.txt`
- Focus on decoded and stack strings — these are what raw strings miss.
- Extract: URLs, IPs, domains, registry paths, mutex names, service
  names, file paths, commands, Base64 blobs, key material.
- FLOSS output trivially small on a binary >50KB: packed or heavily
  obfuscated — note as gap.

### 7. `artifacts/strings/`
- Two files: `strings_ascii.txt` (ASCII) and `strings_utf16le.txt` (wide-char).
- Supplement FLOSS: minimum length 6.
- Prioritize: paths, domains, registry keys, error messages (reveal
  intent), debug paths (reveal build environment), locale strings,
  version info, and anything FLOSS didn't surface.

### 8. `artifacts/pe_elf/rabin2_info.txt`
- Check: entry point offset, imagebase, DLL characteristics flags,
  and subsystem.

### 9. `artifacts/pe_elf/rabin2_imports.txt`
- Group by DLL — groupings reveal capability clusters.
- High-signal combinations:

  | Pattern | Implication |
  |---|---|
  | VirtualAlloc + WriteProcessMemory + CreateRemoteThread/NtCreateThreadEx | Process injection / shellcode |
  | LoadLibrary + GetProcAddress + few other imports | Dynamic resolution, likely packed |
  | WinInet/WinHTTP + URL strings | Network C2 or download |
  | RegSetValue/RegCreateKey + service strings | Persistence |
  | Crypt*/BCrypt* + encoded blobs | Payload or config encryption |
  | Nt*/Zw* direct NTDLL imports | Syscall-level evasion |
  | IsDebuggerPresent / NtQueryInformationProcess | Anti-debug |

- Very few imports + rich strings: packed or reflectively loaded.
- Resolve-by-ordinal only: strong packing indicator.

### 10. `artifacts/pe_elf/rabin2_sections.txt`
- Per section: name, virtual size, raw size, entropy.
- Entropy >7.0: compressed or encrypted.
- Raw size ≠ virtual size by large margin: unpacking stub pattern.
- Non-standard section names (`.upx0`, `.nsp`, `.themida`): packer.
- Executable + writable section: self-modifying code.
- Entropy values absent: note gap, recommend `rabin2 -S`.

### 11. `artifacts/pe_elf/objdump_headers.txt`
- Validate section layout, PE header integrity, characteristics flags.

### 12. `artifacts/decompiled/ghidra_decomp.txt` (if present)
- Pre-generated via Ghidra headless using `DecompileAllFunctions.java`,
  top 50 functions sorted by size descending.
- Read with appropriate skepticism:
  - Packed binary: output is the unpacking stub only — do not interpret
    as malware logic. The largest function will typically be the
    decompression/decryption loop.
  - VM-protected or heavily obfuscated: output will be incoherent
    (meaningless variable names, no recoverable logic) — note and stop.
  - Function boundaries and types are Ghidra's best-effort inference,
    not ground truth — cross-check against imports and strings.
- Extract from decompiled output:
  - Decryption loops (XOR, RC4, AES key schedules).
  - Config parsing or network beacon construction.
  - Anti-analysis checks (timing, debugger, sandbox artifact checks).
  - String construction patterns (character-by-character stack builds).
  - Suspicious API call sequences not visible in the import table
    (dynamically resolved via LoadLibrary/GetProcAddress).
- Treat as hypothesis-generating, same epistemics as CAPA. Confirm
  findings against imports and strings before raising confidence.

---

## Correlation thresholds

Do not make high-confidence claims from a single artifact.

| Claim | Minimum corroboration |
|---|---|
| Packed/protected | 2 of: YARA packer hit, section entropy >7.0, near-empty imports, CAPA near-empty |
| Process injection | Import triad: VirtualAlloc + WriteProcessMemory + CreateRemoteThread or NtCreateThreadEx |
| Network C2 | WinInet/WinHTTP imports + URL/domain in strings or FLOSS |
| Persistence | Registry/service imports + reg path or service name in strings |
| Crypto | Crypt*/BCrypt* imports + encoded blob or key material in strings |
| Anti-debug | NtQueryInformationProcess or IsDebuggerPresent + CAPA anti-analysis hit |
| Family attribution | YARA hit + imports + strings all consistent |

---

## Stop and recommend dynamic analysis when

- Payload is encrypted and no static config is recoverable.
- CAPA/YARA suggest behavior but no imports or strings corroborate —
  runtime unpacking almost certain.
- C2 config or network endpoints appear dynamically generated (DGA,
  runtime construction visible in decompiled output).
- Binary is a loader/dropper and the second stage is not in the artifact
  folder.
- Ghidra decompiled output is incoherent across all functions —
  protected or VM-obfuscated binary.
- More than two capability clusters are unresolvable without execution.

---

## Targeted static verification (operator-run, not agent-executed)

If a specific finding needs confirmation after reading artifacts,
recommend the operator run:

```bash
# Disassemble a specific function by address (no plugins required)
r2 -A -q -c "s <addr>; pdf" <sample>

# Cross-references to a suspicious API
r2 -A -q -c "aaa; axt sym.imp.VirtualAlloc" <sample>

# List all identified functions with sizes
r2 -A -q -c "aaa; afll" <sample>

# Strings in a specific section
r2 -A -q -c "iS; ps @ section.<name>" <sample>

# Entropy per section
r2 -A -q -c "iS~entropy" <sample>

# Decompile a specific function by address (Ghidra headless, one function)
/opt/ghidra/support/analyzeHeadless /tmp/ghidra_verify Triage \
  -import <sample> \
  -postScript DecompileAllFunctions.java \
  -scriptPath ~/triage-scripts/ghidra \
  -deleteProject 2>&1 | grep -v "^INFO\|^WARN\|^ERROR\|^REPORT"
```

All r2 use is read-only (`-A` flag, no patching, no execution). Never
use `ood`, `dc`, or `!` shell escapes. Never execute the sample or
any extracted shellcode directly.

---

## Output format

1. **File profile** — type, arch, subsystem, size, SHA256
2. **Packing assessment** — packed / likely packed / not packed + evidence
3. **Capability assessment** — what the binary likely does, per
   corroborated cluster
4. **Malware category/family** — only if YARA + imports + strings agree
5. **IOCs** — domains, IPs, paths, registry keys, mutexes, service names
6. **ATT&CK mapping** — from CAPA `-vv` output; flag any without
   corroborating imports or strings
7. **Confidence per claim** — high/medium/low with cited evidence
8. **Gaps** — what is unknown and why
9. **Next static steps** — specific commands if targeted verification
   is warranted
10. **Dynamic analysis recommendation** — yes/no with rationale
