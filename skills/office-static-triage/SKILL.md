---
name: office-static-triage
description: >
  Use for Microsoft Office static triage: OLE (.doc, .xls, .ppt),
  OOXML (.docx, .docm, .xlsm, .xlsb, .pptm), RTF, macro-enabled
  documents, embedded payloads, template injection. Reads
  pre-generated artifacts where available and runs oletools directly
  when artifacts are absent. Does not execute the sample or any
  extracted payload.
---

## Goal

Determine whether the document contains malicious automation, embedded
payloads, external relationships, or exploit/payload delivery logic.
Establish the execution chain and recover IOCs where possible.

---

## Artifact resolution rule

For each analysis step below, check whether the artifact file already
exists. If it does, read it. If it does not, run the tool and save
output to the expected path before proceeding. This allows the skill
to work whether or not the triage script pre-generated the artifacts.

Sample path is always `sample/<filename>` inside the case folder.
Artifact root is always `artifacts/` inside the case folder.
Never run a tool twice if the artifact already exists and is non-empty.

Before running any tool, ensure the output directory exists:
```bash
mkdir -p artifacts/oletools/extracted
mkdir -p artifacts/oletools
```
Run this once at the start of the analysis session if oletools
artifacts are absent.

---

## Step 0 — Determine format before anything else

Read `artifacts/metadata/file.txt` and `artifacts/metadata/exiftool.txt`
first. Format determines which analysis path applies.

| Format indicators | Path |
|---|---|
| "Composite Document File" / OLE2 | OLE path: .doc, .xls, .ppt |
| "Zip archive" with Office content types | OOXML path: .docx, .docm, .xlsm, .xlsb, .pptm |
| "Rich Text Format" | RTF path |
| "data" or unrecognized | Possible encryption or corruption — see encrypted docs note |

If exiftool reports encryption or a password prompt, go to the
encrypted documents note before proceeding.

---

## Read order and what to extract

### 1. `artifacts/metadata/file.txt`
- Confirm format class (OLE, OOXML/zip, RTF).
- Note any mismatch between reported format and file extension —
  common masquerading technique.

### 2. `artifacts/metadata/exiftool.txt`
- Extract: author, last saved by, company, create/modify timestamps,
  template name, application version.
- Author or company fields with generic/suspicious values
  (e.g. "user", "admin", Cyrillic/Arabic names on English lure):
  clustering and attribution lead.
- Template field pointing to a remote URL: template injection indicator.
- Last saved by ≠ author: document was modified post-creation.

### 3. `artifacts/strings/strings_ascii.txt` and `strings_utf16le.txt`
- Quick triage before deep artifact reads.
- Look for: URLs, IPs, PowerShell, cmd.exe, WScript, mshta, rundll32,
  regsvr32, certutil, bitsadmin, Base64 blobs, UNC paths.
- Wide-char strings often surface obfuscated VBA or payload fragments
  that ASCII strings miss.

### 4. `artifacts/oletools/oleid.txt`
- If absent: `oleid <sample> > artifacts/oletools/oleid.txt`
- Triage summary: macro presence, encryption, external relationships,
  flash objects, suspicious indicators.
- Use as routing signal:
  - VBA macros present → read or run olevba
  - XLM macros present → read or run xlmdeobfuscator
  - Encrypted → see encrypted documents note
  - External relationships → inspect rels files

### 5. `artifacts/oletools/olevba.txt`
- If absent: `olevba --decode --reveal <sample> > artifacts/oletools/olevba.txt`
- Only run if oleid confirmed VBA macros present.
- Primary VBA analysis artifact.
- Extract: auto-execution triggers, suspicious keywords, IOCs,
  obfuscation patterns, and olevba's own flags.
- Auto-execution triggers to look for:
  `AutoOpen`, `Document_Open`, `Workbook_Open`, `AutoClose`,
  `Auto_Open`, `Document_Close`, `AutoExit`, `AutoNew`.
- Suspicious execution keywords:
  `Shell`, `WScript.Shell`, `CreateObject`, `Shell.Application`,
  `CallByName`, `MacroCommand`, `EXEC`.
- Payload delivery patterns:
  `PowerShell`, `cmd.exe`, `mshta`, `rundll32`, `regsvr32`,
  `certutil`, `bitsadmin`, `wmic`, `cmstp`.
- Obfuscation patterns:
  `Chr`/`ChrW`, `StrReverse`, `Replace`, `Split`, `Join`,
  Base64 blobs, hex-encoded strings, XOR loops,
  character-by-character string construction.
- Anti-analysis patterns:
  username/machine name checks, `Sleep`, recent files checks,
  environment variable inspection, sandbox artifact checks.
- **VBA stomping check**: if olevba reports a mismatch between
  source code and p-code, or flags stomping, do not trust the
  VBA source — the p-code is what executes. Read pcodedmp output.

### 6. `artifacts/oletools/pcodedmp.txt` (if present or if stomping detected)
- If olevba flags stomping and artifact is absent:
  `pcodedmp <sample> > artifacts/oletools/pcodedmp.txt`
  `pcode2code <sample> > artifacts/oletools/pcode2code.txt`
- Only run if olevba explicitly flags a stomping indicator.
- P-code is the compiled form that Office actually executes —
  if it differs from VBA source, p-code is ground truth.
- Extract the same patterns as olevba above but from p-code output.
- `pcode2code` output (if present) provides decompiled VBA from
  p-code — treat as higher confidence than stomped source.

### 7. `artifacts/oletools/mraptor.txt`
- If absent: `mraptor <sample> > artifacts/oletools/mraptor.txt`
- Rapid macro danger classification.
- Flags: reads/writes external resources, executes commands/code.
- Use to calibrate confidence on olevba findings, not as standalone.
- mraptor SUSPICIOUS + olevba auto-exec + shell keywords:
  high-confidence malicious macro.

### 8. `artifacts/oletools/xlmdeobfuscator.txt` (XLM/Excel 4.0 only)
- Only run if oleid flagged XLM macros present.
- If absent: `xlmdeobfuscator --file <sample> > artifacts/oletools/xlmdeobfuscator.txt`
- Extract: `Auto_Open` cell presence, EXEC/CALL formula chains,
  URL or filepath arguments, WORKBOOK.HIDE/UNHIDE patterns
  (used to conceal macro sheets from the victim).
- XLM is harder to fully deobfuscate statically — incomplete output
  is expected on heavily obfuscated samples.

### 9. `artifacts/oletools/oleobj.txt` and `artifacts/oletools/extracted/`
- If absent: `oleobj -i <sample> -d artifacts/oletools/extracted/ > artifacts/oletools/oleobj.txt`
- Lists embedded OLE objects and extracted files.
- Extracted objects saved to `artifacts/oletools/extracted/` or
  similar — check for: PE files, scripts, additional Office docs,
  LNK files, package objects.
- Embedded PE found: hand off to `pe-static-triage` skill.
- Embedded script found: hand off to `script-static-triage` skill.

### 10. OOXML-specific: `artifacts/ooxml/` (OOXML format only)
- Only run if file.txt confirmed Zip/OOXML format.
- If absent:
  ```
  mkdir -p artifacts/ooxml/extracted
  zipdump.py <sample> > artifacts/ooxml/zipdump.txt
  unzip -o <sample> -d artifacts/ooxml/extracted/ 2>/dev/null
  ```
- OOXML files are zip archives — structure inspection reveals
  relationships and embedded content.
- Key files to check:
  - `word/_rels/document.xml.rels` or `xl/_rels/workbook.xml.rels`:
    external relationships — remote template URLs, hyperlinks,
    `oleObject` references.
  - `word/document.xml`: DDE field codes (`DDEAUTO`, `DDE`),
    external reference fields.
  - `[Content_Types].xml`: reveals all content types present,
    including macros, OLE objects, ActiveX.
- External relationship pointing to `http://` or `\\UNC`:
  template injection or forced authentication indicator.
- DDE field present: command execution without macros possible.

### 11. RTF-specific: `artifacts/rtf/` (RTF format only)
- Only run if file.txt confirmed Rich Text Format.
- If absent:
  ```
  mkdir -p artifacts/rtf/extracted
  rtfdump.py <sample> > artifacts/rtf/rtfdump.txt
  rtfobj.py <sample> -d artifacts/rtf/extracted/ > artifacts/rtf/rtfobj.txt
  ```
- RTF does not support macros but can embed objects and exploit
  parser vulnerabilities.
- From `rtfdump.txt`: check for `\object`, `\objdata`,
  `\objclass`, `\objocx` control words — these embed OLE objects.
- From `rtfobj.txt`: extracted embedded objects — check each for
  PE, scripts, or exploit shellcode patterns.
- Suspicious RTF control words: `\dde`, `\ddeauto` (DDE execution),
  `\bin` with large binary blobs (shellcode or PE).
- CVE-related patterns: heavily nested `{` groups, malformed
  structures, unusually large `\objdata` blobs — may indicate
  exploit (CVE-2017-11882, CVE-2018-0802, Equation Editor).

### 12. `artifacts/yara/`
- Family, exploit, and toolbuilder hits.
- YARA hit on known builder (e.g. Trickbot dropper template,
  Emotet lure pattern): corroborate with olevba findings.
- Exploit YARA hit on RTF: elevates confidence of parser
  vulnerability exploitation.

---

## Encrypted documents note

If oleid or exiftool reports encryption:
- `msoffcrypto-tool` can attempt decryption with common passwords
  (`infected`, `virus`, `malware`, `VelvetSweatshop` for Excel).
- If decrypted sample is available in `artifacts/oletools/` or
  `sample/`, treat it as the primary sample and restart from Step 1.
- If decryption fails and no plaintext is recoverable: note as gap,
  recommend dynamic analysis — behavior on open is observable in sandbox.

---

## Execution chain reconstruction

After reading all artifacts, reconstruct in this order:

1. **Trigger** — how does execution start?
   Auto-exec macro / user-click required / DDE / external relationship
   loaded on open / exploit on render.

2. **Stage 1 action** — what does the initial code do?
   Download payload / drop file / execute command / load template /
   decode embedded blob.

3. **Payload source** — where does the next stage come from?
   Hardcoded URL / generated URL / embedded object / remote template /
   UNC path.

4. **Delivery mechanism** — how is the next stage executed?
   PowerShell / WScript.Shell / cmd.exe / rundll32 / regsvr32 /
   scheduled task / registry run key.

5. **User interaction required?**
   Enable macros prompt / enable editing / click button / open attachment.
   Note: if user interaction required, document is a social engineering
   lure — describe the lure content if visible in strings or metadata.

---

## Correlation thresholds

| Claim | Minimum corroboration |
|---|---|
| Malicious macro present | Auto-exec trigger + suspicious execution keyword in olevba or p-code |
| VBA stomping | olevba stomping flag + pcodedmp output differs from source |
| Template injection | External rel URL in rels file + remote http/UNC path in strings |
| DDE execution | DDE/DDEAUTO field in XML + command string in strings |
| Exploit delivery (RTF) | Malformed structure + large objdata + YARA exploit hit |
| Embedded PE dropper | oleobj extracted PE + auto-exec macro referencing extracted path |
| XLM macro execution | Auto_Open cell + EXEC/CALL formula in xlmdeobfuscator output |
| Family attribution | YARA hit + macro patterns + IOCs all consistent |

---

## Stop and recommend dynamic analysis when

- Macro is heavily obfuscated and static decoding is inconclusive —
  payload URL or command not recoverable.
- Document is encrypted and decryption fails.
- Payload is fetched from a URL at runtime with no hardcoded IOC.
- XLM deobfuscation is incomplete and EXEC targets are unresolved.
- Exploit behavior requires Office rendering to trigger
  (RTF parser exploit, Equation Editor).
- Embedded payload is encrypted or compressed and key is runtime-derived.

---

## Tool reference

Commands the agent may run directly if artifacts are absent. Save
all output to the artifact paths shown — do not run if the artifact
already exists and is non-empty. Never execute the sample, extracted
scripts, or embedded payloads.

```bash
# Format triage (always pre-generated by triage script)
file <sample>
oleid <sample> > artifacts/oletools/oleid.txt

# VBA — run only if oleid confirms VBA macros
olevba --decode --reveal <sample> > artifacts/oletools/olevba.txt
mraptor <sample> > artifacts/oletools/mraptor.txt
oledump.py <sample> > artifacts/oletools/oledump.txt
oledump.py -s <N> -v <sample> >> artifacts/oletools/oledump.txt

# P-code — run only if olevba flags stomping
pcodedmp <sample> > artifacts/oletools/pcodedmp.txt
pcode2code <sample> > artifacts/oletools/pcode2code.txt

# XLM — run only if oleid confirms XLM macros
xlmdeobfuscator --file <sample> > artifacts/oletools/xlmdeobfuscator.txt
oledump.py -p plugin_biff -s <N> -x <sample> > artifacts/oletools/biff.txt

# Embedded objects
oleobj -i <sample> -d artifacts/oletools/extracted/ > artifacts/oletools/oleobj.txt

# OOXML — run only if format is Zip/OOXML
mkdir -p artifacts/ooxml/extracted
zipdump.py <sample> > artifacts/ooxml/zipdump.txt
unzip -o <sample> -d artifacts/ooxml/extracted/ 2>/dev/null

# RTF — run only if format is RTF
mkdir -p artifacts/rtf/extracted
rtfdump.py <sample> > artifacts/rtf/rtfdump.txt
rtfobj.py <sample> -d artifacts/rtf/extracted/ > artifacts/rtf/rtfobj.txt

# Encrypted documents
msoffcrypto-tool <sample> --test-password infected
msoffcrypto-tool <sample> -p infected -o artifacts/oletools/decrypted
```

---

## Output format

1. **Document profile** — format, application version, SHA256,
   author/metadata fields
2. **Macro/automation assessment** — type present (VBA/XLM/DDE/none),
   auto-exec triggers found
3. **Execution chain** — trigger → stage 1 → payload source →
   delivery mechanism
4. **Obfuscation assessment** — techniques observed, deobfuscation
   outcome
5. **VBA stomping** — yes/no, p-code vs source discrepancy noted
6. **Embedded objects** — types, extracted files, handoff to other
   skills if applicable
7. **IOCs** — URLs, IPs, domains, file paths, registry keys,
   mutex names, command strings
8. **ATT&CK mapping** — technique IDs where supported by evidence
9. **Confidence per claim** — high/medium/low with cited artifact
10. **Gaps** — what is unknown and why
11. **Next static steps** — specific commands if more work is warranted
12. **Dynamic analysis recommendation** — yes/no with rationale
