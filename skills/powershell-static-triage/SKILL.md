---
name: powershell-static-triage
description: >
  Use for static analysis of PowerShell scripts, encoded commands,
  download cradles, stagers, and PowerShell-based malware. Handles
  .ps1, .psm1, encoded -Command arguments, and PowerShell embedded
  in other file types. Does not execute scripts or decoded payloads.
---

## Goal

Recover the full execution chain and decoded intent without running
the script. Identify obfuscation layers, evasion techniques, IOCs,
and persistence mechanisms purely through static analysis.

---

## Artifact resolution rule

Check for each artifact file before running any tool. If it exists
and is non-empty, read it. If absent, run the tool and save output
to the path shown. Never run a tool twice on the same sample.

```bash
mkdir -p artifacts/powershell
```

---

## Read order and what to extract

### 1. `artifacts/metadata/file.txt`
- Confirm: plain text PS1, encoded command blob, or PowerShell
  embedded in another format.
- If file reports "data" on a .ps1: likely a binary-encoded or
  UTF-16LE script — read with `cat -v` or `strings -el`.

### 2. `artifacts/strings/strings_ascii.txt` and `strings_utf16le.txt`
- PowerShell is often UTF-16LE — wide-char strings are primary.
- Quick triage before deobfuscation: look for URLs, IPs, Base64
  blobs, `IEX`, `DownloadString`, `EncodedCommand`, `FromBase64`,
  `AmsiUtils`, `amsiInitFailed`.
- Large Base64 block present: extract and decode before proceeding.

### 3. `artifacts/yara/`
- Family hits, obfuscation tool hits (Invoke-Obfuscation,
  ISESteroids, XENCRYPT patterns), known cradle signatures.
- YARA silent on heavily obfuscated sample: expected — proceed
  with manual deobfuscation.

### 4. Script content — `artifacts/powershell/script.txt` or direct read
- If the sample is a readable .ps1, read it directly from `sample/`.
- If absent or binary-encoded:
  ```bash
  # UTF-16LE encoded script
  cat sample/<file> | iconv -f UTF-16LE -t UTF-8 \
    > artifacts/powershell/script.txt

  # Base64+UTF-16LE EncodedCommand (most common)
  python3 -c "
  import base64, sys
  data = open('sample/<file>','rb').read().strip()
  print(base64.b64decode(data).decode('utf-16-le'))
  " > artifacts/powershell/script.txt
  ```

---

## Deobfuscation logic

Work layer by layer. Document each layer before moving to the next.
Never skip layers — intermediate state often contains IOCs.

### Layer identification — what to look for first

| Pattern | Technique |
|---|---|
| `-EncodedCommand` / `-enc` / `-en` / `-enco` / `-e` | Base64+UTF-16LE encoded command |
| `[Convert]::FromBase64String` | Inline Base64 decode |
| `[System.Text.Encoding]::Unicode.GetString` | UTF-16LE decode |
| `GZipStream` / `DeflateStream` / `IO.Compression` | Compressed payload |
| `IEX` / `Invoke-Expression` / `.$` / `&(...)` | Dynamic execution sink |
| `$env:` variables used as string parts | Environment variable substitution |
| `-join` / `+` string concatenation / `-f` format operator | String reassembly |
| `[char]` arrays or `[char[]]` casts | Character-code obfuscation |
| `StrReverse` / `-split` / `[Array]::Reverse` | String reversal |
| `'st'+'ri'+'ng'` patterns | String fragmentation |
| XOR loop over byte array | XOR decode |
| `[Regex]::Replace` or `$_.replace` chains | Substitution obfuscation |

### Deobfuscation steps (manual, safe)

```python
# Base64 decode (UTF-16LE, standard PowerShell encoding)
import base64
data = "<base64_string>"
print(base64.b64decode(data).decode('utf-16-le'))

# GZip decompress + Base64
import base64, gzip, io
compressed = base64.b64decode("<base64_string>")
print(gzip.decompress(compressed).decode('utf-8', errors='replace'))

# XOR decode
key = 0x<XX>
data = bytes([<byte_array>])
print(bytes([b ^ key for b in data]).decode('utf-8', errors='replace'))

# Character array reassembly
chars = [<int_list>]
print(''.join(chr(c) for c in chars))
```

Never pipe decoded content into `iex`, `powershell`, or any
execution context. Decode to text only.

---

## Suspicious patterns — what to look for after decoding

### Execution and download
- `IEX`/`Invoke-Expression` wrapping downloaded or decoded content.
- `(New-Object Net.WebClient).DownloadString(<url>)` — fileless
  download and execute.
- `Invoke-WebRequest`, `Invoke-RestMethod`, `Start-BitsTransfer`.
- `DownloadFile` to `$env:TEMP` or `$env:APPDATA`.
- `[Reflection.Assembly]::Load` or `::LoadWithPartialName` —
  reflective .NET assembly loading (common for Cobalt Strike, Meterpreter).
- `Add-Type` with inline C# containing P/Invoke — PE injection
  or shellcode runner.

### AMSI and logging evasion — high-confidence malicious indicator
- `AmsiUtils` + `amsiInitFailed` + `SetValue($null,$true)` —
  classic AMSI disable via reflection.
- `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')` —
  AMSI class resolution via reflection.
- `AmsiScanBuffer` / `AmsiOpenSession` patching via
  `VirtualProtect` + `Marshal.Copy` — memory patch bypass.
- `Set-PSReadlineOption -HistorySaveStyle SaveNothing` —
  history suppression.
- `[ScriptBlock]::Create` with AST manipulation — ScriptBlock
  smuggling to evade logging.
- `ETWEventWrite` patching — ETW logging bypass.
- `Set-MpPreference -DisableRealtimeMonitoring $true` —
  Defender disable.
- Exclusion path addition: `Add-MpPreference -ExclusionPath`.

### Persistence
- `New-ScheduledTask` / `Register-ScheduledJob` / `schtasks`.
- `Set-ItemProperty HKCU:\...\Run` or `HKLM:\...\Run`.
- Startup folder writes: `$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup`.
- WMI subscription: `Set-WmiInstance -Class __EventFilter`.
- Service creation: `New-Service` / `sc.exe`.

### Process and memory injection
- `VirtualAlloc` + `RtlMoveMemory`/`Marshal.Copy` + `CreateThread` —
  shellcode injection pattern.
- `OpenProcess` + `WriteProcessMemory` + `CreateRemoteThread`.
- `[DllImport]` P/Invoke declarations for injection APIs.

### Reconnaissance
- `Get-Process`, `Get-Service`, `Get-LocalUser`, `whoami`, `ipconfig`.
- `[System.Net.Dns]::GetHostEntry` — hostname resolution.
- `$env:COMPUTERNAME`, `$env:USERNAME`, `$env:USERDOMAIN`.

---

## Correlation thresholds

| Claim | Minimum corroboration |
|---|---|
| Downloader/stager | Download cmdlet/class + URL or domain IOC |
| AMSI bypass | Reflection pattern targeting AmsiUtils or AmsiScanBuffer + SetValue or patch bytes |
| Fileless execution | IEX or Load wrapping downloaded/decoded content — no file dropped |
| Reflective PE load | Assembly::Load or Add-Type + base64 PE blob or URL |
| Persistence | Registry/scheduled task write + path or key string |
| Process injection | VirtualAlloc + Marshal.Copy/RtlMoveMemory + CreateThread pattern |
| Defense evasion | Set-MpPreference / exclusion add + execution context |

---

## Stop and recommend dynamic analysis when

- Payload is downloaded from remote infrastructure at runtime —
  no URL or hardcoded content recoverable.
- Decryption key is derived from host state (machine name, SID,
  environment variable) and cannot be computed statically.
- Decoded content is a PE or shellcode requiring sandbox for
  behavioral validation.
- AMSI/ETW bypass is present and subsequent payload is fully
  runtime-resolved — static analysis blind past the bypass.
- Script is a multi-stage loader and later stages are not present
  in the artifact folder.

---

## Tool reference

```bash
# Read UTF-16LE script
iconv -f UTF-16LE -t UTF-8 sample/<file> > artifacts/powershell/script.txt

# Decode Base64+UTF-16LE EncodedCommand
python3 -c "
import base64, sys
b64 = open('sample/<file>','r').read().strip()
print(base64.b64decode(b64).decode('utf-16-le'))
" > artifacts/powershell/decoded_layer1.txt

# Decompress GZip+Base64
python3 -c "
import base64, gzip
data = base64.b64decode(open('sample/<file>','r').read().strip())
print(gzip.decompress(data).decode('utf-8', errors='replace'))
" > artifacts/powershell/decoded_layer1.txt

# String extraction (wide-char for PS1)
strings -a -el -n 6 sample/<file> > artifacts/strings/strings_utf16le.txt
```

Never invoke decoded content in PowerShell, bash, or any interpreter.

---

## Output format

1. **Script profile** — format, encoding, size, SHA256
2. **Obfuscation layers** — each layer identified and decoded
3. **Execution chain** — trigger → decode → download/load → execute
4. **Evasion techniques** — AMSI bypass, ETW bypass, logging
   suppression, Defender tampering — cited with exact pattern
5. **Persistence mechanisms** — method, key/path/task name
6. **IOCs** — URLs, IPs, domains, file paths, registry keys,
   scheduled task names — extracted only after full decode
7. **ATT&CK mapping** — technique IDs where supported by evidence
8. **Confidence per claim** — high/medium/low with cited evidence
9. **Gaps** — layers not fully decoded and why
10. **Dynamic analysis recommendation** — yes/no with rationale
