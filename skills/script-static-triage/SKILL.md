---
name: script-static-triage
description: >
  Use for generic script malware: JavaScript (.js, .jse), JScript,
  VBScript (.vbs, .vbe), HTA (.hta), Python (.py), Bash (.sh),
  BAT/CMD (.bat, .cmd), AutoIt (.au3). Does not execute scripts or
  decoded payloads. For PowerShell (.ps1), use powershell-static-triage.
---

## Goal

Recover script intent, execution chain, IOCs, and payload delivery
logic without running any code. Identify the script's role:
downloader, dropper, loader, recon, persistence, or lateral movement.

---

## Artifact resolution rule

Check for each artifact file before running any tool. If it exists
and is non-empty, read it. If absent, run the tool and save output
to the path shown. Never run a tool twice on the same sample.

```bash
mkdir -p artifacts/script
```

---

## Step 0 — Identify language and host environment

Read `artifacts/metadata/file.txt` first. Language determines
analysis path and what suspicious patterns to look for.

| file output | Language | Host / executor |
|---|---|---|
| ASCII/UTF-8 text + `.js`/`.jse` | JavaScript / JScript | WSH (wscript/cscript), browser |
| ASCII text + `.vbs`/`.vbe` | VBScript | WSH (wscript/cscript) |
| HTML + script tags + `.hta` | HTA (HTML Application) | mshta.exe |
| Python script | Python | python.exe / python3 |
| Bourne shell script | Bash/sh | /bin/sh, /bin/bash |
| DOS batch file | BAT/CMD | cmd.exe |
| AutoIt script | AutoIt | AutoIt3.exe |
| "data" on `.vbe`/`.jse` | Encoded VBE/JSE | decode before analysis |

If `.vbe` or `.jse` and file reports "data": encoded script —
decode first (see tool reference).

---

## Read order and what to extract

### 1. `artifacts/metadata/file.txt` and `artifacts/metadata/exiftool.txt`
- Confirm language, encoding, and any embedded metadata.
- Extension mismatch with actual format: masquerading indicator.

### 2. `artifacts/strings/strings_ascii.txt` and `strings_utf16le.txt`
- Quick pre-read before beautification.
- Look for: URLs, IPs, Base64 blobs, `eval`, `exec`, `WScript`,
  `CreateObject`, `Shell`, `cmd`, `powershell`, `certutil`,
  `bitsadmin`, file paths, registry keys.

### 3. `artifacts/yara/`
- Family hits, dropper/downloader pattern hits.
- Known toolbuilder signatures (e.g. STRRAT, NJRat loader patterns).

### 4. Script content — beautified and decoded

#### JavaScript / JScript
- If absent:
  ```bash
  js-beautify sample/<file> > artifacts/script/beautified.js
  ```
- Encoded `.jse`: decode first:
  ```bash
  decode-vbe.py sample/<file> > artifacts/script/decoded.js
  js-beautify artifacts/script/decoded.js > artifacts/script/beautified.js
  ```

#### VBScript / VBE
- If absent:
  ```bash
  cat sample/<file> > artifacts/script/script.vbs   # plain VBS
  # or for .vbe encoded:
  decode-vbe.py sample/<file> > artifacts/script/decoded.vbs
  ```

#### HTA
- HTA is HTML with embedded JS or VBS — read as text directly.
- Extract: `<script>` blocks, `<object>` tags, `ActiveXObject`
  instantiation, any `src=` pointing to remote resources.

#### Python
- Read directly. Look for `exec(`, `eval(`, `compile(`,
  `marshal.loads(`, `pickle.loads(`, `base64.b64decode(` chains.

#### Bash
- Read directly. Note: `eval $(...)` and `$(echo ... | base64 -d)`
  patterns are the primary obfuscation vectors.

#### BAT/CMD
- Read directly. Note `^` escape character insertion as obfuscation,
  environment variable substring manipulation (`%var:~0,1%`).

#### AutoIt
- If embedded in PE, extract first:
  ```bash
  autoit-ripper sample/<file> artifacts/script/
  ```
- Then read extracted `.au3` script.

---

## Suspicious patterns by language

### JavaScript / JScript (WSH context)
- `eval(...)` / `Function(...)()` — dynamic execution sink.
- `WScript.Shell` + `Run`/`Exec` — process execution.
- `ActiveXObject('MSXML2.XMLHTTP')` — HTTP request.
- `ActiveXObject('ADODB.Stream')` — file write.
- `ActiveXObject('WScript.Shell').RegWrite` — registry write.
- `unescape(` / `String.fromCharCode(` — string deobfuscation.
- `new ActiveXObject('Shell.Application').ShellExecute` — execution.

### VBScript
- `CreateObject("WScript.Shell")` + `.Run` / `.Exec`.
- `CreateObject("MSXML2.XMLHTTP")` — HTTP request.
- `CreateObject("ADODB.Stream")` — file write to disk.
- `CreateObject("Shell.Application")` + `.ShellExecute`.
- `Execute` / `ExecuteGlobal` — dynamic code execution.
- Chr/ChrW string construction, StrReverse, Replace chains.

### HTA
- `mshta.exe` self-execution patterns.
- Embedded VBS or JS with `CreateObject` chains.
- Remote script loading: `<script src="http://...">`.
- `window.resizeTo(0,0)` / `window.moveTo(-2000,-2000)` —
  hidden window (social engineering lure).

### Python
- `exec(base64.b64decode(...).decode())` — encoded payload execution.
- `marshal.loads(` — serialized bytecode execution.
- `pickle.loads(` — deserialization execution.
- `__import__('subprocess').call(` — process execution.
- `socket` + `recv` + `exec` — reverse shell pattern.
- `requests.get(<url>)` + `exec(response.text)` — remote stager.
- `ctypes.windll` / `ctypes.CDLL` — Windows API calls, injection.

### Bash
- `curl`/`wget` + `| bash` or `| sh` — remote execution.
- `eval $(echo ... | base64 -d)` — encoded command execution.
- `chmod +x` + execution from `/tmp` — dropper pattern.
- Crontab write: `crontab -l | { cat; echo "..."; } | crontab -`.
- SSH authorized_keys write — persistence.
- `nohup` / `disown` / `&` backgrounding — persistence.
- `/etc/init.d/` or `systemctl enable` — service persistence.

### BAT/CMD
- `powershell` / `powershell.exe` invocation — handoff to PS.
- `certutil -decode` / `certutil -urlcache` — file download/decode.
- `bitsadmin /transfer` — file download.
- `schtasks /create` — scheduled task persistence.
- `reg add HKCU\...\Run` — registry persistence.
- `wmic process call create` — process creation.
- `^` character insertion obfuscation: `p^o^w^e^r^s^h^e^l^l`.
- Environment variable substring: `%COMSPEC:~0,3%` → `cmd`.

---

## Decoding — language-agnostic helpers

```python
# Base64 decode
import base64
print(base64.b64decode("<string>").decode('utf-8', errors='replace'))

# Hex decode
data = bytes.fromhex("<hex_string>")
print(data.decode('utf-8', errors='replace'))

# XOR decode
key = 0x<XX>
data = bytes([<byte_array>])
print(bytes([b ^ key for b in data]).decode('utf-8', errors='replace'))

# Char code reassembly (JS String.fromCharCode)
chars = [<int_list>]
print(''.join(chr(c) for c in chars))

# URL decode
from urllib.parse import unquote
print(unquote("<url_encoded_string>"))
```

Never execute decoded content. Decode to readable text only.

---

## Payload handoff rules

When decoded content is a different type, hand off to the
appropriate skill:

| Decoded content | Hand off to |
|---|---|
| PE / EXE / DLL / shellcode | `pe-static-triage` |
| PowerShell script or encoded command | `powershell-static-triage` |
| Office document with macros | `office-static-triage` |
| Another script (nested JS, VBS, etc.) | Re-apply this skill |

---

## Correlation thresholds

| Claim | Minimum corroboration |
|---|---|
| Downloader | HTTP/download object + URL or domain string |
| File dropper | File write object/method + path string |
| Persistence | Registry write or scheduled task + key/task name string |
| Process execution | Shell/exec method + command string |
| Encoded payload | Decode function + downstream exec/eval/IEX |
| Recon | System info collection + outbound channel (URL or file write) |

---

## Stop and recommend dynamic analysis when

- Script fetches payload from remote URL and no hardcoded IOC
  is recoverable.
- Decryption or decoding depends on runtime environment
  (machine name, registry values, environment variables).
- Decoded payload is multi-stage and later stages are not present.
- Obfuscation is too deep to fully unpack statically (heavily
  nested eval chains, runtime-only string assembly).
- Payload behavior requires specific host state to manifest.

---

## Tool reference

```bash
# Beautify JavaScript
js-beautify sample/<file> > artifacts/script/beautified.js

# Decode VBE/JSE encoded scripts
decode-vbe.py sample/<file> > artifacts/script/decoded_script

# Extract AutoIt script from PE
autoit-ripper sample/<file> artifacts/script/

# String extraction
strings -a -n 6 sample/<file>        > artifacts/strings/strings_ascii.txt
strings -a -el -n 6 sample/<file>    > artifacts/strings/strings_utf16le.txt

# Python-based decoding (inline, save output)
python3 -c "import base64; print(base64.b64decode('<b64>').decode())"
```

Never run decoded scripts through `wscript`, `cscript`, `mshta`,
`python`, `bash`, `cmd`, or any other interpreter.

---

## Output format

1. **Script profile** — language, host/executor, size, SHA256
2. **Execution chain** — entry point → decode/deobfuscate →
   action (download/drop/execute/persist)
3. **Decoded behavior** — what the script does, per layer
4. **Obfuscation techniques** — methods used, decode outcome
5. **Payload handoff** — if embedded/decoded payload requires
   another skill, note type and recommend handoff
6. **IOCs** — URLs, IPs, domains, file paths, registry keys,
   scheduled task names — extracted after full decode only
7. **ATT&CK mapping** — technique IDs where supported by evidence
8. **Confidence per claim** — high/medium/low with cited evidence
9. **Gaps** — layers not fully decoded and why
10. **Dynamic analysis recommendation** — yes/no with rationale
