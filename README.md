# malpipe-ai
> THIS IS WORK IN PROGRESS

Modular malware triage pipeline for REMnux. Watches a case drop folder, runs static analysis tooling, orchestrates an LLM agent across file-type-specific analysis skills, and produces an evidence-backed report. Supports PE, ELF, Office documents, and scripts. Designed for analysts who want structured, reproducible triage without cloud dependency for sensitive samples.

---

## How it works

malpipe is built around three components: a triage script that runs static analysis tooling and collects artifacts, a set of agent skills that guide an LLM through structured analysis of those artifacts, and a report writer that produces a final PDF from the agent's findings.

---

## Triage script

`bin/triage_sample.sh` accepts a sample file or password-protected ZIP as input. It creates a timestamped job folder alongside the sample, extracts the file if needed, and runs the following tools automatically:

| Tool | Purpose |
|---|---|
| `file`, `exiftool` | Format identification and metadata |
| `sha256sum`, `sha1sum`, `md5sum` | Hashing |
| `strings` (ASCII + UTF-16LE), `floss` | String extraction |
| `capa -vv` | Capability detection |
| `yara-forge`, `yara-rules` | Family and packer identification |
| `rabin2`, `readelf`, `objdump` | Binary structure analysis |
| Ghidra headless + `DecompileAllFunctions.java` | Decompilation of top 50 functions by size |

All tool outputs are saved as `.txt` files under `artifacts/` and referenced by the agent skills by exact path.

---

## Job folder structure

Each analyzed sample produces a self-contained job folder:

```
job_<sample_name>_<timestamp>/
├── original_<sample_name>          # untouched copy of the input
├── report-template.md              # copied from /opt/malpipe/templates/
├── sample/
│   └── <extracted_sample>          # sample the agent and tools operate on
├── artifacts/
│   ├── metadata/
│   │   ├── file.txt
│   │   └── exiftool.txt
│   ├── hashes/
│   │   ├── sha256.txt
│   │   ├── sha1.txt
│   │   └── md5.txt
│   ├── strings/
│   │   ├── strings_ascii.txt
│   │   └── strings_utf16le.txt
│   ├── floss/
│   │   └── floss.txt
│   ├── capa/
│   │   └── capa.txt
│   ├── yara/
│   │   ├── yara_forge.txt
│   │   └── yara_rules.txt
│   ├── pe_elf/
│   │   ├── rabin2_info.txt
│   │   ├── rabin2_imports.txt
│   │   ├── rabin2_sections.txt
│   │   ├── readelf_header.txt
│   │   ├── readelf_sections.txt
│   │   └── objdump_headers.txt
│   └── decompiled/
│       └── ghidra_decomp.txt
└── logs/
    └── status.log                  # per-step exit codes and timestamps
```

---

## Agent skills

Skills live under `~/.config/opencode/skills/` and are loaded automatically by opencode based on file type. The orchestrator agent (`malware-static-triage`) reads `artifacts/metadata/file.txt`, routes to the correct skill, and follows its read order and correlation logic to produce `analysis.md`.

| Skill | Triggers on |
|---|---|
| `pe-static-triage` | PE32, PE32+, EXE, DLL, SYS |
| `elf-static-triage` | ELF executables, shared objects, kernel modules |
| `office-static-triage` | OLE, OOXML, RTF, macro-enabled documents |
| `powershell-static-triage` | PS1, PSM1, encoded PowerShell commands |
| `script-static-triage` | JS, VBS, HTA, Python, Bash, BAT, CMD, AutoIt |
| `malware-report-writer` | Always — converts `analysis.md` into `report.md` |

---

## Output

The agent writes two files into the job folder:

| File | Description |
|---|---|
| `analysis.md` | Technical findings with per-claim confidence levels and artifact citations |
| `report.md` | Structured report for SOC, CTI, and malware analyst audiences |

The pipeline script then combines both into a single PDF using pandoc, with `analysis.md` appended as a technical appendix.

---

## Requirements

- [REMnux](https://remnux.org) — provides `capa`, `floss`, `rabin2`, `yara`, `strings`, `readelf`, `objdump`, `exiftool`
- [Ghidra](https://ghidra-sre.org) — headless decompilation via `analyzeHeadless` at `/opt/ghidra/support/analyzeHeadless`
- [opencode](https://opencode.ai) — LLM agent orchestration
- [pandoc](https://pandoc.org) + `texlive-xetex` — PDF report generation
- An LLM provider — Anthropic Claude (cloud) or a local model via [Ollama](https://ollama.com) for sensitive samples

---

## Local LLM support

By using opencode we can support local analysis via Ollama for sensitive samples that cannot leave the network. 
---

## Status

Work in progress. Contributions welcome.
