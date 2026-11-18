# Java4Shell-LocalScanner

[简体中文](README.md)

Read-only enterprise incident response for **CVE-2026-114938**. Assess JDK builds, CPU eligibility and JVM mitigation evidence for local installations, running processes or offline JSON/CSV inventories. Export TXT, JSON or CSV reports.

## Quick start

The download includes six prebuilt programs in `dist/`. After extracting it, open a terminal in the extracted directory and run the program for your platform to scan the local machine.

```powershell
.\dist\java4shell-windows-amd64.exe
```

```bash
./dist/java4shell-linux-amd64
./dist/java4shell-darwin-arm64
```

The default terminal report gives a short Chinese verdict and lists items needing attention. Use `--details` for the full TXT report.

The scanner application is in `java4shell.go`. Building it requires Go 1.23 or later and the pinned `golang.org/x/sys` CPU detection dependency.

```bash
go build -o java4shell java4shell.go
./java4shell
./java4shell local --processes-only --pid 1234 --out running.json
./java4shell inventory assets.json --out report.csv
```

```powershell
go build -o java4shell.exe java4shell.go
.\java4shell.exe local --format json
```

Run `scripts/build.sh` to build amd64 and arm64 binaries for Linux, Windows and macOS in `dist/`. Linux can verify the mapped HotSpot library and report container hints. Windows and macOS inventory installations and discover Java processes, with their loaded library identity reported as unverified.

## Output examples

The default report is a short Chinese verdict. When there are findings, items are listed under `受影响` (affected), `待确认` (potential) and `无法判断` (unknown):

```
Java4Shell · CVE-2026-114938
已检查 5 项 · 受影响 1 · 待确认 1 · 已缓解 1 · 不受影响 1 · 无法判断 1
  受影响  debian-cpu-eligible · Java 21.0.13+9-1~deb13u2
  待确认  vendor-confirmation-pending · Java 21.0.13.1+2
  无法判断  metadata-missing
```

When nothing is affected:

```
Java4Shell · CVE-2026-114938
已检查 1 项，均不受此漏洞影响。
```

| Status | Meaning |
|---|---|
| `affected` | Known affected build on an eligible CPU, with no matching mitigation flag in the collected evidence. |
| `potential` | Build or version is a candidate, or patch, CPU or effective-flag evidence is incomplete. |
| `mitigated` | Supplied effective JVM flags disable the relevant intrinsic or restrict AVX-512. |
| `not_affected` | Build is fixed, or available build, architecture or CPU evidence places it outside scope. |
| `unknown` | Build identity or version evidence is insufficient to classify the asset. |

The labels describe the evidence and execution context. Application exposure and exploitability require separate assessment.

- [Usage](docs/usage.en.md)
- [Advisories, version rules and patch analysis](docs/research.md)
- [Isolated testing and remediation verification](docs/testing.en.md)
