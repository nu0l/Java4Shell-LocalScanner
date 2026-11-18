# Status

Updated 2026-11-18. Project directory is `/workspace/Java4Shell-LocalScanner`. The repository is local and has no remote.

## Research complete for the built-in rules

- Oracle CNA record and November CSPU reviewed. OpenJDK change 8393212 and side-by-side source tags confirm fixes in 17.0.21.1, 21.0.13.1, 25.0.5.1 and 27.0.1.1. Oracle Java SE release notes identify its build numbers and link to the CSPU. The Debian tracker contains the unfixed package versions used by the rules.
- CPU prerequisites are x86-64 plus AVX-512F, AVX-512BW, AVX-512 VBMI and BMI2. The two documented HotSpot mitigation options are recognized. Details and source links are in `docs/research.md`.

## Implementation and documentation complete

- Go CLI with local inventory and offline JSON/CSV intake, five assessment states, and TXT/JSON/CSV export.
- Linux correlates loaded JVM libraries with installation metadata and reports container hints. Windows/macOS provide installation and process discovery with conservative runtime verification.
- Chinese and English README, usage and test documentation. Scripts and fixture data are under `scripts/` and `testdata/`.

## Verification

- Go 1.25.5 on Linux amd64. `go test -race ./...`, `go vet ./...`, Windows amd64 and macOS arm64 vet, shell syntax checks, six cross-builds and bilingual documentation links verified.
- Ran `scripts/smoke-container.sh` using Debian OpenJDK `21.0.13+9-1~deb13u2` and Oracle JDK `25.0.5.1+4-LTS-20` with its publisher checksum verified. Docker used the local Debian trixie-slim amd64 image, with network disabled and a read-only root. The test detected a container Java process and matched the loaded JVM inode. On a CPU exposing all required features, the old process was affected, the restarted process's mitigation flag was observed, its effective flag produced a mitigated result, and the fixed process was not affected. All three passed a benign Base64 round trip.
- Verified CSV inventory to JSON report and local installation to CSV report. Build artifacts are in `dist/`.

## Remaining evidence gaps

- The OpenJDK advisory page returned HTTP 403 in this environment. Source tags, the CNA record and the Oracle/Debian advisories remain available.
- Fixed build IDs for Oracle Enterprise Performance Pack and the listed GraalVM product lines require product-specific vendor confirmation. Downstream builds with unpublished or unverified backports stay in the potential-risk category unless the inventory supplies patch evidence.
- Windows and macOS native process, CPU and installation behavior awaits native validation. Linux is the platform with a completed live test.

## CLI and download package

Default invocation now runs the local assessment. Added process-only assessment, positional inventory paths, format inference from the output extension, and status counts in TXT and JSON. Existing explicit commands and CSV columns are supported. Go race tests and vet passed. All six binaries were rebuilt. The isolated Linux test passed with the new process-only command and a one-asset summary for each PID. The downloadable ZIP includes source, bilingual docs, fixtures and all six binaries.


## Compact output and single-file source

Default TXT is now a short Chinese verdict. Affected, potential and unknown findings are listed. Both the earlier detailed view and machine-readable exports remain available. macOS auto-discovery skips /usr/bin/java. Native Apple Silicon and Rosetta execution lack AVX-512, which resolves the x86_64 installations reported on the ARM Mac. The regression fixture uses the six reported version and architecture pairs.

Application code is consolidated into java4shell.go. Tests are in java4shell_test.go. The pinned golang.org/x/sys/cpu dependency provides CPU feature detection on Windows. That platform keeps insufficient single-processor evidence unknown. Go race tests, vet, six cross-builds and the isolated Linux JVM regression passed. The archive was refreshed with the consolidated source, module files, docs and six binaries. macOS behavior was checked with fixtures, and the new macOS binaries were cross-built.
