# Usage

[简体中文](usage.md)

## Local assessment

```bash
./java4shell
./java4shell local --no-processes
./java4shell local --jdk /opt/jdk-a --jdk /opt/jdk-b --no-processes --format json
./java4shell local --processes-only --pid 1234 --pid 4567 --out running.json
```

- Running without a command starts a local scan. Use `--processes-only` with `--pid` to focus on selected processes.
- Installation discovery uses `JAVA_HOME`, `PATH` and common platform directories. Repeat `--jdk` to replace the installation search with explicit homes. Use `--no-processes` to skip processes. Supply the directory containing `release` for a JDK or runtime in a custom location.
- Linux uses `/proc` to find Java launchers and embedded HotSpot JVMs. It checks the mapped `libjvm.so` device and inode and resolves associated metadata through the process root. The process's `java_home` uses its filesystem view. Cgroups, container markers and separate PID namespaces provide container hints. Run inside the container when the host cannot inspect its processes.
- Windows discovers `java.exe` and `javaw.exe` with local CIM. macOS uses `ps`. A readable installation version is included as a hint, and the loaded library remains unverified. Process visibility depends on permissions, process lifetime and namespaces.
- Linux checks all visible logical processors in `/proc/cpuinfo`. Windows amd64 uses OS state and a CPUID sample. Intel macOS queries `sysctl`. Apple Silicon has no AVX-512 in native or Rosetta execution. The macOS system Java launcher is skipped during installation discovery. Unavailable CPU evidence is recorded as `unknown`. An explicit `--jdk` path defaults to an unknown execution context. Add `--host-jdk` when that JDK runs on this host. An offline inventory can declare the deployment CPU.
- Linux checks JVM arguments and the three option variables `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS` and `_JAVA_OPTIONS`. Reports retain only relevant options and source names. These startup observations require separate verification before they count as effective.

## Inventory

```bash
./java4shell inventory assets.json --format json
./java4shell inventory assets.csv --out assessment.csv
```

JSON accepts a versioned envelope (`{"schema_version":1,"assets":[...]}`) or the legacy object array. CSV uses the field names as its header and accepts an optional `schema_version` column containing `1`. Each entry needs a unique `id`. Input files can be up to 16 MiB.

| Fields | Values |
|---|---|
| `version`, `vendor`, `product`, `vm`, `arch` | Supply a full runtime version and build. Recognized product labels include `Oracle Java SE`, `Oracle GraalVM for JDK`, `Oracle GraalVM Enterprise Edition` and `OpenJDK`. |
| `cpu`, `cpu_context` | CPU may be `present`, `absent`, `mixed` or `unknown`. Inventory evidence is `declared` or `unknown`. An x86-64 CPU reported as absent in inventory still requires verification. |
| `cpu_features`, `cpu_features_complete` | Alternatively list features as a JSON string array or space-separated CSV cell. Set the boolean to `true` only for a complete feature list. |
| `patch`, `patch_ref` | Supply `fixed` or `unfixed` with a vendor advisory or trusted build record. An independent match of vendor, product, build and advisory against built-in rules produces `patch_attested=true`. |
| `flags`, `flags_effective` | JSON string array or space-separated CSV cell. Set the boolean to `true` only for effective values from the target JVM instance. The last value of each repeated option applies. |
| `kind`, `java_home`, `container`, `notes` | Optional metadata. Use a JSON array for notes or one CSV cell. |

## Output

TXT to stdout is the default. An `--out` path ending in `.json` or `.csv` selects that format unless overridden with `--format`. TXT gives a concise Chinese verdict and lists affected, potential and unknown items. Use `--details` for every asset, counts and supporting evidence. JSON includes `summary.total` and `summary.by_status`. CSV retains one row per asset, alongside any warning rows. Use `--out` to create a new file. The exit code is `0` for a generated report and `2` for argument, input or output errors. An opt-in match via `--fail-on affected,potential` or `--strict` (matches `unknown`) returns `3` after the report is written. Use `--version` for build and rules information. For automation, inspect each finding's `status`, `build_assessment`, `cpu_assessment` and the report warnings. CSV prefixes spreadsheet-formula-like values with an apostrophe. Use JSON for machine processing.
