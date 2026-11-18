# Isolated tests and remediation verification

[简体中文](testing.md)

## Automated regression

```bash
go test -race ./...
go vet ./...
scripts/build.sh
```

Tests cover risk states, vendor build boundaries, incomplete and mixed CPU evidence, repeated flags, deleted and replaced JVM mappings, inventory validation all three report formats, and a fixture representing the reported Apple Silicon installations.

## Linux amd64 container test

Use Docker with a local `debian:trixie-slim` image, a known affected Java runtime and a confirmed fixed JDK with `javac`. The script builds the scanner and runs a normal Base64 round-trip test alongside process checks in a network-disabled container with a read-only root and dropped capabilities.

```bash
docker pull debian:trixie-slim
scripts/smoke-container.sh /path/to/unfixed-jre /path/to/fixed-jdk
```

The executed lab used Debian OpenJDK `21.0.13+9-1~deb13u2` and Oracle JDK `25.0.5.1+4-LTS-20`, verified against Oracle's SHA-256 checksum. All four required CPU features were visible. The old process was `affected`. Its restarted instance with the mitigation flag was `potential` from launch arguments and `mitigated` after its effective value from `PrintFlagsFinal` was supplied in inventory. The fixed process was `not_affected` with `build=fixed`. Every instance passed the valid-data round trip. Windows and macOS were cross-built. Native execution is pending.

## Verify remediation

1. Apply the vendor update and redeploy or restart. Re-scan the new PID and check its `java_home`, build and `build_assessment`. When the loaded runtime cannot be verified, check the service's actual launcher and restart state.
2. For a temporary mitigation, collect the effective flags for the authorized JVM. During a controlled launch, `-XX:+PrintFlagsFinal` can confirm `UseBASE64Intrinsics = false` or, on x86-64, `UseAVX = 2`. Import the effective flag for that instance with `flags_effective=true`.
3. For vendor backports, match the full package version to the vendor advisory and verify that the running JVM uses it. Enter `patch=fixed` with the supporting `patch_ref`.

Verification uses patch provenance, runtime identity and effective configuration. The valid-data smoke test checks basic functionality after the change.
