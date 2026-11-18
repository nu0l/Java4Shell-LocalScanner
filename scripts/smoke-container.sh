#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ $# != 2 ]]; then
  printf 'Usage: %s JRE_HOME FIXED_JDK_WITH_JAVAC\n' "$0" >&2
  exit 2
fi
legacy=$(cd "$1" && pwd -P)
jdk=$(cd "$2" && pwd -P)
go_command=${GO:-go}
binary=dist/java4shell-linux-amd64
image=${SMOKE_IMAGE:-debian:trixie-slim}
mkdir -p dist
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$go_command" build -trimpath -o "$binary" .
docker run --rm --pull=never --network none --read-only --cap-drop ALL \
  --user "$(id -u):$(id -g)" \
  --security-opt no-new-privileges --pids-limit 128 --memory 1g \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m \
  --mount "type=bind,source=$PWD/$binary,target=/scanner,readonly" \
  --mount "type=bind,source=$PWD/testdata/Smoke.java,target=/Smoke.java,readonly" \
  --mount "type=bind,source=$legacy,target=/legacy,readonly" \
  --mount "type=bind,source=$jdk,target=/compiler,readonly" \
  "$image" /bin/sh -eu -c '
    /compiler/bin/javac --release 17 -d /tmp /Smoke.java
    pid=
    trap "[ -z \"\$pid\" ] || kill \"\$pid\" 2>/dev/null || true" EXIT
    run_jvm() {
      java=$1
      shift
      "$java" -Xmx128m -XX:+PrintFlagsFinal "$@" -cp /tmp Smoke >/tmp/jvm.log 2>&1 &
      pid=$!
      for i in $(seq 1 100); do
        if grep -qx SMOKE_READY /tmp/jvm.log; then break; fi
        kill -0 "$pid" 2>/dev/null || { tail -20 /tmp/jvm.log; return 1; }
        sleep .1
      done
      grep -qx SMOKE_READY /tmp/jvm.log
      /scanner --details --processes-only --pid "$pid" >/tmp/report.txt
      grep -q "^Summary total=1 " /tmp/report.txt
      cat /tmp/report.txt
      grep -qF "Mapped HotSpot library matches the device and inode" /tmp/report.txt
      grep -Eq "\(.*process.*\).*container=\"docker \(root marker\)\"|\(.*process.*\).*container=\"docker \(cgroup hint\)\"" /tmp/report.txt
    }
    stop_jvm() {
      kill "$pid"
      wait "$pid" || :
      pid=
    }
    run_jvm /legacy/bin/java
    stop_jvm

    run_jvm /legacy/bin/java -XX:-UseBASE64Intrinsics
    grep -Eq "UseBASE64Intrinsics[[:space:]]*=[[:space:]]*false" /tmp/jvm.log
    grep -qF "flags=\"-XX:-UseBASE64Intrinsics\" effective=false" /tmp/report.txt
    legacy_version=$(sed -n "s/^JAVA_RUNTIME_VERSION=\"\(.*\)\"$/\1/p" /legacy/release)
    legacy_vendor=$(sed -n "s/^IMPLEMENTOR=\"\(.*\)\"$/\1/p" /legacy/release)
    printf "id,version,vendor,arch,flags,flags_effective\n%s,%s,%s,amd64,-XX:-UseBASE64Intrinsics,true\n" \
      "lab-pid-$pid" "$legacy_version" "$legacy_vendor" >/tmp/effective.csv
    /scanner inventory --input /tmp/effective.csv --details >/tmp/verified.txt
    cat /tmp/verified.txt
    grep -q "^mitigated " /tmp/verified.txt
    stop_jvm

    run_jvm /compiler/bin/java
    grep -Eq "^not_affected \"pid:[0-9]+\" .*build=fixed" /tmp/report.txt
    stop_jvm
  '
