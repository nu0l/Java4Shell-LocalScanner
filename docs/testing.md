# 隔离测试与修复验证

[English](testing.en.md)

## 自动化回归

```bash
go test -race ./...
go vet ./...
scripts/build.sh
```

测试覆盖风险状态、厂商修复边界、CPU 证据缺失及混合、启动参数覆盖、已删除或替换的 JVM 映射、JSON/CSV 输入校验、三种报告格式，以及用户报告的 Apple Silicon 安装清单。

## Linux amd64 容器实测

准备 Docker、本地 `debian:trixie-slim` 镜像、一个已知受影响的 JRE 和一个已验证修复且带 `javac` 的 JDK。脚本在本机编译扫描器，在禁网、只读根文件系统、无额外能力的容器中编译并运行测试程序。它使用正常 Base64 数据做往返检查，然后核对运行中的 Java PID、已加载的 HotSpot 库及缓解参数。准备镜像与后续执行是独立命令。

```bash
docker pull debian:trixie-slim
scripts/smoke-container.sh /path/to/unfixed-jre /path/to/fixed-jdk
```

本次实测使用 Debian OpenJDK `21.0.13+9-1~deb13u2` 和经 Oracle SHA-256 校验的 JDK `25.0.5.1+4-LTS-20`。宿主机向容器暴露四项必需 CPU 特性。旧 JVM 为 `affected`，附加缓解参数后进程为 `potential`，经同一实例的 `PrintFlagsFinal` 确认后离线研判为 `mitigated`。修复版正在运行的 PID 为 `not_affected` 且 `build=fixed`，三个进程的正常 Base64 往返均成功。Windows 和 macOS 完成交叉构建，原生运行仍待验证。

## 企业修复验证

1. 更新厂商补丁和运行环境，重新部署或重启应用。根据新 PID 采集，核对 `java_home`、构建号和 `build_assessment`。如已安装修复但运行时映射标为无法核实，继续核对服务的实际启动路径及重启状态。
2. 临时缓解时，从授权的目标启动记录取得 HotSpot 的有效选项。可在受控启动中使用 `-XX:+PrintFlagsFinal`，核对 `UseBASE64Intrinsics = false` 或 x86-64 上的 `UseAVX = 2`。同一 PID 的有效值记录为离线 `flags`，设 `flags_effective=true`。
3. 发行版回移补丁使用所装包的完整版本和公告。核对运行中 JVM 使用该构建后，再记录 `patch=fixed` 及 `patch_ref`。

验证结论来自补丁出处、运行时身份及有效配置证据，正常数据测试覆盖升级后的基本功能。
