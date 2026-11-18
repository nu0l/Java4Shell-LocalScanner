# CVE-2026-114938 研究记录 / Research notes

核对日期为 2026-11-18。Oracle CNA 将它归为 Java SE 与 GraalVM 的 Compiler 组件问题，CVSS 3.1 为 8.1。Calif 披露报告使用 CVSS 4.0，评分为 9.2。Debian 跟踪器列出了已知受影响的包版本，目前所见的条目尚无修复版本。OpenJDK 公告站点在本环境返回 HTTP 403，已通过 Oracle、CVE 记录、发行版跟踪器和 OpenJDK 源码标签交叉核对。 [Oracle CSPU](https://www.oracle.com/security-alerts/cspunov2026.html#JAVA) · [CVE CNA record](https://www.cve.org/CVERecord?id=CVE-2026-114938) · [Calif](https://calif.io/java4shell/) · [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2026-114938) · [OpenJDK advisory](https://openjdk.org/groups/vulnerability/advisories/2026-11-17)

## 根因与补丁 / Root cause and patch

HotSpot C2 的 x86-64 Base64 intrinsic 对带填充的短尾块计算写入范围时缺少有效的长度门槛，可能让向量写入超出逻辑输出边界。Java 层随后报告解码错误。OpenJDK 变更 8393212 增加尾块长度检查，将不足完整块的尾部交回 Java 路径处理。对比四条更新分支相邻的 GA 标签，`.0.3` 标签缺少该检查，下表修复标签均包含它。

The HotSpot C2 Base64 intrinsic on x86-64 lacked a length guard in the vector path for short padded tails. The native write could exceed the logical output bounds before the Java decoder reported the error. Change 8393212 adds the length guard and leaves the short tail to the Java decoder. Source comparison confirmed the guard in the fixed GA tags and its absence in the preceding `.0.3` tags. [OpenJDK change](https://github.com/openjdk/jdk/commit/5177a70b385c16f26ede191fdac7aaba0bed0f8b) · [27u backport](https://github.com/openjdk/jdk27u/commit/564fc7de7effb8a4558604a6339f1b62f3017230)

| 分支 / Branch | Oracle 公告所列受影响版本 / Listed affected | 修复的 Oracle Java SE 构建 / Fixed build | OpenJDK 修复 GA / Fixed GA source |
|---|---|---|---|
| 17 | 17.0.21.0.3 | [17.0.21.1+4](https://www.oracle.com/java/technologies/javase/17-0-21-1-relnotes.html) | [17.0.21.1+2](https://github.com/openjdk/jdk17u/tree/jdk-17.0.21.1-ga) |
| 21 | 21.0.13.0.3 | [21.0.13.1+4](https://www.oracle.com/java/technologies/javase/21-0-13-1-relnotes.html) | [21.0.13.1+2](https://github.com/openjdk/jdk21u/tree/jdk-21.0.13.1-ga) |
| 25 | 25.0.5.0.3 | [25.0.5.1+4](https://www.oracle.com/java/technologies/javase/25-0-5-1-relnotes.html) | [25.0.5.1+2](https://github.com/openjdk/jdk25u/tree/jdk-25.0.5.1-ga) |
| 27 | 27.0.1.0.3 | [27.0.1.1+4](https://www.oracle.com/java/technologies/javase/27-0-1-1-relnotes.html) | [27.0.1.1+4](https://github.com/openjdk/jdk27u/tree/jdk-27.0.1.1-ga) |

Calif 将普通 OpenJDK 影响范围追溯至 17.0.6。Oracle 另外列出 Java SE 8 Enterprise Performance Pack 的 `8u511b33-perf`、Oracle GraalVM for JDK 的 `17.0.21.0.3` 与 `21.0.13.0.3`，以及 Oracle GraalVM Enterprise Edition 的 `21.3.20.0.3`。这些额外产品线的修复构建需要按各自厂商公告确认。Oracle CSPU 指向 My Oracle Support 的补丁可用性文档。Oracle Java SE 和 GA 源码修复号仅用于其各自的产品判定，其他厂商和回移补丁使用对应公告与构建证据。 [Calif affected products](https://calif.io/java4shell/#affected-products) · [Oracle matrix](https://www.oracle.com/security-alerts/cspunov2026.html#JAVA)

Calif traces affected standard OpenJDK builds back to 17.0.6. Oracle additionally lists Java SE 8 Enterprise Performance Pack `8u511b33-perf`, Oracle GraalVM for JDK `17.0.21.0.3` and `21.0.13.0.3`, and Oracle GraalVM Enterprise Edition `21.3.20.0.3`. The scanner uses vendor and product identity for its exact rules. Fixed builds for the additional product lines and downstream backports require product-specific evidence. [Oracle matrix](https://www.oracle.com/security-alerts/cspunov2026.html#JAVA)

## CPU 与缓解 / CPU and mitigation

需要 x86-64，以及运行环境可见的 `avx512f`、`avx512bw`、`avx512vbmi`、`bmi2`。虚拟机和容器应以实际执行环境证据为准。临时缓解可采用 `-XX:-UseBASE64Intrinsics`，或仅在 x86-64 HotSpot 上采用 `-XX:UseAVX=2`。升级或调整服务启动配置后，重新启动并检查新 PID。

The examined runtime needs x86-64 and visible AVX-512F, AVX-512BW, AVX-512 VBMI and BMI2 features. Evaluate the runtime context, including guest CPU exposure. Temporary mitigations are `-XX:-UseBASE64Intrinsics` or, on x86-64 HotSpot, `-XX:UseAVX=2`. Restart the workload after upgrading or changing its startup flags and check the new PID. [Calif recommendations](https://calif.io/java4shell/#recommendations)

项目参考了 NGINX-Rift 的 Go 单文件构建体验、子命令和交叉编译方式。 The CLI and cross-build workflow follow the reference project's Go tooling style. [NGINX-Rift](https://github.com/nu0l/NGINX-Rift)

Apple 确认 Rosetta 支持 AVX 和 AVX2，但不支持 AVX-512，因此在 Apple Silicon 上检查 x86-64 JDK 时也适用 CPU 不满足结论。 Rosetta does not expose AVX-512. [Apple Rosetta documentation](https://developer.apple.com/documentation/apple-silicon/about-the-rosetta-translation-environment)
