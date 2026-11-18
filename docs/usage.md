# 使用说明

[English](usage.en.md)

## 本机排查

```bash
./java4shell
./java4shell local --no-processes
./java4shell local --jdk /opt/jdk-a --jdk /opt/jdk-b --no-processes --format json
./java4shell local --processes-only --pid 1234 --pid 4567 --out running.json
```

- 省略子命令时执行本机扫描。`--processes-only` 仅收集进程，可与 `--pid` 一起用于复查。
- 安装发现使用 `JAVA_HOME`、`PATH` 和平台常用安装目录。传入 `--jdk` 时，仅盘点指定安装目录，同时仍按命令行选项排查进程。对于不在常用目录的嵌入式 JRE，指定包含 `release` 文件的 Java Home。
- Linux 使用 `/proc` 发现 Java 启动器和映射了 `libjvm.so` 的进程，核对文件设备号和 inode，并通过进程根目录读取该 JVM 的 JDK 元数据。进程报告的 `java_home` 使用其文件系统路径。cgroup、容器标记和独立 PID 命名空间用于提供容器线索，可在容器内运行扫描器以检查其可见进程。
- Windows 使用本机 CIM 发现 `java.exe` 和 `javaw.exe`。macOS 使用 `ps`。两者会把可读的磁盘版本记为线索，运行中的库标为未验证。进程跨用户、进程退出或 IPC/命名空间限制可能影响发现。
- Linux 从 `/proc/cpuinfo` 核对可见逻辑 CPU。Windows amd64 查询操作系统状态与 CPUID。macOS Intel 查询 `sysctl`。Apple Silicon 原生和 Rosetta 环境均不提供 AVX-512。自动发现会跳过 macOS 的系统 Java 启动器。证据缺失时会保留 `unknown`。镜像尚未部署时，可通过离线清单提供未来执行节点的 CPU，而在挂载镜像上运行 `local --jdk` 使用的是扫描器当前的 CPU 上下文。
- Linux 进程报告中可见的 `-XX:-UseBASE64Intrinsics` 和 `-XX:UseAVX=2` 是启动证据。扫描器读取相关参数而不读取进程环境变量，JVM 有效值由单独的证据确认。

## 离线清单

```bash
./java4shell inventory assets.json --format json
./java4shell inventory assets.csv --out assessment.csv
```

JSON 使用对象数组，CSV 使用相同名称的表头。每条记录必须有唯一的 `id`。文件上限为 16 MiB。

| 字段 | 填写方式 |
|---|---|
| `version`, `vendor`, `product`, `vm`, `arch` | 使用完整运行时版本和构建号，例如 `25.0.5.1+4-LTS-20`。厂商产品可填 `Oracle Java SE`、`Oracle GraalVM for JDK`、`Oracle GraalVM Enterprise Edition` 或 `OpenJDK`。 |
| `cpu` | 可填 `present`、`absent`、`mixed`、`unknown`。 |
| `cpu_features`, `cpu_features_complete` | 或提供完整 CPU 特性。JSON 为字符串数组，CSV 用空格分隔。只有确认完整时才将后者设为 `true`。 |
| `patch`, `patch_ref` | 厂商公告或受信构建记录确认后，填 `fixed` 或 `unfixed` 并提供引用。扫描器直接采用该资产的补丁声明。 |
| `flags`, `flags_effective` | JSON 为字符串数组，CSV 用空格分隔。只有拿到同一目标 JVM 的有效值时才将后者设为 `true`。重复开关按各自最后一个值解释。 |
| `kind`, `java_home`, `container`, `notes` | 可选。JSON 的 `notes` 为数组，CSV 为单个备注字段。 |

## 报告

默认输出 TXT 到标准输出。指定 `--out report.json` 或 `--out report.csv` 时按扩展名选择格式，也可用 `--format` 覆盖。TXT 默认给出中文结论，仅列出受影响、待确认和无法判断的条目。`--details` 展开所有资产、数量及判断依据。JSON 包含 `summary.total` 和 `summary.by_status`，CSV 保持逐条资产结构。`--out` 创建新文件，已有文件会报错。退出码 `0` 表示报告生成成功，`2` 表示参数、输入或输出错误。自动化应检查报告中各条资产的 `status`、`build_assessment`、`cpu_assessment` 和采集警告。CSV 会对可能被表格软件当作公式的值加前导单引号，机器处理可使用 JSON。
