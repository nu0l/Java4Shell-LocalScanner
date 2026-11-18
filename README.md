# Java4Shell-LocalScanner

[English](README.en.md)

面向企业应急响应的 **CVE-2026-114938** 只读检测工具。分别评估 JDK 构建、CPU 条件和 JVM 缓解证据，可在本机排查安装与运行进程，或离线处理 JSON、CSV 资产清单。报告支持 TXT、JSON、CSV。

## 快速开始

下载包中的 `dist/` 已提供六个预编译程序。解压后打开终端，在解压目录运行对应平台的程序，直接扫描本机。

```powershell
.\dist\java4shell-windows-amd64.exe
```

```bash
./dist/java4shell-linux-amd64
./dist/java4shell-darwin-arm64
```

默认显示中文结论和待处理项。使用 `--details` 查看完整 TXT 明细。

运行源码集中在 `java4shell.go`。从源码构建需要 Go 1.23 或更新版本及固定版本的 `golang.org/x/sys` CPU 检测依赖。

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

运行 `scripts/build.sh` 可交叉构建 Linux、Windows、macOS 的 amd64 和 arm64 版本，产物位于 `dist/`。Linux 支持核对进程实际映射的 HotSpot 库及容器线索。Windows 和 macOS 支持安装清点及 Java 进程发现，运行态库身份标为未核实。

## 输出示例

默认输出为简短结论。发现风险时按 `受影响`、`待确认`、`无法判断` 列出待处理项：

```
Java4Shell · CVE-2026-114938
已检查 5 项 · 受影响 1 · 待确认 1 · 已缓解 1 · 不受影响 1 · 无法判断 1
  受影响  debian-cpu-eligible · Java 21.0.13+9-1~deb13u2
  待确认  vendor-confirmation-pending · Java 21.0.13.1+2
  无法判断  metadata-missing
```

未发现问题时：

```
Java4Shell · CVE-2026-114938
已检查 1 项，均不受此漏洞影响。
```

## 风险状态

| 报告值 | 含义 |
|---|---|
| `affected` | 已知受影响构建与 CPU 条件匹配，未收集到匹配的缓解参数。 |
| `potential` | 版本或构建存在风险线索，厂商补丁、CPU 或有效 JVM 参数仍需确认。 |
| `mitigated` | 有效 JVM 参数证据显示已禁用相关 intrinsic 或限制了 AVX-512。 |
| `not_affected` | 已确认修复，或本次证据显示构建、架构或 CPU 条件超出影响范围。 |
| `unknown` | 缺少构建身份或版本证据，无法分类。 |

这些状态描述已采集证据和运行环境。应用的网络可达性与可利用性需单独评估。

- [使用说明](docs/usage.md)
- [检测规则、公告及补丁分析](docs/research.md)
- [隔离测试与验证步骤](docs/testing.md)
