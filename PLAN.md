# Implementation plan

1. Verify CVE, vendor and CPU scope using primary sources. Record uncertainties and patch semantics in docs/research.md.
2. Implement a read-only local collector and evidence-based evaluator. Support offline JSON/CSV and TXT/JSON/CSV output.
3. Test status boundaries, collector behavior, and report production. Cross-build Linux, Windows and macOS for amd64 and arm64.
4. Run isolated regression and running-process verification. Document capabilities and limits in Chinese and English.
5. Simplify CLI entry points and report summaries. Package the verified source, documentation and six platform binaries for desktop download.
6. Make default TXT output verdict-first, fix macOS launcher and Apple Silicon CPU handling, and consolidate the application into one Go source file.
