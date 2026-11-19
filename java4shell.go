package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/sys/cpu"
)

// Command line and reports.

const cve = "CVE-2026-114938"
const rulesAsOf = "2026-11-18"
const schemaVersion = 1

var version = "dev"
var errPolicyMatch = errors.New("assessment matched the exit policy")

type reportSummary struct {
	Total    int            `json:"total"`
	ByStatus map[string]int `json:"by_status"`
}

var statusOrder = []string{affected, potential, mitigated, unaffected, unknown}

type report struct {
	SchemaVersion int           `json:"schema_version"`
	CVE           string        `json:"cve"`
	RulesAsOf     string        `json:"rules_as_of"`
	Mode          string        `json:"mode"`
	Summary       reportSummary `json:"summary"`
	Warnings      []string      `json:"warnings,omitempty"`
	Findings      []finding     `json:"findings"`
}

type paths []string

func (p *paths) String() string { return strings.Join(*p, ", ") }
func (p *paths) Set(s string) error {
	if strings.TrimSpace(s) == "" {
		return errors.New("empty JDK path")
	}
	*p = append(*p, s)
	return nil
}

type pidList []int

func (p *pidList) String() string { return fmt.Sprint([]int(*p)) }
func (p *pidList) Set(s string) error {
	pid, err := strconv.Atoi(s)
	if err != nil || pid <= 0 {
		return errors.New("expected a positive PID")
	}
	*p = append(*p, pid)
	return nil
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "Java4Shell-LocalScanner ("+cve+")")
	fmt.Fprintln(w, "  java4shell                        Run a local assessment")
	fmt.Fprintln(w, "  java4shell --details              Show full assessment evidence")
	fmt.Fprintln(w, "  java4shell local --processes-only --pid PID")
	fmt.Fprintln(w, "  java4shell inventory FILE.json --out report.csv")
	fmt.Fprintln(w, "  java4shell --version")
	fmt.Fprintln(w, "Use java4shell <command> --help for options. --fail-on or --strict can return exit code 3.")
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 1 && args[0] == "--version" {
		revision, commitTime := "unknown", "unknown"
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, setting := range info.Settings {
				switch setting.Key {
				case "vcs.revision":
					revision = setting.Value
				case "vcs.time":
					commitTime = setting.Value
				}
			}
		}
		_, err := fmt.Fprintf(stdout, "Java4Shell-LocalScanner %s (commit %s, commit time %s, rules %s)\n", version, revision, commitTime, rulesAsOf)
		return err
	}
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		usage(stdout)
		return nil
	}
	mode := "local"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		mode, args = args[0], args[1:]
		if mode != "local" && mode != "inventory" {
			return fmt.Errorf("unknown command %q; use --help", mode)
		}
	}
	fs := flag.NewFlagSet(mode, flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "", "report format: txt, json, or csv (defaults to the --out extension or txt)")
	out := fs.String("out", "", "write to a new file instead of stdout")
	details := fs.Bool("details", false, "show full evidence in TXT reports")
	var input, positionalInput string
	var roots paths
	var pids pidList
	var noProcesses, processesOnly, hostJDK bool
	failOn := fs.String("fail-on", "", "comma-separated finding statuses that return exit code 3")
	strict := fs.Bool("strict", false, "return exit code 3 when a finding is unknown")
	if mode == "inventory" {
		fs.StringVar(&input, "input", "", "input JSON array or CSV with headers; optionally supply as a positional file")
		if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
			positionalInput, args = args[0], args[1:]
		}
	} else {
		fs.Var(&roots, "jdk", "JDK home, repeatable; overrides installation discovery")
		fs.Var(&pids, "pid", "process ID, repeatable; otherwise inspect visible processes")
		fs.BoolVar(&noProcesses, "no-processes", false, "skip process discovery")
		fs.BoolVar(&processesOnly, "processes-only", false, "skip installation discovery")
		fs.BoolVar(&hostJDK, "host-jdk", false, "explicit JDK paths run on the scanner host")
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	extra := fs.NArg()
	if mode == "inventory" {
		if positionalInput != "" {
			if input != "" {
				return errors.New("supply the inventory path once")
			}
			input = positionalInput
		} else if input == "" && fs.NArg() == 1 {
			input = fs.Arg(0)
			extra = 0
		}
	}
	if extra != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *format == "" {
		switch strings.ToLower(filepath.Ext(*out)) {
		case ".json":
			*format = "json"
		case ".csv":
			*format = "csv"
		default:
			*format = "txt"
		}
	}
	if *format != "txt" && *format != "json" && *format != "csv" {
		return errors.New("--format must be txt, json, or csv")
	}
	if noProcesses && len(pids) > 0 {
		return errors.New("--no-processes and --pid are mutually exclusive")
	}
	if processesOnly && (noProcesses || len(roots) > 0) {
		return errors.New("--processes-only cannot be combined with --no-processes or --jdk")
	}
	if hostJDK && len(roots) == 0 {
		return errors.New("--host-jdk requires at least one --jdk path")
	}
	exitStatuses := make(map[string]bool)
	if *failOn != "" {
		for _, status := range strings.Split(*failOn, ",") {
			status = strings.TrimSpace(status)
			if !slices.Contains(statusOrder, status) {
				return fmt.Errorf("invalid --fail-on status %q", status)
			}
			exitStatuses[status] = true
		}
	}
	exitStatuses[unknown] = exitStatuses[unknown] || *strict
	result := report{SchemaVersion: schemaVersion, CVE: cve, RulesAsOf: rulesAsOf, Mode: mode, Findings: []finding{}}
	var assets []asset
	if mode == "inventory" {
		if input == "" {
			return errors.New("an inventory path is required")
		}
		var err error
		assets, err = readInventory(input)
		if err != nil {
			return err
		}
	} else {
		cpu := localCPU()
		if !processesOnly {
			for _, root := range jdkRoots(roots) {
				a := releaseAsset(root, root, "installation", cpu)
				a.CPUContext = "host"
				if len(roots) != 0 && !hostJDK {
					a.CPUContext = unknown
				}
				assets = append(assets, a)
			}
		}
		if !noProcesses {
			procs, warnings := localProcesses(pids, cpu)
			assets = append(assets, procs...)
			result.Warnings = warnings
		}
	}
	if len(assets) == 0 {
		result.Warnings = append(result.Warnings, "No Java assets were found in the examined scope.")
	}
	for _, a := range assets {
		result.Findings = append(result.Findings, classify(a))
	}
	if *out == "" {
		if err := writeReport(stdout, *format, result, *details); err != nil {
			return err
		}
	} else {
		f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		if err := errors.Join(writeReport(f, *format, result, *details), f.Close()); err != nil {
			return err
		}
		fmt.Fprintf(stderr, "Report saved to %q\n", *out)
	}
	for _, f := range result.Findings {
		if exitStatuses[f.Status] {
			return errPolicyMatch
		}
	}
	return nil
}

func readInventory(path string) ([]asset, error) {
	data, err := readBounded(path, 16<<20)
	if err != nil {
		return nil, err
	}
	content := strings.TrimPrefix(string(data), "\uFEFF")
	var assets []asset
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		d := json.NewDecoder(strings.NewReader(content))
		d.DisallowUnknownFields()
		if strings.HasPrefix(strings.TrimSpace(content), "{") {
			var input struct {
				SchemaVersion int     `json:"schema_version"`
				Assets        []asset `json:"assets"`
			}
			if err := d.Decode(&input); err != nil {
				return nil, fmt.Errorf("inventory JSON: %w", err)
			}
			if input.SchemaVersion != schemaVersion {
				return nil, fmt.Errorf("unsupported inventory schema_version %d", input.SchemaVersion)
			}
			assets = input.Assets
		} else if err := d.Decode(&assets); err != nil {
			return nil, fmt.Errorf("inventory JSON: %w", err)
		}
		if assets == nil {
			return nil, errors.New("inventory JSON must be an array")
		}
		var trailing json.RawMessage
		if err := d.Decode(&trailing); err != io.EOF {
			return nil, errors.New("unexpected data after inventory JSON array")
		}
	case ".csv":
		assets, err = readInventoryCSV(content)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("inventory must have .json or .csv extension")
	}
	ids := make(map[string]bool)
	for i := range assets {
		a := &assets[i]
		a.ID = strings.TrimSpace(a.ID)
		if a.ID == "" || ids[a.ID] {
			return nil, fmt.Errorf("inventory record %d needs a nonempty unique id", i+1)
		}
		ids[a.ID] = true
		if a.Patch != "" && (a.Patch != "fixed" && a.Patch != "unfixed" || strings.TrimSpace(a.PatchRef) == "") {
			return nil, fmt.Errorf("inventory record %d needs patch=fixed|unfixed and a supporting patch_ref", i+1)
		}
		if a.CPU != "" && a.CPU != unknown && a.CPU != "present" && a.CPU != "absent" && a.CPU != "mixed" {
			return nil, fmt.Errorf("inventory record %d has an invalid cpu value", i+1)
		}
		if a.CPUFeaturesComplete {
			if len(a.CPUFeatures) == 0 {
				return nil, fmt.Errorf("inventory record %d declares a complete CPU feature list but supplies no features", i+1)
			}
			if a.CPU != "" && a.CPU != unknown {
				return nil, fmt.Errorf("inventory record %d must supply either cpu or a complete feature list", i+1)
			}
		}
		switch a.CPUContext {
		case "":
			a.CPUContext = unknown
			if a.CPU != "" && a.CPU != unknown || len(a.CPUFeatures) != 0 {
				a.CPUContext = "declared"
			}
		case "declared", unknown:
		default:
			return nil, fmt.Errorf("inventory record %d needs cpu_context=declared|unknown", i+1)
		}
		if len(a.Flags) != 0 {
			a.FlagSources = []string{"inventory"}
		} else {
			a.FlagSources = nil
		}
		if a.Kind == "" {
			a.Kind = "inventory"
		}
	}
	return assets, nil
}

func readInventoryCSV(content string) ([]asset, error) {
	r := csv.NewReader(strings.NewReader(content))
	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("inventory CSV header: %w", err)
	}
	allowed := strings.Fields("id kind version java_home vendor product vm arch cpu cpu_features cpu_features_complete patch patch_ref flags flags_effective container notes cpu_context patch_attested schema_version")
	columns := make(map[string]int)
	for i, h := range header {
		h = strings.TrimSpace(h)
		if _, exists := columns[h]; exists || !slices.Contains(allowed, h) {
			return nil, fmt.Errorf("unexpected or duplicate CSV column %q", h)
		}
		columns[h] = i
	}
	if _, exists := columns["id"]; !exists {
		return nil, errors.New("inventory CSV requires an id column")
	}
	var assets []asset
	for row := 2; ; row++ {
		record, err := r.Read()
		if err == io.EOF {
			return assets, nil
		}
		if err != nil {
			return nil, err
		}
		get := func(key string) string {
			if col, ok := columns[key]; ok {
				return strings.TrimSpace(record[col])
			}
			return ""
		}
		if _, hasSchema := columns["schema_version"]; hasSchema && get("schema_version") != strconv.Itoa(schemaVersion) {
			return nil, fmt.Errorf("CSV record %d has an unsupported schema_version", row)
		}
		a := asset{
			CPUContext: get("cpu_context"),
			ID:         get("id"), Kind: get("kind"), Version: get("version"), JavaHome: get("java_home"), Vendor: get("vendor"),
			Product: get("product"), VM: get("vm"), Arch: get("arch"), CPU: get("cpu"),
			Patch: get("patch"), PatchRef: get("patch_ref"), Container: get("container"),
			Flags: strings.Fields(get("flags")), CPUFeatures: strings.Fields(get("cpu_features")),
		}
		if note := get("notes"); note != "" {
			a.Notes = []string{note}
		}
		for _, name := range []string{"flags_effective", "cpu_features_complete", "patch_attested"} {
			value := get(name)
			if value != "" && value != "true" && value != "false" {
				return nil, fmt.Errorf("CSV record %d column %s expects true or false", row, name)
			}
		}
		a.FlagsEffective = get("flags_effective") == "true"
		a.CPUFeaturesComplete = get("cpu_features_complete") == "true"
		assets = append(assets, a)
	}
}

func writeReport(w io.Writer, format string, r report, details bool) error {
	r.Summary = reportSummary{Total: len(r.Findings), ByStatus: make(map[string]int, len(statusOrder))}
	for _, status := range statusOrder {
		r.Summary.ByStatus[status] = 0
	}
	for _, f := range r.Findings {
		r.Summary.ByStatus[f.Status]++
	}
	switch format {
	case "json":
		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		return e.Encode(r)
	case "csv":
		return writeCSV(w, r)
	}
	if !details {
		return writeBriefReport(w, r)
	}
	if _, err := fmt.Fprintf(w, "%s %s (rules %s)\n", r.CVE, r.Mode, r.RulesAsOf); err != nil {
		return err
	}
	parts := []string{fmt.Sprintf("total=%d", r.Summary.Total)}
	for _, status := range statusOrder {
		parts = append(parts, fmt.Sprintf("%s=%d", status, r.Summary.ByStatus[status]))
	}
	if _, err := fmt.Fprintln(w, "Summary", strings.Join(parts, "  ")); err != nil {
		return err
	}
	for _, message := range r.Warnings {
		if _, err := fmt.Fprintf(w, "warning %q\n", message); err != nil {
			return err
		}
	}
	for _, f := range r.Findings {
		if _, err := fmt.Fprintf(w, "%s %q (%s) version=%q java_home=%q vendor=%q product=%q arch=%q build=%s cpu=%s container=%q flags=%q effective=%t cpu_context=%s flag_sources=%q reason_code=%s\n  %q\n",
			f.Status, f.ID, strconv.QuoteToASCII(f.Kind), f.Version, f.JavaHome, f.Vendor, f.Product, f.Arch, f.BuildAssessment,
			f.CPUAssessment, f.Container, strings.Join(f.Flags, " "), f.FlagsEffective, f.CPUContext, strings.Join(f.FlagSources, " "), f.ReasonCode, f.Reason); err != nil {
			return err
		}
		for _, note := range f.Notes {
			if _, err := fmt.Fprintf(w, "  %q\n", note); err != nil {
				return err
			}
		}
	}
	return nil
}

var statusLabels = map[string]string{
	affected: "受影响", potential: "待确认", mitigated: "已缓解",
	unaffected: "不受影响", unknown: "无法判断",
}

func writeBriefReport(w io.Writer, r report) error {
	var output strings.Builder
	fmt.Fprintln(&output, "Java4Shell · "+r.CVE)
	total, counts := r.Summary.Total, r.Summary.ByStatus
	switch {
	case total == 0:
		fmt.Fprintln(&output, "未找到可评估的 Java 项。")
	case counts[unaffected] == total:
		fmt.Fprintf(&output, "已检查 %d 项，均不受此漏洞影响。\n", total)
		if r.Mode == "local" && allUseCPUWithoutRequiredFeatures(r.Findings) {
			fmt.Fprintln(&output, "本机 CPU 环境不具备漏洞所需的 AVX-512 条件。")
		}
	default:
		countLine := []string{fmt.Sprintf("已检查 %d 项", total)}
		for _, status := range statusOrder {
			if counts[status] > 0 {
				countLine = append(countLine, fmt.Sprintf("%s %d", statusLabels[status], counts[status]))
			}
		}
		fmt.Fprintln(&output, strings.Join(countLine, " · "))
		for _, status := range []string{affected, potential, unknown} {
			for _, f := range r.Findings {
				if f.Status == status {
					label := statusLabels[status]
					if f.ReasonCode == "mitigation_observed_unverified" {
						label = "缓解待验证"
					}
					fmt.Fprintf(&output, "  %s  %s\n", label, briefAssetName(f))
				}
			}
		}
	}
	if len(r.Warnings) > 0 && (total > 0 || len(r.Warnings) > 1) {
		fmt.Fprintf(&output, "有 %d 条采集提示，可用 --details 查看。\n", len(r.Warnings))
	}
	_, err := io.WriteString(w, output.String())
	return err
}

func allUseCPUWithoutRequiredFeatures(findings []finding) bool {
	for _, f := range findings {
		if f.CPU != "absent" || f.CPUAssessment != "absent" || f.CPUContext != "host" {
			return false
		}
	}
	return true
}

func briefAssetName(f finding) string {
	id := f.ID
	if f.Kind == "installation" {
		path := filepath.Clean(f.ID)
		if filepath.Base(path) == "Home" && filepath.Base(filepath.Dir(path)) == "Contents" {
			path = filepath.Dir(filepath.Dir(path))
		}
		id = filepath.Base(path)
	}
	if f.Version != "" {
		id += " · Java " + f.Version
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return '�'
		}
		return r
	}, id)
}

var csvColumns = strings.Fields("cve rules_as_of mode id kind status reason build_assessment build_evidence cpu_assessment version java_home vendor product vm arch cpu_features cpu_features_complete patch patch_ref flags flags_effective container notes schema_version cpu_context patch_attested flag_sources mitigation_assessment reason_code")

func writeCSV(w io.Writer, r report) error {
	c := csv.NewWriter(w)
	if err := c.Write(csvColumns); err != nil {
		return err
	}
	for _, message := range r.Warnings {
		row := make([]string, len(csvColumns))
		copy(row, []string{r.CVE, r.RulesAsOf, r.Mode, "", "warning", "", message})
		row[slices.Index(csvColumns, "schema_version")] = strconv.Itoa(r.SchemaVersion)
		if err := c.Write(csvRow(row)); err != nil {
			return err
		}
	}
	for _, f := range r.Findings {
		if err := c.Write(csvRow([]string{r.CVE, r.RulesAsOf, r.Mode, f.ID, f.Kind, f.Status, f.Reason, f.BuildAssessment, f.BuildEvidence, f.CPUAssessment,
			f.Version, f.JavaHome, f.Vendor, f.Product, f.VM, f.Arch, strings.Join(f.CPUFeatures, " "), strconv.FormatBool(f.CPUFeaturesComplete),
			f.Patch, f.PatchRef, strings.Join(f.Flags, " "), strconv.FormatBool(f.FlagsEffective), f.Container, strings.Join(f.Notes, " | "), strconv.Itoa(r.SchemaVersion), f.CPUContext, strconv.FormatBool(f.PatchAttested), strings.Join(f.FlagSources, " "), f.MitigationAssessment, f.ReasonCode})); err != nil {
			return err
		}
	}
	c.Flush()
	return c.Error()
}

func csvRow(row []string) []string {
	for i, cell := range row {
		if trimmed := strings.TrimSpace(cell); strings.HasPrefix(cell, "\t") || strings.HasPrefix(cell, "\r") || strings.HasPrefix(cell, "\n") ||
			(len(trimmed) > 0 && strings.ContainsRune("=+-@", rune(trimmed[0]))) {
			row[i] = "'" + cell
		}
	}
	return append(row, make([]string, len(csvColumns)-len(row))...)
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, errPolicyMatch) {
			os.Exit(3)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}

// Assessment rules.

const (
	affected   = "affected"
	potential  = "potential"
	mitigated  = "mitigated"
	unaffected = "not_affected"
	unknown    = "unknown"
)

var requiredCPU = []string{"avx512f", "avx512bw", "avx512vbmi", "bmi2"}

type asset struct {
	ID                  string   `json:"id"`
	Kind                string   `json:"kind,omitempty"`
	Version             string   `json:"version,omitempty"`
	JavaHome            string   `json:"java_home,omitempty"`
	Vendor              string   `json:"vendor,omitempty"`
	Product             string   `json:"product,omitempty"`
	VM                  string   `json:"vm,omitempty"`
	Arch                string   `json:"arch,omitempty"`
	CPU                 string   `json:"cpu,omitempty"`
	CPUContext          string   `json:"cpu_context,omitempty"`
	CPUFeatures         []string `json:"cpu_features,omitempty"`
	CPUFeaturesComplete bool     `json:"cpu_features_complete,omitempty"`
	Patch               string   `json:"patch,omitempty"`
	PatchRef            string   `json:"patch_ref,omitempty"`
	PatchAttested       bool     `json:"patch_attested"`
	Flags               []string `json:"flags,omitempty"`
	FlagsEffective      bool     `json:"flags_effective,omitempty"`
	FlagSources         []string `json:"flag_sources,omitempty"`
	Container           string   `json:"container,omitempty"`
	Notes               []string `json:"notes,omitempty"`
}

type finding struct {
	asset
	Status               string `json:"status"`
	Reason               string `json:"reason"`
	ReasonCode           string `json:"reason_code"`
	MitigationAssessment string `json:"mitigation_assessment"`
	BuildAssessment      string `json:"build_assessment"`
	CPUAssessment        string `json:"cpu_assessment"`
	BuildEvidence        string `json:"build_evidence"`
}

var modernVersion = regexp.MustCompile(`^([0-9]{1,3})(\.[0-9]+){0,4}(\+[0-9]+([.-][A-Za-z0-9.~+_-]+)?)?$`)
var oracleLTS = regexp.MustCompile(`^\+4-lts(-[0-9]+)?$`)
var legacyVersion = regexp.MustCompile(`^(1\.8\.0_[0-9]+(-[A-Za-z0-9.-]+)?|8u[0-9]+(b[0-9]+)?(-perf)?)$`)

func archName(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "amd64", "x86_64", "x64":
		return "amd64"
	case "arm64", "aarch64":
		return "arm64"
	case "386", "x86", "i386", "i686":
		return "386"
	case "arm", "arm32", "riscv64", "s390x", "ppc64", "ppc64le", "loong64", "loongarch64", "sparcv9":
		return strings.ToLower(s)
	default:
		return ""
	}
}

func cpuAssessment(a asset) string {
	arch := archName(a.Arch)
	if arch == "" {
		return unknown
	}
	if arch != "amd64" {
		return "absent"
	}
	if a.CPU == "present" || a.CPU == "absent" || a.CPU == "mixed" {
		return a.CPU
	}
	if !a.CPUFeaturesComplete || len(a.CPUFeatures) == 0 {
		return unknown
	}
	for _, feature := range requiredCPU {
		found := false
		for _, token := range a.CPUFeatures {
			if strings.EqualFold(strings.TrimSpace(token), feature) {
				found = true
				break
			}
		}
		if !found {
			return "absent"
		}
	}
	return "present"
}

const oracleRef = "https://www.oracle.com/security-alerts/cspunov2026.html#JAVA"
const debianRef = "https://security-tracker.debian.org/tracker/CVE-2026-114938"

func buildAssessment(a asset) (string, string) {
	vm := strings.ToLower(a.VM)
	if strings.Contains(vm, "openj9") {
		return "outside_scope", "Identified OpenJ9 VM. The CVE applies to a HotSpot intrinsic."
	}
	v := strings.ToLower(strings.TrimSpace(a.Version))
	vendor := strings.ToLower(strings.TrimSpace(a.Vendor))
	product := strings.ToLower(strings.TrimSpace(a.Product))
	base := strings.SplitN(v, "+", 2)[0]
	oracle := vendor == "oracle" || vendor == "oracle corporation"
	if (vendor == "openjdk" || oracle) && product == "openjdk" {
		switch v {
		case "17.0.21.1+2", "21.0.13.1+2", "25.0.5.1+2", "27.0.1.1+4":
			return "fixed", openJDKTagRef(base)
		case "17.0.21", "17.0.21.0.3", "21.0.13", "21.0.13.0.3", "25.0.5", "25.0.5.0.3", "27.0.1", "27.0.1.0.3":
			return "unfixed", openJDKTagRef(base)
		}
	}
	if oracle {
		switch product {
		case "oracle java se":
			switch base {
			case "8u511b33-perf", "1.8.0_511-perf-b33", "17.0.21.0.3", "21.0.13.0.3", "25.0.5.0.3", "27.0.1.0.3":
				return "unfixed", oracleRef
			case "17.0.21.1", "21.0.13.1", "25.0.5.1", "27.0.1.1":
				if v == base || v == base+"+4" || oracleLTS.MatchString(strings.TrimPrefix(v, base)) {
					return "fixed", "https://www.oracle.com/java/technologies/javase/" + strings.ReplaceAll(base, ".", "-") + "-relnotes.html"
				}
			}
		case "oracle graalvm for jdk":
			if base == "17.0.21.0.3" || base == "21.0.13.0.3" {
				return "unfixed", oracleRef
			}
		case "oracle graalvm enterprise edition":
			if base == "21.3.20.0.3" {
				return "unfixed", oracleRef
			}
		}
	}
	if vendor == "debian" {
		switch v {
		case "17.0.19+10-1~deb12u2", "17.0.21+9-1~deb12u1", "17.0.21.0.3+1-1",
			"21.0.12.1+1-1~deb13u1", "21.0.13+9-1~deb13u2", "21.0.13+9-1-deb13u2-debian", "21.0.13.0.3+1-1",
			"25.0.3+9-2~deb13u1", "25.0.5+8-1~deb13u1", "25.0.5+8-1", "25.0.5.0.3+1-3", "27.0.1.0.3+1-1":
			return "unfixed", debianRef
		}
	}
	if strings.Contains(product, "graalvm") {
		return "candidate", "GraalVM requires patch evidence for its specific product and build."
	}
	if legacyVersion.MatchString(v) {
		if strings.Contains(v, "perf") || oracle || vendor == "" {
			return "candidate", "Check Oracle Java 8 Enterprise Performance product and vendor patch status."
		}
		if recognizedOpenJDK(vendor, vm) {
			return "outside_scope", "Identified non-Oracle OpenJDK 8 build is outside the upstream affected range."
		}
	}
	if !modernVersion.MatchString(v) {
		return unknown, "No supported Java version metadata."
	}
	parts := strings.Split(base, ".")
	major, _ := strconv.Atoi(parts[0])
	if major < 8 || major > 27 {
		return unknown, "Java feature release is outside the scanner's verified version coverage."
	}
	if major < 17 || (major == 17 && len(parts) >= 3 && parts[1] == "0" && lessThanSix(parts[2])) {
		if recognizedOpenJDK(vendor, vm) && !oracle {
			return "outside_scope", "Identified OpenJDK build predates the upstream affected range."
		}
		return unknown, "Need distribution or VM evidence for this release."
	}
	if base == "17" && recognizedOpenJDK(vendor, vm) && !oracle {
		return "outside_scope", "OpenJDK 17 GA predates the upstream affected range."
	}
	return "candidate", "Version is in upstream investigation scope. Confirm VM family and vendor patch status."
}

func openJDKTagRef(version string) string {
	major, _, _ := strings.Cut(version, ".")
	return "https://github.com/openjdk/jdk" + major + "u/tree/jdk-" + version + "-ga"
}

func lessThanSix(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n < 6
}

func recognizedOpenJDK(vendor, vm string) bool {
	if vm != "" && !strings.Contains(vm, "hotspot") && !strings.Contains(vm, "openjdk") {
		return false
	}
	switch vendor {
	case "openjdk", "debian", "ubuntu", "canonical", "eclipse adoptium", "amazon.com inc.", "microsoft", "azul systems, inc.", "red hat, inc.", "bellsoft", "sap se":
		return true
	}
	return strings.Contains(vm, "openjdk")
}

var safeAVX = regexp.MustCompile(`^-XX:UseAVX=[+-]?[0-9]{1,3}$`)

func relevantFlags(flags []string) []string {
	out := make([]string, 0)
	for _, flag := range flags {
		if flag == "-XX:-UseBASE64Intrinsics" || flag == "-XX:+UseBASE64Intrinsics" || safeAVX.MatchString(flag) {
			out = append(out, flag)
		}
	}
	return out
}

func mitigation(flags []string) bool {
	disable := false
	avx := 3
	for _, flag := range flags {
		switch flag {
		case "-XX:-UseBASE64Intrinsics":
			disable = true
		case "-XX:+UseBASE64Intrinsics":
			disable = false
		default:
			if safeAVX.MatchString(flag) {
				avx, _ = strconv.Atoi(strings.TrimPrefix(flag, "-XX:UseAVX="))
			}
		}
	}
	return disable || (avx >= 0 && avx <= 2)
}

func classify(a asset) finding {
	a.Flags = relevantFlags(a.Flags)
	if a.CPUContext == "" {
		a.CPUContext = unknown
	}
	build, detail := buildAssessment(a)
	cpu := cpuAssessment(a)
	f := finding{asset: a, BuildAssessment: build, CPUAssessment: cpu, BuildEvidence: detail, MitigationAssessment: "not_observed"}
	f.PatchAttested = a.Patch == build && (build == "fixed" || build == "unfixed") && strings.TrimSpace(a.PatchRef) == detail
	if a.Patch != "" && !f.PatchAttested {
		f.Notes = append(slices.Clone(a.Notes), "Inventory patch claim is not corroborated by a built-in rule for this exact build and advisory.")
	}
	if mitigation(a.Flags) {
		f.MitigationAssessment = "observed_unverified"
		if a.FlagsEffective {
			f.MitigationAssessment = "effective_declared"
		}
	}
	arch := archName(a.Arch)
	trustedAbsence := a.CPUContext == "host" || (arch != "" && arch != "amd64")
	switch {
	case build == "fixed" || build == "outside_scope":
		f.Status, f.ReasonCode, f.Reason = unaffected, "build_"+build, detail
	case cpu == "absent" && trustedAbsence:
		f.Status, f.ReasonCode, f.Reason = unaffected, "cpu_features_absent", "The target architecture or verified local CPU lacks required features."
	case cpu == "absent":
		f.Status, f.ReasonCode, f.Reason = unknown, "cpu_context_unverified", "CPU absence was not verified for the target execution context."
	case build == unknown:
		f.Status, f.ReasonCode, f.Reason = unknown, "build_unknown", detail
		if a.Patch == "fixed" && !f.PatchAttested {
			f.ReasonCode, f.Reason = "patch_unverified", "Inventory declares a fix without a corroborating built-in build rule."
		}
	case f.MitigationAssessment == "effective_declared" && arch == "amd64":
		f.Status, f.ReasonCode, f.Reason = mitigated, "mitigation_effective_declared", "Supplied effective JVM flags disable the AVX-512 Base64 path."
	case f.MitigationAssessment == "observed_unverified":
		f.Status, f.ReasonCode, f.Reason = potential, "mitigation_observed_unverified", "A mitigation flag was observed. Verify effective JVM flags after restart."
	case build == "unfixed" && cpu == "present" && a.CPUContext != unknown:
		f.Status, f.ReasonCode, f.Reason = affected, "affected_build_and_cpu", "Known affected build with required CPU features. "+detail
	default:
		f.Status, f.ReasonCode, f.Reason = potential, "needs_evidence", detail
		if a.Patch != "" && !f.PatchAttested {
			f.ReasonCode, f.Reason = "patch_unverified", "Inventory patch claim could not be corroborated. "+detail
		}
		if cpu == unknown || cpu == "mixed" || a.CPUContext == unknown {
			f.Reason += " CPU eligibility or execution context is incomplete."
		}
	}
	return f
}

// Local installation and process discovery.

func readBounded(path string, max int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readLimit(f, max)
}

func readLimit(r io.Reader, max int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err == nil && int64(len(data)) > max {
		err = errors.New("input exceeds size limit")
	}
	return data, err
}

func releaseAsset(id, root, kind string, cpu string) asset {
	a := asset{ID: id, Kind: kind, CPU: cpu, JavaHome: root}
	data, err := readBounded(filepath.Join(root, "release"), 256<<10)
	if err != nil {
		a.Notes = append(a.Notes, "JDK release metadata unavailable: "+err.Error())
		return a
	}
	values := parseRelease(data)
	a.Version = values["JAVA_RUNTIME_VERSION"]
	if a.Version == "" {
		a.Version = values["JAVA_VERSION"]
	}
	a.Vendor, a.VM = values["IMPLEMENTOR"], values["JVM_VARIANT"]
	a.Arch = values["OS_ARCH"]
	if strings.EqualFold(a.Vendor, "Oracle Corporation") {
		label := strings.ToLower(strings.Join([]string{values["GRAALVM_VERSION"], values["GRAALVM_EDITION"], values["IMPLEMENTOR_VERSION"], values["JAVA_RUNTIME_NAME"]}, " "))
		readme, _ := readBounded(filepath.Join(root, "README"), 64<<10)
		oracleJDK := strings.Contains(string(readme), "Thank you for using the Oracle JDK.")
		switch {
		case strings.Contains(label, "graalvm") || values["GRAALVM_VERSION"] != "":
			a.Notes = append(a.Notes, "Verify the exact Oracle GraalVM product through inventory evidence.")
		case oracleJDK || strings.Contains(label, "java(tm)") || strings.Contains(label, "java se"):
			a.Product = "Oracle Java SE"
		default:
			a.Notes = append(a.Notes, "Oracle release metadata does not identify Java SE versus Oracle OpenJDK.")
		}
	}
	return a
}

func parseRelease(data []byte) map[string]string {
	values := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 256<<10)
	for scanner.Scan() {
		k, v, ok := strings.Cut(scanner.Text(), "=")
		if ok {
			values[k] = strings.Trim(strings.TrimSpace(v), "\"")
		}
	}
	return values
}

func javaName(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	return name == "java" || name == "javaw" || name == "java.exe" || name == "javaw.exe"
}

func javaRoot(path string) string {
	root := filepath.Dir(filepath.Dir(path))
	if filepath.Base(root) == "jre" {
		if _, err := os.Stat(filepath.Join(root, "release")); err != nil {
			root = filepath.Dir(root)
		}
	}
	return root
}

func launcherJDKRoot(platform, path string) string {
	if platform == "darwin" && filepath.ToSlash(path) == "/usr/bin/java" {
		return "" // macOS launcher shim, not an installed runtime.
	}
	return javaRoot(path)
}

func jdkRoots(explicit []string) []string {
	roots := append([]string(nil), explicit...)
	if len(explicit) == 0 {
		if home := os.Getenv("JAVA_HOME"); home != "" {
			roots = append(roots, home)
		}
		if java, err := exec.LookPath("java"); err == nil {
			if path, err := filepath.EvalSymlinks(java); err == nil {
				if root := launcherJDKRoot(runtime.GOOS, path); root != "" {
					roots = append(roots, root)
				}
			}
		}
		var patterns []string
		switch runtime.GOOS {
		case "linux":
			patterns = []string{"/usr/lib/jvm/*/release", "/usr/java/*/release"}
		case "darwin":
			patterns = []string{"/Library/Java/JavaVirtualMachines/*/Contents/Home/release"}
			if home, err := os.UserHomeDir(); err == nil {
				patterns = append(patterns, filepath.Join(home, "Library", "Java", "JavaVirtualMachines", "*", "Contents", "Home", "release"))
			}
		case "windows":
			for _, name := range []string{"ProgramFiles", "ProgramFiles(x86)"} {
				if dir := os.Getenv(name); dir != "" {
					for _, vendor := range []string{"Java", "Eclipse Adoptium", "Microsoft", "Amazon Corretto", "Zulu"} {
						patterns = append(patterns, filepath.Join(dir, vendor, "*", "release"))
					}
				}
			}
		}
		for _, pattern := range patterns {
			matches, _ := filepath.Glob(pattern)
			for _, match := range matches {
				roots = append(roots, filepath.Dir(match))
			}
		}
	}
	out := make([]string, 0, len(roots))
	for _, root := range roots {
		if abs, err := filepath.Abs(root); err == nil {
			root = abs
		}
		if real, err := filepath.EvalSymlinks(root); err == nil {
			root = real
		}
		out = append(out, root)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func processID(pid int) string {
	return fmt.Sprintf("pid:%d", pid)
}

func executableAsset(pid int, path, cpu string) asset {
	a := asset{ID: processID(pid), Kind: "process", CPU: cpu}
	if !filepath.IsAbs(path) {
		a.Notes = append(a.Notes, "Java process recognized. Executable path is unavailable.")
		return a
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	disk := releaseAsset(a.ID, javaRoot(path), "process", cpu)
	a.Notes = append(a.Notes, "Loaded JVM identity could not be verified. Launcher: "+path)
	if disk.Version != "" {
		a.Notes = append(a.Notes, "On-disk launcher JDK version: "+disk.Version)
	}
	return a
}

func filterProcesses(pids, order []int, found map[int]asset) []asset {
	if len(pids) == 0 {
		pids = order
	}
	slices.Sort(pids)
	var result []asset
	for _, pid := range slices.Compact(pids) {
		a, ok := found[pid]
		if !ok {
			a = asset{ID: processID(pid), Kind: "process", Notes: []string{"Could not identify a Java process for this PID."}}
		}
		result = append(result, a)
	}
	return result
}

// Linux.

func linuxLocalCPU() string {
	data, err := readBounded("/proc/cpuinfo", 16<<20)
	if err != nil {
		return unknown
	}
	return linuxCPU(data)
}

func linuxCPU(data []byte) string {
	with, without, processors := 0, 0, 0
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "processor":
			processors++
		case "flags":
			features := strings.Fields(value)
			if len(features) == 0 {
				return unknown
			}
			if cpuAssessment(asset{Arch: "amd64", CPUFeatures: features, CPUFeaturesComplete: true}) == "present" {
				with++
			} else {
				without++
			}
		}
	}
	switch {
	case processors == 0 || with+without != processors:
		return unknown
	case with != 0 && without != 0:
		return "mixed"
	case with != 0:
		return "present"
	default:
		return "absent"
	}
}

func containerHint(proc string) string {
	if data, err := readBounded(filepath.Join(proc, "cgroup"), 128<<10); err == nil {
		cgroup := strings.ToLower(string(data))
		for _, token := range []string{"kubepods", "docker", "libpod", "containerd", "/lxc", "cri-o", "crio-"} {
			if strings.Contains(cgroup, token) {
				return token + " (cgroup hint)"
			}
		}
	}
	if _, err := os.Stat(filepath.Join(proc, "root", ".dockerenv")); err == nil {
		return "docker (root marker)"
	}
	if _, err := os.Stat(filepath.Join(proc, "root", "run", ".containerenv")); err == nil {
		return "container (root marker)"
	}
	ns, err := os.Readlink(filepath.Join(proc, "ns", "pid"))
	initNS, initErr := os.Readlink("/proc/1/ns/pid")
	if err == nil && initErr == nil && ns != initNS {
		return "separate PID namespace"
	}
	return ""
}

// A Linux FileInfo exposes syscall.Stat_t. Read the two numeric fields without
// importing that platform type into the single cross-platform source file.
func linuxFileIdentity(info os.FileInfo) (device, inode uint64, ok bool) {
	st := reflect.ValueOf(info.Sys())
	if st.Kind() != reflect.Pointer || st.IsNil() || st.Elem().Kind() != reflect.Struct {
		return 0, 0, false
	}
	dev, ino := st.Elem().FieldByName("Dev"), st.Elem().FieldByName("Ino")
	if !dev.CanUint() || !ino.CanUint() {
		return 0, 0, false
	}
	return dev.Uint(), ino.Uint(), true
}

func linuxDeviceNumbers(dev uint64) (major, minor uint64) {
	return dev>>8&0xfff | dev>>32&0xfffff000, dev&0xff | dev>>12&0xffffff00
}

// The mapped file and on-disk file must have the same device and inode.
func loadedJVM(proc string, maps []byte) (string, bool) {
	var found string
	for _, line := range bytes.Split(maps, []byte("\n")) {
		fields := bytes.Fields(line)
		start := bytes.IndexByte(line, '/')
		if len(fields) < 6 || start < 0 {
			continue
		}
		path := string(line[start:])
		path = strings.ReplaceAll(path, `\012`, "\n")
		if !strings.HasSuffix(path, "/libjvm.so") && !strings.HasSuffix(path, "/libjvm.so (deleted)") {
			continue
		}
		if strings.HasSuffix(path, " (deleted)") || (found != "" && found != path) {
			return "", false
		}
		if found == path {
			continue
		}
		info, err := os.Stat(filepath.Join(proc, "root", path))
		if err != nil {
			return "", false
		}
		device, fileInode, ok := linuxFileIdentity(info)
		inode, inodeErr := strconv.ParseUint(string(fields[4]), 10, 64)
		major, minor, devOK := strings.Cut(string(fields[3]), ":")
		m, e1 := strconv.ParseUint(major, 16, 64)
		n, e2 := strconv.ParseUint(minor, 16, 64)
		if !ok || inodeErr != nil || !devOK || e1 != nil || e2 != nil {
			return "", false
		}
		fileMajor, fileMinor := linuxDeviceNumbers(device)
		if fileInode != inode || fileMajor != m || fileMinor != n {
			return "", false
		}
		found = path
	}
	return found, found != ""
}

func jvmRoot(proc, lib string) string {
	server := filepath.Dir(lib)
	if filepath.Base(server) != "server" {
		return ""
	}
	libDir := filepath.Dir(server)
	if filepath.Base(libDir) == "amd64" || filepath.Base(libDir) == "i386" {
		libDir = filepath.Dir(libDir)
	}
	if filepath.Base(libDir) != "lib" {
		return ""
	}
	root := filepath.Join(proc, "root", filepath.Dir(libDir))
	if filepath.Base(root) == "jre" {
		if _, err := os.Stat(filepath.Join(root, "release")); err != nil {
			root = filepath.Dir(root)
		}
	}
	return root
}

func launcherFlags(argv []byte) []string {
	args := strings.Split(strings.TrimSuffix(string(argv), "\x00"), "\x00")
	var flags []string
	for i := 1; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-cp", "-classpath", "--class-path", "-p", "--module-path", "--upgrade-module-path", "--add-modules", "--limit-modules",
			"--add-exports", "--add-opens", "--add-reads", "--patch-module", "--source", "--enable-native-access":
			i++
			continue
		}
		if !strings.HasPrefix(arg, "-") || arg == "-jar" || arg == "-m" || arg == "--module" || strings.HasPrefix(arg, "--module=") || arg == "--" {
			break
		}
		flags = append(flags, arg)
	}
	return relevantFlags(flags)
}

// Keep only JVM option variables and mitigation flags. Environment values
// never enter a report, and starting options are never marked effective here.
func linuxObservedFlags(argv, environment []byte, launcher bool) (flags, sources []string) {
	relevant := map[string][]string{}
	for _, entry := range bytes.Split(environment, []byte{0}) {
		key, value, ok := bytes.Cut(entry, []byte{'='})
		if !ok {
			continue
		}
		name := string(key)
		switch name {
		case "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS":
		case "JDK_JAVA_OPTIONS":
			if !launcher {
				continue
			}
		default:
			continue
		}
		relevant[name] = relevantFlags(jvmOptionWords(string(value)))
	}
	if launcher {
		relevant["cmdline"] = launcherFlags(argv)
	}
	// HotSpot reads _JAVA_OPTIONS after the launcher-provided VM arguments.
	for _, source := range []string{"JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "cmdline", "_JAVA_OPTIONS"} {
		if len(relevant[source]) != 0 {
			flags = append(flags, relevant[source]...)
			sources = append(sources, source)
		}
	}
	return flags, sources
}

func jvmOptionWords(value string) []string {
	var words []string
	var word strings.Builder
	var quote rune
	for _, c := range value {
		switch {
		case c == '\\':
			// Launcher and VM option sources differ in escape handling.
			return nil
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				word.WriteRune(c)
			}
		case c == '\'' || c == '"':
			quote = c
		case unicode.IsSpace(c):
			words = append(words, word.String())
			word.Reset()
		default:
			word.WriteRune(c)
		}
	}
	if quote != 0 {
		return nil
	}
	return append(words, word.String())
}

func processStart(proc string) string {
	data, err := readBounded(filepath.Join(proc, "stat"), 16<<10)
	if err != nil {
		return ""
	}
	end := bytes.LastIndexByte(data, ')')
	if end < 0 {
		return ""
	}
	fields := bytes.Fields(data[end+1:])
	if len(fields) <= 19 {
		return ""
	}
	return string(fields[19])
}

func linuxProcesses(pids []int, cpu string) ([]asset, []string) {
	explicit := len(pids) > 0
	if !explicit {
		entries, err := os.ReadDir("/proc")
		if err != nil {
			return nil, []string{err.Error()}
		}
		for _, entry := range entries {
			if pid, err := strconv.Atoi(entry.Name()); err == nil && entry.IsDir() {
				pids = append(pids, pid)
			}
		}
	}
	slices.Sort(pids)
	var assets []asset
	var warnings []string
	limited := 0
	for _, pid := range slices.Compact(pids) {
		proc := fmt.Sprintf("/proc/%d", pid)
		start := processStart(proc)
		exe, exeErr := os.Readlink(filepath.Join(proc, "exe"))
		a := asset{ID: processID(pid), Kind: "process", CPU: cpu}
		maps, mapsErr := readBounded(filepath.Join(proc, "maps"), 16<<20)
		lib, verified := loadedJVM(proc, maps)
		named := javaName(strings.TrimSuffix(exe, " (deleted)"))
		if !named && exeErr != nil {
			if comm, err := readBounded(filepath.Join(proc, "comm"), 4096); err == nil {
				named = javaName(strings.TrimSpace(string(comm)))
			}
		}
		isJVM := verified || bytes.Contains(maps, []byte("/libjvm.so"))
		if !named && !isJVM {
			if explicit {
				a.Notes = append(a.Notes, "Could not identify a Java launcher or mapped HotSpot JVM for this PID.")
				assets = append(assets, a)
			} else if os.IsPermission(mapsErr) {
				limited++
			}
			continue
		}
		if root := jvmRoot(proc, lib); verified && root != "" {
			a = releaseAsset(a.ID, root, "process", cpu)
			a.CPUContext = "host"
			a.JavaHome = strings.TrimPrefix(root, filepath.Join(proc, "root"))
			a.Notes = append(a.Notes, "Mapped HotSpot library matches the device and inode of the JDK on disk.")
		} else {
			a.Notes = append(a.Notes, "Mapped JVM identity or JDK release metadata could not be verified.")
		}
		a.Container = containerHint(proc)
		argv, _ := readBounded(filepath.Join(proc, "cmdline"), 2<<20)
		environment, envErr := readBounded(filepath.Join(proc, "environ"), 2<<20)
		if envErr != nil {
			a.Notes = append(a.Notes, "JVM startup environment could not be inspected.")
		}
		a.Flags, a.FlagSources = linuxObservedFlags(argv, environment, named)
		afterExe, afterErr := os.Readlink(filepath.Join(proc, "exe"))
		if start == "" || start != processStart(proc) || (exeErr == nil && (afterErr != nil || exe != afterExe)) {
			a = asset{ID: a.ID, Kind: a.Kind, Notes: []string{"Process exited or changed identity during collection."}}
		}
		assets = append(assets, a)
	}
	if limited > 0 {
		warnings = append(warnings, fmt.Sprintf("Could not inspect JVM mappings for %d other processes. Discovery may be incomplete.", limited))
	}
	return assets, warnings
}

// macOS.

func darwinLocalCPU() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return darwinCPU(runtime.GOARCH, func(key string) string {
		b, err := exec.CommandContext(ctx, "/usr/sbin/sysctl", "-n", key).Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	})
}

func darwinCPU(arch string, sysctl func(string) string) string {
	// Apple Silicon does not expose AVX-512 to native or Rosetta processes.
	if arch == "arm64" || sysctl("sysctl.proc_translated") == "1" {
		return "absent"
	}
	if arch != "amd64" {
		return unknown
	}
	complete := true
	for _, key := range []string{"hw.optional.avx512f", "hw.optional.avx512bw", "hw.optional.avx512vbmi", "hw.optional.bmi2"} {
		switch sysctl(key) {
		case "0":
			return "absent"
		case "1":
		default:
			complete = false
		}
	}
	if complete {
		return "present"
	}
	return unknown
}

func darwinProcesses(pids []int, cpu string) ([]asset, []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "/bin/ps", "-axww", "-o", "pid=,comm=").Output()
	if err != nil {
		return nil, []string{"Process discovery failed: " + err.Error()}
	}
	found := make(map[int]asset)
	var order []int
	for _, row := range strings.Split(string(b), "\n") {
		pidText, path, _ := strings.Cut(strings.TrimSpace(row), " ")
		path = strings.TrimSpace(path)
		pid, err := strconv.Atoi(pidText)
		if err == nil && javaName(path) {
			found[pid] = executableAsset(pid, path, cpu)
			order = append(order, pid)
		}
	}
	return filterProcesses(pids, order, found), nil
}

// Windows.

func windowsProcesses(pids []int, cpu string) ([]asset, []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	win := os.Getenv("SystemRoot")
	if !filepath.IsAbs(win) {
		return nil, []string{"SystemRoot is unavailable. Windows process discovery could not start."}
	}
	ps := filepath.Join(win, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	script := `[Console]::OutputEncoding = [Text.Encoding]::UTF8; $ErrorActionPreference = 'Stop'; $p = @(Get-CimInstance Win32_Process -Filter "Name='java.exe' OR Name='javaw.exe'" | Select-Object ProcessId, ExecutablePath); ConvertTo-Json -InputObject $p -Compress`
	data, err := exec.CommandContext(ctx, ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		return nil, []string{"Windows process discovery failed: " + err.Error()}
	}
	var rows []struct {
		ProcessID      int
		ExecutablePath string
	}
	if err := json.Unmarshal(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}), &rows); err != nil {
		return nil, []string{"Windows process metadata could not be parsed: " + err.Error()}
	}
	found := make(map[int]asset)
	var order []int
	for _, row := range rows {
		pid := row.ProcessID
		found[pid] = executableAsset(pid, row.ExecutablePath, cpu)
		order = append(order, pid)
	}
	return filterProcesses(pids, order, found), nil
}

func localCPU() string {
	switch runtime.GOOS {
	case "linux":
		return linuxLocalCPU()
	case "darwin":
		return darwinLocalCPU()
	case "windows":
		// These CPUID flags account for OS vector state. An incomplete sample
		// is kept unknown because a single logical CPU cannot exclude all CPUs.
		if runtime.GOARCH == "amd64" && cpu.X86.HasAVX512F && cpu.X86.HasAVX512BW && cpu.X86.HasAVX512VBMI && cpu.X86.HasBMI2 {
			return "present"
		}
	}
	return unknown
}

func localProcesses(pids []int, cpu string) ([]asset, []string) {
	switch runtime.GOOS {
	case "linux":
		return linuxProcesses(pids, cpu)
	case "darwin":
		return darwinProcesses(pids, cpu)
	case "windows":
		return windowsProcesses(pids, cpu)
	default:
		return nil, []string{"Running process discovery is unavailable on this platform."}
	}
}
