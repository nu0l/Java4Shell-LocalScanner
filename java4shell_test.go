package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestAssessment(t *testing.T) {
	debian := asset{Version: "21.0.13+9-1-deb13u2-Debian", Vendor: "Debian", Arch: "amd64", CPU: "present"}
	oracle := asset{Version: "21.0.13.1+4-LTS", Vendor: "Oracle Corporation", Product: "Oracle Java SE", Arch: "amd64"}
	tests := []struct {
		name string
		a    asset
		want string
	}{
		{"known unfixed build and eligible CPU", debian, affected},
		{"unknown Debian revision", asset{Version: "21.0.13+9-2~deb13u2", Vendor: "Debian", Arch: "amd64", CPU: "present"}, potential},
		{"observed flags only", change(debian, func(a *asset) { a.Flags = []string{"-XX:-UseBASE64Intrinsics"} }), potential},
		{"effective flags", change(debian, func(a *asset) { a.Flags, a.FlagsEffective = []string{"-XX:UseAVX=2"}, true }), mitigated},
		{"flags reenabled", change(debian, func(a *asset) {
			a.Flags, a.FlagsEffective = []string{"-XX:UseAVX=2", "-XX:UseAVX=3", "-XX:-UseBASE64Intrinsics", "-XX:+UseBASE64Intrinsics"}, true
		}), affected},
		{"default useavx after restriction", change(debian, func(a *asset) {
			a.Flags, a.FlagsEffective = []string{"-XX:UseAVX=2", "-XX:UseAVX=-1"}, true
		}), affected},
		{"mixed CPU", change(debian, func(a *asset) { a.CPU = "mixed" }), potential},
		{"feature list incomplete", change(debian, func(a *asset) { a.CPU, a.CPUFeatures = "", []string{"bmi2"} }), potential},
		{"feature list complete", change(debian, func(a *asset) {
			a.CPU, a.CPUFeatures, a.CPUFeaturesComplete = "", []string{"AVX512F", "avx512bw", "bmi2"}, true
		}), unaffected},
		{"arm64", change(debian, func(a *asset) { a.Arch = "aarch64" }), unaffected},
		{"oracle ga", oracle, unaffected},
		{"oracle without product identity", change(oracle, func(a *asset) { a.Product = "" }), potential},
		{"other vendor reusing version", change(oracle, func(a *asset) { a.Vendor = "custom" }), potential},
		{"openjdk tag", asset{Version: "21.0.13.1+2", Product: "OpenJDK", Vendor: "OpenJDK"}, unaffected},
		{"oracle perf exception", asset{Version: "8u511b33-perf", Product: "Oracle Java SE", Vendor: "Oracle", Arch: "amd64", CPU: "present"}, affected},
		{"upstream before 17.0.6", asset{Version: "17.0.5+8", Vendor: "OpenJDK"}, unaffected},
		{"unconfirmed next feature release", asset{Version: "28.0.1", Vendor: "OpenJDK", Arch: "amd64", CPU: "present"}, unknown},
		{"missing version", asset{}, unknown},
		{"verified vendor backport", change(debian, func(a *asset) { a.Patch, a.PatchRef = "fixed", "Example verified vendor advisory" }), unaffected},
		{"unsupported patch assertion", change(debian, func(a *asset) { a.Patch = "fixed" }), affected},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := classify(test.a); got.Status != test.want {
				t.Fatalf("status %q, want %q. Evidence: %s", got.Status, test.want, got.Reason)
			}
		})
	}
}

func change(a asset, apply func(*asset)) asset {
	apply(&a)
	return a
}

func TestInventoryReports(t *testing.T) {
	for _, format := range []string{"txt", "json", "csv"} {
		t.Run(format, func(t *testing.T) {
			var out bytes.Buffer
			if err := run([]string{"inventory", "--input", "testdata/assets.json", "--format", format, "--details"}, &out, &out); err != nil {
				t.Fatal(err)
			}
			switch format {
			case "json":
				var r report
				if err := json.Unmarshal(out.Bytes(), &r); err != nil || len(r.Findings) != 5 || r.RulesAsOf != rulesAsOf {
					t.Fatalf("unexpected report: %v / %+v", err, r)
				}
			case "csv":
				rows, err := csv.NewReader(&out).ReadAll()
				if err != nil || len(rows) != 6 {
					t.Fatalf("unexpected CSV: %v / %v", err, rows)
				}
			case "txt":
				for _, status := range []string{affected, potential, mitigated, unaffected, unknown} {
					if !strings.Contains(out.String(), "\n"+status+" ") {
						t.Errorf("missing status %s", status)
					}
				}
			}
		})
	}
	var out bytes.Buffer
	if err := run([]string{"inventory", "--input", "testdata/assets.csv", "--details"}, &out, &out); err != nil || !strings.Contains(out.String(), mitigated) {
		t.Fatalf("failed to read CSV inventory: %v %s", err, out.String())
	}
}

func TestRejectUnsafeOrAmbiguousInputs(t *testing.T) {
	dir := t.TempDir()
	for i, data := range []string{
		`[{"id":"a"},{"id":"a"}]`, `[{"id":"a","patch":"fixed"}]`, `[{"id":"a"}][]`,
		`[{"id":"a","typo":"a"}]`, `null`, `[null]`, `[{"id":"a","cpu_features_complete":true}]`,
	} {
		path := filepath.Join(dir, "invalid.json")
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readInventory(path); err == nil {
			t.Errorf("case %d accepted malformed inventory", i)
		}
	}
	row := csvRow([]string{"  =example", "-XX:UseAVX=2", "asset"})
	if row[0] != "'  =example" || row[1] != "'-XX:UseAVX=2" || row[2] != "asset" {
		t.Errorf("unexpected spreadsheet escaping: %q", row)
	}
	path := filepath.Join(dir, "existing.txt")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"inventory", "--input", "testdata/assets.json", "--out", path}, &out, &out); err == nil {
		t.Fatal("existing report destination was accepted")
	}
	if got, _ := os.ReadFile(path); string(got) != "original" {
		t.Fatalf("existing file changed: %q", got)
	}
}

func TestCLIShortcutsAndSummary(t *testing.T) {
	t.Run("positional inventory and inferred JSON", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "report.JSON")
		var stdout, stderr bytes.Buffer
		if err := run([]string{"inventory", "testdata/assets.json", "--out", output}, &stdout, &stderr); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		var r report
		if err := json.Unmarshal(data, &r); err != nil || r.Summary.Total != 5 || len(r.Summary.ByStatus) != 5 {
			t.Fatalf("unexpected summary: %+v, %v", r.Summary, err)
		}
		for _, status := range statusOrder {
			if r.Summary.ByStatus[status] != 1 {
				t.Errorf("unexpected %s count: %d", status, r.Summary.ByStatus[status])
			}
		}
		if stdout.Len() != 0 || !strings.Contains(stderr.String(), "Report saved") {
			t.Fatalf("unexpected stdout %q or stderr %q", stdout.String(), stderr.String())
		}
	})
	t.Run("implicit local subcommand", func(t *testing.T) {
		var out bytes.Buffer
		err := run([]string{"--jdk", t.TempDir(), "--no-processes"}, &out, &out)
		if err != nil || !strings.Contains(out.String(), "已检查 1 项") || !strings.Contains(out.String(), "无法判断 1") {
			t.Fatalf("unexpected report: %v / %s", err, out.String())
		}
	})
	t.Run("conflicting inputs", func(t *testing.T) {
		var out bytes.Buffer
		for _, args := range [][]string{
			{"inventory", "testdata/assets.json", "--input", "testdata/assets.csv"},
			{"local", "--processes-only", "--no-processes"},
			{"local", "--processes-only", "--jdk", "."},
		} {
			if err := run(args, &out, &out); err == nil {
				t.Errorf("accepted invalid options %q", args)
			}
		}
	})
}

func TestLinuxCPU(t *testing.T) {
	supported := "processor: 0\nflags: avx512f avx512bw avx512vbmi bmi2\n"
	unsupported := "processor: 1\nflags: bmi2\n"
	for _, tt := range []struct{ data, want string }{
		{supported, "present"}, {unsupported, "absent"}, {supported + unsupported, "mixed"},
		{"processor: 0\nFeatures: aes\n", unknown}, {supported + "processor: 1\n", unknown},
	} {
		if got := linuxCPU([]byte(tt.data)); got != tt.want {
			t.Errorf("linuxCPU(%q) = %s, want %s", tt.data, got, tt.want)
		}
	}
}

func TestObservedLauncherFlags(t *testing.T) {
	args := []byte("java\x00-XX:UseAVX=2\x00-cp\x00dir with spaces\x00-XX:-UseBASE64Intrinsics\x00-jar\x00app.jar\x00-XX:+UseBASE64Intrinsics\x00")
	want := []string{"-XX:UseAVX=2", "-XX:-UseBASE64Intrinsics"}
	if got := launcherFlags(args); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestLoadedJVMRequiresMatchingIdentity(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux JVM mappings use procfs")
	}
	proc := t.TempDir()
	if err := os.Symlink("/", filepath.Join(proc, "root")); err != nil {
		t.Fatal(err)
	}
	lib := filepath.Join(t.TempDir(), "libjvm.so")
	if err := os.WriteFile(lib, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(lib)
	if err != nil {
		t.Fatal(err)
	}
	dev, inode, ok := linuxFileIdentity(info)
	if !ok {
		t.Fatal("Linux file identity unavailable")
	}
	m, n := linuxDeviceNumbers(dev)
	record := fmt.Sprintf("1000-2000 r-xp 00000000 %x:%x %d %s", m, n, inode, lib)
	if got, verified := loadedJVM(proc, []byte(record)); got != lib || !verified {
		t.Fatalf("could not match fixture: %q %t", got, verified)
	}
	other := lib + ".replaced"
	if err := os.Rename(lib, other); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lib, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, verified := loadedJVM(proc, []byte(record)); verified {
		t.Fatal("accepted an in-place replacement runtime")
	}
	if _, verified := loadedJVM(proc, []byte(record+" (deleted)")); verified {
		t.Fatal("accepted a deleted mapping")
	}
}

func TestBriefReport(t *testing.T) {
	t.Run("displays action items with no evidence dump", func(t *testing.T) {
		var out bytes.Buffer
		if err := run([]string{"inventory", "testdata/assets.json"}, &out, &out); err != nil {
			t.Fatal(err)
		}
		for _, text := range []string{"已检查 5 项", "受影响 1", "待确认 1", "无法判断 1", "debian-cpu-eligible", "metadata-missing"} {
			if !strings.Contains(out.String(), text) {
				t.Errorf("missing %q in %q", text, out.String())
			}
		}
		for _, text := range []string{"java_home=", "flags=", "oracle-java-se-updated", "verified-flags-example"} {
			if strings.Contains(out.String(), text) {
				t.Errorf("unexpected %q in %q", text, out.String())
			}
		}
	})
	t.Run("Apple Silicon with six installed JDKs", func(t *testing.T) {
		cpu := darwinCPU("arm64", func(string) string { return "" })
		var r report
		r.CVE, r.Mode = cve, "local"
		versions := []string{"1.8.0_381-b09", "11.0.25+9-LTS-256", "17.0.13+10-LTS-268", "21.0.5+9-LTS-239", "1.7.0", "1.8.0_111"}
		for i, version := range versions {
			arch := "aarch64"
			if i >= 4 {
				arch = "x86_64"
			}
			r.Findings = append(r.Findings, classify(asset{Version: version, Arch: arch, CPU: cpu}))
		}
		var out bytes.Buffer
		if err := writeReport(&out, "txt", r, false); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "已检查 6 项，均不受此漏洞影响。") || !strings.Contains(out.String(), "AVX-512") {
			t.Fatalf("unexpected report: %s", out.String())
		}
	})
}

func TestDarwinCPUEvidence(t *testing.T) {
	for _, tt := range []struct {
		name, arch, want string
		sysctl           map[string]string
	}{
		{"native arm64", "arm64", "absent", nil},
		{"Rosetta", "amd64", "absent", map[string]string{"sysctl.proc_translated": "1"}},
		{"missing Intel features", "amd64", unknown, nil},
		{"Intel without AVX-512", "amd64", "absent", map[string]string{"hw.optional.avx512f": "0"}},
		{"eligible Intel", "amd64", "present", map[string]string{
			"hw.optional.avx512f": "1", "hw.optional.avx512bw": "1", "hw.optional.avx512vbmi": "1", "hw.optional.bmi2": "1",
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := darwinCPU(tt.arch, func(key string) string { return tt.sysctl[key] })
			if got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
	if root := launcherJDKRoot("darwin", "/usr/bin/java"); root != "" {
		t.Fatalf("system launcher incorrectly found a JDK at %q", root)
	}
}
