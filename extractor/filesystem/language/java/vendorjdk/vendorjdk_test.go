// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vendorjdk_test

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	osvinternal "github.com/bell-sw/osv-internal"
	"github.com/bell-sw/osv-internal/testfix"
	osvjdk "github.com/bell-sw/osv-internal/vendorjdk"
	"github.com/google/go-cmp/cmp"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/vendorjdk"
	vendorjdkmeta "github.com/google/osv-scalibr/extractor/filesystem/language/java/vendorjdk/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
)

func TestFileRequired(t *testing.T) {
	e, err := vendorjdk.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		path string
		want bool
	}{
		{"opt/jdk-21.0.2/lib/server/libjvm.so", true},
		{"usr/lib/jvm/jdk-21.0.2-x86_64/lib/server/libjvm.so", true},
		{"opt/jdk-21.0.2/lib/minimal/libjvm.so", true},
		{"opt/jdk8u402/jre/lib/amd64/server/libjvm.so", true},
		{"Library/Java/JavaVirtualMachines/jdk-21.0.2.jdk/Contents/Home/lib/server/libjvm.dylib", true},
		{"Program Files/Java/jdk-21/bin/server/jvm.dll", true},
		// the release file and rt.jar are candidates too (runtimes whose JVM library is not in the scanned tree)
		{"opt/jdk-21.0.2/release", true},
		{"opt/jdk8u402/jre/lib/rt.jar", true},
		{"opt/jdk-21.0.2/bin/java", false},
		{"opt/jdk-21.0.2/lib/libjava.so", false},
		{"opt/jdk-21.0.2/lib/modules", false},
	}
	for _, tt := range tests {
		if got := e.FileRequired(simplefileapi.New(tt.path, nil)); got != tt.want {
			t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func scanInput(t *testing.T, root, p string) *filesystem.ScanInput {
	t.Helper()
	fsys := scalibrfs.DirFS(root)
	f, err := fsys.Open(p)
	if err != nil {
		t.Fatalf("open %s: %v", p, err)
	}
	t.Cleanup(func() { f.Close() })
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return &filesystem.ScanInput{FS: fsys, Path: p, Root: root, Reader: f, Info: info}
}

// The first family of each kind of the module: the synthetic runtimes of the
// tests carry its vendor-version prefix and are reported in it.
var (
	jdkFamily = testfix.Product(osvinternal.KindJDK).Family
	nikFamily = testfix.Product(osvinternal.KindNIK).Family
)

// fakeDetector stands in for the osv-internal detector so that the glue can
// be tested independently of it: every home under a non-"zulu" path is a
// vendor JDK 21.0.2+14; the JVM library of a home is the first existing
// server library, like the real detector's.
func fakeDetector() vendorjdk.Detector {
	runtime := func(fsys fs.FS, home, libjvm string) *osvjdk.Runtime {
		if strings.HasPrefix(home, "zulu") {
			return nil
		}
		variant := osvjdk.VariantJDK
		if filepath.Base(home) == "jdk21-lite" {
			variant = osvjdk.VariantJDKLite
		}
		if libjvm == "" {
			for _, c := range []string{"lib/server/libjvm.so", "lib/server/libjvm.dylib", "bin/server/jvm.dll", "jre/lib/amd64/server/libjvm.so"} {
				if _, err := fs.Stat(fsys, path.Join(home, c)); err == nil {
					libjvm = path.Join(home, c)
					break
				}
			}
		}
		return &osvjdk.Runtime{
			Product: jdkFamily, Home: home, Major: 21, Variant: variant, Version: "21.0.2+14", Vendor: osvjdk.Vendor,
			LibJVM: libjvm, Evidence: []string{"fake"},
		}
	}
	return vendorjdk.Detector{
		Detect: func(fsys fs.FS, libjvmPath string) (*osvjdk.Runtime, error) {
			home, _ := osvjdk.HomeOf(libjvmPath)
			return runtime(fsys, home, libjvmPath), nil
		},
		DetectHome: func(fsys fs.FS, home string) (*osvjdk.Runtime, error) {
			return runtime(fsys, home, ""), nil
		},
	}
}

func wantPackage(home, variant, libjvm string) []*extractor.Package {
	return []*extractor.Package{{
		Name: variant, Version: "21.0.2+14", PURLType: purl.TypeGeneric,
		Metadata: &vendorjdkmeta.Metadata{
			Ecosystem: osvjdk.EcosystemFor(jdkFamily, 21), PURL: osvjdk.PURL(jdkFamily, variant, "21.0.2+14"),
			Home: home, Major: 21, Variant: variant, Vendor: osvjdk.Vendor, LibJVM: libjvm, Evidence: []string{"fake"},
		},
		Location: extractor.LocationFromPath(home), Plugins: []string{vendorjdk.Name},
	}}
}

func TestExtract_Glue(t *testing.T) {
	e := vendorjdk.NewWithDetector(fakeDetector())
	testdata := buildTestRuntimes(t)

	tests := []struct {
		name string
		root string
		path string
		want []*extractor.Package
	}{
		{name: "JVM library reports the runtime", root: ".", path: "jdk-21.0.2/lib/server/libjvm.so",
			want: wantPackage("jdk-21.0.2", "jdk", "jdk-21.0.2/lib/server/libjvm.so")},
		{name: "second VM flavour of the same runtime stays silent", root: ".", path: "jdk-21.0.2/lib/minimal/libjvm.so"},
		{name: "release file of a runtime that has a JVM library stays silent", root: ".", path: "jdk-21.0.2/release"},
		{name: "rt.jar of a runtime that has a JVM library stays silent", root: ".", path: "jdk8u402/jre/lib/rt.jar"},
		{name: "another vendor (detector returns nil)", root: ".", path: "zulu21/lib/server/libjvm.so"},
		{name: "release file reports a runtime without JVM library (macOS tree)", root: ".", path: "macos/jdk-21.0.2.jdk/release",
			want: wantPackage("macos/jdk-21.0.2.jdk", "jdk", "")},
		{name: "rt.jar stays silent when the home has a release file", root: ".", path: "macos/jdk8u402.jdk/jre/lib/rt.jar"},
		{name: "Windows jvm.dll reports the runtime", root: ".", path: "windows/jdk-21.0.2/bin/server/jvm.dll",
			want: wantPackage("windows/jdk-21.0.2", "jdk", "windows/jdk-21.0.2/bin/server/jvm.dll")},
		{name: "apk-installed runtime on the vendor Linux is covered by the apk ecosystem", root: "vendor-linux", path: "usr/lib/jvm/jdk21-lite/lib/server/libjvm.so"},
		{name: "the same path on another distribution is a standalone install", root: "debian", path: "usr/lib/jvm/jdk-21.0.2-x86_64/lib/server/libjvm.so",
			want: wantPackage("usr/lib/jvm/jdk-21.0.2-x86_64", "jdk", "usr/lib/jvm/jdk-21.0.2-x86_64/lib/server/libjvm.so")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := e.Extract(t.Context(), scanInput(t, filepath.Join(testdata, tt.root), tt.path))
			if err != nil {
				t.Fatalf("Extract(): %v", err)
			}
			if diff := cmp.Diff(inventory.Inventory{Packages: tt.want}, got); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tt.path, diff)
			}
		})
	}
}

func TestPackageIdentity(t *testing.T) {
	nik2321 := osvinternal.Ecosystem(nikFamily, "23-21")
	jdk := &extractor.Package{
		Name: "jdk", Version: "21.0.2+14", PURLType: purl.TypeGeneric,
		Metadata: &vendorjdkmeta.Metadata{Ecosystem: osvjdk.EcosystemFor(jdkFamily, 21), PURL: osvjdk.PURL(jdkFamily, "jdk", "21.0.2+14"), Home: "opt/jdk-21.0.2", Major: 21, Variant: "jdk"},
	}
	if got, want := jdk.Ecosystem().String(), osvjdk.EcosystemFor(jdkFamily, 21); got != want {
		t.Errorf("Ecosystem() = %q, want %q", got, want)
	}
	if got, want := jdk.PURL().String(), osvjdk.PURL(jdkFamily, "jdk", "21.0.2+14"); got != want {
		t.Errorf("PURL() = %q, want %q", got, want)
	}
	if got, want := jdk.Ecosystem().String(), osvjdk.EcosystemFor(jdkFamily, 21); got != want {
		t.Errorf("ecosystem %q differs from the module's %q", got, want)
	}

	// the second product family passes through untouched
	nik := &extractor.Package{
		Name: "core", Version: "23.1.0+1", PURLType: purl.TypeGeneric,
		Metadata: &vendorjdkmeta.Metadata{Ecosystem: nik2321, PURL: osvjdk.PURL(nikFamily, "core", "23.1.0+1"), Major: 21, Variant: "core"},
	}
	if got, want := nik.Ecosystem().String(), nik2321; got != want {
		t.Errorf("Ecosystem() = %q, want %q", got, want)
	}
	if got, want := nik.PURL().String(), osvjdk.PURL(nikFamily, "core", "23.1.0+1"); got != want {
		t.Errorf("PURL() = %q, want %q", got, want)
	}

	// without a purl from the detector the JDK purl is built from variant and version
	jdk8 := &extractor.Package{Name: "jdk", Version: "8u402+7", PURLType: purl.TypeGeneric, Metadata: &vendorjdkmeta.Metadata{Ecosystem: osvjdk.EcosystemFor(jdkFamily, 8), Major: 8, Variant: "jdk"}}
	if got, want := jdk8.PURL().String(), osvjdk.PURL(jdkFamily, "jdk", "8u402+7"); got != want {
		t.Errorf("PURL() = %q, want %q", got, want)
	}
	if got, want := jdk8.Ecosystem().String(), osvjdk.EcosystemFor(jdkFamily, 8); got != want {
		t.Errorf("Ecosystem() = %q, want %q", got, want)
	}
}

// TestExtract_Detector runs the real osv-internal detector over the synthetic
// runtimes in testdata (fake JVM libraries carrying the real strings; macOS
// trees without a JVM library).
func TestExtract_Detector(t *testing.T) {
	nik2321 := osvinternal.Ecosystem(nikFamily, "23-21")
	testdata := buildTestRuntimes(t)
	e, _ := vendorjdk.New(&cpb.PluginConfig{})

	tests := []struct {
		name    string
		root    string
		path    string
		want    *extractor.Package // nil: nothing extracted
		wantEco string
	}{
		{name: "JDK 21", root: ".", path: "jdk-21.0.2/lib/server/libjvm.so",
			want: &extractor.Package{Name: "jdk", Version: "21.0.2+14"}, wantEco: osvjdk.EcosystemFor(jdkFamily, 21)},
		{name: "JDK 21 release file stays silent (JVM library reports)", root: ".", path: "jdk-21.0.2/release"},
		{name: "JRE 21", root: ".", path: "jre-21.0.2/lib/server/libjvm.so",
			want: &extractor.Package{Name: "jre", Version: "21.0.2+14"}, wantEco: osvjdk.EcosystemFor(jdkFamily, 21)},
		{name: "JDK 8 (vendor from rt.jar, version from libjvm.so)", root: ".", path: "jdk8u402/jre/lib/amd64/server/libjvm.so",
			want: &extractor.Package{Name: "jdk", Version: "8u402+7"}, wantEco: osvjdk.EcosystemFor(jdkFamily, 8)},
		{name: "JDK 8 rt.jar stays silent (JVM library reports)", root: ".", path: "jdk8u402/jre/lib/rt.jar"},
		{name: "JDK 21 CSPU (four components)", root: ".", path: "jdk-21.0.12.1/lib/server/libjvm.so",
			want: &extractor.Package{Name: "jdk", Version: "21.0.12.1+1"}, wantEco: osvjdk.EcosystemFor(jdkFamily, 21)},
		{name: "JDK 21 CPU (five components)", root: ".", path: "jdk-21.0.9.0.1/lib/server/libjvm.so",
			want: &extractor.Package{Name: "jdk", Version: "21.0.9.0.1+1"}, wantEco: osvjdk.EcosystemFor(jdkFamily, 21)},
		{name: "JDK 8 CSPU", root: ".", path: "jdk8u504/jre/lib/amd64/server/libjvm.so",
			want: &extractor.Package{Name: "jdk", Version: "8u504+1"}, wantEco: osvjdk.EcosystemFor(jdkFamily, 8)},
		{name: "JDK 8 CPU", root: ".", path: "jdk8u481/jre/lib/amd64/server/libjvm.so",
			want: &extractor.Package{Name: "jdk", Version: "8u481+1"}, wantEco: osvjdk.EcosystemFor(jdkFamily, 8)},
		{name: "macOS JDK 21 without JVM library: release file", root: ".", path: "macos/jdk-21.0.2.jdk/release",
			want: &extractor.Package{Name: "jdk", Version: "21.0.2+14"}, wantEco: osvjdk.EcosystemFor(jdkFamily, 21)},
		{name: "Windows JDK 21: jvm.dll", root: ".", path: "windows/jdk-21.0.2/bin/server/jvm.dll",
			want: &extractor.Package{Name: "jdk", Version: "21.0.2+14"}, wantEco: osvjdk.EcosystemFor(jdkFamily, 21)},
		{name: "NIK 23.1.0 core is reported in its own ecosystem, never as a JDK", root: ".", path: "nik-23.1.0/lib/server/libjvm.so",
			want: &extractor.Package{Name: "core", Version: "23.1.0+1"}, wantEco: nik2321},
		{name: "Azul Zulu is not the vendor's", root: ".", path: "zulu21/lib/server/libjvm.so"},
		{name: "Azul Zulu release file is not the vendor's", root: ".", path: "zulu21/release"},
		{name: "apk-installed runtime on the vendor Linux is skipped", root: "vendor-linux", path: "usr/lib/jvm/jdk21-lite/lib/server/libjvm.so"},
		{name: "a runtime under /usr/lib/jvm on Debian is reported", root: "debian", path: "usr/lib/jvm/jdk-21.0.2-x86_64/lib/server/libjvm.so",
			want: &extractor.Package{Name: "jdk", Version: "21.0.2+14"}, wantEco: osvjdk.EcosystemFor(jdkFamily, 21)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := e.Extract(t.Context(), scanInput(t, filepath.Join(testdata, tt.root), tt.path))
			if err != nil {
				t.Fatalf("Extract(): %v", err)
			}
			if tt.want == nil {
				if len(got.Packages) != 0 {
					t.Fatalf("Extract(%s) = %+v, want nothing", tt.path, got.Packages[0])
				}
				return
			}
			if len(got.Packages) != 1 {
				t.Fatalf("Extract(%s) returned %d packages, want 1", tt.path, len(got.Packages))
			}
			p := got.Packages[0]
			if p.Name != tt.want.Name || p.Version != tt.want.Version || p.Ecosystem().String() != tt.wantEco {
				t.Errorf("Extract(%s) = %s %s %s, want %s %s %s", tt.path, p.Ecosystem(), p.Name, p.Version, tt.wantEco, tt.want.Name, tt.want.Version)
			}
			wantPURL := osvjdk.PURL(osvinternal.Family(tt.wantEco), tt.want.Name, tt.want.Version)
			if p.PURL() == nil || p.PURL().String() != wantPURL {
				t.Errorf("PURL() = %v, want %s", p.PURL(), wantPURL)
			}
		})
	}

	// the macOS 8 tree: release without vendor, rt.jar carries it; the rt.jar candidate stays silent
	// because the home has a release file, which is the anchor
	got, err := e.Extract(t.Context(), scanInput(t, testdata, "macos/jdk8u402.jdk/release"))
	if err != nil {
		t.Fatalf("Extract(macos 8 release): %v", err)
	}
	if len(got.Packages) != 1 || got.Packages[0].Version != "8u402" && got.Packages[0].Version != "8u402+7" {
		t.Errorf("Extract(macos 8 release) = %+v, want jdk 8u402 (vendor from the rt.jar manifest)", got.Packages)
	}
	_ = os.Getenv
}
