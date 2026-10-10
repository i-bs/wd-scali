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

package osvlocal

import (
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/enricher/vulnmatch/osvlocal/internal/fakeserver"
	"github.com/google/osv-scalibr/extractor"
	apkmeta "github.com/google/osv-scalibr/extractor/filesystem/os/apk/metadata"
	"github.com/google/osv-scalibr/purl"
	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
)

func vendorOSVs() map[string]*osvpb.Vulnerability {
	rng := func(introduced, fixed string) []*osvpb.Range {
		return []*osvpb.Range{{Type: osvpb.Range_ECOSYSTEM, Events: []*osvpb.Event{{Introduced: introduced}, {Fixed: fixed}}}}
	}
	return map[string]*osvpb.Vulnerability{
		"BELL-CVE-2025-24855.json": {
			Id:       "BELL-CVE-2025-24855",
			Upstream: []string{"CVE-2025-24855"},
			Affected: []*osvpb.Affected{
				{Package: &osvpb.Package{Ecosystem: "Alpaquita:23", Name: "openjdk21-lite"}, Ranges: rng("21_p37-r0", "21.0.8_p12-r0")},
				{Package: &osvpb.Package{Ecosystem: "Alpaquita:stream", Name: "openjdk21-lite"}, Ranges: rng("21_p37-r0", "21.0.8_p12-r0")},
				{Package: &osvpb.Package{Ecosystem: "BellSoft Hardened Containers:23", Name: "openjdk21-lite"}, Ranges: rng("21_p37-r0", "21.0.8_p12-r0")},
			},
		},
		"BELL-CVE-2024-20918.json": {
			Id:       "BELL-CVE-2024-20918",
			Upstream: []string{"CVE-2024-20918"},
			Affected: []*osvpb.Affected{
				{Package: &osvpb.Package{Ecosystem: "Alpaquita:23", Name: "openjdk21-lite"}, Ranges: rng("21_p37-r0", "21.0.2_p14-r0")},
			},
		},
		"BELL-CVE-2026-19499.json": {
			Id:       "BELL-CVE-2026-19499",
			Upstream: []string{"CVE-2026-19499"},
			Affected: []*osvpb.Affected{
				{Package: &osvpb.Package{Ecosystem: "Alpaquita:stream", Name: "glibc"}, Ranges: rng("0", "2.43.0-r6")},
				{Package: &osvpb.Package{Ecosystem: "BellSoft Hardened Containers:stream", Name: "glibc"}, Ranges: rng("0", "2.43.0-r6")},
			},
		},
		"BELL-ALIAS-TRAP.json": {
			Id: "BELL-ALIAS-TRAP",
			Affected: []*osvpb.Affected{
				{Package: &osvpb.Package{Ecosystem: "Alpaquita:stream", Name: "glibc-bin"}, Ranges: rng("0", "9")},
			},
		},
	}
}

var (
	aliasJDK = &extractor.Package{
		Name: "liberica21-lite-jdk-no-deps", Version: "21.0.2_p14-r1", PURLType: purl.TypeApk,
		Metadata: &apkmeta.Metadata{
			OSID: "alpaquita", OSVersionID: "23",
			PackageName: "liberica21-lite-jdk-no-deps", OriginName: "liberica21-lite",
			Provides: []string{"java-jdk-no-deps", "java21-jdk-no-deps", "openjdk21-lite-jdk-no-deps"},
		},
	}
	aliasGlibc = &extractor.Package{
		Name: "glibc-utils", Version: "2.37.0-r0", PURLType: purl.TypeApk,
		Metadata: &apkmeta.Metadata{
			OSID: "alpaquita", OSVersionID: "stream",
			PackageName: "glibc-utils", OriginName: "glibc",
			Provides: []string{"glibc-bin"},
		},
	}
	aliasBHC = &extractor.Package{
		Name: "liberica21-lite-jre-no-deps", Version: "21.0.9_p11-r0", PURLType: purl.TypeApk,
		Metadata: &apkmeta.Metadata{
			OSID: "bellsoft-hardened-containers", OSVersionID: "23",
			PackageName: "liberica21-lite-jre-no-deps", OriginName: "liberica21-lite",
			Provides: []string{"openjdk21-lite-jre-no-deps"},
		},
	}
)

func matchIDs(t *testing.T, m *localMatcher, pkg *extractor.Package, all []*extractor.Package) []string {
	t.Helper()
	vulns, err := m.MatchVulnerabilities(t.Context(), pkg, all)
	if err != nil {
		t.Fatalf("MatchVulnerabilities(%s): %v", pkg.Name, err)
	}
	ids := make([]string, 0, len(vulns))
	for _, v := range vulns {
		ids = append(ids, v.GetId())
	}
	slices.Sort(ids)
	return ids
}

// TestLocalMatcher_ProvidesAlias: the names of osvutil.QueryNames are tried
// against a local database; the first one the feed knows is used.
func TestLocalMatcher_ProvidesAlias(t *testing.T) {
	testDir := createTestDir(t)

	ts := fakeserver.CreateZipServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/all.zip") {
			http.NotFound(w, r)
			return
		}
		_, _ = fakeserver.WriteOSVsZip(t, w, vendorOSVs())
	})

	m, err := newlocalMatcher(testDir, userAgent, true, ts.URL, http.DefaultClient)
	if err != nil {
		t.Fatalf("newlocalMatcher: %v", err)
	}
	all := []*extractor.Package{aliasJDK, aliasGlibc, aliasBHC}

	// 21.0.2_p14-r1 is past the 21.0.2_p14-r0 fix of BELL-CVE-2024-20918 and
	// inside the range of BELL-CVE-2025-24855.
	if diff := cmp.Diff([]string{"BELL-CVE-2025-24855"}, matchIDs(t, m, aliasJDK, all)); diff != "" {
		t.Errorf("JDK (Alpaquita:23) (-want +got):\n%s", diff)
	}
	// the origin "glibc" is known: the provided name "glibc-bin" is never used
	if diff := cmp.Diff([]string{"BELL-CVE-2026-19499"}, matchIDs(t, m, aliasGlibc, all)); diff != "" {
		t.Errorf("glibc-utils (Alpaquita:stream) (-want +got):\n%s", diff)
	}
	// BHC:23 ranges are evaluated separately; 21.0.9_p11-r0 is fixed
	if diff := cmp.Diff([]string{}, matchIDs(t, m, aliasBHC, all)); diff != "" {
		t.Errorf("JRE (BellSoft Hardened Containers:23) (-want +got):\n%s", diff)
	}

	// the archives were cached under <dir>/osv-scalibr/<ecosystem>/all.zip
	for _, eco := range []string{"Alpaquita", "BellSoft Hardened Containers"} {
		if _, err := os.Stat(filepath.Join(testDir, "osv-scalibr", eco, "all.zip")); err != nil {
			t.Errorf("archive for %q not cached: %v", eco, err)
		}
	}
}

// TestLocalMatcher_FileURLAndLegacyCache: the archive host can be a file://
// directory, and the <dir>/osv-scanner/<ecosystem>/ layout of earlier
// osv-scanner releases is found in offline mode.
func TestLocalMatcher_FileURLAndLegacyCache(t *testing.T) {
	archive := fakeserver.ZipOSVs(t, vendorOSVs())

	t.Run("file url", func(t *testing.T) {
		testDir := createTestDir(t)
		hostDir := filepath.Join(testDir, "host")
		cacheWrite(t, path.Join(hostDir, "Alpaquita", "all.zip"), archive)

		m, err := newlocalMatcher(filepath.Join(testDir, "cache"), userAgent, true, "file://"+hostDir, http.DefaultClient)
		if err != nil {
			t.Fatalf("newlocalMatcher: %v", err)
		}
		if diff := cmp.Diff([]string{"BELL-CVE-2025-24855"}, matchIDs(t, m, aliasJDK, []*extractor.Package{aliasJDK})); diff != "" {
			t.Errorf("(-want +got):\n%s", diff)
		}
		if _, err := os.Stat(filepath.Join(testDir, "cache", "osv-scalibr", "Alpaquita", "all.zip")); err != nil {
			t.Errorf("archive read from file:// was not cached: %v", err)
		}
	})

	t.Run("legacy layout offline", func(t *testing.T) {
		testDir := createTestDir(t)
		cacheWrite(t, path.Join(testDir, "osv-scanner", "Alpaquita", "all.zip"), archive)

		m, err := newlocalMatcher(testDir, userAgent, false, "http://127.0.0.1:1", http.DefaultClient)
		if err != nil {
			t.Fatalf("newlocalMatcher: %v", err)
		}
		if diff := cmp.Diff([]string{"BELL-CVE-2025-24855"}, matchIDs(t, m, aliasJDK, []*extractor.Package{aliasJDK})); diff != "" {
			t.Errorf("(-want +got):\n%s", diff)
		}
	})

	t.Run("missing offline", func(t *testing.T) {
		testDir := createTestDir(t)
		m, err := newlocalMatcher(testDir, userAgent, false, "http://127.0.0.1:1", http.DefaultClient)
		if err != nil {
			t.Fatalf("newlocalMatcher: %v", err)
		}
		// strict: for a family of the vendor's products this is only a warning by default (vendor_test.go)
		m.vendorStrict = true
		if _, err := m.MatchVulnerabilities(t.Context(), aliasJDK, []*extractor.Package{aliasJDK}); err == nil {
			t.Errorf("expected an error for a missing offline database, got none")
		}
	})
}

// TestLocalMatcher_DownloadFailureUsesCache: a failed download falls back to
// the cached copy; without a cache it is an error (for vendor families only
// in strict mode, see vendor_test.go).
func TestLocalMatcher_DownloadFailureUsesCache(t *testing.T) {
	archive := fakeserver.ZipOSVs(t, vendorOSVs())

	ts := fakeserver.CreateZipServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	t.Run("cached copy kept on 404", func(t *testing.T) {
		testDir := createTestDir(t)
		cacheWrite(t, path.Join(testDir, "osv-scalibr", "Alpaquita", "all.zip"), archive)

		m, err := newlocalMatcher(testDir, userAgent, true, ts.URL, http.DefaultClient)
		if err != nil {
			t.Fatalf("newlocalMatcher: %v", err)
		}
		if diff := cmp.Diff([]string{"BELL-CVE-2025-24855"}, matchIDs(t, m, aliasJDK, []*extractor.Package{aliasJDK})); diff != "" {
			t.Errorf("(-want +got):\n%s", diff)
		}
	})

	t.Run("no cache and 404 is an error", func(t *testing.T) {
		testDir := createTestDir(t)
		m, err := newlocalMatcher(testDir, userAgent, true, ts.URL, http.DefaultClient)
		if err != nil {
			t.Fatalf("newlocalMatcher: %v", err)
		}
		m.vendorStrict = true
		if _, err := m.MatchVulnerabilities(t.Context(), aliasJDK, []*extractor.Package{aliasJDK}); err == nil {
			t.Errorf("expected an error, got none")
		}
	})
}
