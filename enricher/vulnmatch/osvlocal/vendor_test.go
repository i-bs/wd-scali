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
	"fmt"
	"maps"
	"net/http"
	"path"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/google/osv-scalibr/enricher/vulnmatch/osvlocal/internal/fakeserver"
	"github.com/google/osv-scalibr/extractor"
	vendorjdkmeta "github.com/google/osv-scalibr/extractor/filesystem/language/java/vendorjdk/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/purl"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
)

// warnings captures what the enricher logs at warning level.
type warnings struct {
	log.DefaultLogger

	mu    sync.Mutex
	lines []string
}

func (w *warnings) Warnf(format string, args ...any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lines = append(w.lines, fmt.Sprintf(format, args...))
}

func captureWarnings(t *testing.T) *warnings {
	t.Helper()
	w := &warnings{}
	log.SetLogger(w)
	t.Cleanup(func() { log.SetLogger(&log.DefaultLogger{}) })

	return w
}

// recorder is an http.RoundTripper that records the requested URLs and
// answers every request with the given status.
type recorder struct {
	mu     sync.Mutex
	status int
	urls   []string
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.urls = append(r.urls, req.Method+" "+req.URL.String())

	return &http.Response{
		StatusCode: r.status, Status: fmt.Sprintf("%d %s", r.status, http.StatusText(r.status)),
		Body: http.NoBody, Header: http.Header{}, Request: req,
	}, nil
}

func vendorJDKPkg(ecosystem, name, version string) *extractor.Package {
	return &extractor.Package{
		Name: name, Version: version, PURLType: purl.TypeGeneric,
		Metadata: &vendorjdkmeta.Metadata{Ecosystem: ecosystem, Variant: name},
	}
}

func vendorJDKOSVs() map[string]*osvpb.Vulnerability {
	return map[string]*osvpb.Vulnerability{
		"BELL-CVE-2025-24855.json": {
			Id:       "BELL-CVE-2025-24855",
			Upstream: []string{"CVE-2025-24855"},
			Affected: []*osvpb.Affected{{
				Package: &osvpb.Package{Ecosystem: "Liberica JDK:21", Name: "jdk"},
				Ranges:  []*osvpb.Range{{Type: osvpb.Range_ECOSYSTEM, Events: []*osvpb.Event{{Introduced: "21"}, {Fixed: "21.0.8+12"}}}},
			}},
		},
	}
}

const (
	osvDevBucket = "https://osv-vulnerabilities.storage.googleapis.com"
	wantJDKURL   = "https://packages.bell-sw.com/osv/Liberica%20JDK/all.zip"
	wantNIKURL   = "https://packages.bell-sw.com/osv/Liberica%20NIK/all.zip"
)

// The runtime archives are requested from the module's default location;
// an HTTP 404 there is one warning per family, not an error.
func TestEnrich_VendorRuntimeDefaultURLAndUnavailableWarning(t *testing.T) {
	w := captureWarnings(t)
	rt := &recorder{status: http.StatusNotFound}
	e := &Enricher{zippedDBRemoteHost: osvDevBucket, localPath: createTestDir(t), download: true, httpClient: &http.Client{Transport: rt}}

	inv := &inventory.Inventory{Packages: []*extractor.Package{
		vendorJDKPkg("Liberica JDK:21", "jdk", "21.0.2+14"),
		vendorJDKPkg("Liberica JDK:8", "jdk", "8u402+7"),
		vendorJDKPkg("Liberica NIK:23-21", "core", "23.1.0+1"),
	}}
	if err := e.Enrich(t.Context(), nil, inv); err != nil {
		t.Fatalf("Enrich() = %v, want no error (an unavailable vendor archive is a warning)", err)
	}
	if len(inv.PackageVulns) != 0 || len(inv.Packages) != 3 {
		t.Errorf("got %d packages and %d findings, want the 3 packages kept without findings", len(inv.Packages), len(inv.PackageVulns))
	}

	for _, want := range []string{"GET " + wantJDKURL, "GET " + wantNIKURL} {
		n := 0
		for _, u := range rt.urls {
			if u == want {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%q requested %d times, want once; requests: %v", want, n, rt.urls)
		}
	}
	for _, u := range rt.urls {
		if strings.Contains(u, "storage.googleapis.com") {
			t.Errorf("the osv.dev bucket was asked for a runtime family: %s", u)
		}
	}

	wantWarnings := []string{
		`BellSoft OSV data for "Liberica JDK" is unavailable (HTTP 404); packages of this product were NOT checked against BellSoft advisories. Source: ` + wantJDKURL,
		`BellSoft OSV data for "Liberica NIK" is unavailable (HTTP 404); packages of this product were NOT checked against BellSoft advisories. Source: ` + wantNIKURL,
	}
	if len(w.lines) != len(wantWarnings) {
		t.Fatalf("warnings = %q, want exactly one per family", w.lines)
	}
	for i, want := range wantWarnings {
		if w.lines[i] != want {
			t.Errorf("warning %d = %q, want %q", i, w.lines[i], want)
		}
	}
}

// Strict mode turns the warning into a failure that carries the same text.
func TestEnrich_UnavailableStrict(t *testing.T) {
	w := captureWarnings(t)
	rt := &recorder{status: http.StatusNotFound}
	e := &Enricher{zippedDBRemoteHost: osvDevBucket, localPath: createTestDir(t), download: true, httpClient: &http.Client{Transport: rt}}
	Configure(e, Options{VendorStrict: true})

	inv := &inventory.Inventory{Packages: []*extractor.Package{vendorJDKPkg("Liberica JDK:21", "jdk", "21.0.2+14")}}
	err := e.Enrich(t.Context(), nil, inv)
	if err == nil || !strings.Contains(err.Error(), `BellSoft OSV data for "Liberica JDK" is unavailable (HTTP 404)`) {
		t.Errorf("Enrich() = %v, want an error with the unavailable text", err)
	}
	if len(w.lines) != 0 {
		t.Errorf("warnings = %q, want none in strict mode (the failure is reported)", w.lines)
	}
}

// The precedence of archiveURL: feed, vendor base URL, built-in default.
func TestArchiveURL(t *testing.T) {
	const mirror = "https://mirror.example/osv"
	tests := []struct {
		name  string
		host  string
		url   string
		feeds map[string]string
		eco   string
		want  string
	}{
		{"defaults: Alpaquita from the bucket", osvDevBucket, "", nil, "Alpaquita", osvDevBucket + "/Alpaquita/all.zip"},
		{"defaults: BHC from the bucket", osvDevBucket, "", nil, "BellSoft Hardened Containers", osvDevBucket + "/BellSoft Hardened Containers/all.zip"},
		{"defaults: Liberica JDK from the BellSoft default", osvDevBucket, "", nil, "Liberica JDK", wantJDKURL},
		{"defaults: Liberica NIK from the BellSoft default", osvDevBucket, "", nil, "Liberica NIK", wantNIKURL},
		{"bucket mirror serves Alpaquita", mirror, "", nil, "Alpaquita", mirror + "/Alpaquita/all.zip"},
		{"bucket mirror never serves Liberica JDK", mirror, "", nil, "Liberica JDK", wantJDKURL},
		{"bucket mirror serves other ecosystems", mirror, "https://bell.example/osv", nil, "PyPI", mirror + "/PyPI/all.zip"},
		{"vendor URL: Alpaquita", mirror, "https://bell.example/osv/", nil, "Alpaquita", "https://bell.example/osv/Alpaquita/all.zip"},
		{"vendor URL: BHC", osvDevBucket, "https://bell.example/osv", nil, "BellSoft Hardened Containers", "https://bell.example/osv/BellSoft%20Hardened%20Containers/all.zip"},
		{"vendor URL: Liberica JDK", osvDevBucket, "https://bell.example/osv", nil, "Liberica JDK", "https://bell.example/osv/Liberica%20JDK/all.zip"},
		{"vendor URL: a directory", osvDevBucket, "/srv/osv", nil, "Liberica NIK", "file:///srv/osv/Liberica NIK/all.zip"},
		{"vendor URL: file://", osvDevBucket, "file:///srv/osv", nil, "Liberica NIK", "file:///srv/osv/Liberica NIK/all.zip"},
		{"feed wins over the vendor URL", osvDevBucket, "https://bell.example/osv", map[string]string{"Liberica JDK": "https://feed.example/x"}, "Liberica JDK", "https://feed.example/x/Liberica%20JDK/all.zip"},
		{"feed of another family does not apply", osvDevBucket, "https://bell.example/osv", map[string]string{"Liberica JDK": "https://feed.example/x"}, "Liberica NIK", "https://bell.example/osv/Liberica%20NIK/all.zip"},
		{"feed: the archive itself", osvDevBucket, "", map[string]string{"Liberica JDK": "https://feed.example/jdk.zip"}, "Liberica JDK", "https://feed.example/jdk.zip"},
		{"feed: a local archive", osvDevBucket, "", map[string]string{"Alpaquita": "/data/linux.zip"}, "Alpaquita", "file:///data/linux.zip"},
		{"feed: a file:// archive", osvDevBucket, "", map[string]string{"Alpaquita": "file:///data/linux.zip"}, "Alpaquita", "file:///data/linux.zip"},
	}
	for _, tt := range tests {
		m := &localMatcher{zippedDBRemoteHost: tt.host, vendorURL: tt.url, vendorFeeds: tt.feeds}
		if got := m.archiveURL(osvconstants.Ecosystem(tt.eco)); got != tt.want {
			t.Errorf("%s: archiveURL(%s) = %q, want %q", tt.name, tt.eco, got, tt.want)
		}
	}
}

func TestParseVendorFeeds(t *testing.T) {
	got, err := ParseVendorFeeds([]string{"liberica jdk=https://a.example/osv", " BellSoft Hardened Containers = /srv/bhc.zip ", "", "ALPAQUITA=file:///x?a=b"})
	want := map[string]string{"Liberica JDK": "https://a.example/osv", "BellSoft Hardened Containers": "/srv/bhc.zip", "Alpaquita": "file:///x?a=b"}
	if err != nil || !maps.Equal(got, want) {
		t.Errorf("ParseVendorFeeds() = %v, %v, want %v", got, err, want)
	}
	for _, bad := range []string{"Liberica JDK", "=https://a.example", "Liberica JDK=", "Zulu=https://a.example"} {
		if _, err := ParseVendorFeeds([]string{bad}); err == nil {
			t.Errorf("ParseVendorFeeds(%q) = nil error, want an error", bad)
		}
	}
}

// The vendor base URL (and a feed, which wins) is where the runtime
// archives are requested, and their records are matched.
func TestEnrich_VendorURLAndFeed(t *testing.T) {
	w := captureWarnings(t)
	var mu sync.Mutex
	var paths []string
	ts := fakeserver.CreateZipServer(t, func(rw http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		if strings.HasPrefix(r.URL.Path, "/base/") {
			http.NotFound(rw, r)

			return
		}
		_, _ = fakeserver.WriteOSVsZip(t, rw, vendorJDKOSVs())
	})
	e := &Enricher{zippedDBRemoteHost: osvDevBucket, localPath: createTestDir(t), download: true, httpClient: http.DefaultClient}
	Configure(e, Options{VendorURL: ts.URL + "/base", VendorFeeds: map[string]string{"Liberica JDK": ts.URL + "/feed"}})

	inv := &inventory.Inventory{Packages: []*extractor.Package{
		vendorJDKPkg("Liberica JDK:21", "jdk", "21.0.2+14"),
		vendorJDKPkg("Liberica NIK:23-21", "core", "23.1.0+1"),
	}}
	if err := e.Enrich(t.Context(), nil, inv); err != nil {
		t.Fatalf("Enrich() = %v", err)
	}
	if len(inv.PackageVulns) != 1 || inv.PackageVulns[0].Vulnerability.GetId() != "BELL-CVE-2025-24855" {
		t.Errorf("findings = %v, want BELL-CVE-2025-24855 for the JDK (from the feed)", inv.PackageVulns)
	}
	if !slices.Contains(paths, "/feed/Liberica JDK/all.zip") || !slices.Contains(paths, "/base/Liberica NIK/all.zip") || slices.Contains(paths, "/base/Liberica JDK/all.zip") {
		t.Errorf("requested paths = %q, want the JDK from /feed and the NIK from /base", paths)
	}
	wantWarning := `BellSoft OSV data for "Liberica NIK" is unavailable (HTTP 404); packages of this product were NOT checked against BellSoft advisories. Source: ` + ts.URL + `/base/Liberica%20NIK/all.zip`
	if len(w.lines) != 1 || w.lines[0] != wantWarning {
		t.Errorf("warnings = %q, want %q", w.lines, wantWarning)
	}
}

// A local feed (the archive itself) is read from disk.
func TestEnrich_VendorFeedFile(t *testing.T) {
	captureWarnings(t)
	dir := createTestDir(t)
	archive := path.Join(dir, "feeds", "jdk.zip")
	cacheWrite(t, archive, fakeserver.ZipOSVs(t, vendorJDKOSVs()))
	e := &Enricher{zippedDBRemoteHost: osvDevBucket, localPath: dir, download: true, httpClient: &http.Client{Transport: &recorder{status: http.StatusNotFound}}}
	Configure(e, Options{VendorFeeds: map[string]string{"Liberica JDK": archive}})

	inv := &inventory.Inventory{Packages: []*extractor.Package{vendorJDKPkg("Liberica JDK:21", "jdk", "21.0.2+14")}}
	if err := e.Enrich(t.Context(), nil, inv); err != nil || len(inv.PackageVulns) != 1 {
		t.Errorf("Enrich() = %v with %d findings, want 1 finding from the local archive", err, len(inv.PackageVulns))
	}
}

// LocalOnlyEcosystems: the enricher handles the ecosystems api.osv.dev does
// not serve, downloads their archives even without downloads enabled, and
// leaves every other package alone.
func TestEnrich_LocalOnlyEcosystems(t *testing.T) {
	captureWarnings(t)
	var mu sync.Mutex
	var paths []string
	ts := fakeserver.CreateZipServer(t, func(rw http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		_, _ = fakeserver.WriteOSVsZip(t, rw, vendorJDKOSVs())
	})
	e := &Enricher{zippedDBRemoteHost: osvDevBucket, localPath: createTestDir(t), download: false, httpClient: http.DefaultClient}
	Configure(e, Options{LocalOnlyEcosystems: true, VendorURL: ts.URL})

	jdk := vendorJDKPkg("Liberica JDK:21", "jdk", "21.0.2+14")
	inv := &inventory.Inventory{Packages: []*extractor.Package{aliasJDK, aliasGlibc, jdk}}
	if err := e.Enrich(t.Context(), nil, inv); err != nil {
		t.Fatalf("Enrich() = %v", err)
	}
	if len(inv.PackageVulns) != 1 || inv.PackageVulns[0].Package != jdk {
		t.Errorf("findings = %v, want one finding for the JDK package only", inv.PackageVulns)
	}
	for _, p := range paths {
		if p != "/Liberica JDK/all.zip" {
			t.Errorf("archive %q requested, want only the Liberica JDK archive", p)
		}
	}
}

// Offline with no cached archive: a warning for the vendor families (all
// four), still an error for every other ecosystem.
func TestEnrich_OfflineNoCache(t *testing.T) {
	w := captureWarnings(t)
	rt := &recorder{status: http.StatusOK}
	dir := createTestDir(t)
	e := &Enricher{zippedDBRemoteHost: osvDevBucket, localPath: dir, download: false, httpClient: &http.Client{Transport: rt}}

	inv := &inventory.Inventory{Packages: []*extractor.Package{aliasJDK, aliasBHC, vendorJDKPkg("Liberica JDK:21", "jdk", "21.0.2+14")}}
	if err := e.Enrich(t.Context(), nil, inv); err != nil {
		t.Fatalf("Enrich() = %v, want no error for vendor families", err)
	}
	want := []string{
		`BellSoft OSV data for "Alpaquita" is unavailable (offline and not cached); packages of this product were NOT checked against BellSoft advisories. Source: ` + osvDevBucket + `/Alpaquita/all.zip`,
		`BellSoft OSV data for "BellSoft Hardened Containers" is unavailable (offline and not cached); packages of this product were NOT checked against BellSoft advisories. Source: ` + osvDevBucket + `/BellSoft Hardened Containers/all.zip`,
		`BellSoft OSV data for "Liberica JDK" is unavailable (offline and not cached); packages of this product were NOT checked against BellSoft advisories. Source: ` + wantJDKURL,
	}
	if strings.Join(w.lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("warnings:\n%s\nwant:\n%s", strings.Join(w.lines, "\n"), strings.Join(want, "\n"))
	}
	if len(rt.urls) != 0 {
		t.Errorf("requests made while offline: %v", rt.urls)
	}

	// a cached archive is used as before
	cacheWrite(t, path.Join(dir, "osv-scalibr", "Liberica JDK", "all.zip"), fakeserver.ZipOSVs(t, vendorJDKOSVs()))
	inv = &inventory.Inventory{Packages: []*extractor.Package{vendorJDKPkg("Liberica JDK:21", "jdk", "21.0.2+14")}}
	if err := e.Enrich(t.Context(), nil, inv); err != nil || len(inv.PackageVulns) != 1 {
		t.Errorf("with a cached archive: err = %v, %d findings, want 1", err, len(inv.PackageVulns))
	}

	// another ecosystem: unchanged, the missing database is an error
	pypi := &extractor.Package{Name: "requests", Version: "2.31.0", PURLType: purl.TypePyPi}
	if err := e.Enrich(t.Context(), nil, &inventory.Inventory{Packages: []*extractor.Package{pypi}}); err == nil {
		t.Errorf("Enrich() of a PyPI package without a cached database = nil, want an error")
	}
}
