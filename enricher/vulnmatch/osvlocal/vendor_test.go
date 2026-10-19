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
	"net/url"
	"path"
	"slices"
	"strings"
	"sync"
	"testing"

	osvinternal "github.com/bell-sw/osv-internal"
	"github.com/bell-sw/osv-internal/testfix"
	"github.com/bell-sw/osv-internal/osvdata"
	"github.com/google/osv-scalibr/enricher/vulnmatch/osvlocal/internal/fakeserver"
	"github.com/google/osv-scalibr/extractor"
	vendorjdkmeta "github.com/google/osv-scalibr/extractor/filesystem/language/java/vendorjdk/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/osvecosystem"
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
				Package: &osvpb.Package{Ecosystem: ecoJDK21, Name: "jdk"},
				Ranges:  []*osvpb.Range{{Type: osvpb.Range_ECOSYSTEM, Events: []*osvpb.Event{{Introduced: "21"}, {Fixed: "21.0.8+12"}}}},
			}},
		},
	}
}

const osvDevBucket = "https://osv-vulnerabilities.storage.googleapis.com"

// The vendor families and ecosystems of the module, and where the module
// fetches the product archives by default.
var (
	famLinux, famHardened, famJDK, famNIK = osvinternal.EcosystemLinux, osvinternal.EcosystemHardened, testfix.Product(osvinternal.KindJDK).Family, testfix.Product(osvinternal.KindNIK).Family
	ecoJDK21, ecoJDK8, ecoNIK2321         = osvinternal.Ecosystem(famJDK, "21"), osvinternal.Ecosystem(famJDK, "8"), osvinternal.Ecosystem(famNIK, "23-21")
	wantJDKURL                            = osvdata.DefaultProductBaseURL + "/" + url.PathEscape(famJDK) + "/all.zip"
	wantNIKURL                            = osvdata.DefaultProductBaseURL + "/" + url.PathEscape(famNIK) + "/all.zip"
)

// unavailableAt is the module's canonical warning for a family whose archive
// could not be obtained from the given source.
func unavailableAt(family, reason, source string) string {
	return (&osvdata.UnavailableError{Family: family, Reason: reason, URL: source}).Warning()
}

// defaultURL is the built-in archive location of a vendor distribution: the
// archive host when osv.dev carries it, else the module's default.
func defaultURL(host, family string) string {
	if osvecosystem.IsLocalOnly(osvconstants.Ecosystem(family)) {
		return osvdata.DefaultBaseURLFor(family) + "/" + url.PathEscape(family) + "/all.zip"
	}
	return host + "/" + family + "/all.zip"
}

// The runtime archives are requested from the module's default location;
// an HTTP 404 there is one warning per family, not an error.
func TestEnrich_VendorRuntimeDefaultURLAndUnavailableWarning(t *testing.T) {
	w := captureWarnings(t)
	rt := &recorder{status: http.StatusNotFound}
	e := &Enricher{zippedDBRemoteHost: osvDevBucket, localPath: createTestDir(t), download: true, httpClient: &http.Client{Transport: rt}}

	inv := &inventory.Inventory{Packages: []*extractor.Package{
		vendorJDKPkg(ecoJDK21, "jdk", "21.0.2+14"),
		vendorJDKPkg(ecoJDK8, "jdk", "8u402+7"),
		vendorJDKPkg(ecoNIK2321, "core", "23.1.0+1"),
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
		unavailableAt(famJDK, "HTTP 404", wantJDKURL),
		unavailableAt(famNIK, "HTTP 404", wantNIKURL),
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

// Strict mode turns the warning into a failure with the same text, also when
// a cached copy exists (it may be stale or from another source); without
// strict mode the cached copy is used, with a warning.
func TestEnrich_UnavailableStrict(t *testing.T) {
	w := captureWarnings(t)
	rt := &recorder{status: http.StatusNotFound}
	dir := createTestDir(t)
	e := &Enricher{zippedDBRemoteHost: osvDevBucket, localPath: dir, download: true, httpClient: &http.Client{Transport: rt}}
	Configure(e, Options{VendorStrict: true})

	inv := &inventory.Inventory{Packages: []*extractor.Package{vendorJDKPkg(ecoJDK21, "jdk", "21.0.2+14")}}
	err := e.Enrich(t.Context(), nil, inv)
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("%s OSV data for %q is unavailable (HTTP 404)", osvinternal.Vendor, famJDK)) {
		t.Errorf("Enrich() = %v, want an error with the unavailable text", err)
	}
	if len(w.lines) != 0 {
		t.Errorf("warnings = %q, want none in strict mode (the failure is reported)", w.lines)
	}

	// a cached copy does not satisfy strict mode
	cacheWrite(t, path.Join(dir, "osv-scalibr", famJDK, "all.zip"), fakeserver.ZipOSVs(t, vendorJDKOSVs()))
	inv = &inventory.Inventory{Packages: []*extractor.Package{vendorJDKPkg(ecoJDK21, "jdk", "21.0.2+14")}}
	err = e.Enrich(t.Context(), nil, inv)
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("%s OSV data for %q is unavailable (HTTP 404)", osvinternal.Vendor, famJDK)) {
		t.Errorf("Enrich() with a cached copy = %v, want the same error (the cached copy must not be used in strict mode)", err)
	}
	if len(inv.PackageVulns) != 0 || len(w.lines) != 0 {
		t.Errorf("with a cached copy: %d findings, warnings = %q, want none of either", len(inv.PackageVulns), w.lines)
	}

	// without strict mode the cached copy is used, and said so
	e = &Enricher{zippedDBRemoteHost: osvDevBucket, localPath: dir, download: true, httpClient: &http.Client{Transport: rt}}
	inv = &inventory.Inventory{Packages: []*extractor.Package{vendorJDKPkg(ecoJDK21, "jdk", "21.0.2+14")}}
	if err := e.Enrich(t.Context(), nil, inv); err != nil || len(inv.PackageVulns) != 1 {
		t.Errorf("Enrich() without strict mode, cached copy: err = %v, %d findings, want 1 from the cached copy", err, len(inv.PackageVulns))
	}
	if len(w.lines) != 1 || !strings.HasPrefix(w.lines[0], "could not update the "+famJDK+" OSV database, using the cached copy: ") {
		t.Errorf("warnings = %q, want one about the cached copy", w.lines)
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
		{"defaults: the distribution from the bucket, unless local-only", osvDevBucket, "", nil, famLinux, defaultURL(osvDevBucket, famLinux)},
		{"defaults: the hardened images from the bucket, unless local-only", osvDevBucket, "", nil, famHardened, defaultURL(osvDevBucket, famHardened)},
		{"defaults: the JDK from the module's default", osvDevBucket, "", nil, famJDK, wantJDKURL},
		{"defaults: the NIK from the module's default", osvDevBucket, "", nil, famNIK, wantNIKURL},
		{"bucket mirror serves the distribution, unless local-only", mirror, "", nil, famLinux, defaultURL(mirror, famLinux)},
		{"bucket mirror never serves the JDK", mirror, "", nil, famJDK, wantJDKURL},
		{"bucket mirror serves other ecosystems", mirror, "https://bell.example/osv", nil, "PyPI", mirror + "/PyPI/all.zip"},
		{"vendor URL: the distribution", mirror, "https://bell.example/osv/", nil, famLinux, "https://bell.example/osv/" + url.PathEscape(famLinux) + "/all.zip"},
		{"vendor URL: the hardened images", osvDevBucket, "https://bell.example/osv", nil, famHardened, "https://bell.example/osv/" + url.PathEscape(famHardened) + "/all.zip"},
		{"vendor URL: the JDK", osvDevBucket, "https://bell.example/osv", nil, famJDK, "https://bell.example/osv/" + url.PathEscape(famJDK) + "/all.zip"},
		{"vendor URL: a directory", osvDevBucket, "/srv/osv", nil, famNIK, "file:///srv/osv/" + famNIK + "/all.zip"},
		{"vendor URL: file://", osvDevBucket, "file:///srv/osv", nil, famNIK, "file:///srv/osv/" + famNIK + "/all.zip"},
		{"feed wins over the vendor URL", osvDevBucket, "https://bell.example/osv", map[string]string{famJDK: "https://feed.example/x"}, famJDK, "https://feed.example/x/" + url.PathEscape(famJDK) + "/all.zip"},
		{"feed of another family does not apply", osvDevBucket, "https://bell.example/osv", map[string]string{famJDK: "https://feed.example/x"}, famNIK, "https://bell.example/osv/" + url.PathEscape(famNIK) + "/all.zip"},
		{"feed: the archive itself", osvDevBucket, "", map[string]string{famJDK: "https://feed.example/jdk.zip"}, famJDK, "https://feed.example/jdk.zip"},
		{"feed: a local archive", osvDevBucket, "", map[string]string{famLinux: "/data/linux.zip"}, famLinux, "file:///data/linux.zip"},
		{"feed: a file:// archive", osvDevBucket, "", map[string]string{famLinux: "file:///data/linux.zip"}, famLinux, "file:///data/linux.zip"},
	}
	for _, tt := range tests {
		m := &localMatcher{zippedDBRemoteHost: tt.host, vendorURL: tt.url, vendorFeeds: tt.feeds}
		if got := m.archiveURL(osvconstants.Ecosystem(tt.eco)); got != tt.want {
			t.Errorf("%s: archiveURL(%s) = %q, want %q", tt.name, tt.eco, got, tt.want)
		}
	}
}

func TestParseVendorFeeds(t *testing.T) {
	got, err := ParseVendorFeeds([]string{strings.ToLower(famJDK) + "=https://a.example/osv", " " + famHardened + " = /srv/bhc.zip ", "", strings.ToUpper(famLinux) + "=file:///x?a=b"})
	want := map[string]string{famJDK: "https://a.example/osv", famHardened: "/srv/bhc.zip", famLinux: "file:///x?a=b"}
	if err != nil || !maps.Equal(got, want) {
		t.Errorf("ParseVendorFeeds() = %v, %v, want %v", got, err, want)
	}
	for _, bad := range []string{famJDK, "=https://a.example", famJDK + "=", "Zulu=https://a.example"} {
		if _, err := ParseVendorFeeds([]string{bad}); err == nil {
			t.Errorf("ParseVendorFeeds(%q) = nil error, want an error", bad)
		}
	}
}

// The vendor base URL (and a feed, which wins) is where the runtime
// archives are requested, and their records are matched; an empty configured
// source is a warning.
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
	Configure(e, Options{VendorURL: ts.URL + "/base", VendorFeeds: map[string]string{famJDK: ts.URL + "/feed"}})

	inv := &inventory.Inventory{Packages: []*extractor.Package{
		vendorJDKPkg(ecoJDK21, "jdk", "21.0.2+14"),
		vendorJDKPkg(ecoNIK2321, "core", "23.1.0+1"),
	}}
	if err := e.Enrich(t.Context(), nil, inv); err != nil {
		t.Fatalf("Enrich() = %v", err)
	}
	if len(inv.PackageVulns) != 1 || inv.PackageVulns[0].Vulnerability.GetId() != "BELL-CVE-2025-24855" {
		t.Errorf("findings = %v, want BELL-CVE-2025-24855 for the JDK (from the feed)", inv.PackageVulns)
	}
	if !slices.Contains(paths, "/feed/"+famJDK+"/all.zip") || !slices.Contains(paths, "/base/"+famNIK+"/all.zip") || slices.Contains(paths, "/base/"+famJDK+"/all.zip") {
		t.Errorf("requested paths = %q, want the JDK from /feed and the NIK from /base", paths)
	}
	wantWarning := unavailableAt(famNIK, "HTTP 404", ts.URL+"/base/"+url.PathEscape(famNIK)+"/all.zip")
	if len(w.lines) != 1 || w.lines[0] != wantWarning {
		t.Errorf("warnings = %q, want %q", w.lines, wantWarning)
	}
}

// An unavailable configured source is handled like a built-in default: a
// warning naming the source, a failure with VendorStrict.
func TestEnrich_ConfiguredSourceUnavailable(t *testing.T) {
	w := captureWarnings(t)
	rt := &recorder{status: http.StatusNotFound}
	e := &Enricher{zippedDBRemoteHost: osvDevBucket, localPath: createTestDir(t), download: true, httpClient: &http.Client{Transport: rt}}
	Configure(e, Options{VendorFeeds: map[string]string{famNIK: "https://feed.example/osv"}})

	inv := &inventory.Inventory{Packages: []*extractor.Package{
		vendorJDKPkg(ecoJDK21, "jdk", "21.0.2+14"),
		vendorJDKPkg(ecoNIK2321, "core", "23.1.0+1"),
	}}
	if err := e.Enrich(t.Context(), nil, inv); err != nil {
		t.Errorf("Enrich() = %v, want nil (an unavailable configured source is a warning)", err)
	}
	warned := func(family, source string) bool {
		return slices.ContainsFunc(w.lines, func(l string) bool {
			return strings.HasPrefix(l, fmt.Sprintf("%s OSV data for %q is unavailable (HTTP 404)", osvinternal.Vendor, family)) && strings.Contains(l, "Source: "+source)
		})
	}
	if len(w.lines) != 2 || !warned(famNIK, "https://feed.example/osv/") || !warned(famJDK, osvdata.DefaultProductBaseURL) {
		t.Errorf("warnings = %q, want one for the NIK naming the configured feed and one for the JDK naming the default source", w.lines)
	}
	if len(inv.Packages) != 2 {
		t.Errorf("got %d packages, want both kept", len(inv.Packages))
	}

	// strict mode: the configured source fails the enricher like a default one
	w.lines = nil
	e = &Enricher{zippedDBRemoteHost: osvDevBucket, localPath: createTestDir(t), download: true, httpClient: &http.Client{Transport: rt}}
	Configure(e, Options{VendorURL: "https://bell.example/osv", VendorStrict: true})
	inv = &inventory.Inventory{Packages: []*extractor.Package{vendorJDKPkg(ecoJDK21, "jdk", "21.0.2+14"), aliasJDK}}
	err := e.Enrich(t.Context(), nil, inv)
	for _, family := range []string{famJDK, famLinux} {
		if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("%s OSV data for %q is unavailable (HTTP 404)", osvinternal.Vendor, family)) {
			t.Errorf("Enrich() = %v, want an error naming %q", err, family)
		}
	}
	if len(w.lines) != 0 {
		t.Errorf("warnings = %q, want none", w.lines)
	}
}

// A local feed (the archive itself) is read from disk.
func TestEnrich_VendorFeedFile(t *testing.T) {
	captureWarnings(t)
	dir := createTestDir(t)
	archive := path.Join(dir, "feeds", "jdk.zip")
	cacheWrite(t, archive, fakeserver.ZipOSVs(t, vendorJDKOSVs()))
	e := &Enricher{zippedDBRemoteHost: osvDevBucket, localPath: dir, download: true, httpClient: &http.Client{Transport: &recorder{status: http.StatusNotFound}}}
	Configure(e, Options{VendorFeeds: map[string]string{famJDK: archive}})

	inv := &inventory.Inventory{Packages: []*extractor.Package{vendorJDKPkg(ecoJDK21, "jdk", "21.0.2+14")}}
	if err := e.Enrich(t.Context(), nil, inv); err != nil || len(inv.PackageVulns) != 1 {
		t.Errorf("Enrich() = %v with %d findings, want 1 finding from the local archive", err, len(inv.PackageVulns))
	}
}

// LocalOnlyEcosystems: the enricher handles the ecosystems api.osv.dev does
// not serve and the vendor families with a configured source, downloads
// their archives even without downloads enabled, and leaves every other
// package alone.
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
	requested := func() []string {
		mu.Lock()
		defer mu.Unlock()
		got := slices.Clone(paths)
		paths = nil
		slices.Sort(got)

		return slices.Compact(got)
	}
	pypi := &extractor.Package{Name: "requests", Version: "2.31.0", PURLType: purl.TypePyPi}
	jdk := vendorJDKPkg(ecoJDK21, "jdk", "21.0.2+14")

	// only the JDK family has a configured source: the distributions stay with api.osv.dev
	e := &Enricher{zippedDBRemoteHost: osvDevBucket, localPath: createTestDir(t), download: false, httpClient: http.DefaultClient}
	Configure(e, Options{LocalOnlyEcosystems: true, VendorFeeds: map[string]string{famJDK: ts.URL}})
	inv := &inventory.Inventory{Packages: []*extractor.Package{aliasJDK, aliasGlibc, aliasBHC, pypi, jdk}}
	if err := e.Enrich(t.Context(), nil, inv); err != nil {
		t.Fatalf("Enrich() = %v", err)
	}
	if len(inv.PackageVulns) != 1 || inv.PackageVulns[0].Package != jdk {
		t.Errorf("findings = %v, want one finding for the JDK package only", inv.PackageVulns)
	}
	if got, want := requested(), []string{"/" + famJDK + "/all.zip"}; !slices.Equal(got, want) {
		t.Errorf("archives requested = %q, want %q", got, want)
	}

	// --vendor-url configures every vendor family: their archives are
	// consulted; the PyPI package is still left to api.osv.dev
	e = &Enricher{zippedDBRemoteHost: osvDevBucket, localPath: createTestDir(t), download: false, httpClient: http.DefaultClient}
	Configure(e, Options{LocalOnlyEcosystems: true, VendorURL: ts.URL})
	inv = &inventory.Inventory{Packages: []*extractor.Package{aliasJDK, aliasGlibc, aliasBHC, pypi, jdk}}
	if err := e.Enrich(t.Context(), nil, inv); err != nil {
		t.Fatalf("Enrich() = %v", err)
	}
	if len(inv.PackageVulns) != 1 || inv.PackageVulns[0].Package != jdk {
		t.Errorf("findings = %v, want one finding for the JDK package only (the served archive has no records of the Linux family)", inv.PackageVulns)
	}
	want := []string{"/" + famLinux + "/all.zip", "/" + famHardened + "/all.zip", "/" + famJDK + "/all.zip"}
	slices.Sort(want)
	if got := requested(); !slices.Equal(got, want) {
		t.Errorf("archives requested = %q, want %q", got, want)
	}
}

// Options.MatchedLocally and Options.Configured, as handed to vulnmatch/osvdev.
func TestOptions_MatchedLocally(t *testing.T) {
	tests := []struct {
		name           string
		opts           Options
		eco            string
		configured     bool
		matchedLocally bool
	}{
		{"nothing configured: the JDK is local-only", Options{}, famJDK, false, true},
		{"nothing configured: the distribution goes to the API, unless local-only", Options{}, famLinux, false, osvecosystem.IsLocalOnly(osvecosystem.EcosystemVendorLinux)},
		{"nothing configured: PyPI goes to the API", Options{}, "PyPI", false, false},
		{"URL: the distribution", Options{VendorURL: "/srv/osv"}, famLinux, true, true},
		{"URL: the hardened images", Options{VendorURL: "https://bell.example/osv"}, famHardened, true, true},
		{"URL: the NIK", Options{VendorURL: "https://bell.example/osv"}, famNIK, true, true},
		{"URL: PyPI is not a vendor family", Options{VendorURL: "https://bell.example/osv"}, "PyPI", false, false},
		{"feed: the family", Options{VendorFeeds: map[string]string{famLinux: "/srv/a.zip"}}, famLinux, true, true},
		{"feed: another family goes to the API, unless local-only", Options{VendorFeeds: map[string]string{famLinux: "/srv/a.zip"}}, famHardened, false, osvecosystem.IsLocalOnly(osvecosystem.EcosystemVendorHardened)},
		{"feed: a full ecosystem string", Options{VendorFeeds: map[string]string{famLinux: "/srv/a.zip"}}, famLinux + ":stream", true, true},
	}
	for _, tt := range tests {
		eco := osvconstants.Ecosystem(tt.eco)
		if got := tt.opts.Configured(eco); got != tt.configured {
			t.Errorf("%s: Configured(%s) = %v, want %v", tt.name, tt.eco, got, tt.configured)
		}
		if got := tt.opts.MatchedLocally(eco); got != tt.matchedLocally {
			t.Errorf("%s: MatchedLocally(%s) = %v, want %v", tt.name, tt.eco, got, tt.matchedLocally)
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

	inv := &inventory.Inventory{Packages: []*extractor.Package{aliasJDK, aliasBHC, vendorJDKPkg(ecoJDK21, "jdk", "21.0.2+14")}}
	want := []string{
		unavailableAt(famLinux, "offline and not cached", defaultURL(osvDevBucket, famLinux)),
		unavailableAt(famHardened, "offline and not cached", defaultURL(osvDevBucket, famHardened)),
		unavailableAt(famJDK, "offline and not cached", wantJDKURL),
	}
	if err := e.Enrich(t.Context(), nil, inv); err != nil {
		t.Fatalf("Enrich() = %v, want no error for vendor families", err)
	}
	if strings.Join(w.lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("warnings:\n%s\nwant:\n%s", strings.Join(w.lines, "\n"), strings.Join(want, "\n"))
	}
	if len(rt.urls) != 0 {
		t.Errorf("requests made while offline: %v", rt.urls)
	}

	// a cached archive is used as before
	cacheWrite(t, path.Join(dir, "osv-scalibr", famJDK, "all.zip"), fakeserver.ZipOSVs(t, vendorJDKOSVs()))
	inv = &inventory.Inventory{Packages: []*extractor.Package{vendorJDKPkg(ecoJDK21, "jdk", "21.0.2+14")}}
	if err := e.Enrich(t.Context(), nil, inv); err != nil || len(inv.PackageVulns) != 1 {
		t.Errorf("with a cached archive: err = %v, %d findings, want 1", err, len(inv.PackageVulns))
	}

	// another ecosystem: unchanged, the missing database is an error
	pypi := &extractor.Package{Name: "requests", Version: "2.31.0", PURLType: purl.TypePyPi}
	if err := e.Enrich(t.Context(), nil, &inventory.Inventory{Packages: []*extractor.Package{pypi}}); err == nil {
		t.Errorf("Enrich() of a PyPI package without a cached database = nil, want an error")
	}
}
