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

package osvdev

import (
	"testing"

	osvinternal "github.com/bell-sw/osv-internal"

	"github.com/google/osv-scalibr/extractor"
	vendorjdkmeta "github.com/google/osv-scalibr/extractor/filesystem/language/java/vendorjdk/metadata"
	apkmeta "github.com/google/osv-scalibr/extractor/filesystem/os/apk/metadata"
	"github.com/google/osv-scalibr/purl"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
)

// A package of an ecosystem osv.dev does not serve is not queried.
func TestPkgToQueries_LocalOnlyEcosystem(t *testing.T) {
	e := &Enricher{}
	jdk := &extractor.Package{
		Name: "jdk", Version: "21.0.2+14", PURLType: purl.TypeGeneric,
		Metadata: &vendorjdkmeta.Metadata{Ecosystem: osvinternal.Ecosystem(osvinternal.EcosystemJDK, "21"), Major: 21, Variant: "jdk"},
	}
	if got := e.pkgToQueries(jdk); len(got) != 0 {
		t.Errorf("pkgToQueries(vendor JDK package) = %d queries, want none", len(got))
	}
	npm := &extractor.Package{Name: "express", Version: "4.17.1", PURLType: purl.TypeNPM}
	if got := e.pkgToQueries(npm); len(got) != 1 {
		t.Errorf("pkgToQueries(npm package) = %d queries, want 1", len(got))
	}
}

// The ecosystems another enricher was configured to match locally
// (Options.MatchedLocally) are not queried either; the others are unaffected.
func TestPkgToQueries_MatchedLocally(t *testing.T) {
	linux := &extractor.Package{
		Name: "glibc-utils", Version: "2.37.0-r0", PURLType: purl.TypeApk,
		Metadata: &apkmeta.Metadata{OSID: "alpaquita", OSVersionID: "stream", PackageName: "glibc-utils", OriginName: "glibc"},
	}
	hardened := &extractor.Package{
		Name: "zlib", Version: "1.3.1-r0", PURLType: purl.TypeApk,
		Metadata: &apkmeta.Metadata{OSID: "bellsoft-hardened-containers", OSVersionID: "stream", PackageName: "zlib", OriginName: "zlib"},
	}
	npm := &extractor.Package{Name: "express", Version: "4.17.1", PURLType: purl.TypeNPM}

	e := &Enricher{}
	for _, pkg := range []*extractor.Package{linux, hardened, npm} {
		if got := e.pkgToQueries(pkg); len(got) == 0 {
			t.Errorf("unconfigured: pkgToQueries(%s) = no queries, want some", pkg.Name)
		}
	}

	Configure(e, Options{MatchedLocally: func(eco osvconstants.Ecosystem) bool { return eco == osvconstants.EcosystemAlpaquita }})
	if got := e.pkgToQueries(linux); len(got) != 0 {
		t.Errorf("Linux family matched locally: pkgToQueries() = %d queries, want none", len(got))
	}
	for _, pkg := range []*extractor.Package{hardened, npm} {
		if got := e.pkgToQueries(pkg); len(got) == 0 {
			t.Errorf("Linux family matched locally: pkgToQueries(%s) = no queries, want some", pkg.Name)
		}
	}
}
