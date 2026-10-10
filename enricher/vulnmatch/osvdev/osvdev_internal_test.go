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
	"github.com/google/osv-scalibr/purl"
)

// A package of an ecosystem osv.dev does not serve is not queried.
func TestPkgToQueries_LocalOnlyEcosystem(t *testing.T) {
	jdk := &extractor.Package{
		Name: "jdk", Version: "21.0.2+14", PURLType: purl.TypeGeneric,
		Metadata: &vendorjdkmeta.Metadata{Ecosystem: osvinternal.Ecosystem(osvinternal.EcosystemJDK, "21"), Major: 21, Variant: "jdk"},
	}
	if got := pkgToQueries(jdk); len(got) != 0 {
		t.Errorf("pkgToQueries(vendor JDK package) = %d queries, want none", len(got))
	}
	npm := &extractor.Package{Name: "express", Version: "4.17.1", PURLType: purl.TypeNPM}
	if got := pkgToQueries(npm); len(got) != 1 {
		t.Errorf("pkgToQueries(npm package) = %d queries, want 1", len(got))
	}
}
