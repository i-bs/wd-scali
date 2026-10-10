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

package vulns_test

import (
	"testing"

	"github.com/google/osv-scalibr/enricher/vulnmatch/osvlocal/internal/vulns"
	"github.com/google/osv-scalibr/extractor"
	apkmeta "github.com/google/osv-scalibr/extractor/filesystem/os/apk/metadata"
	"github.com/google/osv-scalibr/purl"
	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestOSV_IsAffectedAs_Alias(t *testing.T) {
	vuln := buildOSVWithAffected(
		&osvpb.Affected{
			Package: &osvpb.Package{Ecosystem: "Alpaquita:23", Name: "openjdk21-lite"},
			Ranges:  []*osvpb.Range{buildEcosystemAffectsRange(&osvpb.Event{Introduced: "21_p37-r0"}, &osvpb.Event{Fixed: "21.0.8_p12-r0"})},
		},
		&osvpb.Affected{
			Package: &osvpb.Package{Ecosystem: "BellSoft Hardened Containers:23", Name: "openjdk21-lite"},
			Ranges:  []*osvpb.Range{buildEcosystemAffectsRange(&osvpb.Event{Introduced: "21_p37-r0"}, &osvpb.Event{Fixed: "21.0.2_p14-r0"})},
		},
	)

	pkg := func(osID, version string) *extractor.Package {
		return &extractor.Package{
			Name: "liberica21-lite-jdk-no-deps", Version: version, PURLType: purl.TypeApk,
			Metadata: &apkmeta.Metadata{OSID: osID, OSVersionID: "23", PackageName: "liberica21-lite-jdk-no-deps", OriginName: "liberica21-lite"},
		}
	}

	if vulns.IsAffected(vuln, pkg("alpaquita", "21.0.2_p14-r1")) {
		t.Errorf("IsAffected() under the origin name must not match an advisory keyed on the alias")
	}
	if !vulns.IsAffectedAs(vuln, pkg("alpaquita", "21.0.2_p14-r1"), "openjdk21-lite") {
		t.Errorf("IsAffectedAs(openjdk21-lite) = false, want true for 21.0.2_p14-r1 in [21_p37-r0, 21.0.8_p12-r0)")
	}
	if vulns.IsAffectedAs(vuln, pkg("alpaquita", "21.0.8_p12-r0"), "openjdk21-lite") {
		t.Errorf("IsAffectedAs(openjdk21-lite) = true for the fixed version 21.0.8_p12-r0")
	}
	// the BHC family has its own range for the same package: fixed at 21.0.2_p14-r0
	if vulns.IsAffectedAs(vuln, pkg("bellsoft-hardened-containers", "21.0.2_p14-r1"), "openjdk21-lite") {
		t.Errorf("IsAffectedAs() evaluated the Alpaquita range for a BellSoft Hardened Containers package")
	}
}
