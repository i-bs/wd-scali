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

	osvinternal "github.com/bell-sw/osv-internal"
	"github.com/bell-sw/osv-internal/testfix"

	"github.com/google/osv-scalibr/enricher/vulnmatch/osvlocal/internal/vulns"
	"github.com/google/osv-scalibr/extractor"
	vendorjdkmeta "github.com/google/osv-scalibr/extractor/filesystem/language/java/vendorjdk/metadata"
	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
)

// The three kinds of JDK update release (PSU, CSPU, CPU) against
// advisory ranges; the cases mirror the range tests of osv-internal/jdkver.
func TestOSV_IsAffected_VendorJDKReleaseTypes(t *testing.T) {
	vuln := func(ecosystem, introduced, fixed, last string) *osvpb.Vulnerability {
		events := []*osvpb.Event{{Introduced: introduced}}
		if fixed != "" {
			events = append(events, &osvpb.Event{Fixed: fixed})
		}
		if last != "" {
			events = append(events, &osvpb.Event{LastAffected: last})
		}

		return buildOSVWithAffected(&osvpb.Affected{
			Package: &osvpb.Package{Ecosystem: ecosystem, Name: "jdk"},
			Ranges:  []*osvpb.Range{buildEcosystemAffectsRange(events...)},
		})
	}
	pkg := func(ecosystem, version string) *extractor.Package {
		return &extractor.Package{
			Name: "jdk", Version: version,
			Metadata: &vendorjdkmeta.Metadata{Ecosystem: ecosystem, Variant: "jdk"},
		}
	}

	jdk21, jdk8 := osvinternal.Ecosystem(testfix.Product(osvinternal.KindJDK).Family, "21"), osvinternal.Ecosystem(testfix.Product(osvinternal.KindJDK).Family, "8")
	tests := []struct {
		name                                        string
		ecosystem, version, introduced, fixed, last string
		want                                        bool
	}{
		// fixed only in the August 2026 CSPU
		{"PSU before the CSPU fix", jdk21, "21.0.12+10", "21", "21.0.12.1+1", "", true},
		{"CSPU clears", jdk21, "21.0.12.1+1", "21", "21.0.12.1+1", "", false},
		{"CSPU release-file form clears", jdk21, "21.0.12.1+1-LTS", "21", "21.0.12.1+1", "", false},
		{"CRaC CSPU build clears", jdk21, "21.0.12.1+2", "21", "21.0.12.1+1", "", false},
		{"next PSU clears", jdk21, "21.0.13+5", "21", "21.0.12.1+1", "", false},
		{"older PSU affected", jdk21, "21.0.2+14", "21", "21.0.12.1+1", "", true},
		{"CPU of the quarter does not carry the CSPU fix", jdk21, "21.0.11.0.1+1", "21", "21.0.12.1+1", "", true},
		{"Java 8 PSU before the CSPU fix", jdk8, "8u502+9", "8u0", "8u504+1", "", true},
		{"Java 8 CSPU clears", jdk8, "8u504+1", "8u0", "8u504+1", "", false},
		{"Java 8 CSPU banner form clears", jdk8, "1.8.0_504-b01", "8u0", "8u504+1", "", false},
		{"Java 8 CPU before the CSPU fix", jdk8, "8u501+1", "8u0", "8u504+1", "", true},
		// fixed in the July 2026 PSU
		{"PSU fix: previous PSU affected", jdk21, "21.0.11+11", "21", "21.0.12+10", "", true},
		{"PSU fix: PSU clears", jdk21, "21.0.12+10", "21", "21.0.12+10", "", false},
		{"PSU fix: later CSPU clears", jdk21, "21.0.12.1+1", "21", "21.0.12+10", "", false},
		{"PSU fix: CPU of the same quarter clears", jdk21, "21.0.11.0.1+1", "21", "21.0.12+10", "", false},
		{"PSU fix: CPU of the previous quarter affected", jdk21, "21.0.10.0.1+1", "21", "21.0.12+10", "", true},
		{"PSU fix: Java 8 CPU of the same quarter clears", jdk8, "8u501+1", "8u0", "8u502+9", "", false},
		{"PSU fix: Java 8 CPU banner form clears", jdk8, "1.8.0_501-b01", "8u0", "8u502+9", "", false},
		{"PSU fix: Java 8 previous CPU affected", jdk8, "8u491+1", "8u0", "8u502+9", "", true},
		{"PSU fix: Java 8 previous PSU affected", jdk8, "8u492+9", "8u0", "8u502+9", "", true},
		// January 2026 cycle (the advisories list "Fixed (21.0.10+10)", "Fixed (8u482+10)")
		{"Jan CPU vs its cycle's PSU fix", jdk21, "21.0.9.0.1", "21", "21.0.10+10", "", false},
		{"Jan CPU with build vs its cycle's PSU fix", jdk21, "21.0.9.0.1+1-LTS", "21", "21.0.10+10", "", false},
		{"Jan CPU vs a later cycle's fix", jdk21, "21.0.9.0.1", "21", "21.0.11+11", "", true},
		{"PSU before the Jan PSU fix", jdk21, "21.0.9+15", "21", "21.0.10+10", "", true},
		{"Java 8 Jan CPU vs its cycle's PSU fix", jdk8, "8u481", "8u0", "8u482+10", "", false},
		{"Java 8 Jan CPU vs a later cycle's fix", jdk8, "8u481+1", "8u0", "8u492+9", "", true},
		{"Java 8 PSU before the Jan PSU fix", jdk8, "8u472+11", "8u0", "8u482+10", "", true},
		// a regression introduced in a PSU does not reach the CPU of that quarter
		{"regression in the PSU, CPU not affected", jdk21, "21.0.11.0.1+1", "21.0.12+10", "21.0.12.1+1", "", false},
		{"regression in the PSU, PSU affected", jdk21, "21.0.12+10", "21.0.12+10", "21.0.12.1+1", "", true},
		// last_affected bounds
		{"last_affected PSU, CPU of that quarter affected", jdk21, "21.0.11.0.1+1", "21", "", "21.0.12+10", true},
		{"last_affected PSU, CSPU not affected", jdk21, "21.0.12.1+1", "21", "", "21.0.12+10", false},
		// line-start boundaries of the prototype data
		{"line start 21, GA", jdk21, "21+37", "21", "21.0.12.1+1", "", true},
		{"line start 21, CPU", jdk21, "21.0.0.0.1+1", "21", "21.0.1+12", "", false},
		{"line start 8u0", jdk8, "8u402+7", "8u0", "8u504+1", "", true},
		{"line start 8u0, banner", jdk8, "1.8.0_442-b09", "8u0", "8u442+9", "", false},
		{"introduced 0", jdk21, "21.0.9.0.1+1", "0", "21.0.10+10", "", false},
		{"unfixed", jdk21, "21.0.12.1+1", "21", "", "", true},
	}
	for _, tt := range tests {
		got := vulns.IsAffected(vuln(tt.ecosystem, tt.introduced, tt.fixed, tt.last), pkg(tt.ecosystem, tt.version))
		if got != tt.want {
			t.Errorf("%s: %s %s, introduced %q fixed %q last_affected %q: IsAffected() = %v, want %v",
				tt.name, tt.ecosystem, tt.version, tt.introduced, tt.fixed, tt.last, got, tt.want)
		}
	}
}
