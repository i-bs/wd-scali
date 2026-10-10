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

package osvdev_test

import (
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/enricher/vulnmatch/osvdev"
	"github.com/google/osv-scalibr/enricher/vulnmatch/osvdev/fakeclient"
	"github.com/google/osv-scalibr/extractor"
	apkmeta "github.com/google/osv-scalibr/extractor/filesystem/os/apk/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
)

// TestEnrich_ProvidesAlias: the names of osvutil.QueryNames are queried in
// order and the first one osv.dev knows wins.
func TestEnrich_ProvidesAlias(t *testing.T) {
	alpaquitaJDK := &extractor.Package{
		Name: "liberica21-lite-jdk-no-deps", Version: "21.0.2_p14-r1", PURLType: purl.TypeApk,
		Metadata: &apkmeta.Metadata{
			OSID: "alpaquita", OSVersionID: "23",
			PackageName: "liberica21-lite-jdk-no-deps", OriginName: "liberica21-lite",
			Provides: []string{"java-jdk-no-deps", "java21-jdk-no-deps", "openjdk21-lite-jdk-no-deps"},
		},
	}
	alpaquitaGlibc := &extractor.Package{
		Name: "glibc-utils", Version: "2.37.0-r0", PURLType: purl.TypeApk,
		Metadata: &apkmeta.Metadata{
			OSID: "alpaquita", OSVersionID: "stream",
			PackageName: "glibc-utils", OriginName: "glibc",
			Provides: []string{"glibc-bin"},
		},
	}
	alpineBundle := &extractor.Package{
		Name: "ca-certificates-bundle", Version: "20230506-r0", PURLType: purl.TypeApk,
		Metadata: &apkmeta.Metadata{
			OSID: "alpine", OSVersionID: "3.18.0",
			PackageName: "ca-certificates-bundle", OriginName: "ca-certificates",
			Provides: []string{"ca-certificates-cacert"},
		},
	}

	bell1 := &osvpb.Vulnerability{Id: "BELL-CVE-2025-24855"}
	bell2 := &osvpb.Vulnerability{Id: "BELL-CVE-2026-19499"}
	alias := &osvpb.Vulnerability{Id: "BELL-SHOULD-NOT-MATCH"}
	alpine := &osvpb.Vulnerability{Id: "CVE-ALPINE-CACERT"}

	client := fakeclient.New(map[string][]*osvpb.Vulnerability{
		// keyed on "<name>:<version>:<commit>" by the fake client
		"openjdk21-lite:21.0.2_p14-r1:":       {bell1},
		"glibc:2.37.0-r0:":                    {bell2},
		"glibc-bin:2.37.0-r0:":                {alias},
		"ca-certificates-cacert:20230506-r0:": {alpine},
	})

	inv := &inventory.Inventory{Packages: []*extractor.Package{alpaquitaJDK, alpaquitaGlibc, alpineBundle}}
	e := osvdev.NewWithClient(client, 0)
	if err := e.Enrich(t.Context(), nil, inv); err != nil {
		t.Fatalf("Enrich(): %v", err)
	}

	got := map[string][]string{}
	for _, pv := range inv.PackageVulns {
		got[pv.Package.Name] = append(got[pv.Package.Name], pv.Vulnerability.Id)
		slices.Sort(got[pv.Package.Name])
	}
	want := map[string][]string{
		// resolved through the stripped provided name openjdk21-lite
		"liberica21-lite-jdk-no-deps": {"BELL-CVE-2025-24855"},
		// the origin is known, so the provided name is never consulted
		"glibc-utils": {"BELL-CVE-2026-19499"},
		// Alpine: origin only, the provided name is not queried at all
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("package vulns (-want +got):\n%s", diff)
	}
}
