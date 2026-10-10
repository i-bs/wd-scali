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

package osvutil_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/enricher/vulnmatch/internal/osvutil"
	"github.com/google/osv-scalibr/extractor"
	apkmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/apk/metadata"
	"github.com/google/osv-scalibr/purl"
)

func TestQueryNames(t *testing.T) {
	tests := []struct {
		name string
		pkg  *extractor.Package
		want []string
	}{
		{
			name: "non-apk package has a single name",
			pkg:  &extractor.Package{PURLType: purl.TypeNPM, Name: "express", Version: "4.17.1"},
			want: []string{"express"},
		},
		{
			name: "alpaquita JDK sub-package resolves through provides and suffix stripping",
			pkg: &extractor.Package{
				PURLType: purl.TypeApk, Name: "liberica21-lite-jdk-no-deps", Version: "21.0.2_p14-r1",
				Metadata: &apkmetadata.Metadata{
					OSID: "alpaquita", OSVersionID: "23",
					PackageName: "liberica21-lite-jdk-no-deps", OriginName: "liberica21-lite",
					Provides: []string{"java-jdk-no-deps", "java21-jdk-no-deps", "openjdk21-lite-jdk-no-deps"},
				},
			},
			// every provided name, then every provided name without the "-jdk-no-deps" suffix
			want: []string{"liberica21-lite", "java-jdk-no-deps", "java21-jdk-no-deps", "openjdk21-lite-jdk-no-deps", "java", "java21", "openjdk21-lite"},
		},
		{
			name: "bellsoft hardened containers main package (no suffix)",
			pkg: &extractor.Package{
				PURLType: purl.TypeApk, Name: "liberica21", Version: "21.0.2_p14-r1",
				Metadata: &apkmetadata.Metadata{
					OSID: "bellsoft-hardened-containers", OSVersionID: "stream",
					PackageName: "liberica21", OriginName: "liberica21",
					Provides: []string{"openjdk21", "java-jdk"},
				},
			},
			want: []string{"liberica21", "openjdk21", "java-jdk"},
		},
		{
			name: "duplicates are removed and the origin stays first",
			pkg: &extractor.Package{
				PURLType: purl.TypeApk, Name: "glibc-utils", Version: "2.43.0-r10",
				Metadata: &apkmetadata.Metadata{
					OSID: "alpaquita", OSVersionID: "stream",
					PackageName: "glibc-utils", OriginName: "glibc",
					Provides: []string{"glibc-utils", "glibc"},
				},
			},
			want: []string{"glibc", "glibc-utils"},
		},
		{
			name: "alpine keeps origin-only matching",
			pkg: &extractor.Package{
				PURLType: purl.TypeApk, Name: "ca-certificates-bundle", Version: "20230506-r0",
				Metadata: &apkmetadata.Metadata{
					OSID: "alpine", OSVersionID: "3.18.0",
					PackageName: "ca-certificates-bundle", OriginName: "ca-certificates",
					Provides: []string{"ca-certificates-cacert"},
				},
			},
			want: []string{"ca-certificates"},
		},
		{
			name: "alpaquita package without provides",
			pkg: &extractor.Package{
				PURLType: purl.TypeApk, Name: "zlib", Version: "1.3.2-r1",
				Metadata: &apkmetadata.Metadata{OSID: "alpaquita", OSVersionID: "25", PackageName: "zlib", OriginName: "zlib"},
			},
			want: []string{"zlib"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := osvutil.QueryNames(tc.pkg)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("QueryNames() (-want +got):\n%s", diff)
			}
		})
	}
}
