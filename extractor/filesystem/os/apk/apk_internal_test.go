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

package apk

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseProvides(t *testing.T) {
	tests := []struct {
		name  string
		field string
		want  []string
	}{
		{name: "empty", field: "", want: nil},
		{name: "only_shared_objects_and_commands", field: "so:libapk.so.2.14.0=2.14.0 cmd:apk=2.14.0-r0", want: nil},
		{name: "path_entry_is_not_a_name", field: "/bin/sh cmd:sh=1.36.0-r9", want: nil},
		{name: "versioned_and_unversioned_names", field: "java-jdk-no-deps java21-jdk-no-deps openjdk21-lite-jdk-no-deps=21.0.2_p14-r1 cmd:java=21.0.2_p14-r1", want: []string{"java-jdk-no-deps", "java21-jdk-no-deps", "openjdk21-lite-jdk-no-deps"}},
		{name: "pkgconfig_entries_dropped", field: "pc:zlib=1.3.1 zlib-compat=1.3.1-r1", want: []string{"zlib-compat"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseProvides(tt.field)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("parseProvides(%q) (-want +got):\n%s", tt.field, diff)
			}
		})
	}
}
