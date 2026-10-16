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

package apk_test

import (
	"os"
	"testing"

	osvinternal "github.com/bell-sw/osv-internal"
	osvdistro "github.com/bell-sw/osv-internal/distro"
	"github.com/google/go-cmp/cmp"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	apkmeta "github.com/google/osv-scalibr/extractor/filesystem/os/apk/metadata"
	scalibrfs "github.com/google/osv-scalibr/fs"
)

// TestExtract_VendorProvides: the provided names are recorded, and the
// ecosystem and PURL use VERSION_ID verbatim.
func TestExtract_VendorProvides(t *testing.T) {
	osRelease := "ID=" + osvdistro.IDLinux + `
NAME="BellSoft Alpaquita Linux"
VERSION_ID=23
PRETTY_NAME="BellSoft Alpaquita Linux Stream 23 (musl)"`

	e, err := apk.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("apk.New: %v", err)
	}

	d := t.TempDir()
	createOsRelease(t, d, osRelease)

	const path = "testdata/provides-installed"
	r, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	got, err := e.Extract(t.Context(), &filesystem.ScanInput{
		FS: scalibrfs.DirFS(d), Path: path, Reader: r, Root: d, Info: info,
	})
	if err != nil {
		t.Fatalf("Extract(): %v", err)
	}
	if len(got.Packages) != 2 {
		t.Fatalf("Extract() returned %d packages, want 2", len(got.Packages))
	}

	jdk := got.Packages[0]
	wantMeta := &apkmeta.Metadata{
		PackageName:  "liberica21-lite-jdk-no-deps",
		OriginName:   "liberica21-lite",
		OSID:         osvdistro.IDLinux,
		OSVersionID:  "23",
		Maintainer:   "BellSoft <info@bell-sw.com>",
		Architecture: "x86_64",
		Provides:     []string{"java-jdk-no-deps", "java21-jdk-no-deps", "openjdk21-lite-jdk-no-deps"},
	}
	if diff := cmp.Diff(wantMeta, jdk.Metadata); diff != "" {
		t.Errorf("metadata (-want +got):\n%s", diff)
	}
	if got, want := jdk.Ecosystem().String(), osvinternal.Ecosystem(osvinternal.EcosystemLinux, "23"); got != want {
		t.Errorf("Ecosystem() = %q, want %q", got, want)
	}
	if got, want := jdk.PURL().String(), "pkg:apk/"+osvdistro.IDLinux+"/liberica21-lite-jdk-no-deps@21.0.2_p14-r1?arch=x86_64&distro=23&origin=liberica21-lite"; got != want {
		t.Errorf("PURL() = %q, want %q", got, want)
	}

	sh := got.Packages[1]
	if sh.Metadata.(*apkmeta.Metadata).Provides != nil {
		t.Errorf("busybox-binsh Provides = %v, want nil (path and cmd: entries are not package names)", sh.Metadata.(*apkmeta.Metadata).Provides)
	}
}
