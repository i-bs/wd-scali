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

package osvecosystem_test

import (
	"testing"

	osvinternal "github.com/bell-sw/osv-internal"

	"github.com/google/osv-scalibr/inventory/osvecosystem"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
)

func TestParse_VendorJDK(t *testing.T) {
	jdk21 := osvinternal.Ecosystem(osvinternal.EcosystemJDK, "21")
	got, err := osvecosystem.Parse(jdk21)
	if err != nil {
		t.Fatalf("Parse(%s): %v", jdk21, err)
	}
	want := osvecosystem.Parsed{Ecosystem: osvecosystem.EcosystemVendorJDK, Suffix: "21"}
	if got != want {
		t.Errorf("Parse(%s) = %+v, want %+v", jdk21, got, want)
	}
	if got.String() != jdk21 {
		t.Errorf("String() = %q", got.String())
	}
	if !got.Equal(osvecosystem.Parsed{Ecosystem: osvecosystem.EcosystemVendorJDK, Suffix: "21"}) ||
		got.Equal(osvecosystem.Parsed{Ecosystem: osvecosystem.EcosystemVendorJDK, Suffix: "17"}) {
		t.Errorf("Equal() does not key on the major version suffix")
	}
}

func TestParse_VendorNIK(t *testing.T) {
	nik2321 := osvinternal.Ecosystem(osvinternal.EcosystemNIK, "23-21")
	got, err := osvecosystem.Parse(nik2321)
	if err != nil {
		t.Fatalf("Parse(%s): %v", nik2321, err)
	}
	want := osvecosystem.Parsed{Ecosystem: osvecosystem.EcosystemVendorNIK, Suffix: "23-21"}
	if got != want || got.String() != nik2321 {
		t.Errorf("Parse(%s) = %+v (%q), want %+v", nik2321, got, got.String(), want)
	}
}

func TestIsLocalOnly(t *testing.T) {
	for eco, want := range map[osvconstants.Ecosystem]bool{
		osvecosystem.EcosystemVendorJDK: true, osvecosystem.EcosystemVendorNIK: true,
		osvconstants.EcosystemAlpaquita: false, osvconstants.EcosystemBellSoftHardenedContainers: false, osvconstants.EcosystemAlpine: false,
	} {
		if got := osvecosystem.IsLocalOnly(eco); got != want {
			t.Errorf("IsLocalOnly(%q) = %v, want %v", eco, got, want)
		}
	}
}
