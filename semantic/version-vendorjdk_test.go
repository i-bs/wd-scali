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

package semantic_test

import (
	"errors"
	"testing"

	osvinternal "github.com/bell-sw/osv-internal"
	"github.com/bell-sw/osv-internal/testfix"

	"github.com/google/osv-scalibr/semantic"
)

func TestVendorJDKVersion_Compare(t *testing.T) {
	runAgainstEcosystemFixture(t, testfix.Product(osvinternal.KindJDK).Family, "vendorjdk-versions.txt")
}

func TestVendorNIKVersion_Compare(t *testing.T) {
	runAgainstEcosystemFixture(t, testfix.Product(osvinternal.KindNIK).Family, "vendornik-versions.txt")
}

func TestVendorJDKVersion_Suffix(t *testing.T) {
	// the ecosystem suffix (Java major line) must not change the comparison
	v, err := semantic.Parse("21.0.2+14", osvinternal.Ecosystem(testfix.Product(osvinternal.KindJDK).Family, "21"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, _ := v.CompareStr("21.0.8+12"); got != -1 {
		t.Errorf("21.0.2+14 vs 21.0.8+12 = %d, want -1", got)
	}
}

func TestParseVendorJDKVersion(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"21.0.2+14-LTS", "21.0.2+14"},
		{"21.0.2+14", "21.0.2+14"},
		{"21+37", "21+37"},
		{"1.8.0_402-b07", "8u402+7"},
		{"1.8.0_402", "8u402"},
		{"8u402+7", "8u402+7"},
		{"21.0.12.1+1", "21.0.12.1+1"},
		{"26-ea+5", "26+5"},
		// CSPU builds
		{"21.0.12.1+1-LTS", "21.0.12.1+1"},
		{"8u504+1", "8u504+1"},
		{"1.8.0_504-b01", "8u504+1"},
		// CPU builds
		{"21.0.11.0.1+1-LTS", "21.0.11.0.1+1"},
		{"21.0.9.0.1+1-LTS", "21.0.9.0.1+1"},
		{"21.0.9.0.1", "21.0.9.0.1"},
		{"8u481", "8u481"},
		{"8u501+1", "8u501+1"},
	}
	for _, tt := range tests {
		got, err := semantic.ParseVendorJDKVersion(tt.in)
		if err != nil {
			t.Errorf("ParseVendorJDKVersion(%q): %v", tt.in, err)
			continue
		}
		if got.String() != tt.want {
			t.Errorf("ParseVendorJDKVersion(%q) = %q, want %q", tt.in, got.String(), tt.want)
		}
	}

	for _, bad := range []string{"abc", "21.x", "8u", "1.8.0_402-b"} {
		if _, err := semantic.ParseVendorJDKVersion(bad); !errors.Is(err, semantic.ErrInvalidVersion) {
			t.Errorf("ParseVendorJDKVersion(%q) error = %v, want ErrInvalidVersion", bad, err)
		}
	}
}

func TestVendorJDKVersion_ReleaseType(t *testing.T) {
	tests := map[string]string{
		"21.0.11.0.1+1": "cpu",
		"21.0.9.0.1":    "cpu",
		"11.0.29.0.1+1": "cpu",
		"17.0.17.0.1+1": "cpu",
		"25.0.1.0.1+1":  "cpu",
		"8u501+1":       "cpu",
		"8u481":         "cpu",
		"1.8.0_501-b01": "cpu",
		"21.0.12+10":    "psu",
		"21.0.10+10":    "psu",
		"21+37":         "psu",
		"21.0.1+12":     "psu",
		"8u502+9":       "psu",
		"8u482+10":      "psu",
		"21.0.12.1+1":   "cspu",
		"8u504+1":       "cspu",
	}
	for in, want := range tests {
		v, err := semantic.ParseVendorJDKVersion(in)
		if err != nil {
			t.Errorf("ParseVendorJDKVersion(%q): %v", in, err)
			continue
		}
		if got := v.ReleaseType(); got != want {
			t.Errorf("ParseVendorJDKVersion(%q).ReleaseType() = %q, want %q", in, got, want)
		}
	}
}

func TestVendorJDKVersion_CompareUpperBoundStr(t *testing.T) {
	// Compare and CompareStr are the plain numeric order
	cpu, _ := semantic.ParseVendorJDKVersion("21.0.9.0.1+1")
	psu, _ := semantic.ParseVendorJDKVersion("21.0.10+10")
	if got, err := cpu.Compare(psu); err != nil || got != -1 {
		t.Errorf("Compare(21.0.9.0.1+1, 21.0.10+10) = %d, %v, want -1", got, err)
	}
	if got, err := cpu.CompareStr("21.0.10+10"); err != nil || got != -1 {
		t.Errorf("21.0.9.0.1+1 CompareStr 21.0.10+10 = %d, %v, want -1", got, err)
	}

	// against the upper bound of a range a CPU counts as the quarterly update
	// it is released with
	tests := []struct {
		installed, bound string
		want             int
	}{
		{"21.0.9.0.1", "21.0.10+10", 0}, // fixed in the PSU of the cycle: the CPU has the fix
		{"21.0.9.0.1+1", "21.0.10+10", 0},
		{"21.0.9.0.1+1-LTS", "21.0.10+10", 0},
		{"21.0.9.0.1+1", "21.0.10", 0},
		{"21.0.9.0.1+1", "21.0.11+11", -1}, // fixed in a later cycle: affected
		{"21.0.9.0.1+1", "21.0.9+11", 1},
		{"21.0.11.0.1+1", "21.0.12+10", 0},
		{"21.0.11.0.1+1", "21.0.12.1+1", -1}, // fixed in the CSPU after it: affected
		{"21.0.11.0.1+1", "21.0.13+1", -1},
		{"21.0.10.0.1+1", "21.0.12+10", -1},
		{"8u481", "8u482+10", 0},
		{"8u481+1", "8u482+10", 0},
		{"1.8.0_481-b01", "8u482+10", 0},
		{"8u481+1", "8u492+9", -1},
		{"8u501+1", "8u502+9", 0},
		{"8u501+1", "8u504+1", -1},
		{"8u491+1", "8u502+9", -1},
		// the other release types are compared numerically
		{"21.0.9+11", "21.0.10+10", -1},
		{"21.0.10+10", "21.0.10+10", 0},
		{"21.0.12+10", "21.0.12.1+1", -1},
		{"21.0.12.1+1", "21.0.12.1+1", 0},
		{"21.0.12.1+2", "21.0.12.1+1", 1},
		{"21.0.12.1+1", "21.0.13+1", -1},
		{"8u472+11", "8u482+10", -1},
		{"8u502+9", "8u504+1", -1},
		{"8u504+1", "8u504+1", 0},
	}
	for _, tt := range tests {
		v, err := semantic.ParseVendorJDKVersion(tt.installed)
		if err != nil {
			t.Errorf("ParseVendorJDKVersion(%q): %v", tt.installed, err)
			continue
		}
		if got, err := v.CompareUpperBoundStr(tt.bound); err != nil || got != tt.want {
			t.Errorf("%s CompareUpperBoundStr %s = %d, %v, want %d", tt.installed, tt.bound, got, err, tt.want)
		}
	}
}

func TestParseVendorNIKVersion(t *testing.T) {
	// a fictional NIK family: its java.vendor.version form carries the family's prefix
	saved := osvinternal.Products
	t.Cleanup(func() { osvinternal.Products = saved })
	osvinternal.Products = []osvinternal.Product{{Family: "Test NIK", PURLName: "test-nik", Kind: osvinternal.KindNIK, VendorVersionPrefix: "Test-NIK-"}}
	for in, want := range map[string]string{
		"23.1.0+1":          "23.1.0+1",
		"23.1.8":            "23.1.8",
		"Test-NIK-23.1.0-1": "23.1.0+1",
	} {
		got, err := semantic.ParseVendorNIKVersion(in)
		if err != nil {
			t.Errorf("ParseVendorNIKVersion(%q): %v", in, err)
			continue
		}
		if got.String() != want {
			t.Errorf("ParseVendorNIKVersion(%q) = %q, want %q", in, got.String(), want)
		}
	}
	if _, err := semantic.ParseVendorNIKVersion("abc"); !errors.Is(err, semantic.ErrInvalidVersion) {
		t.Errorf("ParseVendorNIKVersion(abc) error = %v, want ErrInvalidVersion", err)
	}
	// a fixed version without a build is reached by every build of it
	v, _ := semantic.ParseVendorNIKVersion("23.1.8+1")
	if got, err := v.CompareStr("23.1.8"); err != nil || got != 0 {
		t.Errorf("23.1.8+1 CompareStr 23.1.8 = %d, %v, want 0", got, err)
	}
	if _, err := v.Compare(semantic.VendorJDKVersion{}); !errors.Is(err, semantic.ErrNotSameEcosystem) {
		t.Errorf("Compare(NIK, JDK) error = %v, want ErrNotSameEcosystem", err)
	}
}
