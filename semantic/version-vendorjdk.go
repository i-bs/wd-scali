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

package semantic

import (
	"fmt"

	osvinternal "github.com/bell-sw/osv-internal"
	"github.com/bell-sw/osv-internal/jdkver"
	"github.com/bell-sw/osv-internal/nikver"
)

// The vendor's JDK and NIK ecosystems are defined by its shared module
// github.com/bell-sw/osv-internal; parsing, ordering and the
// range rules are those of its jdkver and nikver packages.
//
// JDK versions use the product notation of the runtime:
//
//	9 and later: "21.0.2+14", "21+37" (GA) - JAVA_RUNTIME_VERSION without
//	             the "-LTS" / "-ea" qualifier
//	8:           "8u402+7" - from "1.8.0_402-b07"
//
// The raw forms ("21.0.2+14-LTS", "1.8.0_402-b07") are accepted as well.
// The vendor ships three kinds of update release:
//
//	           PSU (quarterly)   CPU (security only, with the PSU)   CSPU (out of cycle)
//	Java 9+    21.0.12+10        21.0.11.0.1+1                       21.0.12.1+1
//	Java 8     8u502+9           8u501+1                             8u504+1
//
// The order is numeric on every component, then on the build. A CPU sorts
// below the PSU it is released with although it carries the same security
// fixes, and advisories name the PSU as the fixed version; a matcher
// therefore compares the upper bound of a range with CompareUpperBoundStr.

// VendorJDKVersion is a parsed version of the JDK ecosystem.
type VendorJDKVersion struct {
	v jdkver.Version
}

var _ Version = VendorJDKVersion{}

// ParseVendorJDKVersion parses a JDK product version (see above).
func ParseVendorJDKVersion(str string) (VendorJDKVersion, error) {
	if str == "" {
		str = "0"
	}
	v, err := jdkver.Parse(str)
	if err != nil {
		return VendorJDKVersion{}, fmt.Errorf("%w: %q is not a %s version", ErrInvalidVersion, str, osvinternal.EcosystemJDK)
	}

	return VendorJDKVersion{v: v}, nil
}

// String returns the product notation of the version.
func (v VendorJDKVersion) String() string {
	return v.v.String()
}

// ReleaseType returns the kind of update release: "psu", "cpu", "cspu" or
// "unknown".
func (v VendorJDKVersion) ReleaseType() string {
	return v.v.ReleaseType().String()
}

// Compare compares two JDK versions numerically.
func (v VendorJDKVersion) Compare(w Version) (int, error) {
	if w, ok := w.(VendorJDKVersion); ok {
		return v.v.Compare(w.v), nil
	}

	return 0, ErrNotSameEcosystem
}

// CompareStr compares the version with a version string of the same ecosystem.
func (v VendorJDKVersion) CompareStr(str string) (int, error) {
	w, err := ParseVendorJDKVersion(str)
	if err != nil {
		return 0, err
	}

	return v.v.Compare(w.v), nil
}

// CompareUpperBoundStr compares v with the upper bound of an advisory range
// ("fixed", "last_affected"). It is CompareStr except for a CPU, which counts
// as the PSU it is released with: 21.0.9.0.1+1 is not below a fix in
// 21.0.10+10 (0) but is below one in 21.0.11+11 (-1).
func (v VendorJDKVersion) CompareUpperBoundStr(str string) (int, error) {
	below, err := jdkver.InRangeVersion(v.v, "", str, "")
	if err != nil {
		return 0, fmt.Errorf("%w: %q is not a %s version", ErrInvalidVersion, str, osvinternal.EcosystemJDK)
	}
	if below {
		return -1, nil
	}
	notAbove, err := jdkver.InRangeVersion(v.v, "", "", str)
	if err != nil {
		return 0, fmt.Errorf("%w: %q is not a %s version", ErrInvalidVersion, str, osvinternal.EcosystemJDK)
	}
	if notAbove {
		return 0, nil
	}

	return +1, nil
}

// VendorNIKVersion is a parsed NIK version ("23.1.0+1"); a
// version without a build ("23.1.8", as advisories write fixed versions)
// compares equal to any build of it.
type VendorNIKVersion struct {
	v nikver.Version
}

var _ Version = VendorNIKVersion{}

// ParseVendorNIKVersion parses a NIK version.
func ParseVendorNIKVersion(str string) (VendorNIKVersion, error) {
	if str == "" {
		str = "0"
	}
	v, err := nikver.Parse(str)
	if err != nil {
		return VendorNIKVersion{}, fmt.Errorf("%w: %q is not a %s version", ErrInvalidVersion, str, osvinternal.EcosystemNIK)
	}

	return VendorNIKVersion{v: v}, nil
}

// String returns the NIK notation of the version.
func (v VendorNIKVersion) String() string {
	return v.v.String()
}

// Compare compares two NIK versions.
func (v VendorNIKVersion) Compare(w Version) (int, error) {
	if w, ok := w.(VendorNIKVersion); ok {
		return v.v.Compare(w.v), nil
	}

	return 0, ErrNotSameEcosystem
}

// CompareStr compares the version with a version string of the same ecosystem.
func (v VendorNIKVersion) CompareStr(str string) (int, error) {
	w, err := ParseVendorNIKVersion(str)
	if err != nil {
		return 0, err
	}

	return v.v.Compare(w.v), nil
}
