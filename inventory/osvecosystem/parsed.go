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

// Package osvecosystem provides the Parsed type which represents an OSV ecosystem string.
package osvecosystem

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	osvinternal "github.com/bell-sw/osv-internal"
	"github.com/bell-sw/osv-internal/osvdata"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
)

// Parsed represents an ecosystem-with-suffix string as defined by the [spec], parsed into
// a structured format.
//
// The suffix is optional and is separated from the ecosystem by a colon.
//
// For example, "Debian:7" would be parsed into Parsed{Ecosystem: constants.EcosystemDebian, Suffix: "7"}
//
// Ecosystems that are not (yet) part of the osv-schema constants but are
// produced by SCALIBR extractors and understood by the vulnerability matchers.
//
// [spec]: https://ossf.github.io/osv-schema/
//
//nolint:recvcheck
const (
	// EcosystemVendorLinux and EcosystemVendorHardened are the ecosystems of
	// the vendor's Linux distribution and hardened container images
	// ("<family>:<VERSION_ID>"), see extractor os/ecosystem.
	EcosystemVendorLinux    osvconstants.Ecosystem = osvinternal.EcosystemLinux
	EcosystemVendorHardened osvconstants.Ecosystem = osvinternal.EcosystemHardened
	// EcosystemVendorJDK is the ecosystem of the vendor's standalone JDK
	// runtimes ("<family>:<java major>"), see extractor java/vendorjdk.
	EcosystemVendorJDK osvconstants.Ecosystem = osvinternal.EcosystemJDK
	// EcosystemVendorNIK is the ecosystem of the vendor's standalone Native
	// Image Kit runtimes ("<family>:<nik major>-<java major>").
	EcosystemVendorNIK osvconstants.Ecosystem = osvinternal.EcosystemNIK
)

// osvDevBucket is the osv.dev export bucket, where every ecosystem osv.dev
// serves is published.
const osvDevBucket = "https://osv-vulnerabilities.storage.googleapis.com"

// IsLocalOnly reports whether the ecosystem is one osv.dev does not serve:
// its advisories come from local archives only, and api.osv.dev rejects a
// whole batch query naming it ("invalid ecosystem", HTTP 400). That is every
// vendor family whose default source (osvdata.DefaultBaseURLFor) is not the
// osv.dev bucket: the standalone runtimes, and the distributions of a vendor
// that publishes them on its own server.
func IsLocalOnly(ecosystem osvconstants.Ecosystem) bool {
	family := osvinternal.Family(string(ecosystem))
	return slices.Contains(osvinternal.Ecosystems, family) && osvdata.DefaultBaseURLFor(family) != osvDevBucket
}

type Parsed struct {
	Ecosystem osvconstants.Ecosystem
	Suffix    string
}

// IsEmpty returns true if the Ecosystem struct is empty.
func (p Parsed) IsEmpty() bool {
	return p.Ecosystem == ""
}

// Equal returns true if the two Parsed structs are equal.
func (p Parsed) Equal(other Parsed) bool {
	// only care about the minor version if both ecosystems have one
	// otherwise we just assume that they're the same and move on
	if p.Suffix != "" && other.Suffix != "" {
		return p.Ecosystem == other.Ecosystem && p.Suffix == other.Suffix
	}

	return p.Ecosystem == other.Ecosystem
}

func (p Parsed) String() string {
	str := string(p.Ecosystem)

	if p.Suffix != "" {
		str += ":" + p.Suffix
	}

	return str
}

// UnmarshalJSON handles unmarshalls a JSON string into a Parsed struct.
//
// This method implements the json.Unmarshaler interface.
func (p *Parsed) UnmarshalJSON(data []byte) error {
	var str string
	err := json.Unmarshal(data, &str)

	if err != nil {
		return err
	}

	*p, err = Parse(str)

	return err
}

// MarshalJSON handles marshals a Parsed struct into a JSON string.
//
// This method implements the json.Marshaler interface.
func (p Parsed) MarshalJSON() ([]byte, error) {
	return []byte(`"` + p.String() + `"`), nil
}

// GetValidity checks if the ecosystem is a valid OSV ecosystem value. Returns nil if valid, error otherwise.
func (p Parsed) GetValidity() error {
	if p.IsEmpty() {
		return nil
	}

	// Missing ecosystems here would be caught by the "exhaustive" linter
	//exhaustive:enforce
	switch p.Ecosystem {
	case osvconstants.EcosystemAlmaLinux,
		osvconstants.EcosystemAlpine,
		osvconstants.EcosystemAndroid,
		osvconstants.EcosystemAzureLinux,
		osvconstants.EcosystemBioconductor,
		osvconstants.EcosystemBitnami,
		osvconstants.EcosystemChainguard,
		osvconstants.EcosystemCleanStart,
		osvconstants.EcosystemConanCenter,
		osvconstants.EcosystemCRAN,
		osvconstants.EcosystemCratesIO,
		osvconstants.EcosystemDebian,
		osvconstants.EcosystemDockerHardenedImages,
		osvconstants.EcosystemEcho,
		osvconstants.EcosystemFreeBSD,
		osvconstants.EcosystemGHC,
		osvconstants.EcosystemGitHubActions,
		osvconstants.EcosystemGo,
		osvconstants.EcosystemHackage,
		osvconstants.EcosystemHex,
		osvconstants.EcosystemJulia,
		osvconstants.EcosystemKubernetes,
		osvconstants.EcosystemLinux,
		osvconstants.EcosystemMageia,
		osvconstants.EcosystemMaven,
		osvconstants.EcosystemMinimOS,
		osvconstants.EcosystemNPM,
		osvconstants.EcosystemNuGet,
		osvconstants.EcosystemOpam,
		osvconstants.EcosystemOpenEuler,
		osvconstants.EcosystemOpenSUSE,
		osvconstants.EcosystemOSSFuzz,
		osvconstants.EcosystemPackagist,
		osvconstants.EcosystemPhotonOS,
		osvconstants.EcosystemPub,
		osvconstants.EcosystemPyPI,
		osvconstants.EcosystemRedHat,
		osvconstants.EcosystemRockyLinux,
		osvconstants.EcosystemRoot,
		osvconstants.EcosystemRubyGems,
		osvconstants.EcosystemSUSE,
		osvconstants.EcosystemSwiftURL,
		osvconstants.EcosystemTuxCare,
		osvconstants.EcosystemUbuntu,
		osvconstants.EcosystemVSCode,
		osvconstants.EcosystemWolfi,
		// GIT is a pseudo ecosystem that can be used in queries, so should be considered valid.
		"GIT",
		// the vendor's ecosystems (see above)
		EcosystemVendorLinux,
		EcosystemVendorHardened,
		EcosystemVendorJDK,
		EcosystemVendorNIK:

	default:
		return fmt.Errorf("base ecosystem does not exist in osvschema: %q", p.Ecosystem)
	}

	return nil
}

// MustParse parses a string into a constants.Ecosystem and an optional suffix specified with a ":"
// Panics if there is an invalid ecosystem
func MustParse(str string) Parsed {
	parsed, err := Parse(str)
	if err != nil {
		panic("Failed MustParse: " + err.Error())
	}

	return parsed
}

// Parse parses a string into a constants.Ecosystem and an optional suffix specified with a ":"
func Parse(str string) (Parsed, error) {
	// Special case to return an empty ecosystem if str is empty
	// This is not considered an error.
	if str == "" {
		return Parsed{}, nil
	}

	// We will also add a check for whether the ecosystem is valid to have a suffix here.
	// And return an error if not.
	ecosystem, suffix, _ := strings.Cut(str, ":")

	result := Parsed{osvconstants.Ecosystem(ecosystem), suffix}

	return result, result.GetValidity()
}

// FromEcosystem creates a Parsed struct from an osvschema.Ecosystem.
func FromEcosystem(ecosystem osvconstants.Ecosystem) Parsed {
	return Parsed{Ecosystem: ecosystem}
}
