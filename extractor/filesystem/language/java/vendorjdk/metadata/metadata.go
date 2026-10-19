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

// Package metadata defines the Metadata of the runtimes found by the
// java/vendorjdk extractor. Ecosystem and purl are the detector's
// (github.com/bell-sw/osv-internal/vendorjdk), not derived here.
package metadata

import (
	osvinternal "github.com/bell-sw/osv-internal"
	osvjdk "github.com/bell-sw/osv-internal/vendorjdk"
	"github.com/google/osv-scalibr/binary/proto/metadata"
	"github.com/google/osv-scalibr/inventory/osvecosystem"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/purl"
)

func init() {
	// no proto representation yet: the metadata is dropped when a scan result is serialized
	metadata.RegisterNil[*Metadata]()
}

// Metadata holds the detection details of a vendor runtime.
type Metadata struct {
	// Ecosystem is the OSV ecosystem string of the runtime as the detector
	// reports it: "<JDK family>:<java major>" or "<NIK family>:<nik major>-<java major>".
	Ecosystem string
	// PURL is the package URL as the detector reports it, e.g.
	// pkg:generic/<namespace>/<name>@21.0.2%2B14?package_type=jdk.
	PURL string
	// Home is the runtime root inside the scanned file system (fs.FS
	// notation, no leading slash), e.g. "opt/jdk-21.0.2".
	Home string
	// Major is the Java major version (8, 11, 17, 21, ...).
	Major int
	// Variant is the OSV package name ("jdk", "jre", "jdk-lite", ...; for
	// NIK the bundle "core", "standard", "full").
	Variant string
	// Vendor is the vendor string read from the runtime (the module's RuntimeVendor).
	Vendor string
	// LibJVM is the path of the JVM library that anchored the detection;
	// empty when the runtime was accepted on structured evidence alone.
	LibJVM string
	// Evidence lists where the vendor and the version were read, one line each.
	Evidence []string
}

// IsProtoable marks the struct as a metadata type.
func (m *Metadata) IsProtoable() {}

// OSVEcosystem returns the parsed OSV ecosystem of the runtime.
func (m *Metadata) OSVEcosystem() osvecosystem.Parsed {
	if m == nil || m.Ecosystem == "" {
		return osvecosystem.Parsed{}
	}
	eco, err := osvecosystem.Parse(m.Ecosystem)
	if err != nil {
		log.Errorf("vendorjdk: ecosystem %q: %v", m.Ecosystem, err)
		return osvecosystem.Parsed{}
	}
	return eco
}

// MakePackageURL returns the package URL of the runtime; when the detector
// gave none it is built from the family of the ecosystem, the variant and
// the version.
func MakePackageURL(version string, m *Metadata) *purl.PackageURL {
	if m == nil {
		return nil
	}
	s := m.PURL
	if s == "" {
		s = osvjdk.PURL(osvinternal.Family(m.Ecosystem), m.Variant, version)
	}
	p, err := purl.FromString(s)
	if err != nil {
		log.Errorf("vendorjdk: purl %q: %v", s, err)
		return nil
	}
	return &p
}
