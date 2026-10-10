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

// Package vendorjdk extracts standalone vendor runtimes (JDK/JRE and
// Native Image Kit installed from a tarball or package, or copied into
// an image) as packages of the module's JDK and NIK OSV ecosystems
// ("<family>:<major>" and "<family>:<nik major>-<java major>").
//
// It is glue around the shared detector github.com/bell-sw/osv-internal/vendorjdk:
// the detector's candidate files (JVM library, release file, rt.jar) are
// handed to it and a detected runtime becomes one package per runtime home
// with name, version, ecosystem and purl from the detector. Other vendors
// are never reported; on the vendor distributions the apk-installed
// runtimes under /usr/lib/jvm are left to the apk ecosystems.
package vendorjdk

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"strings"

	"github.com/bell-sw/osv-internal/distro"
	osvjdk "github.com/bell-sw/osv-internal/vendorjdk"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	vendorjdkmeta "github.com/google/osv-scalibr/extractor/filesystem/language/java/vendorjdk/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/os/osrelease"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "java/vendorjdk"
)

// vmDirServer is the VM flavour preferred when a runtime ships several
// (server, client, minimal): only one JVM library per home is extracted.
const vmDirServer = "server"

// apkJVMDir is the directory of the apk-installed runtimes on the vendor distributions.
const apkJVMDir = "usr/lib/jvm"

// Detector is the detection back end: the module's vendorjdk.Detect (by JVM
// library) and vendorjdk.DetectHome (by runtime home) unless replaced in tests.
type Detector struct {
	Detect     func(fsys fs.FS, libjvmPath string) (*osvjdk.Runtime, error)
	DetectHome func(fsys fs.FS, home string) (*osvjdk.Runtime, error)
}

// Extractor extracts standalone vendor runtimes.
type Extractor struct {
	detector Detector
}

// New returns a vendor runtime extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) {
	return &Extractor{detector: Detector{Detect: osvjdk.Detect, DetectHome: osvjdk.DetectHome}}, nil
}

// NewWithDetector returns an extractor using the given detection back end
// (tests).
func NewWithDetector(d Detector) *Extractor {
	return &Extractor{detector: d}
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true for the files the detector works from: the JVM
// library of a runtime (<home>/lib/<vm>/libjvm.so or libjvm.dylib,
// <home>/bin/<vm>/jvm.dll, the Java 8 layouts under jre/), its release file
// and rt.jar. Which of them produces the package is decided in Extract.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return osvjdk.IsCandidate(filepath.ToSlash(api.Path()))
}

// isJVMLibrary reports whether base is the file name of a HotSpot library.
func isJVMLibrary(base string) bool {
	switch base {
	case "libjvm.so", "libjvm.dylib", "jvm.dll":
		return true
	}
	return false
}

// Extract detects the runtime the candidate file belongs to and reports it
// once per runtime home.
func (e Extractor) Extract(_ context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	p := path.Clean(filepath.ToSlash(input.Path))
	base := path.Base(p)

	var rt *osvjdk.Runtime
	var err error
	if isJVMLibrary(base) {
		// one package per runtime: when several VM flavours are installed the
		// server VM is the one extracted
		if vm := path.Base(path.Dir(p)); vm != vmDirServer {
			if _, statErr := fs.Stat(input.FS, path.Join(path.Dir(path.Dir(p)), vmDirServer, base)); statErr == nil {
				return inventory.Inventory{}, nil
			}
		}
		rt, err = e.detector.Detect(input.FS, p)
	} else {
		home, ok := osvjdk.HomeOf(p)
		if !ok {
			return inventory.Inventory{}, nil
		}
		rt, err = e.detector.DetectHome(input.FS, home)
	}
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("%s: %w", Name, err)
	}
	if rt == nil {
		// another vendor, or not enough evidence
		return inventory.Inventory{}, nil
	}

	// The file that reports the runtime is its JVM library when it has one
	// (read by the detector for vendor and version), else its release file,
	// else rt.jar; the other candidates of the same home stay silent.
	if !anchors(input.FS, p, rt) {
		return inventory.Inventory{}, nil
	}

	if managedByAPK(rt.Home) && isVendorDistribution(input.FS) {
		log.Debugf("%s: skipping %s, installed by apk and covered by the OS ecosystem", Name, rt.Home)
		return inventory.Inventory{}, nil
	}

	pkg := &extractor.Package{
		Name:     rt.Variant,
		Version:  rt.Version,
		PURLType: purl.TypeGeneric,
		Metadata: &vendorjdkmeta.Metadata{
			Ecosystem: rt.Ecosystem(),
			PURL:      rt.PURL(),
			Home:      rt.Home,
			Major:     rt.Major,
			Variant:   rt.Variant,
			Vendor:    rt.Vendor,
			LibJVM:    rt.LibJVM,
			Evidence:  rt.Evidence,
		},
		Location: extractor.LocationFromPath(rt.Home),
		Plugins:  []string{Name},
	}

	return inventory.Inventory{Packages: []*extractor.Package{pkg}}, nil
}

// anchors reports whether candidate p is the file that reports runtime rt.
func anchors(fsys fs.FS, p string, rt *osvjdk.Runtime) bool {
	if rt.LibJVM != "" {
		return p == path.Clean(filepath.ToSlash(rt.LibJVM))
	}
	release := path.Join(rt.Home, "release")
	switch path.Base(p) {
	case "release":
		return p == release
	case "rt.jar":
		_, err := fs.Stat(fsys, release)
		return err != nil // no release file: rt.jar is all there is
	}
	return false
}

// managedByAPK reports whether the home is where the vendor distributions
// install their apk-packaged runtimes (usr/lib/jvm).
func managedByAPK(home string) bool {
	return osvjdk.ManagedByAPK(home) || strings.HasPrefix(path.Clean(home)+"/", apkJVMDir+"/")
}

// isVendorDistribution reports whether the scanned file system is a root
// of one of the vendor distributions (os-release ID).
func isVendorDistribution(fsys scalibrfs.FS) bool {
	m, err := osrelease.GetOSRelease(fsys)
	if err != nil {
		if !errors.Is(err, osrelease.ErrNotADistro) && !errors.Is(err, fs.ErrNotExist) {
			log.Debugf("%s: os-release: %v", Name, err)
		}
		return false
	}
	return distro.IsVendor(m["ID"])
}
