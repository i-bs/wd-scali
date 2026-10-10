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

package vendorjdk_test

import (
	"testing"

	osvinternal "github.com/bell-sw/osv-internal"
	"github.com/bell-sw/osv-internal/testfix"
)

// buildTestRuntimes creates synthetic runtimes with the osv-internal testfix
// package (fake JVM libraries carrying the strings the detector looks for,
// release files, the Java 8 rt.jar manifest) under a temporary directory and
// returns its path:
//
//	jdk-21.0.2/   JDK 21.0.2+14 with a server and a minimal VM
//	jre-21.0.2/   JRE 21.0.2+14 (no bin/javac)
//	jdk8u402/     JDK 8u402: release without IMPLEMENTOR, vendor in jre/lib/rt.jar
//	zulu21/       Azul Zulu 21.0.2+13 (another vendor)
//	vendor-linux/ a root of the vendor's distribution with the apk-installed usr/lib/jvm/jdk21-lite (stripped release)
//	debian/       a Debian root with a standalone runtime under usr/lib/jvm
func buildTestRuntimes(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	lib21 := string(testfix.LibJVM(testfix.Banner("21.0.2+14-LTS"), osvinternal.RuntimeVendor))
	testfix.Write(t, root,
		// JDK 21.0.2+14 (tarball layout) with two VM flavours
		testfix.Runtime{Home: "jdk-21.0.2", Version: "21.0.2+14-LTS", JDK: true, Extra: map[string]string{"lib/minimal/libjvm.so": lib21}},
		testfix.Runtime{Home: "jre-21.0.2", Version: "21.0.2+14-LTS"},
		// JDK 8u402 (JDK layout with the embedded jre/, vendor only in rt.jar and libjvm.so)
		testfix.Runtime{Home: "jdk8u402", Version: "1.8.0_402-b07", JDK: true, Java8: true},
		// another vendor
		testfix.Runtime{Home: "zulu21", Version: "21.0.2+13-LTS", JDK: true, Vendor: "Azul Systems, Inc."},
		// the vendor's distribution: an apk-installed runtime (stripped release, as apk ships it)
		testfix.Runtime{Home: "vendor-linux/usr/lib/jvm/jdk21-lite", Version: "21.0.2+14-LTS", JDK: true, StrippedRelease: true},
		// macOS tarball layouts: the JVM library (libjvm.dylib) is not part of these trees,
		// the runtime is accepted on the structured evidence (release / rt.jar manifest)
		testfix.Runtime{Home: "macos/jdk-21.0.2.jdk", Version: "21.0.2+14-LTS", JDK: true, NoLibrary: true},
		testfix.Runtime{Home: "macos/jdk8u402.jdk", Version: "1.8.0_402-b07", JDK: true, Java8: true, NoLibrary: true},
		// Windows layout: bin\server\jvm.dll, java.exe
		testfix.Runtime{Home: "windows/jdk-21.0.2", Version: "21.0.2+14-LTS", JDK: true, OS: "windows"},
		// Native Image Kit 23.1.0 core (GraalVM markers and the java.vendor.version string)
		testfix.Runtime{Home: "nik-23.1.0", Version: "21.0.1+12-LTS", JDK: true, NIK: "23.1.0+1"},
		// the other kinds of update release: a CSPU (out-of-cycle security release, four components) and a CPU
		// (security-only build released with a PSU: five components on 9+, the odd update on 8)
		testfix.Runtime{Home: "jdk-21.0.12.1", Version: "21.0.12.1+1-LTS", JDK: true},
		testfix.Runtime{Home: "jdk-21.0.9.0.1", Version: "21.0.9.0.1+1-LTS", JDK: true},
		testfix.Runtime{Home: "jdk8u504", Version: "1.8.0_504-b01", JDK: true, Java8: true},
		testfix.Runtime{Home: "jdk8u481", Version: "1.8.0_481-b01", JDK: true, Java8: true},
		// the same layout on a Debian root is a standalone install
		testfix.Runtime{Home: "debian/usr/lib/jvm/jdk-21.0.2-x86_64", Version: "21.0.2+14-LTS", JDK: true},
	)
	testfix.WriteFiles(t, root, map[string][]byte{
		"vendor-linux/etc/os-release": []byte(testfix.OSRelease(osvinternal.EcosystemLinux, "23")),
		"debian/etc/os-release":       []byte("PRETTY_NAME=\"Debian GNU/Linux 11 (bullseye)\"\nID=debian\nVERSION_ID=\"11\"\n"),
	})

	return root
}
