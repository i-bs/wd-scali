package osvecosystem_test

import (
	"testing"

	osvinternal "github.com/bell-sw/osv-internal"
	"github.com/bell-sw/osv-internal/osvdata"

	"github.com/google/osv-scalibr/inventory/osvecosystem"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
)

// release is a release of a product family of the kind.
func release(p osvinternal.Product) string {
	if p.Kind == osvinternal.KindNIK {
		return "23-21"
	}
	return "21"
}

// Every product family of the module parses into its family and release,
// whatever the family name looks like, and is valid and local-only.
func TestParse_VendorProducts(t *testing.T) {
	for _, p := range osvinternal.Products {
		eco := p.Ecosystem(release(p))
		got, err := osvecosystem.Parse(eco)
		if err != nil {
			t.Fatalf("Parse(%s): %v", eco, err)
		}
		want := osvecosystem.Parsed{Ecosystem: osvconstants.Ecosystem(p.Family), Suffix: release(p)}
		if got != want || got.String() != eco {
			t.Errorf("Parse(%s) = %+v (%q), want %+v", eco, got, got.String(), want)
		}
		if !got.Equal(want) || got.Equal(osvecosystem.Parsed{Ecosystem: want.Ecosystem, Suffix: "17"}) {
			t.Errorf("%s: Equal() does not key on the suffix", eco)
		}
		if !osvecosystem.IsVendorProduct(want.Ecosystem) || !osvecosystem.IsLocalOnly(want.Ecosystem) {
			t.Errorf("%s: not a local-only vendor product", eco)
		}
	}
	if osvecosystem.IsVendorProduct(osvconstants.EcosystemAlpine) || osvecosystem.IsVendorProduct(osvecosystem.EcosystemVendorLinux) {
		t.Error("IsVendorProduct of a distribution")
	}
	if _, err := osvecosystem.Parse("Nope:1"); err == nil {
		t.Error("an unknown ecosystem is accepted")
	}
}

func TestIsLocalOnly(t *testing.T) {
	// the distributions are local-only when the module does not fetch them from the osv.dev bucket
	distros := osvdata.DefaultBaseURLFor(osvinternal.EcosystemLinux) != "https://osv-vulnerabilities.storage.googleapis.com"
	for eco, want := range map[osvconstants.Ecosystem]bool{
		osvecosystem.EcosystemVendorLinux: distros, osvecosystem.EcosystemVendorHardened: distros, osvconstants.EcosystemAlpine: false,
	} {
		if got := osvecosystem.IsLocalOnly(eco); got != want {
			t.Errorf("IsLocalOnly(%q) = %v, want %v", eco, got, want)
		}
	}
}
