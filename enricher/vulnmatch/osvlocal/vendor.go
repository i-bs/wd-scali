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

package osvlocal

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"slices"
	"strings"

	osvinternal "github.com/bell-sw/osv-internal"
	"github.com/bell-sw/osv-internal/osvdata"
	"github.com/google/osv-scalibr/inventory/osvecosystem"
	"github.com/google/osv-scalibr/plugin"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
)

// Options are the settings of the Enricher that have no field in the plugin's
// proto config; they concern the vendor families (osvinternal.Ecosystems).
type Options struct {
	// LocalOnlyEcosystems restricts the enricher to the ecosystems MatchedLocally
	// reports, whose archives it downloads as needed; the other packages are
	// left to vulnmatch/osvdev, which must skip the same ecosystems
	// (osvdev.Options.MatchedLocally).
	LocalOnlyEcosystems bool
	// VendorURL is the base location of the archives of all vendor
	// families (<url>/<family>/all.zip): an http(s) URL, a file:// URL or a
	// directory. Empty means the built-in default of each family.
	VendorURL string
	// VendorFeeds is the location of the archive of single families, keyed
	// by family name (see ParseVendorFeeds): a base as in VendorURL or the
	// .zip itself. It wins over VendorURL.
	VendorFeeds map[string]string
	// VendorStrict turns an unavailable archive of a vendor family into a
	// failure of the enricher instead of a warning.
	VendorStrict bool
}

// Configured reports whether the family of the ecosystem has a source in the
// options (VendorFeeds or VendorURL) rather than its built-in default.
func (o Options) Configured(eco osvconstants.Ecosystem) bool {
	return configuredSource(eco, o.VendorURL, o.VendorFeeds)
}

// MatchedLocally reports whether the enricher handles the ecosystem under
// LocalOnlyEcosystems: those api.osv.dev does not serve and the vendor
// families with a configured source.
func (o Options) MatchedLocally(eco osvconstants.Ecosystem) bool {
	return osvecosystem.IsLocalOnly(eco) || o.Configured(eco)
}

// configuredSource is Options.Configured on the fields the Enricher and the
// localMatcher keep.
func configuredSource(eco osvconstants.Ecosystem, vendorURL string, feeds map[string]string) bool {
	if !isVendorFamily(eco) {
		return false
	}

	return feeds[osvinternal.Family(string(eco))] != "" || vendorURL != ""
}

// Configure applies opts to p when p is this package's Enricher.
func Configure(p plugin.Plugin, opts Options) {
	e, ok := p.(*Enricher)
	if !ok {
		return
	}
	e.localOnly = opts.LocalOnlyEcosystems
	e.vendorStrict = opts.VendorStrict
	e.vendorURL = opts.VendorURL
	e.vendorFeeds = opts.VendorFeeds
	if e.localOnly {
		e.download = true
	}
}

// isVendorFamily reports whether the ecosystem is one of osvinternal.Ecosystems.
func isVendorFamily(eco osvconstants.Ecosystem) bool {
	return slices.Contains(osvinternal.Ecosystems, osvinternal.Family(string(eco)))
}

// ParseVendorFeeds parses "<family>=<location>" pairs into Options.VendorFeeds;
// family names are matched case-insensitively against osvinternal.Ecosystems.
func ParseVendorFeeds(pairs []string) (map[string]string, error) {
	feeds := map[string]string{}
	for _, pair := range pairs {
		if strings.TrimSpace(pair) == "" {
			continue
		}
		name, location, ok := strings.Cut(pair, "=")
		name, location = strings.TrimSpace(name), strings.TrimSpace(location)
		if !ok || name == "" || location == "" {
			return nil, fmt.Errorf("invalid --vendor-feed %q: want \"<product>=<url>\"", pair)
		}
		family := ""
		for _, f := range osvinternal.Ecosystems {
			if strings.EqualFold(f, name) {
				family = f
			}
		}
		if family == "" {
			return nil, fmt.Errorf("invalid --vendor-feed %q: unknown product %q (products: %s)", pair, name, strings.Join(osvinternal.Ecosystems, ", "))
		}
		feeds[family] = location
	}

	return feeds, nil
}

// archiveURL returns the location of the archive of an ecosystem:
// <host>/<ecosystem>/all.zip on the archive host (the osv.dev bucket or a
// mirror), except for the vendor families, which follow the precedence of
// osvdata.Source.ArchiveURL: the feed of the family, else the vendor base
// URL, else the built-in default - the archive host for the families osv.dev
// carries, the module's default for the others (osvecosystem.IsLocalOnly).
func (matcher *localMatcher) archiveURL(eco osvconstants.Ecosystem) string {
	family := string(eco)
	if isVendorFamily(eco) {
		if matcher.vendorFeeds[family] != "" || matcher.vendorURL != "" || osvecosystem.IsLocalOnly(eco) {
			src := &osvdata.Source{BaseURL: matcher.vendorURL, URLs: matcher.vendorFeeds}
			location := src.ArchiveURL(family)
			lower := strings.ToLower(location)
			if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") && !strings.HasPrefix(lower, "file://") {
				// a local path: zipDB reads those through file://
				location = "file://" + location
			}

			return location
		}
	}

	return fmt.Sprintf("%s/%s/all.zip", matcher.zippedDBRemoteHost, eco)
}

// httpStatusError is a response of the archive host other than 200.
type httpStatusError struct {
	code   int
	status string
}

func (e *httpStatusError) Error() string { return "db host returned " + e.status }

// unavailable builds the module's canonical UnavailableError for a vendor family.
func unavailable(eco osvconstants.Ecosystem, url string, err error) *osvdata.UnavailableError {
	return &osvdata.UnavailableError{Family: string(eco), URL: url, Reason: unavailableReason(err), Err: err}
}

// unavailableReason is the short human reason of a failure to get an archive.
func unavailableReason(err error) string {
	var status *httpStatusError
	var dns *net.DNSError
	var nerr net.Error
	msg := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, errOfflineDatabaseNotFound):
		return "offline and not cached"
	case errors.As(err, &status):
		return fmt.Sprintf("HTTP %d", status.code)
	case errors.Is(err, fs.ErrNotExist):
		return "file not found"
	case errors.Is(err, fs.ErrPermission):
		return "permission denied"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &nerr) && nerr.Timeout():
		return "timeout"
	case errors.As(err, &dns):
		return "host not found"
	case strings.Contains(msg, "connection refused"):
		return "connection refused"
	case strings.Contains(msg, "x509:"), strings.Contains(msg, "tls:"):
		return "TLS error"
	case strings.Contains(msg, "could not read osv database archive"):
		return "not a valid OSV archive"
	}

	return "download failed"
}
