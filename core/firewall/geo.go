package firewall

// Optional GeoIP lookups for firewall rules (ip.country, ip.asn).
//
// The proxy reads MaxMind DB (.mmdb) files supplied by the operator — for
// example the free GeoLite2 Country and ASN databases, downloaded with the
// operator's own MaxMind account and license key. No database is bundled,
// fetched, or committed; see docs/configuration.md for how to obtain one.
//
// Both database paths are optional and independent: a Country database
// supplies ip.country, an ASN database supplies ip.asn. When a database
// is not configured, cannot be opened, or has no record for an IP, the
// lookup returns the zero value (""/0) and rules simply do not match on
// that field (fail-open). Lookups only run when a domain has firewall
// rules, so there is no cost for domains without rules.
//
// Readers are swapped atomically, so a config reload can point at new
// database files without restarting and without ever serving a
// half-opened reader. A failed reload keeps the previous readers.

import (
	"net"
	"sync/atomic"

	"github.com/oschwald/geoip2-golang"
)

var (
	countryDB atomic.Pointer[geoip2.Reader]
	asnDB     atomic.Pointer[geoip2.Reader]
)

// InitGeoIP opens the configured GeoIP databases and swaps them in.
// An empty path leaves the current reader for that database untouched
// (so on first load the lookup stays disabled, and on reload a removed
// path keeps serving the previously loaded database rather than dropping
// lookups mid-flight). A path that fails to open leaves the previous
// reader in place and returns an error describing the failure; callers
// log it and continue.
func InitGeoIP(countryPath, asnPath string) error {
	if countryPath != "" {
		reader, err := geoip2.Open(countryPath)
		if err != nil {
			return err
		}
		if old := countryDB.Swap(reader); old != nil {
			old.Close()
		}
	}
	if asnPath != "" {
		reader, err := geoip2.Open(asnPath)
		if err != nil {
			return err
		}
		if old := asnDB.Swap(reader); old != nil {
			old.Close()
		}
	}
	return nil
}

// GeoConfigured reports whether at least one GeoIP database is loaded.
func GeoConfigured() bool {
	return countryDB.Load() != nil || asnDB.Load() != nil
}

// GeoStatus reports separately whether the Country and ASN databases
// are loaded, for operator-facing status output.
func GeoStatus() (countryLoaded, asnLoaded bool) {
	return countryDB.Load() != nil, asnDB.Load() != nil
}

// LookupGeo returns the ISO country code and autonomous system number for
// an IP address. Either value may be the zero value (""/0) when no
// database is configured, the lookup fails, or the database has no record
// for the address. Private and unparseable addresses return zero values.
func LookupGeo(ipStr string) (country string, asn int) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", 0
	}
	if reader := countryDB.Load(); reader != nil {
		if record, err := reader.Country(ip); err == nil {
			country = record.Country.IsoCode
		}
	}
	if reader := asnDB.Load(); reader != nil {
		if record, err := reader.ASN(ip); err == nil {
			asn = int(record.AutonomousSystemNumber)
		}
	}
	return country, asn
}
