package whoislookup

import (
	"testing"
	b64 "encoding/base64"
	"regexp"
	"github.com/foureyekid/whoislookup"
)

type Source struct {
	query string
	expected string
}

var domains = []Source {
	Source{ query: "www.github.com", expected: `(?i)domain\sname:\s+github.com`},
}

var ips = []Source {
	Source{ query: "212.149.0.0", expected: `(?i)netname:\s+COMMERZBANK`},
}

func checkWhois(b64Whois string, tt Source, t *testing.T) {

	if b64Whois == "" {
		t.Error("Empty whois returned!")
	}

	whois, err := b64.StdEncoding.DecodeString(b64Whois)

	if err != nil {
		t.Error("Whois decode error!")
	}

	matched, err := regexp.MatchString(tt.expected, string(whois))

	if err != nil {
		t.Error("regex error!")
	}

	if ! matched {
		t.Error("Not a valid whois response")
	}
}


// Only Domain
func TestRunLocalWhois(t *testing.T) {

	// queries := append(domains, ips...)
	for _, tt := range domains {

		b64Whois   := whoislookup.RunLocalWhois(tt.query)
		checkWhois(b64Whois, tt, t)
	}
}

// Only Domain
func TestScrapeFromWhoisLookupSite(t *testing.T) {

	for _, tt := range domains {

		b64Whois   := whoislookup.ScrapeFromWhoisLookupSite(tt.query)
		checkWhois(b64Whois, tt, t)
	}
}

func TestScrapeFromDomainBigDataSite(t *testing.T) {

	queries := append(domains, ips...)

	for _, tt := range queries {

		b64Whois   := whoislookup.ScrapeFromDomainBigDataSite(tt.query)
		checkWhois(b64Whois, tt, t)
	}
}

func TestScrapeFromMarkMonitorSite(t *testing.T) {

	queries := append(domains, ips...)

	for _, tt := range queries {

		b64Whois   := whoislookup.ScrapeFromMarkMonitorSite(tt.query)
		checkWhois(b64Whois, tt, t)
	}
}

// Only Domain
func TestScrapeFromYouGetSignalSite(t *testing.T) {

	for _, tt := range domains {

		b64Whois   := whoislookup.ScrapeFromYouGetSignalSite(tt.query)
		checkWhois(b64Whois, tt, t)
	}
	
}

func TestScrapeFromIPAddressOrgSite(t *testing.T) {

	queries := append(domains, ips...)

	for _, tt := range queries {

		b64Whois   := whoislookup.ScrapeFromIPAddressOrgSite(tt.query)
		checkWhois(b64Whois, tt, t)
	}
	
}

func TestScrapeFromRobTexSite(t *testing.T) {

	queries := append(domains, ips...)

	for _, tt := range queries {

		b64Whois   := whoislookup.ScrapeFromRobTexSite(tt.query)
		checkWhois(b64Whois, tt, t)
	}
}

// Only domain
func TestScrapeFromDomainPunch(t *testing.T) {

	for _, tt := range domains {

		b64Whois   := whoislookup.ScrapeFromDomainPunch(tt.query)
		checkWhois(b64Whois, tt, t)
	}
	
}

func TestScrapeFromWhoisDomainSearch(t *testing.T) {

	queries := append(domains, ips...)

	for _, tt := range queries {

		b64Whois   := whoislookup.ScrapeFromWhoisDomainSearch(tt.query)
		checkWhois(b64Whois, tt, t)
	}
	
}