package whoislookup

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/PuerkitiBio/goquery"
	"github.com/davecgh/go-spew/spew"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// use for dumping in nicer format
// "github.com/davecgh/go-spew/spew"
// spew.Dump(<anything>)

const localWhois = 1
const whoisLookupSite = 2
const domainBigDataSite = 3
const markMonitorSite = 4
const youGetSignalSite = 5
const ipAddressOrgSite = 6
const robTexSite = 7
const domainPunchSite = 8
const whoisDomainSearch = 9

type Blocked struct {
    Source int
    Status bool
    Count  int
}

type Header struct {
	Name  string
	Value string
}

type Query struct {
	Key   string
	Value string
}

// used for get or post request
type Request struct {
	Method  string   // Request Method
	Url     *url.URL // Url requried
	Body    []byte   // Post request body
	Headers []Header
	Params  []Query // Get params ( Post params are build at request time )
}

// domainbigdata response is in the format
// {"d": "whois information"}
type DomainBigDataMessage struct {
	D string // keys need to be in capital when doing json mapping
}

// yougetsignal json response is in below format
type YouGetSignalMessage struct {
	DomainAvailable string
	Message         string
	RemoteAddress   string
	Status          string
	WhoisData       string
}

// from domainpunch response we'll only take the RAW part
type DomainPunchMessage struct {
	RAW string
}

// output structure
type Output struct {
	Query  string
	Method int
	Whois  string
	IP     string
}

// global
// initial default block status & count
var blockers = make(map[int]Blocked)

func initBlockers() {

    for _, source := range getAllSources() {

        blockers[source] = Blocked{ Source: source, Status: false, Count: 0 }
    }
}

func getHostIPAddress() (string, error) {

	interfaces, err := net.Interfaces()

	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {

		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}

		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}

		addrs, err := iface.Addrs()

		if err != nil {
			return "", err
		}

		for _, addr := range addrs {

			var ip net.IP

			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.IsLoopback() {
				continue
			}

			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}

			return ip.String(), nil
		}
	}

	return "", errors.New("are you connected to the network?")
}

func getAllSources() []int {

    return []int{
        localWhois,
        whoisLookupSite,
        domainBigDataSite,
        markMonitorSite,
        youGetSignalSite,
        ipAddressOrgSite,
        robTexSite,
        domainPunchSite,
        whoisDomainSearch,
    }
}

func getSources(search string) []int {

	sources := make([]int, 0)

	if isIP(search) {

		return append(sources,
			localWhois,
			domainBigDataSite,
			markMonitorSite,
			ipAddressOrgSite,
			robTexSite,
			whoisDomainSearch)
	}

	return append(sources,
		localWhois,
		whoisLookupSite,
		domainBigDataSite,
		markMonitorSite,
		youGetSignalSite,
		ipAddressOrgSite,
		robTexSite,
		domainPunchSite,
		whoisDomainSearch)
}

func areMaximumSitesBlockingUs(sources []int) bool {

    count  := 0

    for _, source := range sources {

        if blockers[source].Status {

            count++
        }
    }

    if count >= int( ( float64(len(sources)/80) ) * 100 ) {
        return true
    }

    return false
}

func isLocalWhoisBlockingUs() bool {

    return isSourceBlockingUs(localWhois)
}

func isSourceBlockingUs(source int) bool {

    return blockers[source].Status
}

func randomMethod(search string) int {

	sources := getSources(search)

	// Fisher–Yates shuffle
	// shuffle without allocating any additional slices.
	for i := range sources {
		j := rand.Intn(i + 1)
		sources[i], sources[j] = sources[j], sources[i]
	}

	source := sources[rand.Intn(len(sources))]

    if isSourceBlockingUs(source) {

        if areMaximumSitesBlockingUs(sources) {

            if isLocalWhoisBlockingUs() {

                // Give Up!
                log.Fatal("All sources are blocking us!")

            } else {

                // exhaust local usage
                return localWhois
            }

        } else {

            randomMethod(search)
        }
    }

    return source
}

func randomUserAgent() string {

	userAgents := make([]string, 0)
	userAgents = append(userAgents,
		"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36",
		"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/1.0.154.53 Safari/525.19",
		"Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en-US) AppleWebKit/533.4 (KHTML, like Gecko) Chrome/5.0.375.86 Safari/533.4",
		"Mozilla/5.0 (X11; U; Linux x86_64; en-US) AppleWebKit/540.0 (KHTML,like Gecko) Chrome/9.1.0.0 Safari/540.0",
		"Mozilla/5.0 (X11; U; Linux x86_64; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Ubuntu/10.10 Chromium/8.0.552.237 Chrome/8.0.552.237 Safari/534.10",
		"Opera/9.80 (X11; Linux i686; Ubuntu/14.10) Presto/2.12.388 Version/12.16",
		"Mozilla/5.0 (Windows; U; Windows NT 6.1; x64; fr; rv:1.9.2.13) Gecko/20101203 Firebird/3.6.13",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A",
		"Mozilla/5.0 (iPad; CPU OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5355d Safari/8536.25",
		"Mozilla/5.0 (Windows NT 5.2; RW; rv:7.0a1) Gecko/20091211 SeaMonkey/9.23a1pre",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1",
		"Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10; rv:33.0) Gecko/20100101 Firefox/33.0",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0",
	)

	// Fisher–Yates shuffle
	// shuffle without allocating any additional slices.
	for i := range userAgents {
		j := rand.Intn(i + 1)
		userAgents[i], userAgents[j] = userAgents[j], userAgents[i]
	}

	return userAgents[rand.Intn(len(userAgents))]
}

// replaces the html tags present in the whois string
func replaceHTMLTags(whois string) string {

	cleanedWhois := strings.TrimSpace(whois)
	reg := regexp.MustCompile(`(?U)<.*>`)

	return reg.ReplaceAllString(cleanedWhois, "\n")
}

// extra blank lines are replaced
func replaceBlankLines(whois string) string {

	// in case of error, let's send back the original whois string
	regex, err := regexp.Compile("\n\n")
	if err != nil {
		return whois
	}

	return regex.ReplaceAllString(whois, "\n")
}

func dumpResponse(response *http.Response) {

	body, err := ioutil.ReadAll(response.Body)

	if err != nil {
		spew.Dump(err)
	}

	spew.Dump(string(body))
}

func bakeRequest(request Request) *http.Request {

	req, err := http.NewRequest(request.Method, request.Url.String(), bytes.NewBuffer(request.Body))
	if err != nil {
		panic(err)
	}

	for _, header := range request.Headers {

		req.Header.Set(header.Name, header.Value)
	}

	if len(request.Params) > 0 {

		query := req.URL.Query()

		for _, Query := range request.Params {

			query.Add(Query.Key, Query.Value)
		}

		req.URL.RawQuery = query.Encode()
	}

	return req
}

// makes http get or post query
func query(request Request) *http.Response {

	req := bakeRequest(request)
	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		panic(err)
	}

	return resp
}

// checks if the user whois lookup is IP
func isIP(search string) bool {

	if net.ParseIP(search) != nil {
		return true
	}

	return false
}

// currently all errors occurred while parsing the url
// string or response error or any other erros are
// replied back as no match found
func noMatchFound(search string) string {

	return "No match for " + search + "."
}

// Method: 1
func RunLocalWhois(search string) string {

	var out bytes.Buffer

	// https://golang.org/src/os/exec/exec.go?s=4289:4334#L119
	cmd := exec.Command("sh", "-c", "whois "+search)
	cmd.Stdout = &out

	err := cmd.Run()

	if err != nil {
		return noMatchFound(search)
	}

	return base64.StdEncoding.EncodeToString(out.Bytes())
}

// Method: 2
func ScrapeFromWhoisLookupSite(search string) string {

	uri := "http://www.whoislookup.com/whoislookupORIG.php?domain=" + search
	doc, err := goquery.NewDocument(uri)

	if err != nil {
		return noMatchFound(search)
	}

	return base64.StdEncoding.EncodeToString([]byte(replaceBlankLines(replaceHTMLTags(doc.Find("table.cwhoisform > tbody > tr > td").Text()))))
}

// Method: 3
func ScrapeFromDomainBigDataSite(search string) string {

    url, err := url.Parse("http://domainbigdata.com/" + search)

	if err != nil {
		return noMatchFound(search)
	}

	body := []byte("")
    headers := []Header{
		Header{Name: "Host", Value: "domainbigdata.com"},
		Header{Name: "Proxy-Connection", Value: "keep-alive"},
		Header{Name: "Pragma", Value: "no-cache"},
		Header{Name: "Cache-Control", Value: "no-cache"},
		Header{Name: "Origin", Value: "http://domainbigdata.com"},
        Header{Name: "Referer", Value: "http://domainbigdata.com/"},
		Header{Name: "User-Agent", Value: randomUserAgent()},
		Header{Name: "Accept-Language", Value: "en-US,en;q=0.8"},
        Header{Name: "Upgrade-Insecure-Requests", Value: "1"},
		Header{Name: "Accept", Value: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"},
	}

	resp := query(Request{Method: "GET", Url: url, Body: body, Headers: headers})
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromResponse(resp)
	if err != nil {
		return noMatchFound(search)
	}

    html := ""

    if isIP(search) {
        html, err = doc.Find("p#plitwhoisip").Html()
	} else {
        html, err = doc.Find("#whois .pd5").Html() // for domain
    }

    if err != nil {
        return noMatchFound(search)
    }

	// checking if there are any errors in response
    if strings.EqualFold(html, "ERROR") || strings.Contains(html, "ERROR") {
        html = "" // blank is detected as error!
    }

    // checking if the site has blocked us
    if strings.Contains(html, "ip logged") {
        html = ""
        // site has blocked has, no more queries to this site
        site := blockers[domainBigDataSite]
        site.Status = true
    }

	return base64.StdEncoding.EncodeToString([]byte(replaceHTMLTags(html)))
}

// Method: 4
func ScrapeFromMarkMonitorSite(search string) string {

	url, err := url.Parse("https://www.markmonitor.com/cgi-bin/affsearch.cgi")

	if err != nil {
		return noMatchFound(search)
	}

	body := []byte("")
	headers := []Header{
		Header{Name: "Host", Value: "www.markmonitor.com"},
		Header{Name: "Connection", Value: "keep-alive"},
		Header{Name: "Pragma", Value: "no-cache"},
		Header{Name: "Cache-Control", Value: "no-cache"},
		Header{Name: "Upgrade-Insecure-Requests", Value: "1"},
		Header{Name: "Accept", Value: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"},
		Header{Name: "User-Agent", Value: randomUserAgent()},
		Header{Name: "Accept-Language", Value: "en-US,en;q=0.8"},
	}

	params := []Query{
		Query{Key: "q", Value: search},
		Query{Key: "dn", Value: search},
		Query{Key: "partner", Value: "yes"},
	}

	resp := query(Request{Method: "GET", Url: url, Body: body, Headers: headers, Params: params})
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromResponse(resp)
	if err != nil {
		return noMatchFound(search)
	}

	html, err := doc.Find("pre").Html()
	if err != nil {
		return noMatchFound(search)
	}

	return base64.StdEncoding.EncodeToString([]byte(replaceBlankLines(replaceHTMLTags(html))))
}

// Method: 5
func ScrapeFromYouGetSignalSite(search string) string {

	url, err := url.Parse("http://www.yougetsignal.com/tools/whois-lookup/php/get-whois-lookup-json-data.php")
	if err != nil {
		return noMatchFound(search)
	}

	body := []byte("remoteAddress=" + search + "&_=")
	headers := []Header{
		Header{Name: "Host", Value: "www.yougetsignal.com"},
		Header{Name: "Connection", Value: "keep-alive"},
		Header{Name: "Pragma", Value: "no-cache"},
		Header{Name: "Cache-Control", Value: "no-cache"},
		Header{Name: "Origin", Value: "http://www.yougetsignal.com"},
		Header{Name: "User-Agent", Value: randomUserAgent()},
		Header{Name: "Content-Type", Value: "application/x-www-form-urlencoded; charset=UTF-8"},
		Header{Name: "Accept", Value: "text/javascript, text/html, application/xml, text/xml, */*"},
		Header{Name: "X-Prototype-Version", Value: "1.6.0"},
		Header{Name: "X-Requested-With", Value: "XMLHttpRequest"},
		Header{Name: "Referer", Value: "http://www.yougetsignal.com/tools/whois-lookup/"},
		Header{Name: "Accept-Language", Value: "en-US,en;q=0.8"},
	}

	resp := query(Request{Method: "POST", Url: url, Body: body, Headers: headers})
	defer resp.Body.Close()

	message := new(YouGetSignalMessage)
	json.NewDecoder(resp.Body).Decode(message)

	return base64.StdEncoding.EncodeToString([]byte(message.WhoisData))
}

// Method: 6
func ScrapeFromIPAddressOrgSite(search string) string {

	url, err := url.Parse("http://www.ip-address.org/tracer/ip-whois.php")

	if err != nil {
		return noMatchFound(search)
	}

	body := []byte("query=" + search + "&Submit=IP Whois Lookup")
	headers := []Header{
		Header{Name: "Host", Value: "www.ip-address.org"},
		Header{Name: "Connection", Value: "keep-alive"},
		Header{Name: "Pragma", Value: "no-cache"},
		Header{Name: "Cache-Control", Value: "no-cache"},
		Header{Name: "Upgrade-Insecure-Requests", Value: "1"},
		Header{Name: "Origin", Value: "http://www.ip-address.org"},
		Header{Name: "User-Agent", Value: randomUserAgent()},
		Header{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
		Header{Name: "Accept", Value: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"},
		Header{Name: "Referer", Value: "http://www.ip-address.org/tracer/ip-whois.php"},
		Header{Name: "Accept-Language", Value: "en-US,en;q=0.8"},
	}

	resp := query(Request{Method: "POST", Url: url, Body: body, Headers: headers})
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromResponse(resp)
	if err != nil {
		return noMatchFound(search)
	}

	html, err := doc.Find("pre").Html()
	if err != nil {
		return noMatchFound(search)
	}

	return base64.StdEncoding.EncodeToString([]byte(replaceBlankLines(replaceHTMLTags(html))))
}

// Method: 7
func ScrapeFromRobTexSite(search string) string {

	url, err := url.Parse(getRobTexSiteUrl(search))
	if err != nil {
		return noMatchFound(search)
	}

	body := []byte("")
	headers := []Header{
		Header{Name: "Pragma", Value: "no-cache"},
		Header{Name: "Cache-Control", Value: "no-cache"},
		Header{Name: "Upgrade-Insecure-Requests", Value: "1"},
		Header{Name: "Accept", Value: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"},
		Header{Name: "User-Agent", Value: randomUserAgent()},
		Header{Name: "Accept-Language", Value: "en-US,en;q=0.8"},
	}

	resp := query(Request{Method: "GET", Url: url, Body: body, Headers: headers})
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromResponse(resp)
	if err != nil {
		return noMatchFound(search)
	}

	var whois bytes.Buffer

	doc.Find("table.s").Each(func(i int, table *goquery.Selection) {

		table.Find("tr").Each(func(i int, tr *goquery.Selection) {

			key := tr.Find("td:first-child > b")
			value := tr.Find("td:last-child")

			if key.Text() != "" {

				whois.WriteString(key.Text())
				whois.WriteString(value.Text())
				whois.WriteString("\n")
			}
		})
	})

	return base64.StdEncoding.EncodeToString(whois.Bytes())
}

func getRobTexSiteUrl(search string) string {

	return "https://www.dnswhois.info/" + search
}

// Method:  8
// Website: Domainpunch
func ScrapeFromDomainPunch(search string) string {

	url, err := url.Parse("https://domainpunch.com/whois/whois.php?tld=" + search)
	if err != nil {
		return noMatchFound(search)
	}

	body := []byte("")
	headers := []Header{
		Header{Name: "Host", Value: "domainpunch.com"},
		Header{Name: "User-Agent", Value: randomUserAgent()},
		Header{Name: "Accept", Value: "*/*"},
		Header{Name: "Accept-Language", Value: "en-US,en;q=0.5"},
		Header{Name: "Referer", Value: "https://domainpunch.com/whois/"},
		Header{Name: "X-Requested-With", Value: "XMLHttpRequest"},
	}

	resp := query(Request{Method: "POST", Url: url, Body: body, Headers: headers})
	defer resp.Body.Close()

	message := new(DomainPunchMessage)
	json.NewDecoder(resp.Body).Decode(message)

	return base64.StdEncoding.EncodeToString([]byte(message.RAW))
}

func ScrapeFromWhoisDomainSearch(search string) string {

	url, err := url.Parse("https://whoisds.com/whois-lookup/lookup?domain=" + search)
	if err != nil {
		return noMatchFound(search)
	}

	body := []byte("")
	headers := []Header{
		Header{Name: "Host", Value: "whoisds.com"},
		Header{Name: "User-Agent", Value: randomUserAgent()},
		Header{Name: "Accept", Value: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		Header{Name: "Accept-Language", Value: "en-US,en;q=0.5"},
	}

	resp := query(Request{Method: "GET", Url: url, Body: body, Headers: headers})
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromResponse(resp)
	if err != nil {
		return noMatchFound(search)
	}

	// $$('.container .row .row .col-md-12:last-child')
	// getting raw html for applying the regex
	html, err := doc.Find(".container .row .row .col-md-12:last-child").Html()
	if err != nil {
		return noMatchFound(search)
	}

	html = strings.TrimSpace(html)

	// <h4 class="heading-primary">(.*)<\/h4>
	// domainAvailableReg  := regexp.MustCompile(`(?i)<h4 class="heading-primary">(.*)<\/h4>`)
	// domainRegistered    := false
	// registrationReg     := regexp.MustCompile(`(?i)already registered`)

	// if len(domainAvailableReg.FindStringIndex(html)) > 0 {

	//     availabilityStr  := domainAvailableReg.FindStringSubmatch(html)[1]

	//     if len(registrationReg.FindStringIndex(availabilityStr)) > 0 {
	//         domainRegistered = true
	//     }
	// }

	// <h4 class="heading-primary">.*<\/h4>\s+(.*)
	whoisReg := regexp.MustCompile(`(?is)<h4 class="heading-primary">.*<\/h4>\s+(.*)\s+`)
	whois := ""

	if len(whoisReg.FindStringIndex(html)) > 0 {

		whois = whoisReg.FindStringSubmatch(html)[1]

		if whois != "" {
			whois = replaceBlankLines(replaceHTMLTags(whois)) // clean it
		}
	}

	return base64.StdEncoding.EncodeToString([]byte(whois))
}

// init will be called before the main function
// Its the right place to initialize the seed Value
func init() {

	// note:
	// Each time you set the same seed, you get the same sequence
	// You have to set the seed only once
	// you simply call Intn to get the next random integer

	rand.Seed(time.Now().UTC().UnixNano())
}

func lookup(query string, method int) Output {

	ip, err := getHostIPAddress()

	if err != nil {
		log.Fatal("Failed getting the host IP address.")
	}

    if method == 0 {
        method = randomMethod(query)
    }

	var whois string

	switch method {

	case localWhois:
		whois = RunLocalWhois(query)

	case whoisLookupSite:
		whois = ScrapeFromWhoisLookupSite(query)

	case domainBigDataSite:
		whois = ScrapeFromDomainBigDataSite(query)

	case markMonitorSite:
		whois = ScrapeFromMarkMonitorSite(query)

	case youGetSignalSite:
		whois = ScrapeFromYouGetSignalSite(query)

	case ipAddressOrgSite:
		whois = ScrapeFromIPAddressOrgSite(query)

	case robTexSite:
		whois = ScrapeFromRobTexSite(query)

	case domainPunchSite:
		whois = ScrapeFromDomainPunch(query)

	case whoisDomainSearch:
		whois = ScrapeFromWhoisDomainSearch(query)

	default:
		whois = RunLocalWhois(query)
	}

	return Output{Query: query, Method: method, Whois: whois, IP: ip}
}

func main() {

	if 2 > len(os.Args) {
		log.Fatal("Usage: whoislookup queries")
	}

    initBlockers()

	queries  := strings.Split(os.Args[1], "*")
	throttle := 5

	type empty struct{}
    
	var wg sync.WaitGroup
	var sem = make(chan empty, throttle)

	outputs := make([]Output, 0)

	for _, query := range queries {

		wg.Add(1)
		sem <- struct{}{}

		go func(value string) {

			defer wg.Done()
			defer func() { <-sem }()
			defer func() {

				if r := recover(); r != nil {
					fmt.Println("Recovered in defer", r)
				}
			}()

			// lookup(value)
			o := lookup(value, 0)

			if o.Whois == "" {
                
				o = lookup(value, 0)
			}

			if o.Whois == "" {

				o = lookup(value, localWhois)
			}

			outputs = append(outputs, o)

		}(query)
	}

	wg.Wait()

	m, err := json.Marshal(outputs)

	if err != nil {
		fmt.Println("Error occurred!")
	}

	fmt.Println(string(m))
}
