package main

import (
	"archive/zip"
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/cavaliercoder/grab"
	"github.com/fatih/color"
	"github.com/likexian/whois-go"
	"github.com/likexian/whois-parser-go"
	"github.com/mholt/archiver/v3"
	"github.com/oschwald/maxminddb-golang"
	"github.com/tcnksm/go-latest"
	"golang.org/x/net/publicsuffix"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
	"unicode"
)

// program version
const version = "1.2.8"

var (
	githubTag = &latest.GithubTag{
		Owner:             "netevert",
		Repository:        "dnsmorph",
		FixVersionStrFunc: latest.DeleteFrontV()}
	g                 = color.New(color.FgHiGreen)
	y                 = color.New(color.FgHiYellow)
	r                 = color.New(color.FgHiRed)
	blue              = color.New(color.FgHiBlue).SprintFunc()
	yellow            = color.New(color.FgHiYellow).SprintFunc()
	white             = color.New(color.FgWhite).SprintFunc()
	red               = color.New(color.FgHiRed).SprintFunc()
	w                 = new(tabwriter.Writer)
	wg                = &sync.WaitGroup{}
	newSet            = flag.NewFlagSet("newSet", flag.ContinueOnError)
	whoisflag         = newSet.Bool("w", false, "whois lookup")
	check             = newSet.Bool("u", false, "update check")
	domain            = newSet.String("d", "", "target domain")
	geolocate         = newSet.Bool("g", false, "geolocate domain")
	list              = newSet.String("l", "", "domain list filepath")
	verbose           = newSet.Bool("v", false, "enable verbosity")
	includeSubDomains = newSet.Bool("i", false, "include subdomain")
	resolve           = newSet.Bool("r", false, "resolve domain")
	outcsv            = newSet.Bool("csv", false, "output to csv")
	outjson           = newSet.Bool("json", false, "output to json")
	utilDescription   = "dnsmorph -d domain | -l domains_file [-girvuw] [-csv | -json]"
	banner            = `
╔╦╗╔╗╔╔═╗╔╦╗╔═╗╦═╗╔═╗╦ ╦
 ║║║║║╚═╗║║║║ ║╠╦╝╠═╝╠═╣
═╩╝╝╚╝╚═╝╩ ╩╚═╝╩╚═╩  ╩ ╩`  // Calvin S on http://patorjk.com/
)

// GeoIPRecord struct
type GeoIPRecord struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		IsoCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// Record struct
type Record struct {
	Technique         string `json:"technique"`
	Domain            string `json:"domain"`
	A                 string `json:"a_record"`
	Geolocation       string `json:"geolocation"`
	WhoisCreation     string `json:"whoiscreation"`
	WhoisModification string `json:"whoismodification"`
}

// Target struct
type Target struct {
	Technique    string
	TargetDomain string
	Function     func(string) []string
}

// OutJSON struct
type OutJSON struct {
	Results []Record `json:"results"`
}

// prints Record data
func (r *Record) printRecordData(writer *tabwriter.Writer, verbose bool) {
	if verbose != false {
		fmt.Fprintln(writer, r.Technique+"\t"+r.Domain+"\t"+r.A+
			"\t"+r.WhoisCreation+"\t"+r.WhoisModification+"\t"+r.Geolocation)
		writer.Flush()
	} else {
		fmt.Fprintln(writer, r.Domain+"\t"+r.A+"\t"+r.WhoisCreation+"\t"+r.WhoisModification+"\t"+r.Geolocation)
		writer.Flush()
	}
}

// checks if new version of dnsmorph is available
func checkVersion() {
	y.Printf("DNSMORPH")
	fmt.Printf(" v.%s\n", version)
	res, _ := latest.Check(githubTag, version)
	if res.Outdated {
		r.Printf("v.%s released\n", res.Current)
		requestDownload()
	} else {
		g.Printf("you have the latest version\n")
	}
	os.Exit(1)
}

// asks the user permission to download new software version
func requestDownload() {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("upgrade? [y|n] ")
	for scanner.Scan() {
		switch res := scanner.Text(); res {
		case "y":
			downloadRelease()
		case "yes":
			downloadRelease()
		case "n":
			os.Exit(1)
		case "no":
			os.Exit(1)
		default:
			r.Printf("answer not valid\n")
			requestDownload()
		}
	}
	if scanner.Err() != nil {
		fmt.Println("error reading answer")
	}
}

// downloads new software version
func downloadRelease() {
	buffer := "                                  "
	binary := buildBinaryNameTarget()
	targetDirectory := buildBinaryDirectoryTarget()
	version, _ := latest.Check(githubTag, version)
	downloadTarget := buildDownloadTarget()
	os.Mkdir("tmp", os.ModePerm)
	url := fmt.Sprintf("https://github.com/netevert/dnsmorph/releases/download/v%s/%s", version.Current, downloadTarget)
	client := grab.NewClient()
	req, _ := grab.NewRequest("tmp", url)

	// start download
	g.Printf("\rstarting upgrade procedure...       ")
	resp := client.Do(req)
	y.Printf("\r%v"+buffer, resp.HTTPResponse.Status)

	// start UI loop
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()

Loop:
	for {
		select {
		case <-t.C:
			y.Printf("\rtransferred %v / %v bytes (%.2f%%)",
				resp.BytesComplete(),
				resp.Size,
				100*resp.Progress())

		case <-resp.Done:
			// download is complete
			break Loop
		}
	}

	// check for errors
	if err := resp.Err(); err != nil {
		r.Fprintf(os.Stderr, "\rupgrade failed: %v\n", err)
		os.Exit(1)
	}

	// unzip and store binaries in tmp folder for swap
	y.Printf("\r%v"+buffer, "unzipping...")
	os.Mkdir("tmp/"+targetDirectory, os.ModePerm)
	archiver.Unarchive("tmp/"+downloadTarget, "tmp/"+targetDirectory)
	src := fmt.Sprintf("tmp/%s/%s", targetDirectory, binary)
	dst := fmt.Sprintf("tmp/copy_%s", binary)
	copyFile(src, dst)
	f, err := os.Create(fmt.Sprintf("tmp/%s/.upgrade", targetDirectory))
	if err != nil {
		panic(err)
	}
	f.Close()
	os.Chdir(fmt.Sprintf("tmp/%s/", targetDirectory))
	cmd := exec.Command(binary)
	err = cmd.Start()
	if err != nil {
		r.Printf("\rupgrade failed: %v\n", err)
	}
	g.Printf("\r%v\n"+buffer, "upgrade finished")
	os.Exit(1)
}

// upgrades the current program executable to the newest version
func updateRelease() {
	binary := buildBinaryNameTarget()
	if _, err := os.Stat("tmp"); !os.IsNotExist(err) {
		// clean up tmp directory
		os.RemoveAll("tmp")
	}
	if _, err := os.Stat(".upgrade"); !os.IsNotExist(err) {
		// swap executables and update release
		os.RemoveAll(fmt.Sprintf("../../%s", binary))
		copyFile(fmt.Sprintf("../copy_%s", binary), fmt.Sprintf("../../copy_%s", binary))
		err = os.Rename(fmt.Sprintf("../../copy_%s", binary), fmt.Sprintf("../../%s", binary))
		os.Exit(1)
	}
}

// copies file from src to dst
func copyFile(src, dst string) {
	source, err := os.Open(src)
	if err != nil {
		r.Printf("error copying %v to %v", src, dst)
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		r.Printf("error copying %v to %v", src, dst)
	}
	defer destination.Close()
	_, err = io.Copy(destination, source)
	source.Close()

}

// determines host platform and architecture to build appropriate download target
func buildDownloadTarget() string {
	ext := "tar.gz"
	version, _ := latest.Check(githubTag, version)
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "64-bit"
	} else {
		arch = "32-bit"
	}
	os := runtime.GOOS
	if os == "darwin" {
		os = "macOS"
	}
	if os == "windows" {
		ext = "zip"
	}
	return fmt.Sprintf("dnsmorph_%s_%s_%s.%s", version.Current, os, arch, ext)
}

// determines host platform to build appropriate binary name
func buildBinaryNameTarget() string {
	binary := "dnsmorph"
	if runtime.GOOS == "windows" {
		binary = "dnsmorph.exe"
	}
	return binary
}

// determines host platform to build appropriate binary directory name
func buildBinaryDirectoryTarget() string {
	directory := buildDownloadTarget()
	if runtime.GOOS == "windows" {
		directory = strings.Replace(directory, ".zip", "", -1)
	} else {
		directory = strings.Replace(directory, ".tar.gz", "", -1)
	}
	return directory
}

// sets up command-line arguments
func setup() {

	newSet.Usage = func() {
		g.Printf(banner)
		fmt.Printf(" v.%s\n", version)
		y.Printf("written & maintained by NetEvert\n\n")
		fmt.Println(utilDescription)
		newSet.PrintDefaults()
		os.Exit(1)
	}

	newSet.Parse(os.Args[1:])

	// workaround to suppress glog errors, as per https://github.com/kubernetes/kubernetes/issues/17162#issuecomment-225596212
	flag.CommandLine.Parse([]string{})

	if *check {
		checkVersion()
	}

	if *domain == "" && *list == "" {
		r.Printf("\nplease supply domains\n\n")
		fmt.Println(utilDescription)
		newSet.PrintDefaults()
		os.Exit(1)
	}

	if *list != "" && *domain != "" {
		r.Printf("\nplease supply either option -d or -l\n\n")
		fmt.Println(utilDescription)
		newSet.PrintDefaults()
		os.Exit(1)
	}

	if *outjson != false && *outcsv != false {
		r.Printf("\nplease supply either csv or json ouput\n\n")
		fmt.Println(utilDescription)
		newSet.PrintDefaults()
		os.Exit(1)
	}
}

// returns a count of characters in a word
func countChar(word string) map[rune]int {
	count := make(map[rune]int)
	for _, r := range []rune(word) {
		count[r]++
	}
	return count
}

// performs an A record DNS lookup
func aLookup(Domain string) string {
	ip, err := net.ResolveIPAddr("ip4", Domain)
	if err != nil {
		return ""

	}
	return ip.String() // todo: fix to return only one IP
}

// performs a geolocation lookup on input IP, returns country + city
func geoLookup(inputIP string) string {
	if inputIP != "" {
		db, err := maxminddb.Open("data/GeoLite2-City.mmdb")
		if err != nil {
			log.Fatal(err)
		}
		defer db.Close()
		ip := net.ParseIP(inputIP)
		var record GeoIPRecord
		err = db.Lookup(ip, &record)
		if err != nil {
			log.Fatal(err)
		}
		return record.Country.IsoCode + " " + record.City.Names["en"]
	}
	return ""
}

// performs a whois lookup on input IP, return creation and modification date
func whoisLookup(inputDomain string) []string {
	var data []string
	if inputDomain != "" {
		whoisRaw, _ := whois.Whois(inputDomain)
		result, err := whoisparser.Parse(whoisRaw)
		if err == nil {

			// Add the domain created date
			data = append(data, result.Domain.CreatedDate)

			// Print the domain modification date
			data = append(data, result.Domain.UpdatedDate)
		}
	}
	return data
}

// performs lookups on individual records
func doLookups(Technique, Domain, tld string, out chan<- Record, resolve, geolocate, whoisflag bool) {
	defer wg.Done()
	r := new(Record)
	r.Technique = Technique
	r.Domain = Domain + "." + tld
	if resolve {
		r.A = aLookup(r.Domain)
	}
	if geolocate {
		r.Geolocation = geoLookup(aLookup(r.Domain))
	}
	if whoisflag {
		record := whoisLookup(r.Domain)
		if len(record) > 0 {
			r.WhoisCreation = record[0]
			r.WhoisModification = record[1]
		} else {
			r.WhoisCreation = ""
			r.WhoisModification = ""
		}
	}
	out <- *r
}

// runs bulk lookups on list of domains
func runLookups(technique string, results []string, tld string, out chan<- Record, resolve, geolocate, whoisflag bool) {
	for _, r := range results {
		wg.Add(1)
		go doLookups(technique, r, tld, out, resolve, geolocate, whoisflag)
	}
}

// validates domains using regex
func validateDomainName(Domain string) bool {

	patternStr := `^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$`

	RegExp := regexp.MustCompile(patternStr)
	return RegExp.MatchString(Domain)
}

// sanitizes domains inputted into dnsmorph
func processInput(input string) (sanitizedDomain, tld string) {
	if !validateDomainName(input) {
		r.Printf("\nplease supply a valid Domain\n\n")
		fmt.Println(utilDescription)
		newSet.PrintDefaults()
		os.Exit(1)
	} else {
		if *includeSubDomains == false {
			tldPlusOne, _ := publicsuffix.EffectiveTLDPlusOne(input)
			tld, _ = publicsuffix.PublicSuffix(tldPlusOne)
			sanitizedDomain = strings.Replace(tldPlusOne, "."+tld, "", -1)
		} else if *includeSubDomains == true {
			tld, _ = publicsuffix.PublicSuffix(input)
			sanitizedDomain = strings.Replace(input, "."+tld, "", -1)
		}
	}
	return sanitizedDomain, tld
}

// helper function to print permutation report and miscellaneous information
func printReport(technique string, results []string, tld string) {
	out := make(chan Record)
	w.Init(os.Stdout, 0, 22, 0, '\t', 0)
	switch {
	case *resolve == true && *geolocate == true && *whoisflag == true:
		runLookups(technique, results, tld, out, *resolve, *geolocate, *whoisflag)
	case *verbose == true && *resolve == true && *geolocate == true && *whoisflag == true:
		runLookups(technique, results, tld, out, *resolve, *geolocate, *whoisflag)
	case *verbose == true && *resolve == true && *whoisflag == true:
		runLookups(technique, results, tld, out, *resolve, false, *whoisflag)
	case *verbose == true && *geolocate == true && *whoisflag == true:
		runLookups(technique, results, tld, out, false, *geolocate, *whoisflag)
	case *verbose == true && *whoisflag == true:
		runLookups(technique, results, tld, out, false, false, *whoisflag)
	case *resolve == true && *whoisflag == true:
		runLookups(technique, results, tld, out, *resolve, false, *whoisflag)
	case *geolocate == true && *whoisflag == true:
		runLookups(technique, results, tld, out, false, *geolocate, *whoisflag)
	case *verbose == true && *resolve == true && *geolocate == true:
		runLookups(technique, results, tld, out, *resolve, *geolocate, false)
	case *verbose == true && *geolocate == true:
		runLookups(technique, results, tld, out, false, *geolocate, false)
	case *verbose == true && *resolve == true:
		runLookups(technique, results, tld, out, *resolve, *geolocate, false)
	case *resolve == true && *geolocate == true:
		runLookups(technique, results, tld, out, *resolve, *geolocate, false)
	case *geolocate == true:
		runLookups(technique, results, tld, out, false, *geolocate, false)
	case *resolve == true:
		runLookups(technique, results, tld, out, *resolve, *geolocate, false)
	case *whoisflag == true:
		runLookups(technique, results, tld, out, false, false, *whoisflag)
	case *verbose == true:
		for _, result := range results {
			printResults(w, technique, result, tld)
		}
	case *verbose == false && *resolve == false:
		for _, result := range results {
			fmt.Println(result + "." + tld)
		}
	}
	go monitorWorker(wg, out)
	for r := range out {
		r.printRecordData(w, *verbose)
	}
}

// prints results data when records are not returned
func printResults(writer *tabwriter.Writer, technique, result, tld string) {
	if runtime.GOOS == "windows" {
		fmt.Fprintln(w, technique+"\t"+result+"."+tld+"\t")
		w.Flush()
	} else {
		fmt.Fprintln(w, blue(technique)+"\t"+result+"."+tld+"\t")
		w.Flush()
	}
}

// helper function to print output information during csv generation
func printOutputInfo(results [][]string) {
	y.Printf("%s ", "[*]")
	fmt.Printf("%s", "found ")
	r.Printf("%v", len(results))
	fmt.Printf("%s\n", " permutations")
	lookups := []string{}
	y.Printf("%s ", "[*]")
	fmt.Printf("%s", "lookups selected: ")
	if *resolve != false {
		lookups = append(lookups, "a record")
	}
	if *geolocate != false {
		lookups = append(lookups, "geolocation")
	}
	if *whoisflag != false {
		lookups = append(lookups, "whois lookup")
	}
	for _, lookup := range lookups {
		y.Printf("[%s] ", lookup)
	}
	fmt.Printf("\n")
}

// helper function to wait for goroutines collection to finish and close channel
func monitorWorker(wg *sync.WaitGroup, channel chan Record) {
	wg.Wait()
	close(channel)
}

// outputs results data to a csv file
func outputToFile(targets []string) {
	// create results list
	out := make(chan Record)
	results := [][]string{}
	for _, target := range targets {
		sanitizedDomain, tld := processInput(target)
		for _, t := range []Target{
			{"transposition", sanitizedDomain, transpositionAttack},
			{"addition", sanitizedDomain, additionAttack},
			{"vowelswap", sanitizedDomain, vowelswapAttack},
			{"subdomain", sanitizedDomain, subdomainAttack},
			{"replacement", sanitizedDomain, replacementAttack},
			{"repetition", sanitizedDomain, repetitionAttack},
			{"omission", sanitizedDomain, omissionAttack},
			{"hyphenation", sanitizedDomain, hyphenationAttack},
			{"bitsquatting", sanitizedDomain, bitsquattingAttack},
			{"homograph", sanitizedDomain, homographAttack}} {
			for _, r := range t.Function(t.TargetDomain) {
				results = append(results, []string{r + "." + tld, t.Technique})
			}
		}
	}
	for _, r := range results {
		wg.Add(1)
		s := strings.Split(r[0], ".")
		domain, tld := s[0], s[1]
		go doLookups(r[1], domain, tld, out, *resolve, *geolocate, *whoisflag)
	}
	go monitorWorker(wg, out)
	if *outcsv != false {
		if *verbose != false {
			printOutputInfo(results)
		}
		file, err := os.Create("result.csv")
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()
		writer := csv.NewWriter(file)
		defer writer.Flush()
		for r := range out {
			var data = []string{r.Technique, r.Domain, r.A, r.Geolocation, r.WhoisCreation, r.WhoisModification}
			err := writer.Write(data)
			if err != nil {
				log.Fatal(err)
			}
		}
		if *verbose != false {
			y.Printf("%s ", "[*]")
			g.Printf("done")
		} else {
			g.Printf("done")
		}
	}
	if *outjson != false {
		var output OutJSON
		for r := range out {
			output.Results = append(output.Results, r)
		}
		data, err := json.Marshal(output)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s\n", data)
	}
}

// helper function to specify permutation attacks to be performed
func runPermutations(targets []string) {
	if *outcsv != false || *outjson != false {
		outputToFile(targets)
	} else {
		for _, target := range targets {
			sanitizedDomain, tld := processInput(target)
			printReport("addition", additionAttack(sanitizedDomain), tld)
			printReport("omission", omissionAttack(sanitizedDomain), tld)
			printReport("homograph", homographAttack(sanitizedDomain), tld)
			printReport("subdomain", subdomainAttack(sanitizedDomain), tld)
			printReport("vowel swap", vowelswapAttack(sanitizedDomain), tld)
			printReport("repetition", repetitionAttack(sanitizedDomain), tld)
			printReport("hyphenation", hyphenationAttack(sanitizedDomain), tld)
			printReport("replacement", replacementAttack(sanitizedDomain), tld)
			printReport("bitsquatting", bitsquattingAttack(sanitizedDomain), tld)
			printReport("transposition", transpositionAttack(sanitizedDomain), tld)
		}
	}
}

// performs an addition attack adding a single character to the domain
func additionAttack(domain string) []string {
	results := []string{}

	for i := 97; i < 123; i++ {
		results = append(results, fmt.Sprintf("%s%c", domain, i))
	}
	return results
}

// performs a vowel swap attack
func vowelswapAttack(domain string) []string {
	results := []string{}
	vowels := []rune{'a', 'e', 'i', 'o', 'u', 'y'}
	runes := []rune(domain)

	for i := 0; i < len(runes); i++ {
		for _, v := range vowels {
			switch runes[i] {
			case 'a', 'e', 'i', 'o', 'u', 'y':
				if runes[i] != v {
					results = append(results, fmt.Sprintf("%s%c%s", string(runes[:i]), v, string(runes[i+1:])))
				}
			default:
			}
		}
	}
	return results
}

// performs a transposition attack swapping adjacent characters in the domain
func transpositionAttack(domain string) []string {
	results := []string{}
	for i := 0; i < len(domain)-1; i++ {
		if domain[i+1] != domain[i] {
			results = append(results, fmt.Sprintf("%s%c%c%s", domain[:i], domain[i+1], domain[i], domain[i+2:]))
		}
	}
	return results
}

// performs a subdomain attack by inserting dots between characters, effectively turning the
// domain in a subdomain
func subdomainAttack(domain string) []string {
	results := []string{}
	runes := []rune(domain)

	for i := 1; i < len(runes); i++ {
		if (rune(runes[i]) != '-' || rune(runes[i]) != '.') && (rune(runes[i-1]) != '-' || rune(runes[i-1]) != '.') {
			results = append(results, fmt.Sprintf("%s.%s", string(runes[:i]), string(runes[i:])))
		}
	}
	return results
}

// performs a replacement attack simulating a user pressing the wrong keys
func replacementAttack(domain string) []string {
	results := []string{}
	keyboards := make([]map[rune]string, 0)
	count := make(map[string]int)
	keyboardEn := map[rune]string{'q': "12wa", '2': "3wq1", '3': "4ew2", '4': "5re3", '5': "6tr4", '6': "7yt5", '7': "8uy6", '8': "9iu7", '9': "0oi8", '0': "po9",
		'w': "3esaq2", 'e': "4rdsw3", 'r': "5tfde4", 't': "6ygfr5", 'y': "7uhgt6", 'u': "8ijhy7", 'i': "9okju8", 'o': "0plki9", 'p': "lo0",
		'a': "qwsz", 's': "edxzaw", 'd': "rfcxse", 'f': "tgvcdr", 'g': "yhbvft", 'h': "ujnbgy", 'j': "ikmnhu", 'k': "olmji", 'l': "kop",
		'z': "asx", 'x': "zsdc", 'c': "xdfv", 'v': "cfgb", 'b': "vghn", 'n': "bhjm", 'm': "njk"}
	keyboardDe := map[rune]string{'q': "12wa", 'w': "23esaq", 'e': "34rdsw", 'r': "45tfde", 't': "56zgfr", 'z': "67uhgt", 'u': "78ijhz", 'i': "89okju",
		'o': "90plki", 'p': "0ßüölo", 'ü': "ß+äöp", 'a': "qwsy", 's': "wedxya", 'd': "erfcxs", 'f': "rtgvcd", 'g': "tzhbvf", 'h': "zujnbg", 'j': "uikmnh",
		'k': "iolmj", 'l': "opök", 'ö': "püäl-", 'ä': "ü-ö", 'y': "asx", 'x': "sdcy", 'c': "dfvx", 'v': "fgbc", 'b': "ghnv", 'n': "hjmb", 'm': "jkn",
		'1': "2q", '2': "13wq", '3': "24ew", '4': "35re", '5': "46tr", '6': "57zt", '7': "68uz", '8': "79iu", '9': "80oi", '0': "9ßpo", 'ß': "0üp"}
	keyboardEs := map[rune]string{'q': "12wa", 'w': "23esaq", 'e': "34rdsw", 'r': "45tfde", 't': "56ygfr", 'y': "67uhgt", 'u': "78ijhy", 'i': "89okju",
		'o': "90plki", 'p': "0loñ", 'a': "qwsz", 's': "wedxza", 'd': "erfcxs", 'f': "rtgvcd", 'g': "tyhbvf", 'h': "yujnbg", 'j': "uikmnh", 'k': "iolmj",
		'l': "opkñ", 'ñ': "pl", 'z': "asx", 'x': "sdcz", 'c': "dfvx", 'v': "fgbc", 'b': "ghnv", 'n': "hjmb", 'm': "jkn", '1': "2q", '2': "13wq",
		'3': "24ew", '4': "35re", '5': "46tr", '6': "57yt", '7': "68uy", '8': "79iu", '9': "80oi", '0': "9po"}
	keyboardFr := map[rune]string{'a': "12zqé", 'z': "23eésaq", 'e': "34rdsz", 'r': "45tfde", 't': "56ygfr-", 'y': "67uhgtè-", 'u': "78ijhyè",
		'i': "89okjuç", 'o': "90plkiçà", 'p': "0àlo", 'q': "azsw", 's': "zedxwq", 'd': "erfcxs", 'f': "rtgvcd", 'g': "tzhbvf", 'h': "zujnbg",
		'j': "uikmnh", 'k': "iolmj", 'l': "opmk", 'm': "pùl", 'w': "qsx", 'x': "sdcw", 'c': "dfvx", 'v': "fgbc", 'b': "ghnv", 'n': "hjb",
		'1': "2aé", '2': "13azé", '3': "24ewé", '4': "35re", '5': "46tr", '6': "57ytè", '7': "68uyè", '8': "79iuèç", '9': "80oiçà", '0': "9àçpo"}
	keyboards = append(keyboards, keyboardEn, keyboardDe, keyboardEs, keyboardFr)
	for i, c := range domain {
		for _, keyboard := range keyboards {
			for _, char := range []rune(keyboard[c]) {
				result := fmt.Sprintf("%s%c%s", domain[:i], char, domain[i+1:])
				// remove duplicates
				count[result]++
				if count[result] < 2 {
					results = append(results, result)
				}
			}
		}
	}
	return results
}

// performs a repetition attack simulating a user pressing a key twice
func repetitionAttack(domain string) []string {
	results := []string{}
	count := make(map[string]int)
	for i, c := range domain {
		if unicode.IsLetter(c) {
			result := fmt.Sprintf("%s%c%c%s", domain[:i], domain[i], domain[i], domain[i+1:])
			// remove duplicates
			count[result]++
			if count[result] < 2 {
				results = append(results, result)
			}
		}
	}
	return results
}

// performs an omission attack removing characters across the domain name
func omissionAttack(domain string) []string {
	results := []string{}
	for i := range domain {
		results = append(results, fmt.Sprintf("%s%s", domain[:i], domain[i+1:]))
	}
	return results
}

// performs a hyphenation attack adding hyphens between characters
func hyphenationAttack(domain string) []string {
	results := []string{}
	for i := 1; i < len(domain); i++ {
		if (rune(domain[i]) != '-' || rune(domain[i]) != '.') && (rune(domain[i-1]) != '-' || rune(domain[i-1]) != '.') {
			results = append(results, fmt.Sprintf("%s-%s", domain[:i], domain[i:]))
		}
	}
	return results
}

// performs a bitsquat permutation attack
func bitsquattingAttack(domain string) []string {

	results := []string{}
	masks := []int32{1, 2, 4, 8, 16, 32, 64, 128}

	for i, c := range domain {
		for m := range masks {
			b := rune(int(c) ^ m)
			o := int(b)
			if (o >= 48 && o <= 57) || (o >= 97 && o <= 122) || o == 45 {
				results = append(results, fmt.Sprintf("%s%c%s", domain[:i], b, domain[i+1:]))
			}
		}
	}
	return results
}

// performs a homograph permutation attack
func homographAttack(domain string) []string {
	// set local variables
	glyphs := map[rune][]rune{
		'a': {'à', 'á', 'â', 'ã', 'ä', 'å', 'ɑ', 'а', 'ạ', 'ǎ', 'ă', 'ȧ', 'α', 'ａ'},
		'b': {'d', 'ʙ', 'Ь', 'ɓ', 'Б', 'ß', 'β', 'ᛒ', '\u1E05', '\u1E03', '\u1D6C'}, // 'lb', 'ib'
		'c': {'ϲ', 'с', 'ƈ', 'ċ', 'ć', 'ç', 'ｃ'},
		'd': {'b', 'ԁ', 'ժ', 'ɗ', 'đ'}, // 'cl', 'dl', 'di'
		'e': {'é', 'ê', 'ë', 'ē', 'ĕ', 'ě', 'ė', 'е', 'ẹ', 'ę', 'є', 'ϵ', 'ҽ'},
		'f': {'Ϝ', 'ƒ', 'Ғ'},
		'g': {'q', 'ɢ', 'ɡ', 'Ԍ', 'Ԍ', 'ġ', 'ğ', 'ց', 'ǵ', 'ģ'},
		'h': {'һ', 'հ', '\u13C2', 'н'}, // 'lh', 'ih'
		'i': {'1', 'l', '\u13A5', 'í', 'ï', 'ı', 'ɩ', 'ι', 'ꙇ', 'ǐ', 'ĭ'},
		'j': {'ј', 'ʝ', 'ϳ', 'ɉ'},
		'k': {'κ', 'κ'}, // 'lk', 'ik', 'lc'
		'l': {'1', 'i', 'ɫ', 'ł'},
		'm': {'n', 'ṃ', 'ᴍ', 'м', 'ɱ'}, // 'nn', 'rn', 'rr'
		'n': {'m', 'r', 'ń'},
		'o': {'0', 'Ο', 'ο', 'О', 'о', 'Օ', 'ȯ', 'ọ', 'ỏ', 'ơ', 'ó', 'ö', 'ӧ', 'ｏ'},
		'p': {'ρ', 'р', 'ƿ', 'Ϸ', 'Þ'},
		'q': {'g', 'զ', 'ԛ', 'գ', 'ʠ'},
		'r': {'ʀ', 'Г', 'ᴦ', 'ɼ', 'ɽ'},
		's': {'Ⴝ', '\u13DA', 'ʂ', 'ś', 'ѕ'},
		't': {'τ', 'т', 'ţ'},
		'u': {'μ', 'υ', 'Ս', 'ս', 'ц', 'ᴜ', 'ǔ', 'ŭ'},
		'v': {'ѵ', 'ν', '\u1E7F', '\u1E7D'}, // 'v̇'
		'w': {'ѡ', 'ա', 'ԝ'},                // 'vv'
		'x': {'х', 'ҳ', '\u1E8B'},
		'y': {'ʏ', 'γ', 'у', 'Ү', 'ý'},
		'z': {'ʐ', 'ż', 'ź', 'ʐ', 'ᴢ'},
	}
	doneCount := make(map[rune]bool)
	results := []string{}
	runes := []rune(domain)
	count := countChar(domain)

	for i, char := range runes {
		// perform attack against single character
		for _, glyph := range glyphs[char] {
			results = append(results, fmt.Sprintf("%s%c%s", string(runes[:i]), glyph, string(runes[i+1:])))
		}
		// determine if character is a duplicate
		// and if the attack has already been performed
		// against all characters at the same time
		if count[char] > 1 && doneCount[char] != true {
			doneCount[char] = true
			for _, glyph := range glyphs[char] {
				result := strings.Replace(domain, string(char), string(glyph), -1)
				results = append(results, result)
			}
		}
	}
	return results
}

// Unzip will decompress a zip archive, moving all files and folders
// within the zip file (parameter 1) to an output directory (parameter 2).
func Unzip(src string, dest string) ([]string, error) {

	var filenames []string

	r, err := zip.OpenReader(src)
	if err != nil {
		return filenames, err
	}
	defer r.Close()

	for _, f := range r.File {

		rc, err := f.Open()
		if err != nil {
			return filenames, err
		}
		defer rc.Close()

		// Store filename/path for returning and using later on
		fpath := filepath.Join(dest, f.Name)

		// Check for ZipSlip. More Info: http://bit.ly/2MsjAWE
		if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return filenames, fmt.Errorf("%s: illegal file path", fpath)
		}

		filenames = append(filenames, fpath)

		if f.FileInfo().IsDir() {

			// Make Folder
			os.MkdirAll(fpath, os.ModePerm)

		} else {

			// Make File
			if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
				return filenames, err
			}

			outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				return filenames, err
			}

			_, err = io.Copy(outFile, rc)

			// Close the file without defer to close before next iteration of loop
			outFile.Close()

			if err != nil {
				return filenames, err
			}

		}
	}
	return filenames, nil
}

// main program entry point
func main() {
	updateRelease()
	// check if geolocation database is zipped, if so unzip
	if _, err := os.Stat("data/GeoLite2-City.zip"); !os.IsNotExist(err) {
		_, err := Unzip("data/GeoLite2-City.zip", "data")
		if err != nil {
			log.Fatal(err)
		}
		os.Remove("data/GeoLite2-City.zip")
	}
	setup()

	if *domain != "" && *list == "" {
		sanitizedDomain, tld := processInput(*domain)
		targets := []string{sanitizedDomain + "." + tld}
		runPermutations(targets)
	}

	if *list != "" && *domain == "" {
		targets := []string{}
		file, err := os.Open(*list)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			sanitizedDomain, tld := processInput(scanner.Text())
			targets = append(targets, sanitizedDomain+"."+tld)
		}
		runPermutations(targets)
	}
}
