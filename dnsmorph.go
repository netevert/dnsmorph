package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/fatih/color"
	"github.com/oschwald/maxminddb-golang"
	"golang.org/x/net/publicsuffix"
	"log"
	"net"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"text/tabwriter"
	"unicode"
)

// program version
const version = "1.2.0"

var (
	g                 = color.New(color.FgHiGreen)
	y                 = color.New(color.FgHiYellow)
	r                 = color.New(color.FgHiRed)
	blue              = color.New(color.FgHiBlue).SprintFunc()
	yellow            = color.New(color.FgHiYellow).SprintFunc()
	white             = color.New(color.FgWhite).SprintFunc()
	red               = color.New(color.FgHiRed).SprintFunc()
	w                 = new(tabwriter.Writer)
	wg                = &sync.WaitGroup{}
	domain            = flag.String("d", "", "target domain")
	geolocate         = flag.Bool("g", false, "geolocate domain")
	list              = flag.String("l", "", "domain list filepath")
	verbose           = flag.Bool("v", false, "enable verbosity")
	includeSubDomains = flag.Bool("i", false, "include subdomain")
	resolve           = flag.Bool("r", false, "resolve domain")
	outcsv            = flag.Bool("csv", false, "output to csv")
	outjson           = flag.Bool("json", false, "output to json")
	utilDescription   = "dnsmorph -d domain | -l domains_file [-girv] [-csv | -json]"
	banner            = `
╔╦╗╔╗╔╔═╗╔╦╗╔═╗╦═╗╔═╗╦ ╦
 ║║║║║╚═╗║║║║ ║╠╦╝╠═╝╠═╣
═╩╝╝╚╝╚═╝╩ ╩╚═╝╩╚═╩  ╩ ╩` // Calvin S on http://patorjk.com/
)

type GeoIPRecord struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		IsoCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

type Record struct {
	Technique   string `json:"technique"`
	Domain      string `json:"domain"`
	A           string `json:"a_record"`
	Geolocation string `json:"geolocation"`
}

type Target struct {
	Technique    string
	TargetDomain string
	Function     func(string) []string
}

type OutJson struct {
	Results []Record `json:"results"`
}

// prints all Record data
func (r *Record) printAll(writer *tabwriter.Writer, verbose bool) {
	if runtime.GOOS == "windows" {
		if verbose != false {
			fmt.Fprintln(writer, r.Technique+"\t"+r.Domain+"\t"+"A:"+r.A+"\t"+"GEO:"+r.Geolocation+"\t")
			writer.Flush()
		} else {
			fmt.Fprintln(writer, r.Domain+"\t"+r.A+"\t"+r.Geolocation+"\t")
			writer.Flush()
		}
	} else {
		if verbose != false {
			fmt.Fprintln(writer, blue(r.Technique)+"\t"+r.Domain+"\t"+white("A:")+yellow(r.A)+"\t"+white("GEO:")+yellow(r.Geolocation)+"\t")
			writer.Flush()
		} else {
			fmt.Fprintln(writer, r.Domain+"\t"+yellow(r.A)+"\t"+yellow(r.Geolocation)+"\t")
			writer.Flush()
		}
	}
}

// print method for Record structs that have a data but not Geolocation data
func (r *Record) printANotGeo(writer *tabwriter.Writer, verbose bool) {
	if runtime.GOOS == "windows" {
		if verbose != false {
			fmt.Fprintln(writer, r.Technique+"\t"+r.Domain+"\t"+"A:"+r.A+"\t"+"GEO:-"+"\t")
			writer.Flush()
		} else {
			fmt.Fprintln(writer, r.Domain+"\t"+r.A+"\t"+""+"\t")
			writer.Flush()
		}
	} else {
		if verbose != false {
			fmt.Fprintln(writer, blue(r.Technique)+"\t"+r.Domain+"\t"+white("A:")+yellow(r.A)+"\t"+white("GEO:")+red("-")+"\t")
			writer.Flush()
		} else {
			fmt.Fprintln(writer, r.Domain+"\t"+yellow(r.A)+"\t"+""+"\t")
			writer.Flush()
		}
	}
}

// print method for Record structs that have Geolocation data but not a data
func (r *Record) printGeoNotA(writer *tabwriter.Writer, verbose bool) {
	if runtime.GOOS == "windows" {
		if verbose != true {
			fmt.Fprintln(writer, r.Technique+"\t"+r.Domain+"\t"+"A:-"+"\t"+"GEO:"+r.Geolocation+"\t")
			writer.Flush()
		} else {
			fmt.Fprintln(writer, r.Domain+"\t"+""+"\t"+r.Geolocation+"\t")
			writer.Flush()
		}
	} else {
		if verbose != false {
			fmt.Fprintln(writer, blue(r.Technique)+"\t"+r.Domain+"\t"+white("A:")+red("-")+"\t"+white("GEO:")+yellow(r.Geolocation)+"\t")
			writer.Flush()
		} else {
			fmt.Fprintln(writer, r.Domain+"\t"+""+"\t"+yellow(r.Geolocation)+"\t")
			writer.Flush()
		}
	}
}

// print method for empty Record structs
func (r *Record) printEmptyRecord(writer *tabwriter.Writer, verbose bool) {
	if runtime.GOOS == "windows" {
		if verbose != false {
			fmt.Fprintln(writer, r.Technique+"\t"+r.Domain+"\t"+"A:-"+"\t"+"GEO:-"+"\t")
			writer.Flush()
		} else {
			fmt.Fprintln(writer, r.Domain+"\t"+""+"\t"+""+"\t")
			writer.Flush()
		}
	} else {
		if verbose != false {
			fmt.Fprintln(writer, blue(r.Technique)+"\t"+r.Domain+"\t"+white("A:")+red("-")+"\t"+white("GEO:")+red("-")+"\t")
			writer.Flush()
		} else {
			fmt.Fprintln(writer, r.Domain+"\t"+""+"\t"+""+"\t")
			writer.Flush()
		}
	}
}

// prints A record data non verbosely
func (r *Record) printARecord(writer *tabwriter.Writer) {
	fmt.Fprintln(writer, r.Domain+"\t"+r.A+"\t")
	writer.Flush()
}

// prints Geolocation record data non verbosely
func (r *Record) printGeoRecord(writer *tabwriter.Writer) {
	fmt.Fprintln(writer, r.Domain+"\t"+r.Geolocation+"\t")
	writer.Flush()
}

// prints a record data verbosely
func (r *Record) printARecordVerbose(writer *tabwriter.Writer) {
	if runtime.GOOS == "windows" {
		fmt.Fprintln(writer, r.Technique+"\t"+r.Domain+"\t"+"A:"+r.A+"\t")
		writer.Flush()
	} else {
		fmt.Fprintln(writer, blue(r.Technique)+"\t"+r.Domain+"\t"+white("A:")+yellow(r.A)+"\t")
		writer.Flush()
	}
}

// verbosely prints a Record with missing a record data
func (r *Record) printNoARecordVerbose(writer *tabwriter.Writer) {
	if runtime.GOOS == "windows" {
		fmt.Fprintln(writer, r.Technique+"\t"+r.Domain+"\t"+"A:-"+"\t")
		writer.Flush()
	} else {
		fmt.Fprintln(writer, blue(r.Technique)+"\t"+r.Domain+"\t"+white("A:")+red("-")+"\t")
		writer.Flush()
	}
}

// prints Geolocation data verbosely
func (r *Record) printGeoRecordVerbose(writer *tabwriter.Writer) {
	if runtime.GOOS == "windows" {
		fmt.Fprintln(writer, r.Technique+"\t"+r.Domain+"\t"+"GEO:"+r.Geolocation+"\t")
		writer.Flush()
	} else {
		fmt.Fprintln(writer, blue(r.Technique)+"\t"+r.Domain+"\t"+white("GEO:")+yellow(r.Geolocation)+"\t")
		writer.Flush()
	}
}

// verbosely prints a Record with missing Geolocation data
func (r *Record) printNoGeoRecordVerbose(writer *tabwriter.Writer) {
	if runtime.GOOS == "windows" {
		fmt.Fprintln(writer, r.Technique+"\t"+r.Domain+"\t"+"GEO:-"+"\t")
		writer.Flush()
	} else {
		fmt.Fprintln(writer, blue(r.Technique)+"\t"+r.Domain+"\t"+white("GEO:")+red("-")+"\t")
		writer.Flush()
	}
}

// prints results data when Records are not returned
func printResults(writer *tabwriter.Writer, technique, result, tld string) {
	if runtime.GOOS == "windows" {
		fmt.Fprintln(w, technique+"\t"+result+"."+tld+"\t")
		w.Flush()
	} else {
		fmt.Fprintln(w, blue(technique)+"\t"+result+"."+tld+"\t")
		w.Flush()
	}
}

// sets up command-line arguments
func setup() {

	flag.Usage = func() {
		g.Printf(banner)
		fmt.Printf(" v.%s\n", version)
		y.Printf("written & maintained by NetEvert\n\n")
		fmt.Println(utilDescription)
		flag.PrintDefaults()
	}

	flag.Parse()

	if *domain == "" && *list == "" {
		r.Printf("\nplease supply domains\n\n")
		fmt.Println(utilDescription)
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *list != "" && *domain != "" {
		r.Printf("\nplease supply either option -d or -l\n\n")
		fmt.Println(utilDescription)
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *outjson != false && *outcsv != false {
		r.Printf("\nplease supply either csv or json ouput\n\n")
		fmt.Println(utilDescription)
		flag.PrintDefaults()
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

// performs an a recors DNS lookup
func aLookup(Domain string) string {
	ip, err := net.ResolveIPAddr("ip4", Domain)
	if err != nil {
		return ""

	}
	return ip.String() // todo: fix so that only onel IP is returned
}

// performs a Geolocation lookup on input ip, returns country + city
func geoLookup(input_ip string) string {
	if input_ip != "" {
		db, err := maxminddb.Open("data/GeoLite2-City.mmdb")
		if err != nil {
			log.Fatal(err)
		}
		defer db.Close()
		ip := net.ParseIP(input_ip)
		var record GeoIPRecord
		err = db.Lookup(ip, &record)
		if err != nil {
			log.Fatal(err)
		}
		return record.Country.IsoCode + " " + record.City.Names["en"]
	}
	return ""
}

// performs an a record lookup
func doLookups(Technique, Domain, tld string, out chan<- Record, resolve, geolocate bool) {
	defer wg.Done()
	r := new(Record)
	r.Technique = Technique
	r.Domain = Domain + "." + tld
	if resolve {
		r.A = aLookup(r.Domain)
	}
	if geolocate {
		r.Geolocation = geoLookup(r.A)
	}
	out <- *r
}

// validates Domains using regex
func validateDomainName(Domain string) bool {

	patternStr := `^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$`

	RegExp := regexp.MustCompile(patternStr)
	return RegExp.MatchString(Domain)
}

// sanitizes Domains inputted into dnsmorph
func processInput(input string) (sanitizedDomain, tld string) {
	if !validateDomainName(input) {
		r.Printf("\nplease supply a valid Domain\n\n")
		fmt.Println(utilDescription)
		flag.PrintDefaults()
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
	w.Init(os.Stdout, 18, 8, 2, '\t', 0)
	if *verbose == true && *resolve == true && *geolocate == true {
		for _, r := range results {
			wg.Add(1)
			go doLookups(technique, r, tld, out, *resolve, *geolocate)
		}
		go monitorWorker(wg, out)
		for r := range out {
			switch {
			case r.A != "" && r.Geolocation != "":
				r.printAll(w, *verbose)
			case r.A != "" && r.Geolocation == "":
				r.printANotGeo(w, *verbose)
			case r.A == "" && r.Geolocation != "":
				r.printGeoNotA(w, *verbose)
			default:
				r.printEmptyRecord(w, *verbose)
			}
		}
	} else if *verbose == true && *resolve == true {
		for _, r := range results {
			wg.Add(1)
			go doLookups(technique, r, tld, out, *resolve, *geolocate)
		}
		go monitorWorker(wg, out)
		for i := range out {
			switch {
			case i.A != "":
				i.printARecordVerbose(w)
			default:
				i.printNoARecordVerbose(w)
			}
		}
	} else if *verbose == true && *geolocate == true {
		for _, r := range results {
			wg.Add(1)
			go doLookups(technique, r, tld, out, true, *geolocate)
		}
		go monitorWorker(wg, out)
		for i := range out {
			switch {
			case i.Geolocation != "":
				i.printGeoRecordVerbose(w)
			default:
				i.printNoGeoRecordVerbose(w)
			}
		}
	} else if *resolve == true && *geolocate == true {
		for _, r := range results {
			wg.Add(1)
			go doLookups(technique, r, tld, out, *resolve, *geolocate)
		}
		go monitorWorker(wg, out)
		for r := range out {
			switch {
			case r.A != "" && r.Geolocation != "":
				r.printAll(w, *verbose)
			case r.A != "" && r.Geolocation == "":
				r.printANotGeo(w, *verbose)
			case r.A == "" && r.Geolocation != "":
				r.printGeoNotA(w, *verbose)
			default:
				r.printEmptyRecord(w, *verbose)
			}
		}
	} else if *geolocate == true {
		for _, r := range results {
			wg.Add(1)
			go doLookups(technique, r, tld, out, true, *geolocate)
		}
		go monitorWorker(wg, out)
		for i := range out {
			i.printGeoRecord(w)
		}
	} else if *verbose == false && *resolve == false {
		for _, result := range results {
			fmt.Println(result + "." + tld)
		}
	} else if *resolve == true {
		for _, r := range results {
			wg.Add(1)
			go doLookups(technique, r, tld, out, *resolve, *geolocate)
		}
		go monitorWorker(wg, out)
		for i := range out {
			i.printARecord(w)
		}
	} else if *verbose == true {
		for _, result := range results {
			printResults(w, technique, result, tld)
		}
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
		go doLookups(r[1], domain, tld, out, *resolve, *geolocate)
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
			var data = []string{r.Technique, r.Domain, r.A, r.Geolocation}
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
		var output OutJson
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
		'b': {'d', 'ʙ', 'Ь', 'ɓ', 'Б', 'ß', 'β', 'ᛒ'}, // 'lb', 'ib', 'b̔'
		'c': {'ϲ', 'с', 'ƈ', 'ċ', 'ć', 'ç', 'ｃ'},
		'd': {'b', 'ԁ', 'ժ', 'ɗ', 'đ'}, // 'cl', 'dl', 'di'
		'e': {'é', 'ê', 'ë', 'ē', 'ĕ', 'ě', 'ė', 'е', 'ẹ', 'ę', 'є', 'ϵ', 'ҽ'},
		'f': {'Ϝ', 'ƒ', 'Ғ'},
		'g': {'q', 'ɢ', 'ɡ', 'Ԍ', 'Ԍ', 'ġ', 'ğ', 'ց', 'ǵ', 'ģ'},
		'h': {'һ', 'հ', 'Ꮒ', 'н'}, // 'lh', 'ih'
		'i': {'1', 'l', 'Ꭵ', 'í', 'ï', 'ı', 'ɩ', 'ι', 'ꙇ', 'ǐ', 'ĭ'},
		'j': {'ј', 'ʝ', 'ϳ', 'ɉ'},
		'k': {'κ', 'ⲕ', 'κ'}, // 'lk', 'ik', 'lc'
		'l': {'1', 'i', 'ɫ', 'ł'},
		'm': {'n', 'ṃ', 'ᴍ', 'м', 'ɱ'}, // 'nn', 'rn', 'rr'
		'n': {'m', 'r', 'ń'},
		'o': {'0', 'Ο', 'ο', 'О', 'о', 'Օ', 'ȯ', 'ọ', 'ỏ', 'ơ', 'ó', 'ö', 'ӧ', 'ｏ'},
		'p': {'ρ', 'р', 'ƿ', 'Ϸ', 'Þ'},
		'q': {'g', 'զ', 'ԛ', 'գ', 'ʠ'},
		'r': {'ʀ', 'Г', 'ᴦ', 'ɼ', 'ɽ'},
		's': {'Ⴝ', 'Ꮪ', 'ʂ', 'ś', 'ѕ'},
		't': {'τ', 'т', 'ţ'},
		'u': {'μ', 'υ', 'Ս', 'ս', 'ц', 'ᴜ', 'ǔ', 'ŭ'},
		'v': {'ѵ', 'ν'},      // 'v̇'
		'w': {'ѡ', 'ա', 'ԝ'}, // 'vv'
		'x': {'х', 'ҳ'},      // 'ẋ'
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

// main program entry point
func main() {
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
