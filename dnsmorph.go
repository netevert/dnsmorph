package main

import (
	"flag"
	"fmt"
	"github.com/fatih/color"
	"golang.org/x/net/publicsuffix"
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
const version = "1.1.3"

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
	verbose           = flag.Bool("v", false, "enable verbosity")
	includeSubdomains = flag.Bool("i", false, "include subdomains")
	resolve           = flag.Bool("r", false, "resolve domain")
	utilDescription   = "dnsmorph -d domain [-i] [-v] [-r]"
	banner            = `
╔╦╗╔╗╔╔═╗╔╦╗╔═╗╦═╗╔═╗╦ ╦
 ║║║║║╚═╗║║║║ ║╠╦╝╠═╝╠═╣
═╩╝╝╚╝╚═╝╩ ╩╚═╝╩╚═╩  ╩ ╩` // Calvin S on http://patorjk.com/
)

type record struct {
	domain string
	a      []string
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

	if *domain == "" {
		r.Printf("\nplease supply a domain\n\n")
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

// performs an A record lookup
func doLookups(domain string, tld string, out chan<- record) {
	defer wg.Done()
	r := new(record)
	r.domain = domain
	ip, err := net.ResolveIPAddr("ip4", r.domain+"."+tld)
	if err != nil {
		r.a = []string{""}

	} else {
		r.a = append(r.a, ip.String())
	}
	out <- *r
	// fmt.Println("routine done")
}

// validates domains using regex
func validateDomainName(domain string) bool {

	patternStr := `^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$`

	RegExp := regexp.MustCompile(patternStr)
	return RegExp.MatchString(domain)
}

// sanitizes domains inputted into dnsmorph
func processInput(input string) (sanitizedDomain, tld string) {
	if !validateDomainName(input) {
		r.Printf("\nplease supply a valid domain\n\n")
		fmt.Println(utilDescription)
		flag.PrintDefaults()
		os.Exit(1)
	} else {
		if *includeSubdomains == false {
			tldPlusOne, _ := publicsuffix.EffectiveTLDPlusOne(input)
			tld, _ = publicsuffix.PublicSuffix(tldPlusOne)
			sanitizedDomain = strings.Replace(tldPlusOne, "."+tld, "", -1)
		} else if *includeSubdomains == true {
			tld, _ = publicsuffix.PublicSuffix(input)
			sanitizedDomain = strings.Replace(input, "."+tld, "", -1)
		}
	}
	return sanitizedDomain, tld
}

// helper function to print permutation report and miscellaneous information
func printReport(technique string, results []string, tld string, verbose bool, resolve bool) {
	out := make(chan record)
	w.Init(os.Stdout, 0, 8, 2, '\t', tabwriter.TabIndent|tabwriter.AlignRight)
	if verbose == false && resolve == false {
		for _, result := range results {
			fmt.Println(result + "." + tld)
		}
	} else if verbose == true && resolve == true {
		for _, i := range results {
			wg.Add(1)
			go doLookups(i, tld, out)
		}
		go monitorWorker(wg, out)
		for i := range out {
			if i.a[0] != "" {
				if runtime.GOOS == "windows" {
					fmt.Fprintln(w, technique+"\t"+i.domain+"."+tld+"\t"+"A: "+strings.Join(i.a, ",")+"\t")
					w.Flush()
				} else {
					fmt.Fprintln(w, blue(technique)+"\t"+i.domain+"."+tld+"\t"+white("A: ")+yellow(strings.Join(i.a, ","))+"\t")
					w.Flush()
				}
			} else {
				if runtime.GOOS == "windows" {
					fmt.Fprintln(w, technique+"\t"+i.domain+"."+tld+"\t"+"-"+"\t")
					w.Flush()
				} else {
					fmt.Fprintln(w, blue(technique)+"\t"+i.domain+"."+tld+"\t"+red("-")+"\t")
					w.Flush()
				}
			}
		}
	} else if resolve == true {
		for _, i := range results {
			wg.Add(1)
			go doLookups(i, tld, out)
		}
		go monitorWorker(wg, out)
		for i := range out {
			fmt.Fprintln(w, i.domain+"."+tld+"\t"+i.a[0]+"\t")
			w.Flush()
		}
	} else if verbose == true {
		for _, result := range results {
			if runtime.GOOS == "windows" {
				fmt.Fprintln(w, technique+"\t"+result+"."+tld+"\t")
				w.Flush()
			} else {
				fmt.Fprintln(w, blue(technique)+"\t"+result+"."+tld+"\t")
				w.Flush()
			}
		}
	}
}

// helper function to wait for goroutines collection to finish and close channel
func monitorWorker(wg *sync.WaitGroup, channel chan record) {
	wg.Wait()
	close(channel)
}

// helper function to specify permutation attacks to be performed
func runPermutations(target, tld string) {
	printReport("addition", additionAttack(target), tld, *verbose, *resolve)
	printReport("omission", omissionAttack(target), tld, *verbose, *resolve)
	printReport("homograph", homographAttack(target), tld, *verbose, *resolve)
	printReport("subdomain", subdomainAttack(target), tld, *verbose, *resolve)
	printReport("vowel swap", vowelswapAttack(target), tld, *verbose, *resolve)
	printReport("repetition", repetitionAttack(target), tld, *verbose, *resolve)
	printReport("hyphenation", hyphenationAttack(target), tld, *verbose, *resolve)
	printReport("replacement", replacementAttack(target), tld, *verbose, *resolve)
	printReport("bitsquatting", bitsquattingAttack(target), tld, *verbose, *resolve)
	printReport("transposition", transpositionAttack(target), tld, *verbose, *resolve)
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
	sanitizedDomain, tld := processInput(*domain)
	runPermutations(sanitizedDomain, tld)
}
