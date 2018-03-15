package main

import ("flag"
	"fmt"
	"github.com/fatih/color"
	"os"
	"strings"
	"text/tabwriter"
	"unicode")

// program version
const version = "1.0.0-dev4"

var (
	g = color.New(color.FgGreen)
	y = color.New(color.FgYellow)
	r = color.New(color.FgRed)
	b = color.New(color.FgBlue)
	blue = color.New(color.FgBlue).SprintFunc()  // this isn't working on windows
	domain = flag.String("d", "", "target domain")
	verbose = flag.Bool("v", false, "enable verbosity")
	credits = flag.Bool("c", false, "view credits")
	)

// sets up command-line arguments
func setup(){

	flag.Parse()

	if *credits == true && *domain == "" {
		y.Printf("DNSMORPH")
		fmt.Printf(" v.%s\n\n", version)
		g.Printf("Released under the terms of the MIT license\n")
		g.Printf("Written and maintained with ❤ by NetEvert\n\n")
		os.Exit(1)
	} else if *domain == "" {
		r.Printf("\nplease supply a domain\n\n")
		flag.Usage()
		os.Exit(1)
	}
}

// returns a count of characters in a word
func countChar(word string) map[rune]int {
	count := make(map[rune]int)
	for _, r := range []rune(word){
		count[r]++
	}
	return count
}

// helper function to print permutation report and miscellaneous information
func printReport(technique string, results []string, tld string, verbose bool){
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 8, 2, '\t', tabwriter.TabIndent|tabwriter.AlignRight)
	if verbose == false {
		for _, result := range results {
			fmt.Println(result + "." + tld)
		}
	} else if verbose == true {
		for _, result := range results {
			fmt.Fprintln(w, technique + "\t" + result + "." + tld + "\t")
		}
		w.Flush()
	}
}

// performs a repetition attack
func repetitionAttack(domain string) []string {
	results := []string{}
	count := make(map[string]int)
	for i, c := range domain {
		if unicode.IsLetter(c) {
			result := fmt.Sprintf("%s%c%c%s", domain[:i], domain[i], domain[i], domain[i+1:])
			count[result]++
			// remove duplicates
			if count[result] < 2 {
				results = append(results, result)
			}
		}
	}
	return results
}

// performs an omission attack
func omissionAttack(domain string) []string {
	results := []string{}
	for i := range domain {
		results = append(results, fmt.Sprintf("%s%s", domain[:i], domain[i+1:]))
	}
	return results
}

// performs a hyphenation attack
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
		'a': []rune{'à', 'á', 'â', 'ã', 'ä', 'å', 'ɑ', 'а', 'ạ', 'ǎ', 'ă', 'ȧ','α','ａ'},
		'b': []rune{'d', 'ʙ', 'Ь', 'ɓ', 'Б', 'ß', 'β', 'ᛒ'}, // 'lb', 'ib', 'b̔'
		'c': []rune{'ϲ', 'с', 'ƈ', 'ċ', 'ć', 'ç', 'ｃ'},
		'd': []rune{'b', 'ԁ', 'ժ', 'ɗ', 'đ'}, // 'cl', 'dl', 'di'
		'e': []rune{'é', 'ê', 'ë', 'ē', 'ĕ', 'ě', 'ė', 'е', 'ẹ', 'ę', 'є', 'ϵ', 'ҽ'},
		'f': []rune{'Ϝ', 'ƒ', 'Ғ'},
		'g': []rune{'q', 'ɢ', 'ɡ', 'Ԍ', 'Ԍ', 'ġ', 'ğ', 'ց', 'ǵ', 'ģ'},
		'h': []rune{'һ', 'հ', 'Ꮒ', 'н'}, // 'lh', 'ih'
		'i': []rune{'1', 'l', 'Ꭵ', 'í', 'ï', 'ı', 'ɩ', 'ι', 'ꙇ', 'ǐ', 'ĭ'},
		'j': []rune{'ј', 'ʝ', 'ϳ', 'ɉ'},
		'k': []rune{'κ', 'ⲕ', 'κ'}, // 'lk', 'ik', 'lc'
		'l': []rune{'1', 'i', 'ɫ', 'ł'},
		'm': []rune{'n', 'ṃ', 'ᴍ', 'м', 'ɱ'}, // 'nn', 'rn', 'rr'
		'n': []rune{'m', 'r', 'ń'},
		'o': []rune{'0', 'Ο', 'ο', 'О', 'о', 'Օ', 'ȯ', 'ọ', 'ỏ', 'ơ', 'ó', 'ö', 'ӧ', 'ｏ'},
		'p': []rune{'ρ', 'р', 'ƿ', 'Ϸ', 'Þ'},
		'q': []rune{'g', 'զ', 'ԛ', 'գ', 'ʠ'},
		'r': []rune{'ʀ', 'Г', 'ᴦ', 'ɼ', 'ɽ'},
		's': []rune{'Ⴝ', 'Ꮪ', 'ʂ', 'ś', 'ѕ'},
		't': []rune{'τ', 'т', 'ţ'},
		'u': []rune{'μ', 'υ', 'Ս', 'ս', 'ц', 'ᴜ', 'ǔ', 'ŭ'},
		'v': []rune{'ѵ', 'ν'}, // 'v̇'
		'w': []rune{'ѡ', 'ա', 'ԝ'}, // 'vv'
		'x': []rune{'х', 'ҳ'}, // 'ẋ'
		'y': []rune{'ʏ', 'γ', 'у', 'Ү', 'ý'},
		'z': []rune{'ʐ', 'ż', 'ź', 'ʐ', 'ᴢ'},
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
		if (count[char] > 1 && doneCount[char]!= true) {
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
func main(){
	setup()
	target := *domain
	tld := strings.Split(target, ".")[1]
	dom := strings.Split(target, ".")[0]

	printReport("omission", omissionAttack(dom), tld, *verbose)
	printReport("homograph", homographAttack(dom), tld, *verbose)
	printReport("repetition", repetitionAttack(dom), tld, *verbose)
	printReport("hyphenation", hyphenationAttack(dom), tld, *verbose)
	printReport("bitsquatting", bitsquattingAttack(dom), tld, *verbose)
}