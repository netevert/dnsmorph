/*
this software is work in progress
*/

package main

import ("flag"
	"fmt"
	"github.com/fatih/color"
	"os"
	"strings")

// program version
const Version = "1.0.0-alpha"

var (
	g = color.New(color.FgGreen)
	y = color.New(color.FgYellow)
	r = color.New(color.FgRed)
	b = color.New(color.FgBlue)
	help = `Usage of %s:
	dnsmorph [domain]		# runs permutation on domain
`
)

func setup(){
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, help, os.Args[0])
	}
	y.Printf("DNSMORPH")
	fmt.Printf(" v.%s\n\n", Version)

	flag.Parse()

	if flag.Arg(0) == "" {
		r.Printf("please supply a domain\n")
		os.Exit(0)
	}
}

func homoglyph(domain string){
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
	tld := strings.Split(domain, ".")[1]
	dom := strings.Split(domain, ".")[0]
	runes := []rune(dom)
	for i, char := range runes {
		a := i
		a += 1
		charGlyph := glyphs[char]
		for _, glyph := range charGlyph {
			// str := strings.Replace(dom, string(r), string(char), -1)
			// fmt.Println(str + "." + tld)
			fmt.Println(string(runes[:i]) + string(glyph) + string(runes[a:]) + "." + tld)
			// todo: add duplicate character substitutions
		}
	}
}

// main program entry point
func main(){
	setup()
	domain := flag.Arg(0)
	homoglyph(domain)
}