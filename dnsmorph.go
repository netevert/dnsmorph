/*
this software is work in progress
*/

package main

import ("flag"
	"fmt"
	"github.com/fatih/color")

// program version
const Version = "1.0.0"

var (
	g = color.New(color.FgGreen)
	y = color.New(color.FgYellow)
	r = color.New(color.FgRed)
	b = color.New(color.FgBlue)
)

func setup(){
	y.Printf("DNSMORPH")
	fmt.Printf(" v.%s\n\n", Version)

	flag.Parse()

	if flag.Arg(0) == "" {
		r.Printf("please supply a domain\n\n")
	}
}

// main program entry point
func main(){
	setup()
}