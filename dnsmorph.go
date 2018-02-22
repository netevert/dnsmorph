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
	banner = " _____  _   _  _____ __  __  ____  _____  _____  _    _\n" + 
	         "|  __ \\| \\ | |/ ____|  \\/  |/ __ \\|  __ \\|  __ \\| |  | |\n" +
	         "| |  | |  \\| | (___ | \\  / | |  | | |__) | |__) | |__| |\n" +
	         "| |  | | . ` |\\___ \\| |\\/| | |  | |  _  /|  ___/|  __  |\n"+
	         "| |__| | |\\  |____) | |  | | |__| | | \\ \\| |    | |  | |\n" +
	         "|_____/|_| \\_|_____/|_|  |_|\\____/|_|  \\_\\_|    |_|  |_|"
)

func setup(){
	y.Printf(banner)
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