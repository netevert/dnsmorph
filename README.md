![Icon](https://github.com/netevert/dnsmorph/blob/master/docs/icon.png)
==================================================================
[![baby-gopher](https://raw.githubusercontent.com/drnic/babygopher-site/gh-pages/images/babygopher-logo-small.png)](http://www.babygopher.org)
[![GitHub release](https://img.shields.io/github/release/netevert/dnsmorph.svg?style=flat-square)](https://github.com/netevert/dnsmorph/releases)
[![license](https://img.shields.io/github/license/netevert/dnsmorph.svg?style=flat-square)](https://github.com/netevert/dnsmorph/blob/master/LICENSE)
[![Travis](https://img.shields.io/travis/netevert/dnsmorph.svg?style=flat-square)](https://travis-ci.org/netevert/dnsmorph)
[![Go Report Card](https://goreportcard.com/badge/github.com/netevert/dnsmorph?style=flat-square)](https://goreportcard.com/report/github.com/netevert/dnsmorph)
[![Coveralls github](https://img.shields.io/coveralls/github/netevert/dnsmorph.svg?style=flat-square)](https://coveralls.io/github/netevert/dnsmorph)
[![Maintenance](https://img.shields.io/maintenance/yes/2019.svg?style=flat-square)]()
[![GitHub last commit](https://img.shields.io/github/last-commit/errantbot/dnsmorph.svg?style=flat-square)](https://github.com/netevert/dnsmorph/commit/master)

DNSMORPH is a domain name permutation engine, inspired by [dnstwist](https://github.com/elceef/dnstwist). It is written in [Go](https://golang.org/) making for a compact and **very** fast tool. It robustly handles any domain or subdomain supplied and provides a number of configuration options to tune permutation runs. 

![demo](https://github.com/netevert/dnsmorph/blob/master/docs/demo.gif)

DNSMORPH includes the following domain permutation attack types:
- Homograph attack (both on single and duplicate characters)
- Bitsquat attack
- Hyphenation attack
- Omission attack
- Repetition attack
- Replacement attack
- Subdomain attack
- Transposition attack
- Vowel swap attack
- Addition attack

Installation
============
There are two ways to install dnsmorph on your system:

1. Downloading the pre-compiled binaries for your platform from the [latest release page](https://github.com/netevert/dnsmorph/releases) and extracting in a directory of your choosing.

2. Downloading and compiling the source code yourself by running the following commands:

    - ```go get -v github.com/netevert/dnsmorph```
    - `cd /$GOPATH/src/github.com/netevert/dnsmorph`
    - `go get -v ./...`
    - `go build`

An Arch Linux package is also [available](https://aur.archlinux.org/packages/dnsmorph/).

Usage
========
<details><summary>Usage menu output</summary>
<p>

    dnsmorph -d domain | -l domains_file [-girv] [-csv | -json]
      -csv
            output to csv
      -d string
            target domain
      -g    geolocate domain
      -i    include subdomain
      -json
            output to json
      -l string
            domain list filepath
      -r    resolve domain
      -u    update check
      -v    enable verbosity
</p>
</details>
<details><summary>Run attacks against a target domain</summary>
<p>

    ./dnsmorph -d amazon.com
</p>
</details>
<details><summary>Run attacks against a list of domains</summary>
<p>

    ./dnsmorph -l domains.txt
</p>
</details>
<details><summary>Include subdomain in attack</summary>
<p>

    ./dnsmorph -d staging.amazon.com -i
</p>
</details>
<details><summary>Run dns resolutions against permutated domains</summary>
<p>

    ./dnsmorph -d amazon.com -r
</p>
</details>
<details><summary>Run geolocation against permutated domains</summary>
<p>

    ./dnsmorph -d amazon.com -g
</p>
</details>
<details><summary>Output results to csv or json</summary>
<p>

    ./dnsmorph -d amazon.com -r -g -csv
    ./dnsmorph -d amazon.com -r -g -json
</p>
</details>
<details><summary>Activate verbose output</summary>
<p>

    ./dnsmorph -d staging.amazon.com -v
</p>
</details>
<p></p>

**DNSMORPH is under active development**, much needs to be done to match and surpass the quality of comparable tools. Consult the [issues page](https://github.com/netevert/dnsmorph/issues) to see what's in the pipeline and how the project is progressing.

License
=======

Distributed under the terms of the [MIT](http://www.linfo.org/mitlicense.html) license, DNSMORPH is free and open
source software written and maintained with ❤ by NetEvert.

Versioning
==========

This project adheres to [Semantic Versioning](https://semver.org/).

Like it?
=========
If you like the tool please consider [contributing](https://github.com/netevert/dnsmorph/blob/master/CONTRIBUTING.md). DNSMORPH is developed and maintained during nuggets of spare time and any help to speed up the improvement of the tool would be hugely appreciated :)

The tool received a few "honourable" mentions, including:

- [KitPloit](https://www.kitploit.com/2018/05/dnsmorph-domain-name-permutation-engine.html)
- [Seclist](http://seclist.us/dnsmorph-is-a-domain-name-permutation-engine.html)
- [HackPlayers](https://www.hackplayers.com/2018/05/dnsmorph-permutacion-dominios.html)
- [Segu-Info](https://blog.segu-info.com.ar/2018/05/dnsmorph-herramienta-de-permutacion-de.html)
