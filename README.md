![Icon](https://github.com/netevert/dnsmorph/blob/master/docs/icon.png)
==================================================================
[![baby-gopher](https://raw.githubusercontent.com/drnic/babygopher-site/gh-pages/images/babygopher-logo-small.png)](http://www.babygopher.org)
[![GitHub release](https://img.shields.io/github/release/netevert/dnsmorph.svg?style=flat-square)](https://github.com/netevert/dnsmorph/releases)
[![Maintenance](https://img.shields.io/maintenance/yes/2021.svg?style=flat-square)]()
[![GitHub last commit](https://img.shields.io/github/last-commit/errantbot/dnsmorph.svg?style=flat-square)](https://github.com/netevert/dnsmorph/commit/master)
![GitHub All Releases](https://img.shields.io/github/downloads/netevert/dnsmorph/total.svg?style=flat-square)
[![Twitter Follow](https://img.shields.io/twitter/follow/netevert.svg?style=social)](https://twitter.com/netevert)

<!--[![Travis](https://img.shields.io/travis/netevert/dnsmorph.svg?style=flat-square)](https://travis-ci.org/netevert/dnsmorph)
[![Go Report Card](https://goreportcard.com/badge/github.com/netevert/dnsmorph?style=flat-square)](https://goreportcard.com/report/github.com/netevert/dnsmorph)
[![Coveralls github](https://img.shields.io/coveralls/github/netevert/dnsmorph.svg?style=flat-square)](https://coveralls.io/github/netevert/dnsmorph)-->

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

    dnsmorph -d domain | -l domains_file [-girvuw] [-csv | -json]
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
      -w    whois lookup
</p>
</details>
<details><summary>Run attacks against a target domain</summary>
<p>

    ./dnsmorph -d amazon.com

![demo](https://github.com/netevert/dnsmorph/blob/master/docs/simple_permutation.gif)

</p>
</details>
<details><summary>Run attacks against a list of domains</summary>
<p>

    ./dnsmorph -l domains.txt

![demo](https://github.com/netevert/dnsmorph/blob/master/docs/list_permutation.gif)

</p>
</details>
<details><summary>Include subdomain in attack</summary>
<p>

    ./dnsmorph -d staging.amazon.com -i

![demo](https://github.com/netevert/dnsmorph/blob/master/docs/subdomain_permutation.gif)

</p>
</details>
<details><summary>Run dns resolutions against permutated domains</summary>
<p>

    ./dnsmorph -d amazon.com -r

![demo](https://github.com/netevert/dnsmorph/blob/master/docs/resolution.gif)

</p>
</details>
<details><summary>Run geolocation against permutated domains</summary>
<p>

    ./dnsmorph -d amazon.com -g

![demo](https://github.com/netevert/dnsmorph/blob/master/docs/geolocation.gif)

</p>
</details>
<details><summary>Run whois lookup against permutated domains</summary>
<p>

    ./dnsmorph -d amazon.com -w

![demo](https://github.com/netevert/dnsmorph/blob/master/docs/whois_lookup.gif)

</p>
</details>
<details><summary>Output results to csv or json</summary>
<p>

    ./dnsmorph -d amazon.com -r -g -csv
    ./dnsmorph -d amazon.com -r -g -json

![demo](https://github.com/netevert/dnsmorph/blob/master/docs/write_to_file.gif)

</p>
</details>
<details><summary>Activate verbose output</summary>
<p>

    ./dnsmorph -d staging.amazon.com -v

![demo](https://github.com/netevert/dnsmorph/blob/master/docs/verbose_output.gif)

</p>
</details>
<p></p>

License
=======

Distributed under the terms of the [MIT](http://www.linfo.org/mitlicense.html) license, DNSMORPH is free and open
source software written and maintained with ❤ by NetEvert.

This tool includes GeoLite2 data created by MaxMind, available from [maxmind.com](https://www.maxmind.com).

Versioning
==========

This project adheres to [Semantic Versioning](https://semver.org/).

Like it?
=========
If you like the tool please consider [contributing](https://github.com/netevert/dnsmorph/blob/master/CONTRIBUTING.md).

The tool received a few "honourable" mentions, including:

- [KitPloit](https://www.kitploit.com/2018/05/dnsmorph-domain-name-permutation-engine.html)
- [Seclist](http://seclist.us/dnsmorph-is-a-domain-name-permutation-engine.html)
- [HackPlayers](https://www.hackplayers.com/2018/05/dnsmorph-permutacion-dominios.html)
- [Segu-Info](https://blog.segu-info.com.ar/2018/05/dnsmorph-herramienta-de-permutacion-de.html)
- [True Blue IT - Security Review](http://news.security-intelligence.info/?edition_id=c6f2e150-998f-11e9-a7d8-0cc47a0d15fd#/science)
