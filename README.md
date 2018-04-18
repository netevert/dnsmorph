![Icon](https://github.com/netevert/dnsmorph/blob/master/docs/icon.png)
==================================================================
[![baby-gopher](https://raw.githubusercontent.com/drnic/babygopher-site/gh-pages/images/babygopher-logo-small.png)](http://www.babygopher.org)
[![GitHub release](https://img.shields.io/github/release/netevert/dnsmorph.svg?style=flat-square)](https://github.com/netevert/dnsmorph/releases)
[![license](https://img.shields.io/github/license/netevert/dnsmorph.svg?style=flat-square)](https://github.com/netevert/dnsmorph/blob/master/LICENSE)
[![Travis](https://img.shields.io/travis/netevert/dnsmorph.svg?style=flat-square)](https://travis-ci.org/netevert/dnsmorph)
[![Go Report Card](https://goreportcard.com/badge/github.com/netevert/dnsmorph?style=flat-square)](https://goreportcard.com/report/github.com/netevert/dnsmorph)
[![Coveralls github](https://img.shields.io/coveralls/github/netevert/dnsmorph.svg?style=flat-square)](https://coveralls.io/github/netevert/dnsmorph)
[![Maintenance](https://img.shields.io/maintenance/yes/2018.svg?style=flat-square)]()
[![GitHub last commit](https://img.shields.io/github/last-commit/errantbot/dnsmorph.svg?style=flat-square)](https://github.com/netevert/dnsmorph/commit/master)
[![Donations](https://img.shields.io/badge/donate-bitcoin-orange.svg?logo=bitcoin&style=flat-square)](https://github.com/netevert/dnsmorph#donations)


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

    - ```go get github.com/netevert/dnsmorph```
    - `cd /$GOPATH/src/github.com/netevert/dnsmorph`
    - `go build`

Usage
========
<details><summary>Usage menu output</summary>
<p>

    dnsmorph -d domain [-g] [-i] [-r] [-v]
      -d string
            target domain
      -g    geolocate domain
      -i    include subdomain
      -r    resolve domain
      -v    enable verbosity
</p>
</details>
<details><summary>Run attacks against a target domain</summary>
<p>

    ./dnsmorph -d amazon.com
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

Donations
=========

<details><summary>If you like DNSMORPH please consider donating</summary>
<p>
    
    Bitcoin:  13i3hFGN1RaQqdeWqmPTMuYEj9FiJWuMWf
    Litecoin: LZqLoRNHvJyuKz99mNAgVUj6M8iyEQuio9
</p>
</details>