# DNSMORPH

[![baby-gopher](https://raw.githubusercontent.com/drnic/babygopher-site/gh-pages/images/babygopher-logo-small.png)](http://www.babygopher.org)
[![GitHub release](https://img.shields.io/github/release/dnsmorph/releases.svg)](https://github.com/netevert/dnsmorph/releases)
[![license](https://img.shields.io/github/license/netevert/dnsmorph.svg)](https://github.com/netevert/dnsmorph/blob/master/LICENSE)
[![Maintenance](https://img.shields.io/maintenance/yes/2018.svg)]()
[![](https://img.shields.io/github/issues-raw/netevert/dnsmorph.svg)](https://github.com/netevert/dnsmorph/issues)
[![](https://img.shields.io/github/issues-closed-raw/netevert/dnsmorph.svg)](https://github.com/netevert/dnsmorph/issues?q=is%3Aissue+is%3Aclosed)
[![GitHub last commit](https://img.shields.io/github/last-commit/errantbot/dnsmorph.svg)](https://github.com/netevert/dnsmorph/commit/master)
[![Donations](https://img.shields.io/badge/donate-bitcoin-orange.svg?logo=bitcoin)](https://github.com/netevert/dnsmorph#donations)


DNSMORPH is a domain name permutation engine, broadly inspired by [dnstwist](https://github.com/elceef/dnstwist). It is written in [Go](https://golang.org/) making for a small and fast tool ideal for everyday use. It robustly handles any domain or subdomain supplied and provides a number of configuration options to tune permutation attacks. 

![demo](https://github.com/netevert/dnsmorph/blob/master/docs/demo.gif)

DNSMORPH includes the following domain permutation attacks:
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
To install DNSMORPH run the following commands:

```go get github.com/netevert/dnsmorph```

`cd /$GOPATH/src/github.com/netevert/dnsmorph`

`go build`

Usage
========
<details><summary>Usage menu output</summary>
<p>

    Usage of dnsmorph.exe:
      -c    view credits
      -d string
            target domain
      -s    include subdomain
      -v    enable verbosity
</p>
</details>
<details><summary>Run attack against a target domain</summary>
<p>

    ./dnsmorph -d amazon.com
</p>
</details>
<details><summary>Include subdomain in attack</summary>
<p>

    ./dnsmorph -s -d staging.amazon.com
</p>
</details>
<details><summary>View types of attack performed (verbose output)</summary>
<p>

    ./dnsmorph -s -d staging.amazon.com -v
</p>
</details>

**DNSMORPH is under active development**, much needs to be done to reach and surpass the quality of comparable tools. Consult the [issues page](https://github.com/netevert/dnsmorph/issues) to see what's in the pipeline and how the project is progressing.

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