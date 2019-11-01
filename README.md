# Scanner

Learning python with a simple TCP scanner wrapping `nmap`. The goal is to make this scanner simple, easy to use, easy to contribute/enhanced and yet powerful enough.

* accepts targets in various format: ipv4, ipv6, hostname, CIDR
* allows a `--fast` and `--stealth` mode
* no dependencies used: increase portability, ease of use on remote machines.
* leveraging `nmap` functionalities and flags to avoid coding extra logic (ex: progress display)
* no Windows compatibity in mind, as no platform to test it on.
* compatible python 2 and 3

## Usage

Full usage and examples are documented in the scanner's help 

```sh
$ ./scanner.py -h
```

## Examples

Scan list of targets given various format 
```sh
$ ./scanner.py 93.184.216.34 example.com 2606:2800:220:1:248:1893:25c8:1946 172.16.36.12/28
```

Fast scan (i.e. fewer ports)
```sh
$ ./scanner.py --fast example.com 93.184.216.34/32
```

In environments where one can be more aggressive during the scanning
```sh
$ ./scanner.py --aggressive example.com 93.184.216.34/32
```

Stealth and quicker scan (i.e. using TCP SYN)
```sh
$ sudo ./scanner.py --stealth example.com 93.184.216.34/32
```

You can combine the 3 options above to have the fastest scan
```sh
$ sudo ./scanner.py -S -A -F example.com 93.184.216.34/32
```

Working from a file containing all the targets to be scanned (i.e. one entry per newline)
```sh
$ ./scanner.py -f targets.txt
```

## Notes

* the `git` commits and history show my coding timeline and approach.
* on purpose we did not use the very useful `--webxml` nmap option that already provides HTML reporting using XSLT.
* our basic HTML report can be easily made better looking with time.
* the code around HTML generation can be considered rightfully ugly since it embeds logic and view information. A small templating python library could be used. But since the HTML generated is so simple we keep it that way for more portability with the script.