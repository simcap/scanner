# Scanner

Learning python with a simple TCP scanner wrapping `nmap`.

* accepts targets in various format: ipv4, ipv6, hostname, CIDR
* allows a `--fast` and `--stealth` mode
* no dependencies used: increase portability, ease of use on remote machines.
* leveraging `nmap` functionalities and flags to avoid coding extra logic (ex: progress display)
* not made Windows compatible as no platform to test it on.
* compatible python 2 and 3

## Usage

Display help 

```sh
$ ./scanner.py -h
```

Scan list of targets given various format 
```sh
$ ./scanner.py 93.184.216.34 example.com 2606:2800:220:1:248:1893:25c8:1946 172.16.36.12/28
```

Fast scan (i.e. fewer ports)
```sh
$ ./scanner.py --fast example.com 93.184.216.34/32
```

Scan targets given from file (one entry per newline)
```sh
$ ./scanner.py -f targets.txt
```

## Notes

The `git` commits and history show my coding timeline and approach.