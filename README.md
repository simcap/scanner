# Scanner

Learning python with a simple TCP scanner wrapping `nmap`. The goal is to make this scanner simple, easy to use, easy to enhanced and yet useful enough.

* accepts targets in various format: ipv4, ipv6, hostname, CIDR
* allows a `--fast` and `--stealth` mode
* no dependencies used: increase portability, ease of use on remote machines.
* leveraging `nmap` functionalities and flags to avoid coding extra logic (ex: progress display)
* no Windows compatibity in mind, as no platform to test it on.
* compatible python 2 and 3

## Usage

Full usage and examples are documented in the help 

```sh
$ ./scanner.py -h

or 

$ python scanner.py
```

## Deploy

Deploy to a machine running python

```sh
$ scp scanner.py user@10.0.0.2:/tmp
10.0.0.2:/tmp $ chmod +x scanner.py
10.0.0.2:/tmp $ ./scanner.py -h
```

## Test

To test and validate the scanner you can run it on your localhost if you have some services running

```sh
./scanner.py -V localhost # it will detect any services you have running
```

A better testing strategy - that can be used for local integration tests and/or CI for this project - is if you have `docker` installed. You can run a specific service and verify that the detection is correct. 

First launch an Apache service (you can choose any exposed port to trick the scanner :)):

```sh
docker run -d --name apache-test-server --rm -p 8080:80 httpd
```

Then verify you can detect it along with the Apache product and its version
```sh
./scanner.py -V localhost
```

You should see the detection in the console and the HTML report. Remove the service with `docker stop apache-test-server`

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

Allow port software detection and versioning, although it can add significant overhead and can be unreliable!
```sh
$ sudo ./scanner.py -V example.com
```

Working from a file containing all the targets to be scanned (i.e. one entry per newline)
```sh
$ ./scanner.py -f targets.txt
```

## Notes

* the `git` commits and history show my coding timeline and approach.
* we did not use on purpose the very useful `--webxml` nmap option that already provides HTML reporting using XSLT.
* our basic HTML report can be easily made better looking.
* the code around HTML generation can be considered rightfully ugly since it embeds logic and view information. A small templating python library could be used. But since the HTML generated is so simple we keep it that way for more portability with the script.
* program could be made faster by using threading the different jobs on IPv6 targets and other types of targets. Note that `nmap` is already good enough for optimizing when given multiple targets.
* the automated testing of this project (see Test section above) would be easily captured in a bash script.