#!/usr/bin/python

from __future__ import print_function
import os, sys, subprocess, argparse, tempfile, re
import xml.etree.ElementTree as XML

parser = argparse.ArgumentParser(description='TCP Scan list of given targets', epilog='Made by Simon with fun and love!')
parser.add_argument('targets', help='List of target to be scanned. Format can be any of ipv4, ipv6 or hostname', nargs='*')
parser.add_argument('--fast', help='Fast mode - Scan fewer ports than the default scan', action='store_true')
args = parser.parse_args()

class NmapScan:

    bin_name = 'nmap'

    def run(self, targets):
        ipv6s, others = filter_ipv6(targets)
        options = []
        if args.fast:   
            options.append("-F")
        ipv6s_hosts = self.scan(ipv6s, options + ["-6"])
        other_hosts = self.scan(others, options)
        return ipv6s_hosts + other_hosts

    def scan(self, targets, extraflags=[]):
        if len(targets) == 0:
            return []

        xmlfile = tempfile.NamedTemporaryFile(suffix='-scan.xml', delete=False)
        process = subprocess.Popen(
            ["nmap", "--stats-every", "0.2", "-oX", xmlfile.name, "-Pn", "-n"] + extraflags + targets, stdout=subprocess.PIPE
        )
       
        while process.returncode is None:
            line = process.stdout.readline()
            match = re.search('About (.*)% done;', line.decode('utf-8'), re.IGNORECASE)
            if match:
                print('{}% progress scanning {}'.format(match.group(1), targets), file=sys.stderr)
            process.poll()
        
        process.wait()

        return Results(xmlfile.name).parse()

    def verify_system(self):
        discard = open(os.devnull, 'w')
        if subprocess.call(['which', NmapScan.bin_name], stdout=discard, stderr=discard):
            sys.exit('cannot find local {n} executable. {n} is required to run this program'.format(n=NmapScan.bin_name))
        discard.close()

class Host:
    def __init__(self, addr, addr_type):
        self.addr = addr
        self.addr_type = addr_type
        self.ports = []
        self.hostnames = []

    def add_port(self, port):
        self.ports.append(port)

    def add_hostname(self, hostnames):
        self.hostnames.append(hostnames)

class Port:
    def __init__(self, num, status, service):
        self.num = num
        self.status = status
        self.service = service

class Results:
    def __init__(self, filename):
        self.filename = filename
        self.hosts = []

    def parse(self):
        tree = XML.parse(self.filename)
        root = tree.getroot()
        for host_element in root.findall('host'):
            addr_element = host_element.find('address')
            host =  Host(addr_element.get('addr'), addr_element.get('addrtype'))
            self.hosts.append(host)
            for hostname_element in host_element.findall('hostnames/hostname'):
                host.add_hostname(hostname_element.get('name'))
            for port_element in host_element.findall('ports/port'):
                num = port_element.get('portid')
                status = port_element.find('state').get('state')
                service = port_element.find('service').get('name')
                host.add_port(Port(num, status, service))   
       
        os.remove(self.filename) 
       
        return self.hosts
            
def write_console(hosts):
    print('\n-> Results:')
    for host in hosts:
        print(host.addr)
        for port in host.ports:
            print('\t', port.num, port.status, port.service)

def write_html(hosts):
    f = open('scan-report.html', 'w')
    f.write('<html><body>')
    for host in hosts:
        f.write('<h2>Host {}={} {}</h2>'.format(host.addr_type, host.addr, ', '.join(host.hostnames)))
        f.write('<table style="border: 1px solid;"><tr><th>Port</th><th>Status</th><th>Service</th></tr>')
        for port in host.ports:
            f.write('<tr><td>{}</td><td>{}</td><td>{}</td></tr>'.format(port.num, port.status, port.service))
        f.write('</table>')
    f.write('</body></html>')
    f.close()
    return f.name


def filter_ipv6(targets): 
    others, ipv6s = [], []
    for t in targets:
        ipv6s.append(t) if is_ipv6(t) else others.append(t)             
    return ipv6s, others

def is_ipv6(target):
    return target.count(':') == 7

if __name__ == '__main__':    
    scanner = NmapScan()
    scanner.verify_system()
    hosts = scanner.run(args.targets)
    write_console(hosts)
    htmlfile = write_html(hosts)
    print('\n-> Generated HTML report "{}"'.format(htmlfile), file=sys.stderr)