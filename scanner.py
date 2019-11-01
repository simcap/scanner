#!/usr/bin/python

from __future__ import print_function
import os, sys, subprocess, argparse, tempfile, re
import xml.etree.ElementTree as XML

examples = '''Examples:
  ./scanner.py 93.184.216.34 example.com 2606:2800:220:1:248:1893:25c8:1946 172.16.36.12/28
  ./scanner.py --fast example.com
  ./scanner.py --aggressive 93.184.216.34/32
  sudo ./scanner.py --stealth 172.16.36.12/28

Made by Simon with fun and love!
'''

parser = argparse.ArgumentParser(description='TCP scanner list of given targets with various format', epilog=examples, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument('targets', help='List of target to be scanned. Format can be any of ipv4, ipv6 or hostname', nargs='*')
parser.add_argument('--file', '-f', help='Path of file containing targets. A newline for each entries')
parser.add_argument('--fast', '-F', help='Fast mode - Scan fewer ports than the default scan', action='store_true')
parser.add_argument('--stealth', '-S', help='Stealth mode - Require privilege, run with `sudo`. Faster and less obtrusive using TCP SYN', action='store_true')
parser.add_argument('--aggressive', '-A', help='Aggressive mode - Faster in environment where you can scan more aggressively', action='store_true')
parser.add_argument('--port-versioning', '-V', help='Enabled version/product detection on port. Not by default since it can add significant overhead and can be unreliable', action='store_true')

args = parser.parse_args()

class NmapScan:

    bin_name = 'nmap'

    def run(self, targets):
        ipv6s, others = filter_ipv6(targets)
        options = []
        if args.port_versioning:
            options.append("-sV")
        if args.fast:   
            options.append("-F")
        if args.stealth:   
            options.append("-sS")
        if args.aggressive:   
            options.append("-T4")
        ipv6s_hosts = self.scan(ipv6s, options + ["-6"])
        other_hosts = self.scan(others, options)

        return ipv6s_hosts + other_hosts

    def scan(self, targets, extraflags=[]):
        if len(targets) == 0:
            return []

        xmlfile = tempfile.NamedTemporaryFile(suffix='-scan.xml', delete=False)
        process = subprocess.Popen(
            ["nmap", "--stats-every", "0.5", "-oX", xmlfile.name, "-Pn", "-n"] + extraflags + targets, stdout=subprocess.PIPE
        )
       
        while process.returncode is None:
            line = process.stdout.readline().decode('utf-8')
            match = re.search('About (.*)% done;', line, re.IGNORECASE)
            if match:
                info = line[:line.rfind(';')]
                print('{} for {}'.format(info, targets), file=sys.stderr)
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
    def __init__(self, num, status, service, product, version):
        self.num = num
        self.status = status
        self.service = service
        self.product = product
        self.version = version

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
                product = port_element.find('service').get('product')
                version = port_element.find('service').get('version')
                host.add_port(Port(num, status, service, product, version))   
        
        os.remove(self.filename)
       
        return self.hosts
            
def write_console(hosts):
    print('\n-> Results:')
    for host in hosts:
        print(host.addr)
        for port in host.ports:
            print('\t', port.num, port.status, port.service, port.product, port.version)

def write_html(hosts):
    f = open('scan-report.html', 'w')
    f.write('<html><body>')
    for host in hosts:
        f.write('<h2>Host {}={} {}</h2>'.format(host.addr_type, host.addr, ', '.join(host.hostnames)))
        f.write('<table style="border: 1px solid;"><tr><th>Port</th><th>Status</th><th>Service</th><th>Product</th><th>Version</th></tr>')
        for port in host.ports:
            f.write('<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>'.format(port.num, port.status, port.service, port.product, port.version))
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
    return target.count(':') > 4

def get_targets():
    filepath = args.file
    if not filepath:
        return args.targets

    targets = []
    f = open(filepath, "r")
    for line in f:
        item = line.strip()
        if not item or item.startswith('#'):
            continue
        targets.append(item)
    f.close()    
    return targets

if __name__ == '__main__':    
    scanner = NmapScan()
    scanner.verify_system()
    hosts = scanner.run(get_targets())
    write_console(hosts)
    print('\n-> Generated HTML report "{}"'.format(write_html(hosts)), file=sys.stderr)