import os, sys, subprocess, argparse, tempfile, re
import xml.etree.ElementTree as XML

parser = argparse.ArgumentParser(description='TCP Scan list of given hosts', epilog='Made by Simon with fun and love!')
parser.add_argument('hosts', help='Host list to be scanned. Host can be any of ipv4, ipv6 or hostname', nargs='*')
parser.add_argument('--fast', help='Fast mode - Scan fewer ports than the default scan', action='store_true')
args = parser.parse_args()

class NmapScan:

    bin_name = 'nmap'

    def run(self, hosts):
        ipv6s, others = filter_ipv6(hosts)
        options = []
        if args.fast:   
            options.append("-F")
        return self.process_output([self.scan(ipv6s, options + ["-6"]), self.scan(others, options)])

    def scan(self, hosts, extraflags=[]):
        xmlfile = tempfile.NamedTemporaryFile(suffix='-scan.xml', delete=False)
        process = subprocess.Popen(
            ["nmap", "--stats-every", "0.2", "-oX", xmlfile.name, "-Pn", "-n"] + extraflags + hosts,
            stdout=subprocess.PIPE)
       
        while process.returncode is None:
            line = process.stdout.readline()
            match = re.search('About (.*)% done;', line, re.IGNORECASE)
            if match:
                sys.stderr.write('{}% progress scanning {}\n'.format(match.group(1), hosts))
            process.poll()

        process.wait()
        return xmlfile.name

    def process_output(self, filenames=[]):        
        results = Results(filenames)
        results.parse()
        return results

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
    def __init__(self, filenames=[]):
        self.filenames = filenames
        self.hosts = []

    def parse(self):
        for filename in self.filenames:
            tree = XML.parse(filename)
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
            os.remove(filename)
            
    def write_console(self):
        print '\n-> Results:\n'
        for host in self.hosts:
            print host.addr
            for port in host.ports:
                print '\t', port.num, port.status, port.service

    def write_html(self):
        f = open('scan-report.html', 'w')
        f.write('<html><body>')
        for host in self.hosts:
            f.write('<h2>Host {}={} {}</h2>'.format(host.addr_type, host.addr, ', '.join(host.hostnames)))
            f.write('<table style="border: 1px solid;"><tr><th>Port</th><th>Status</th><th>Service</th></tr>')
            for port in host.ports:
                f.write('<tr><td>{}</td><td>{}</td><td>{}</td></tr>'.format(port.num, port.status, port.service))
            f.write('</table>')
        f.write('</body></html>')
        f.close()
        return f.name


def filter_ipv6(hosts): 
    others, ipv6s = [], []
    for h in hosts:
        ipv6s.append(h) if is_ipv6(h) else others.append(h)             
    return ipv6s, others

def is_ipv6(host):
    return host.count(':') == 7

if __name__ == '__main__':    
    scanner = NmapScan()
    scanner.verify_system()
    results = scanner.run(args.hosts)
    results.write_console()
    htmlfile = results.write_html()
    sys.stderr.write('\n-> Generated HTML report "{}"\n'.format(htmlfile))

