import os, sys, subprocess, argparse, tempfile
import xml.etree.ElementTree as XML

parser = argparse.ArgumentParser(description='TCP Scan list of given IP addresses', epilog='Made by Simon with fun and love!')
parser.add_argument('hosts', help='IPv4 address list to be scanned', nargs='*')
args = parser.parse_args()

class NmapScan:

    bin_name = 'nmap'

    def run(self, hosts):
        xmlfile = tempfile.NamedTemporaryFile(suffix='-scan.xml', delete=False)
        process = subprocess.Popen(
            ["nmap", "--stats-every", "1", "-oX", xmlfile.name, "-F", "-Pn", "-n"] + hosts,
            stdout=subprocess.PIPE)
       
        while process.returncode is None:
            line = process.stdout.readline()
            if '% done' in line:
                sys.stderr.write('{}\n'.format(line.rstrip()))
            process.poll()

        process.wait()

        return self.process_output(xmlfile.name)

    def process_output(self, filename):        
        results = Results(filename)
        results.parse()
        results.write_console()
        os.remove(filename)
        return results.hosts

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
            
    def write_console(self):
        print '\n'
        for host in self.hosts:
            print host.addr
            for port in host.ports:
                print '\t', port.num, port.status, port.service

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

if __name__ == '__main__':    
    scan = NmapScan()
    scan.verify_system()
    hosts = scan.run(args.hosts)
    htmlfile = write_html(hosts)
    sys.stderr.write('\n-> Generated HTML report "{}"\n'.format(htmlfile))

