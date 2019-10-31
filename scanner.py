import os, sys, subprocess, argparse, tempfile
import xml.etree.ElementTree as XML

parser = argparse.ArgumentParser(description='TCP Scan list of given IP addresses', epilog='Made by Simon with fun and love!')
parser.add_argument('ips', help='IPv4 address to be scanned', nargs='*')
args = parser.parse_args()

class NmapScan:

    bin_name = 'nmap'

    def run(self, ips):
        xmlfile = tempfile.NamedTemporaryFile(suffix='-scan.xml', delete=False)
        process = subprocess.Popen(
            ["nmap", "--stats-every", "1", "-oX", xmlfile.name, "-F", "-Pn", "-n"] + ips,
            stdout=subprocess.PIPE)
       
        while process.returncode is None:
            line = process.stdout.readline()
            if '% done' in line:
                print(line.rstrip())
            process.poll()

        process.wait()
        
        results = Results(xmlfile.name)
        results.parse()
        results.write()

        print '\n-> Generated HTML report "{}"'.format(write_html(results.hosts))

        os.remove(xmlfile.name)

    def verify_system(self):
        discard = open(os.devnull, 'w')
        if subprocess.call(['which', NmapScan.bin_name], stdout=discard, stderr=discard):
            sys.exit('cannot find local {n} executable. {n} is required to run this program'.format(n=NmapScan.bin_name))
        discard.close()

class Host:
    def __init__(self, addr):
        self.addr = addr
        self.ports = []

    def add_port(self, port):
        self.ports.append(port)

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
            host =  Host(addr_element.get('addr'))
            self.hosts.append(host)
            for port_element in host_element.findall('ports/port'):
                num = port_element.get('portid')
                status = port_element.find('state').get('state')
                service = port_element.find('service').get('name')
                host.add_port(Port(num, status, service))    
            
    def write(self):
        print '\n'
        for host in self.hosts:
            print host.addr
            for port in host.ports:
                print '\t', port.num, port.status, port.service

def write_html(hosts):
    f = open('scan-report.html', 'w')
    f.write('<html><body>')
    for host in hosts:
        f.write('<h2>Host {}</h2>'.format(host.addr))
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
    scan.run(args.ips)