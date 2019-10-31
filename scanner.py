import os, sys, subprocess, argparse, tempfile
import xml.etree.ElementTree as XML

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

parser = argparse.ArgumentParser(description='TCP Scan list of given IP addresses', epilog='Made by Simon with fun and love!')
parser.add_argument('ips', help='IPv4 address to be scanned', nargs='*')
args = parser.parse_args()

if __name__ == '__main__':    
    scan = NmapScan()
    scan.verify_system()
    scan.run(args.ips)