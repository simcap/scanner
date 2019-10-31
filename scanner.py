import os, sys, subprocess, argparse, tempfile
import xml.etree.ElementTree as XML

class NmapScan:
    def run(self, ips):
        xmlfile = tempfile.NamedTemporaryFile(suffix='-scan.xml', delete=False)
        process = subprocess.Popen(
            ["nmap", "-F", "-Pn", "-n", "--stats-every", "2", "--open", "-oX", xmlfile.name, ] + ips,
            stdout=subprocess.PIPE)
       
        print 'scanning', ips
        while process.returncode is None:
            line = process.stdout.readline()
            if '% done' in line:
                print(line.rstrip())
            process.poll()
        
        print xmlfile.name
        results = Results(xmlfile.name)
        results.parse()
        results.out()

class Host:
    def __init__(self, addr):
        self.addr = addr
        self.open_ports = []

class Results:
    def __init__(self, filename):
        self.filename = filename
        self.hosts = []

    def parse(self):
        tree = XML.parse(self.filename)
        root = tree.getroot()
        self.hosts = []
        for host in root.iter('host'):
            address = host.find('address')
            self.hosts.append(Host(address.get('addr')))

    def out(self):
        for host in self.hosts:
            print host.addr

parser = argparse.ArgumentParser(description='TCP Scan list of given IP addresses', epilog='Made by Simon with fun and love!')
parser.add_argument('ips', help='IPv4 address to be scanned', nargs='*')
args = parser.parse_args()

if __name__ == '__main__':
    discard = open(os.devnull, 'w')
    if subprocess.call(["which", "nmap"], stdout=discard, stderr=discard):
        sys.exit("cannot find local nmap executable. nmap is required to run this program")
    
    scan = NmapScan()
    scan.run(args.ips)