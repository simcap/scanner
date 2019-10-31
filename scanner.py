import os, sys, subprocess, argparse

class Nmap(object):
    def run(self, ips):
        process = subprocess.Popen(
            ["nmap", "-F", "-Pn", "-n", "--open", "--stats-every", "2", ips],
            stdout=subprocess.PIPE)

        while process.returncode is None:
            line = process.stdout.readline()
            if '% done' in line:
                print(line.rstrip())
            process.poll()

parser = argparse.ArgumentParser(description='TCP Scan list of given IP addresses', epilog='Made by Simon with fun and love!')
parser.add_argument('ip', help='IPv4 address to be scanned')

args = parser.parse_args()

if __name__ == '__main__':
    discard = open(os.devnull, 'w')
    if subprocess.call(["which", "nmap"], stdout=discard, stderr=discard):
        sys.exit("cannot find local nmap executable. nmap is required to run this program")
    
    nmap = Nmap()
    nmap.run(args.ip)