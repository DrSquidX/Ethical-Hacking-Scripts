import socket, threading, sys, ipaddress, time, os
from optparse import OptionParser
from scapy.all import *
class Port_Scanner:
    def __init__(self, ip, ports):
        self.ip = str(ip)
        self.logfile = "squidmap.txt"
        file = open(self.logfile,"w")
        file.close()
        self.isnetwork = False
        self.isonehost = True
        if "/24" in self.ip:
            self.hosts = []
            self.uphosts = []
            self.isnetwork = True
            self.isonehost = False
        print(self.logo())
        self.log_output(self.logo())
        print(f"[+] Output will be saved in file: {os.path.join(os.getcwd(),self.logfile)}")
        self.max_port = ports
        self.ports = range(ports)
        self.ports_scanned = 0
        self.open_ports = []
        self.checked_hosts = 0
        self.banners = []
        if self.isnetwork:
            print("[+] Sending ICMP Packets to Network to check for online IP's.\n[+] Please wait.....\n")
            self.networkscan()
        if self.isonehost:
            self.port_scan(self.ip)
    def ping_host(self, host):
        if sys.platform == "win32":
            result = os.popen(f"ping {host} -n 1")
            result2 = result.read()
        else:
            try:
                result = os.popen(f"ping {host} -c 1")
                result2 = result.read()
            except:
                result2 = ""
        if "unreachable" in result2 or "100% loss" in result2 or "100.0% packet loss" in result2:
            pass
        else:
            print(f"[+] {host} is up!")
            self.uphosts.append(str(host))
        self.checked_hosts += 1
    def networkscan(self):
        self.ip = str(self.ip)
        self.split_ip = self.ip.split(".")
        if not self.split_ip[len(self.split_ip)-1].startswith("0"):
            self.split_ip.remove(self.split_ip[len(self.split_ip)-1])
            self.split_ip.append("0/24")
            self.result = ""
            item = 0
            for i in self.split_ip:
                if item != len(self.split_ip)-1:
                    self.result = self.result + i + "."
                else:
                    self.result = self.result + i
                item += 1
            self.ip = self.result
        self.network = ipaddress.IPv4Network(self.ip)
        for host in self.network.hosts():
            self.hosts.append(str(host))
        for host in self.hosts:
            check_host = threading.Thread(target=self.ping_host, args=(host,))
            check_host.start()
        while True:
            if self.checked_hosts >= len(self.hosts):
                print(f"[+] Hosts Scan done.\n[+] Online Hosts: {self.uphosts}")
                break
        for host in self.uphosts:
            portscan = threading.Thread(target=self.port_scan, args=(host,))
            portscan.start()
    def get_mac(self, ip):
        arp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ip)
        recv = srp(arp, timeout=2, verbose=False)
        return recv[0][0][1].hwsrc
    def log_output(self,msg):
        time.sleep(1)
        file = open(self.logfile,"r")
        content = file.read()
        file.close()
        file = open(self.logfile,"w")
        file.write(content+"\n")
        file.write(msg)
        file.close()
    def logo(self):
        return """
  _________            .__    .___ _____                          _____    _______   
 /   _____/ ________ __|__| __| _//     \ _____  ______   ___  __/  |  |   \   _  \  
 \_____  \ / ____/  |  \  |/ __ |/  \ /  \\\__  \ \____ \  \  \/ /   |  |_  /  /_\  \ 
 /        < <_|  |  |  /  / /_/ /    Y    \/ __ \|  |_> >  \   /    ^   /  \  \_/   \\
/_______  /\__   |____/|__\____ \____|__  (____  /   __/    \_/\____   | /\ \_____  /
        \/    |__|             \/       \/     \/|__|               |__| \/       \/                              
Vulnerability-Scanner By DrSquid"""
    def port_scan(self, ip):
        print(f"[+] Beginning Port Scan On {ip}.")
        mac = "Unknown"
        reversedns = "Unknown"
        try:
            mac = self.get_mac(ip)
            print(f"[+] {ip}'s MAC Address: {mac}")
        except:
            print(f"[+] Unable to obtain MAC Address from: {ip}")
        try:
            reversedns = socket.gethostbyaddr(ip)
            print(f"[+] Reverse DNS of {ip}: {reversedns[0]}")
        except:
            print(f"[+] Unable to get Reverse DNS of {ip}.")
        for port in self.ports:
            scanning = threading.Thread(target=self.scan,args=(ip, port))
            scanning.start()
        while True:
            if self.ports_scanned >= self.max_port:
                open_ports = []
                appendmsg = ""
                msg=f"[+] Port Scan on {ip} Completed.\n[+] Obtained Banners For {ip}."
                for port in self.open_ports:
                    if ip+" " in port:
                        port_split = port.split()
                        open_ports.append(port_split[1])
                if len(open_ports) == 0:
                    appendmsg=f"\n[+] There are no Ports Open on {ip}."
                else:
                    appendmsg=f"\n[+] Open Ports on {ip}: {open_ports}"
                    for port in open_ports:
                        for banner in self.banners:
                            split_banner = banner.split()
                            if ip in split_banner[0] and port in split_banner[1]:
                                result = ""
                                del split_banner[0]
                                del split_banner[0]
                                for item in split_banner:
                                    result = result + " " + item
                                result = result.strip()
                                appendmsg += f"\n[+] {ip} Port {port} Banner: {result}"
                msg += appendmsg
                print(msg)
                logmsg = "\n"+msg+f"\n[+] {ip}'s MAC Address: {mac}\n[+] Reverse DNS of {ip}: {reversedns}"
                self.log_output(logmsg)
                break
    def scan(self, ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((ip, port))
            self.open_ports.append(f"{ip} {port}")
            s.settimeout(10)
            print(f"[!] Discovered Open Port on {ip}: {port}")
            try:
                banner = s.recv(65500).decode().strip("\n").strip("\r")
                self.banners.append(f"{ip} {port} {banner}")
            except Exception as e:
                self.banners.append(f"{ip} {port} None")
            s.close()
        except Exception as e:
            pass
        self.ports_scanned += 1
class OptionParse:
    def __init__(self):
        if len(sys.argv) < 2:
            self.usage()
        else:
            self.get_args()
    def usage(self):
        print(Port_Scanner.logo(None))
        print("""
[+] Option-Parsing Help:
[+] --ip, --ipaddr - Specifies an IP Address to Scan(can be a network).
[+] --p,  --ports  - Specifies the amount of ports to Scan.
[+] Optional Arguements:
[+] --i,  --info   - Shows this message.
[+] Usage:""")
        if sys.argv[0].endswith(".py"):
            print("[+] python3 Squidmap.py --ip <ipaddr> --p <ports>")
            print("[+] python3 Squidmap.py --i")
        else:
            print("[+] Squidmap --ip <ipaddr> --p <ports>")
            print("[+] Squidmap --i")
    def get_args(self):
        self.opts = OptionParser()
        self.opts.add_option("--ip","--ipaddr",dest="ip")
        self.opts.add_option("--p","--port",dest="port")
        self.opts.add_option("--i","--info",dest="info",action="store_true")
        args, opt =self.opts.parse_args()
        if args.info is not None:
            self.usage()
            sys.exit()
        else:
            pass
        if args.ip is None:
            self.usage()
        else:
            ip = args.ip
        if args.port is None:
            ports = 1024
        else:
            try:
                ports = int(args.port)
            except:
                print("[+] Invalid Port!")
                sys.exit()
        SquidMap = Port_Scanner(ip, ports)
try:
    from scapy.all import *
except:
    Port_Scanner.logo(None)
    print("[+] Scapy is required to run this script.\n[+] Run this command if you have python: pip install scapy")
    sys.exit()
parser = OptionParse()
