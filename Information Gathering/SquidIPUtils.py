import socket, sys
from optparse import OptionParser
class IPTools:
    def __init__(self):
        self.parse_args()
    def usage(self):
        print("""
[+] Option-Parsing Help:

[+] Optional Arguements:
[+] --i, --info         - Shows this message.
[+] --ip, --ipaddr      - Specify an IP Address/Hostname
[+] --ri, --resolveip   - Attempts to resolve the Host into an IP Address.
[+] --ti, --trackip     - Attempts to obtain the geolocation info of the IP Address.
[+] --rd, --reversedns  - Attempts to resolve the IP Address into a hostname.
[+] --la, --latlng      - Attempts to obtain the approximate latlng coordinates of the IP.

[+] Usage:
[+] python3 SquidIPUtils.py --ip <ipaddr/host> --ri --ti --rd --la
[+] python3 SquidIPUtils.py --i""")
    def logo(self):
        print("""
  _____             _     _ _____ _____        _    _ _   _ _            __   ___  
 / ____|           (_)   | |_   _|  __ \      | |  | | | (_) |          /_ | / _ \ 
| (___   __ _ _   _ _  __| | | | | |__) |_____| |  | | |_ _| |___  __   _| || | | |
 \___ \ / _` | | | | |/ _` | | | |  ___/______| |  | | __| | / __| \ \ / / || | | |
 ____) | (_| | |_| | | (_| |_| |_| |          | |__| | |_| | \__ \  \ V /| || |_| |
|_____/ \__, |\__,_|_|\__,_|_____|_|           \____/ \__|_|_|___/   \_/ |_(_)___/ 
           | |                                                                     
           |_|                                                                   
IP Utilities Script By DrSquid""")
    def resolve_ip(self, ip):
        try:
            print(f"[+] {ip} is {socket.gethostbyname(ip)}")
        except:
            print(f"[+] Unable to resolve {ip} into an IP Address")
    def reverse_dns(self, ip):
        try:
            print(f"[+] Reverse DNS Of {ip} is {socket.gethostbyaddr(ip)}")
        except:
            print(f"[+] Unable to Reverse DNS {ip}.")
    def get_lat_lng(self, ip):
        try:
            ip = socket.gethostbyname(ip)
            trackip = geocoder.ip(ip)
            print(f"[+] Approximate Coordinates for {ip}: {trackip.latlng}")
        except:
            print(f"[+] Unable to obtain the Geolocation info of {ip}.")
    def get_geo_info(self, ip):
        try:
            ip = socket.gethostbyname(ip)
            trackip = geocoder.ip(ip)
            print(f"[+] Geolocation Info: {trackip.geojson}")
        except:
            print(f"[+] Unable to obtain the Geolocation info of {ip}.")
    def parse_args(self):
        args = OptionParser()
        args.add_option("--ip", "--ipaddr", dest="ip")
        args.add_option("--ri", "--resolveip",dest="ri", action="store_true")
        args.add_option("--ti", "--trackip", dest="ti", action="store_true")
        args.add_option("--rd", "--reversedns", dest="rd", action="store_true")
        args.add_option("--la", "--latlng", dest="la", action="store_true")
        args.add_option("--i", "--info", dest="i", action="store_true")
        arg, opt = args.parse_args()
        if arg.i is not None:
            self.usage()
            sys.exit()
        if arg.ip is not None:
            self.ip = arg.ip
        else:
            self.usage()
            sys.exit()
        print("")
        if arg.ri is not None:
            self.resolve_ip(self.ip)
        if arg.ti is not None:
            self.get_geo_info(self.ip)
        if arg.rd is not None:
            self.reverse_dns(self.ip)
        if arg.la is not None:
            self.get_lat_lng(self.ip)
IPTools.logo(None)
try:
    import geocoder
except:
    print("[+] Unable to Import Module 'geocoder'. You will not be able to use the IP Tracking Functions!")
iptools = IPTools()
