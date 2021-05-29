import socket, sys, urllib.request
from optparse import OptionParser
class IPTools:
    def __init__(self):
        self.parse_args()
    def usage(self):
        print("""
[+] Option-Parsing Help:
[+] --i, --info         - Shows this message.
[+] --ip, --ipaddr      - Specify an IP Address/Hostname
[+] --ri, --resolveip   - Attempts to resolve the Host into an IP Address.
[+] --ti, --trackip     - Attempts to obtain the geolocation info of the IP Address.
[+] --rd, --reversedns  - Attempts to resolve the IP Address into a hostname.
[+] --la, --latlng      - Attempts to obtain the approximate latlng coordinates of the IP.
[+] --gi, --getinfo     - Gets more info(cleaner version of trackip function and doesn't require geocoder).

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
    def get_more_info(self, ip):
        print(f"[+] Attempting to get IP Info of {ip}.")
        print("[+] Please wait....\n")
        try:
            req = urllib.request.Request(url=f"https://ip-info.org/en/?ip={ip}")
            e = urllib.request.urlopen(req)
            item = e.read().decode().split('<table class="overview1"')
            i2 = 0
            info = item[1].split("<br>")[0]
            info2 = str(info).replace("<", " ").replace(">", " ").replace("td", "").replace("<tr>", "").replace("</tr>",
                                                                                                                "").replace(
                'class="overview1"', "").replace("/", "").replace("SPAN", "").replace('id="outpape101"', "").replace(
                'id="outpape102"', "").replace('id="outpape103"', "").replace('id="outpape104"', "").replace(
                'id="outpape105"', "").strip().split()
            info = []
            for i in info2:
                if i != "tr" and i != "table" and i != "div":
                    info.append(i)
            url = ""
            ip = ""
            hostname = ""
            isp = ""
            rir = ""
            origin = ""
            netrange = ""
            country = ""
            inurl = False
            inip = False
            inhost = False
            inisp = False
            inrir = False
            inorigin = False
            innetrange = False
            incountry = False
            has_done_ip = False
            for i in info:
                if i == "URL":
                    inurl = True
                    inip = False
                    inhost = False
                    inisp = False
                    inrir = False
                    inorigin = False
                    innetrange = False
                    incountry = False
                elif i == "IP":
                    if not has_done_ip:
                        inurl = False
                        inip = True
                        inhost = False
                        inisp = False
                        inrir = False
                        inorigin = False
                        innetrange = False
                        incountry = False
                        has_done_ip = True
                elif i == "Hostname":
                    inurl = False
                    inip = False
                    inhost = True
                    inisp = False
                    inrir = False
                    inorigin = False
                    innetrange = False
                    incountry = False
                elif i == "ISP":
                    inurl = False
                    inip = False
                    inhost = False
                    inisp = True
                    inrir = False
                    inorigin = False
                    innetrange = False
                    incountry = False
                elif i == "RIR":
                    inurl = False
                    inip = False
                    inhost = False
                    inisp = False
                    inrir = True
                    inorigin = False
                    innetrange = False
                    incountry = False
                elif i == "Origin":
                    inurl = False
                    inip = False
                    inhost = False
                    inisp = False
                    inrir = False
                    inorigin = True
                    innetrange = False
                    incountry = False
                elif i == "Netrange":
                    inurl = False
                    inip = False
                    inhost = False
                    inisp = False
                    inrir = False
                    inorigin = False
                    innetrange = True
                    incountry = False
                elif i == "Country":
                    inurl = False
                    inip = False
                    inhost = False
                    inisp = False
                    inrir = False
                    inorigin = False
                    innetrange = False
                    incountry = True
                else:
                    if inurl:
                        url += f" {i}"
                    if inisp:
                        isp += f" {i}"
                    if inip:
                        ip += f" {i}"
                    if inhost:
                        hostname += f" {i}"
                    if inrir:
                        rir += f" {i}"
                    if inorigin:
                        origin += f" {i}"
                    if innetrange:
                        netrange += f" {i}"
                    if incountry:
                        country += f" {i}"
            print("[+] Here's what I could find:")
            print(f"[+] URL: {url}")
            print(f"[+] IP: {ip}")
            print(f"[+] Hostname: {hostname}")
            print(f"[+] ISP: {isp}")
            print(f"[+] Origin: {origin}")
            print(f"[+] RIR: {rir}")
            print(f"[+] Netrange: {netrange}")
            print(f"[+] Country: {country}")
            self.get_lat_lng(ip.strip())
        except Exception as e:
            print(f"[+] There was an error with obtaining the IP Info for {ip}: {e}.")
    def parse_args(self):
        args = OptionParser()
        args.add_option("--ip", "--ipaddr", dest="ip")
        args.add_option("--ri", "--resolveip",dest="ri", action="store_true")
        args.add_option("--ti", "--trackip", dest="ti", action="store_true")
        args.add_option("--rd", "--reversedns", dest="rd", action="store_true")
        args.add_option("--la", "--latlng", dest="la", action="store_true")
        args.add_option("--gi","--getinfo",dest="gi",action="store_true")
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
        if arg.gi is not None:
            self.get_more_info(self.ip)
IPTools.logo(None)
try:
    import geocoder
except:
    print("[+] Unable to Import Module 'geocoder'. You will not be able to use the IP Tracking Functions(Can use 'getinfo' function)!")
iptools = IPTools()
