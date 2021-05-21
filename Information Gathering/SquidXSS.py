import urllib.request, sys
from optparse import OptionParser

class XSSPayloadChecker:
    def __init__(self, website, payloadfile):
        self.website = website
        try:
            self.payloadfile = open(payloadfile, "r")
        except:
            print("[+] The file provided is invalid!")
            sys.exit()
        self.payloads = []
        if "/?" not in self.website:
            print("[+] Invalid Website! You need to provide a query string for the link.\n[+] Example: http://example.com/?search=")
            sys.exit()
        self.check_payloads()
    def check_payloads(self):
        for i in self.payloadfile.read().splitlines():
            try:
                payload = self.website + i
                req = urllib.request.Request(url=payload)
                linkopen = urllib.request.urlopen(req)
                try:
                    info = linkopen.read().decode()
                except:
                    info = linkopen.read()
                if i in info:
                    print(f"[!] The site is vulnerable to: {i}")
                    if i not in self.payloads:
                        self.payloads.append(i)
            except:
                pass
        print(f"[+] Available Cross-Site-Scripting Payloads: {self.payloads}")
        self.payloadfile.close()
class OptionParse:
    def __init__(self):
        self.logo()
        self.parse_args()
    def logo(self):
        print("""
  _____             _     ___   __ _____ _____        __   ___  
 / ____|           (_)   | \ \ / // ____/ ____|      /_ | / _ \ 
| (___   __ _ _   _ _  __| |\ V /| (___| (___   __   _| || | | |
 \___ \ / _` | | | | |/ _` | > <  \___ \ ___ \  \ \ / / || | | |
 ____) | (_| | |_| | | (_| |/ . \ ____) |___) |  \ V /| || |_| |
|_____/ \__, |\__,_|_|\__,_/_/ \_\_____/_____/    \_/ |_(_)___/ 
           | |                                                  
           |_|                                                  
XSS-Payload Checker Script By DrSquid""")
    def usage(self):
        print("""
[+] Option-Parsing Help:
[+] -w, --website     - Specify the Target Website(add a search query string at the end).
[+] -p, --payloadfile - Specify the File with the XSS Payloads.
[+] -i, --info        - Shows this message.

[+] Usage:
[+] python3 SquidXSS.py -w <website> -p <payloadfile>
[+] python3 SquidXSS.py -i""")
    def parse_args(self):
        args = OptionParser()
        args.add_option("-w","--website", dest="web")
        args.add_option("-p","--payloadfile", dest="plfile")
        args.add_option("-i","--info",dest="info",action="store_true")
        opt, arg = args.parse_args()
        if opt.info is not None:
            self.usage()
            sys.exit()
        if opt.web is not None:
            web = opt.web
        else:
            self.usage()
            sys.exit()
        if opt.plfile is not None:
            plfile = opt.plfile
        else:
            self.usage()
            sys.exit()
        XSSPayload = XSSPayloadChecker(web, plfile)
Argparse = OptionParse()