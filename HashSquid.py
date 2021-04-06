import hashlib, threading, time, sys
from optparse import OptionParser
class Hashcracker:
    def __init__(self, hash ,hashType, passfile):
        self.start = time.time()
        self.hash = hash
        self.stop = False
        self.logo()
        try:
            self.passlist = open(passfile, 'r')
        except:
            print("[+] Password list provided is invalid.")
            sys.exit()
        self.checked = 0
        if "md5" in hashType:
            self.hashtype = hashlib.md5
        elif "sha1" in hashType:
            self.hashtype = hashlib.sha1
        elif "sha224" in hashType:
            self.hashtype = hashlib.sha224
        elif "sha256" in hashType:
            self.hashtype = hashlib.sha256
        elif "sha384" in hashType:
            self.hashtype = hashlib.sha384
        elif "sha512" in hashType:
            self.hashtype = hashlib.sha512
        else:
            print("[+] Invalid hashing method.")
            sys.exit()
        self.crackit = threading.Thread(target=self.cracker)
        self.crackit.start()
    def logo(self):
        print("""
 _    _           _      _____             _     _        __   _____ 
| |  | |         | |    / ____|           (_)   | |      /_ | | ____|
| |__| | __ _ ___| |__ | (___   __ _ _   _ _  __| | __   _| | | |__  
|  __  |/ _` / __| '_ \ \___ \ / _` | | | | |/ _` | \ \ / / | |___ \ 
| |  | | (_| \__ \ | | |____) | (_| | |_| | | (_| |  \ V /| |_ ___) |
|_|  |_|\__,_|___/_| |_|_____/ \__, |\__,_|_|\__,_|   \_/ |_(_)____/ 
                                  | |                                
                                  |_|                                
Hash-Cracker by DrSquid""")
    def cracker(self):
        success = False
        while True:
            try:
                for line in self.passlist:
                    if self.hashtype(line.strip().encode()).hexdigest() == self.hash:
                        end = time.time()
                        print("[!] Hash has been cracked!")
                        print(f"[!] Hash: {self.hashtype(line.strip().encode()).hexdigest()} String: {line.strip()}")
                        print(f"[!] Passwords checked: {self.checked}")
                        print(f"[!] Time elapsed: {end - self.start}")
                        input("[!] Press enter to exit.")
                        success = True
                        break
                    else:
                        self.checked += 1
                if not success:
                    print(f"[?] Unable to crack Hash: {self.hash}")
                break
            except:
                pass
class OptionParse:
    def __init__(self):
        if len(sys.argv) < 3:
            self.usage()
        else:
            self.get_args()
    def usage(self):
        Hashcracker.logo(None)
        print("""
[+] Option-Parsing Help:
[+] --h,  --hash     - Specifies the Hash to crack.
[+] --hT, --hashtype - Specifies Hash type
[+] --pL, --passlist - Specifies the Brute Forcing TxT File.

[+] Optional Arguements:
[+] --i,  --info   - Shows this message.

[+] Usage:""")
        if sys.argv[0].endswith(".py"):
            print("[+] python3 HashSquid.py --h <hash> --hT <hashtype> --pL <passlist>")
            print("[+] python3 HashSquid.py --i")
        else:
            print("[+] HashSquid --h <hash> --hT <hashtype> --pL <passlist>")
            print("[+] HashSquid --i")
    def get_args(self):
        self.opts = OptionParser()
        self.opts.add_option("--h","--hash",dest="hash")
        self.opts.add_option("--hT","--hashtype",dest="hashtype")
        self.opts.add_option("--pL","--passlist",dest="passlist")
        self.opts.add_option("--i","--info",dest="info",action="store_true")
        args, opt = self.opts.parse_args()
        if args.info is not None:
            self.usage()
        else:
            pass
        if args.hash is None:
            self.usage()
        else:
            hash = args.hash
        if args.hashtype is None:
            hashtype = "md5"
        else:
            hashtype = args.hashtype
        if args.passlist is None:
            self.usage()
        else:
            passlist = args.passlist
        HashSquid = Hashcracker(hash, hashtype, passlist)
optionparser = OptionParse()