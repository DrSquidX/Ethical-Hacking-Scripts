import hashlib, threading, time, sys
from optparse import OptionParser
from string import ascii_letters, digits, punctuation
from itertools import product
class Hashcracker:
    def __init__(self, hash ,hashType, passfile, nofile, passdigits, combolist):
        self.start = time.time()
        self.hash = hash
        self.stop = False
        self.logo()
        self.combolist = combolist
        self.nofile = nofile
        self.passdigits = passdigits
        try:
            self.passlist = open(passfile, 'r')
        except:
            if not self.nofile:
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
        if self.nofile:
            print("[+] The hash cracking may take time, depending on the length of the password.")
            self.crackit = threading.Thread(target=self.nofile_cracker)
        else:
            self.crackit = threading.Thread(target=self.cracker)
        self.crackit.start()
    def save_hash(self,hash,realdef):
        file = open(hash+".txt","w")
        file.write(f"{hash}:{realdef}")
        file.close()
    def logo(self):
        print("""
  ___ ___               .__      _________            .__    .___       ________     _______   
 /   |   \_____    _____|  |__  /   _____/ ________ __|__| __| _/ ___  _\_____  \    \   _  \  
/    ~    \__  \  /  ___/  |  \ \_____  \ / ____/  |  \  |/ __ |  \  \/ //  ____/    /  /_\  \ 
\    Y    // __ \_\___ \|   Y  \/        < <_|  |  |  /  / /_/ |   \   //       \    \  \_/   \\
 \___|_  /(____  /____  >___|  /_______  /\__   |____/|__\____ |    \_/ \_______ \ /\ \_____  /
       \/      \/     \/     \/        \/    |__|             \/                \/ \/       \/ 
Hash-Cracker by DrSquid""")
    def display_packet(self, hash, string):
        end = time.time()
        return f"""[!] Hash has been cracked!
[!] Hash: {hash} String: {string.strip()}
[!] Passwords checked: {self.checked}
[!] Time elapsed: {end - self.start}"""
    def nofile_cracker(self):
        success = False
        for passcode in product(self.combolist, repeat=self.passdigits):
            new_passcode = ""
            for i in passcode:
                new_passcode += i
            if str(self.hashtype(new_passcode.encode()).hexdigest()) == self.hash:
                success = True
                print(self.display_packet(self.hash, new_passcode))
                self.save_hash(self.hash,new_passcode)
                input("[!] Press enter to exit.")
                break
            else:
                self.checked += 1
        if not success:
            print(f"[?] Unable to crack Hash: {self.hash}")
    def cracker(self):
        success = False
        while True:
            try:
                for line in self.passlist:
                    if self.hashtype(line.strip().encode()).hexdigest() == self.hash:
                        print(self.display_packet(self.hash, line.strip()))
                        self.save_hash(self.hash,line.strip())
                        success = True
                        input("[!] Press enter to exit.")
                        break
                    else:
                        self.checked += 1
                if not success:
                    print(f"[?] Unable to crack Hash: {self.hash}")
                break
            except Exception as e:
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
[+] --h,  --hash        - Specifies the Hash to crack.
[+] --hT, --hashtype    - Specifies Hash type(default is md5).

[+] With Brute Force File:
[+] --pL, --passlist    - Specifies the Brute Forcing TxT File.

[+] Without Brute Force File:
[+] --nF, --nofile      - Makes the script use computing power rather than a txt file to crack a hash.
[+] --pD, --passdigits  - Specify the amount of digits the password contains(default is 6).
[+] --oL, --onlyletters - Makes the no file brute forcing brute force through only letter passwords.
[+] --oN, --onlynumbers - Makes the no file brute forcing brute force through only number passwords.

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
        self.opts.add_option("--nF","--nofile",dest="nofile", action="store_true")
        self.opts.add_option("--pD","--passdigits",dest="passdigits")
        self.opts.add_option("--oL","--onlyletters",dest="onlyletters", action="store_true")
        self.opts.add_option("--oN","--onlynumbers",dest="onlynumbers", action="store_true")
        self.opts.add_option("--i","--info",dest="info",action="store_true")
        args, opt = self.opts.parse_args()
        nofile = False
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
        if args.nofile is not None:
            nofile = True
        if args.passdigits is not None:
            try:
                passdigits = int(args.passdigits)
            except:
                passdigits = 6
        else:
            if nofile:
                passdigits = 6
        if args.onlyletters is not None:
            combolist = ascii_letters
        elif args.onlynumbers is not None:
            combolist = digits
        else:
            combolist = ascii_letters+digits+punctuation
        if args.passlist is None:
            if not nofile:
                self.usage()
            else:
                passlist = None
        else:
            passlist = args.passlist
        HashSquid = Hashcracker(hash, hashtype, passlist, nofile, passdigits, combolist)
optionparser = OptionParse()
