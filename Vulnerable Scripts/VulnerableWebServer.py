import socket, threading, sys
class WebServer:
    def __init__(self):
        self.logo()
        self.valid = False
        try:
            self.ip = sys.argv[1]
            self.port = int(sys.argv)[2]
            try:
                self.externalip = sys.argv[3]
            except:
                self.externalip = self.ip
            self.valid = True
        except:
            print("[+] Invalid Arguments!\n[+] Usage: python3 VulnerableServer.py <ip> <port> <externalip>\n[+] Note: The External IP argument is optional.")
        if self.valid:
            try:
                self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server.bind((self.ip, self.port))
                self.msgs = []
                self.packet = self.gen_packet()
                print(f"[+] Vulnerable Server Started on: {self.ip}:{self.port}")
            except Exception as e:
                print(f"[+] Server Cannot be started due to Error: {e}")
                self.valid = False
    def logo(self=None):
        print("""
__          __        _     __          __  _        _____                                 __   ___  
\ \        / /       | |    \ \        / / | |      / ____|                               /_ | / _ \ 
 \ \  /\  / /__  __ _| | __  \ \  /\  / /__| |__   | (___   ___ _ ____   _____ _ __  __   _| || | | |
  \ \/  \/ / _ \/ _` | |/ /   \ \/  \/ / _ \ '_ \   \___ \ / _ \ '__\ \ / / _ \ '__| \ \ / / || | | |
   \  /\  /  __/ (_| |   <     \  /\  /  __/ |_) |  ____) |  __/ |   \ V /  __/ |     \ V /| || |_| |
    \/  \/ \___|\__,_|_|\_\     \/  \/ \___|_.__/  |_____/ \___|_|    \_/ \___|_|      \_/ |_(_)___/                                                                                      
Vulnerable Web-Server Made for Pen-Testing By DrSquid
""")
    def gen_packet(self):
        packet = f"""
<h1>Horrific Looking Chat Server</h1>
This is an anonoymous Chat Site.
The Server is also made to be vulnerable to Cross site scripting attacks.
        
<form action="http://{self.ip}:{self.port}">
    <input type="text" placeholder="Enter your blog message!" name="msg"> 
    <input type="submit" value="Submit Message to blog">
</form>
"""
        for i in self.msgs:
            packet += f"<h5>Anonoymous: {i}</h5>\n"
        return packet
    def listen(self):
        if self.valid:
            print("[+] Server is listening For Connections.....")
            while True:
                self.server.listen()
                conn, ip = self.server.accept()
                self.packet = self.gen_packet()
                msg = conn.recv(1024).decode()
                handler = threading.Thread(target=self.handler, args=(conn, msg))
                handler.start()
    def handler(self, conn, msg):
        try:
            conn.send('HTTP/1.0 200 OK\n'.encode())
            conn.send('Content-Type: text/html\n'.encode())
            if "/?msg=" in msg.split()[1]:
                try:
                    main_msg = str(msg).split()[1].split("=")[1].replace("+", " ").replace("%3C", "<").replace("%3E",">").replace(
                        "%2F", "/").replace("%22", '"').replace("%27", "'").replace("%3D", "=").replace("%2B","+").replace(
                        "%3A", ":").replace("%28", "(").replace("%29", ")").replace("%2C", ",").replace("%3B",";").replace(
                        "%20", " ")
                    if main_msg.strip() != "":
                        self.msgs.append(main_msg)
                        self.packet = self.gen_packet()
                except:
                    pass
            conn.send(self.packet.encode())
            conn.close()
        except:
            pass
serv = WebServer()
serv.listen()