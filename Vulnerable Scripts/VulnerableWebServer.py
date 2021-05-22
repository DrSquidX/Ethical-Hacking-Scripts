import socket, threading, sys
class WebServer:
    def __init__(self):
        self.logo()
        self.valid = False
        try:
            self.ip = sys.argv[1]
            self.port = int(sys.argv[2])
            try:
                self.externalip = sys.argv[3]
            except:
                self.externalip = self.ip
            self.valid = True
        except Exception as e:
            print("[+] Invalid Arguments!\n[+] Usage: python3 VulnerableServer.py <ip> <port> <externalip>\n[+] Note: The External IP argument is optional.")
        if self.valid:
            try:
                self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server.bind((self.ip, self.port))
                self.msgs = []
                self.packet = self.gen_packet()
                print(f"[+] Vulnerable Web Server Started on: {self.ip}:{self.port}")
            except Exception as e:
                print(f"[+] Server Cannot be started due to Error: {e}")
                self.valid = False
    def logo(self=None):
        print("""
__   __ _____ _____    __      __    _                      _     _       _____                        __   _____ 
\ \ / // ____/ ____|   \ \    / /   | |                    | |   | |     / ____|                      /_ | | ____|
 \ V /| (___| (___ _____\ \  / /   _| |_ __   ___ _ __ __ _| |__ | | ___| (___   ___ _ ____   __ __   _| | | |__  
  > <  \___ \ ___ \______\ \/ / | | | | '_ \ / _ \ '__/ _` | '_ \| |/ _ \ ___ \ / _ \ '__\ \ / / \ \ / / | |___ \ 
 / . \ ____) |___) |      \  /| |_| | | | | |  __/ | | (_| | |_) | |  __/____) |  __/ |   \ V /   \ V /| |_ ___) |
/_/ \_\_____/_____/        \/  \__,_|_|_| |_|\___|_|  \__,_|_.__/|_|\___|_____/ \___|_|    \_/     \_/ |_(_)____/                                                                                                                                                                                     
Vulnerable Web-Server Made for Pen-Testing By DrSquid
""")
    def gen_packet(self):
        packet = f"""
<title>Vulnerable Web Server</title>
<h1>Horrific Looking Chat Server</h1>
This is an anonoymous Chat Site.
The Server is also made to be vulnerable to Cross site scripting attacks.
        
<form action="http://{self.externalip}:{self.port}">
   <textarea name="msg" cols="50" rows="10" placeholder="Enter your message here."></textarea>
   <h1></h1>
    <input type="submit" value="Send Message">
</form>
"""
        for i in self.msgs:
            packet += f"<h5>Anonoymous: {i}</h5>\n"
        return packet
    def listen(self):
        if self.valid:
            print("[+] Server is listening For Connections.....")
            while True:
                ipaddr = ""
                self.server.listen()
                conn, ip = self.server.accept()
                self.packet = self.gen_packet()
                msg = conn.recv(1024).decode()
                item = 0
                msg_split = msg.split()
                for i in msg_split:
                    if 'x-forwarded-for' in i.lower():
                        ipaddr = msg_split[item + 1]
                        break
                    item += 1
                if ipaddr == "":
                    ipaddr = ip[0]
                handler = threading.Thread(target=self.handler, args=(conn, msg, ipaddr))
                handler.start()
    def handler(self, conn, msg, ip):
        try:
            conn.send('HTTP/1.0 200 OK\n'.encode())
            conn.send('Content-Type: text/html\n'.encode())
            if "/?msg=" in msg.split()[1]:
                try:
                    main_msg = str(msg).split()[1].split("=")[1].replace("+", " ").replace("%3C", "<").replace("%3E",">").replace(
                        "%2F", "/").replace("%22", '"').replace("%27", "'").replace("%3D", "=").replace("%2B","+").replace(
                        "%3A", ":").replace("%28", "(").replace("%29", ")").replace("%2C", ",").replace("%3B",";").replace(
                        "%20", " ").replace("%3F", "?").replace("%5C","\\").replace("%7B", "{").replace("%7D","}").replace(
                        "%24", "$").replace("%0D", "\n").replace("%0A", "   ").replace("%40","@")
                    if main_msg.strip() != "":
                        print(f"[+] {ip}: {main_msg}")
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
