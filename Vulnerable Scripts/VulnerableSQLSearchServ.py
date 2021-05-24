import sqlite3, socket, threading, sys, random

class WebServer:
    def __init__(self):
        self.logo()
        self.valid = False
        self.name_list = ["admin adminpassword123456","bobby cheeseburger69","david 19216801","mine craft","jerry password","tom jerry"]
        self.names = ["admin", "bobby", "david", "mine", "jerry", "tom"]
        self.items = ["cheeseburger","fries","nuggies","fetus","chicken","rtx 3090","i9 11900kf"]
        try:
            self.ip = sys.argv[1]
            self.port = int(sys.argv[2])
            self.dbfile = "users.db"
            try:
                file = open(self.dbfile,"r")
            except:
                file = open(self.dbfile,"w")
            db = sqlite3.connect(self.dbfile)
            cursor = db.cursor()
            try:
                cursor.execute("select * from users")
            except:
                cursor.execute("create table users(name, password, logins)")
            try:
                for i in self.name_list:
                    cursor.execute(f"delete from users where name = '{i.split()[0]}'")
            except:
                pass
            for i in self.name_list:
                cursor.execute(f"insert into users values('{i.split()[0]}', '{i.split()[1]}', '0')")
            try:
                cursor.execute("select * from items")
            except:
                cursor.execute("create table items(item, price)")
            try:
                for i in self.items:
                    cursor.execute(f"delete from items where item = '{i}'")
            except:
                pass
            for i in self.items:
                cursor.execute(f"insert into items values('{i}', '${random.randint(10,100)}.{random.randint(10,99)}')")
            print(f"\n[+] Try to use SQL Injections to obtain the passwords of these accounts: {self.names}")
            print(f"[+] Here are the 'normal' things you can search for: {self.items}\n")
            try:
                self.externalip = sys.argv[3]
            except Exception as e:
                self.externalip = self.ip
            self.valid = True
            db.commit()
            cursor.close()
            db.close()
        except Exception as e:
            print("[+] Invalid Arguments!\n[+] Usage: python3 VulnerableServer.py <ip> <port> <externalip>\n[+] Note: The External IP argument is optional.")
        if self.valid:
            try:
                self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server.bind((self.ip, self.port))
                self.msgs = []
                self.packet = self.gen_packet()
                print(f"[+] Vulnerable SQL Web Server Started on: {self.ip}:{self.port}")
            except Exception as e:
                print(f"[+] Server Cannot be started due to Error: {e}")
                self.valid = False
    def logo(self):
        print("""
__      __    _                      _     _       _____  ____  _         _____                                 __   ___  
\ \    / /   | |                    | |   | |     / ____|/ __ \| |       / ____|                               /_ | / _ \ 
 \ \  / /   _| |_ __   ___ _ __ __ _| |__ | | ___| (___ | |  | | |      | (___   ___ _ ____   _____ _ __  __   _| || | | |
  \ \/ / | | | | '_ \ / _ \ '__/ _` | '_ \| |/ _ \ ___ \| |  | | |       \___ \ / _ \ '__\ \ / / _ \ '__| \ \ / / || | | |
   \  /| |_| | | | | |  __/ | | (_| | |_) | |  __/____) | |__| | |____   ____) |  __/ |   \ V /  __/ |     \ V /| || |_| |
    \/  \__,_|_|_| |_|\___|_|  \__,_|_.__/|_|\___|_____/ \___\_\______| |_____/ \___|_|    \_/ \___|_|      \_/ |_(_)___/ 
Vulnerable Web Server made for Testing SQL Injections by DrSquid""")
    def gen_packet(self, sqlquery="", results=""):
        if results != "":
            new_packet = "<h2>Search Results:</h2>"
            for i in results:
                if f"{i[0]}   {i[1]}" in results:
                    pass
                else:
                    new_packet += f"\n<h6>{i[0]}   {i[1]}</h6>"
            results = new_packet
        packet = f"""
<title>Vulnerable SQL Web Server</title>
<h1>Horrific Looking Search Page</h1>
This is a horrible looking search page. It is meant to be vulnerable to SQL Injections.
<form action="http://{self.externalip}:{self.port}">
   Where would you like to go?  <input type="text" placeholder="Your Search" name="search">
    <input type="submit" value="Search">
    <h4>Sql Query: {sqlquery}</h4>
</form>
{results}
        """
        return packet
    def listen(self):
        if self.valid:
            print("[+] Server is listening For Connections.....")
            if self.externalip != self.ip:
                print(f"[+] Also listening on(for external connections): {self.externalip}:{self.port}")
            print("")
            while True:
                try:
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
                    print(f"[+] {ipaddr} has connected.")
                    handler = threading.Thread(target=self.handler, args=(conn, msg, ipaddr))
                    handler.start()
                except:
                    pass
    def simplify_str(self, item):
        return item.replace("+", " ").replace("%3C", "<").replace("%3E", ">").replace(
        "%2F", "/").replace("%22", '"').replace("%27", "'").replace("%3D", "=").replace("%2B",
        "+").replace("%3A", ":").replace("%28", "(").replace("%29", ")").replace("%2C", ","
        ).replace("%3B", ";").replace("%20", " ").replace("%3F", "?").replace("%5C", "\\"
        ).replace("%7B", "{").replace("%7D", "}").replace("%24", "$").replace("%0D", "\n"
        ).replace("%0A", "   ").replace("%40","@").replace("%25", "%")
    def search(self, query):
        db = sqlite3.connect(self.dbfile)
        cursor = db.cursor()
        cursor.execute(query)
        item = cursor.fetchall()
        if len(item) >= 1:
            return item
        else:
            return [("No Results.", "")]
    def handler(self, conn, msg, ip):
        try:
            conn.send('HTTP/1.0 200 OK\n'.encode())
            conn.send('Content-Type: text/html\n'.encode())
            if "/?search=" in msg.split()[1]:
                try:
                    search = self.simplify_str(str(msg).split()[1].split("=")[1]).lower()
                    results = ""
                    if search.strip() == "":
                        conn.send(self.packet.encode())
                    else:
                        query = f"select item, price from items where item = '{search}'"
                        results = self.search(query)
                        packet = self.gen_packet(sqlquery=query, results=results)
                        conn.send(packet.encode())
                except Exception as e:
                    print(f"[+] Error: {e}")
                    packet = self.gen_packet(sqlquery=query, results=results)
                    conn.send(packet.encode())
            else:
                conn.send(self.packet.encode())
            conn.close()
        except:
            pass
e = WebServer()
e.listen()
