import pyshark, sys # Wireshark needs to be installed as well as pyshark!
from optparse import OptionParser
class PacketSniffer:
    def __init__(self, filter=None):
        self.capture = pyshark.LiveCapture(display_filter=filter)
        self.capture.sniff(timeout=0.01)
        self.filter = filter
        self.hasfilter = False
    def sniff(self):
        while True:
            for packet in self.capture.sniff_continuously(packet_count=1000):
                try:
                    print(f"[+] {packet.transport_layer} | {packet.ip.src}:{packet[packet.transport_layer].srcport}->{packet.ip.dst}:{packet[packet.transport_layer].dstport} | {packet.eth.src}->{packet.eth.dst} | Length: {packet.length} |")
                except KeyboardInterrupt:
                    print("[+] Stopped sniffing packets.")
                    sys.exit()
                except Exception as e:
                    try:
                        print(f"[+] {packet.transport_layer} | {packet.ipv6.src}:{packet[packet.transport_layer].srcport}->{packet.ipv6.dst}:{packet[packet.transport_layer].dstport} | {packet.eth.src}->{packet.eth.dst} | Length: {packet.length} |")
                    except:
                        pass
class OptionParse:
    """Option-Parsing Class for parsing arguements."""
    def __init__(self):
        """Starts to parse the arguements."""
        self.parse_args()
    def logo(self):
        print("""
__          ___           _____             _     _        __   ___  
\ \        / (_)         / ____|           (_)   | |      /_ | / _ \ 
 \ \  /\  / / _ _ __ ___| (___   __ _ _   _ _  __| | __   _| || | | |
  \ \/  \/ / | | '__/ _ \ ___ \ / _` | | | | |/ _` | \ \ / / || | | |
   \  /\  /  | | | |  __/____) | (_| | |_| | | (_| |  \ V /| || |_| |
    \/  \/   |_|_|  \___|_____/ \__, |\__,_|_|\__,_|   \_/ |_(_)___/ 
                                   | |                               
                                   |_|
Packet-Sniffer by DrSquid""")
    def usage(self):
        """Displays the help message for option-parsing(in case you need it)."""
        self.logo()
        print("""
[+] Option-Parsing Help:

[+] Optional Arguements:
[+] --i, --info     - Shows this message.
[+] --f, --filter   - Specify the Database file to store passwords on(must be a .db).
[+] Note: These optional arguements have defaults, so you are able to leave them.

[+] Usage:
[+] python3 WireSquid.py --f <filter>
[+] python3 WireSquid.py --i""")
    def parse_args(self):
        """This function parses the arguements."""
        self.logo()
        args = OptionParser()
        args.add_option("--f", "--filter", dest="filter")
        args.add_option("--i",  "--info",dest="i", action="store_true")
        arg, opt = args.parse_args()
        if arg.i is not None:
            self.usage()
            sys.exit()
        if arg.filter is not None:
            filter = arg.filter
        else:
            filter = None
        sniff = PacketSniffer(filter)
        sniff.sniff()
parser = OptionParse()
