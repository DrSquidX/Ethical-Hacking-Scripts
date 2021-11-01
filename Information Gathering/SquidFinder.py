import os, sys, time, threading
from optparse import OptionParser
class FileFinder:
    def __init__(self, search, drive):
        OptionParse.logo(None)
        self.dirlist = []
        self.file_list = []
        self.drive = drive
        self.keep_search = True
        self.search = search.lower()
        self.timeout = 15
        self.maxtime = 15
        self.startdir = os.getcwd()
        self.outputname = "squidfoundfiles.txt"
        self.founditems = []
    def timeouttimer(self):
        while True:
            time.sleep(1)
            self.timeout -= 1
            if self.timeout == 0:
                self.keep_search = False
                break
    def get_filelist(self):
        try:
            found = False
            for i in os.listdir():
                if "." in i:
                    if os.path.join(os.getcwd(),i) not in self.file_list:
                        if self.search in i.lower():
                            self.file_list.append(os.path.join(os.getcwd(),i))
                            itemtype = "File"
                            found = True
                else:
                    if os.path.join(os.getcwd(), i) not in self.dirlist:
                        self.dirlist.append(os.path.join(os.getcwd(),i))
                        if self.search in i.lower():
                            itemtype = "Directory"
                            found = True
                if found:
                    print(f"[+] {itemtype} Found: {os.path.join(os.getcwd(), i)}")
                    self.timeout = self.maxtime
                    found = False
                    self.founditems.append("[+] "+os.path.join(os.getcwd(),i)+"\n")
        except:
            pass
    def get_files(self):
        try:
            os.chdir(self.drive)
        except:
            print("[+] The directory specified does not exist! Did you mispell it?")
            quit()
        self.timer = threading.Thread(target=self.timeouttimer)
        self.timer.start()
        self.get_filelist()
        for i in self.dirlist:
            try:
                os.chdir(i)
                self.get_filelist()
                if not self.keep_search:
                    break
            except Exception as e:
                pass
        print("\n[+] Scan Completed.")
        if len(self.file_list) > 0:
            print(f"[+] Did you find what you were looking for?\n[+] File with all of the found directories/files: {self.startdir}\{self.outputname}")
            self.timeout = 1
            os.chdir(self.startdir)
            file = open(self.outputname,"w")
            file.writelines(self.founditems)
            file.close()
        else:
            print("[+] I was not able to find anything. Did you spell the name of your file correctly?")
class OptionParse:
    def logo(self):
        print("""
  _________            .__    .______________.__            .___                   ________     _______   
 /   _____/ ________ __|__| __| _/\_   _____/|__| ____    __| _/___________  ___  _\_____  \    \   _  \  
 \_____  \ / ____/  |  \  |/ __ |  |    __)  |  |/    \  / __ |/ __ \_  __ \ \  \/ //  ____/    /  /_\  \ 
 /        < <_|  |  |  /  / /_/ |  |     \   |  |   |  \/ /_/ \  ___/|  | \/  \   //       \    \  \_/   \\
/_______  /\__   |____/|__\____ |  \___  /   |__|___|  /\____ |\___  >__|      \_/ \_______ \ /\ \_____  /
        \/    |__|             \/      \/            \/      \/    \/                      \/ \/       \/                                                           
Script By DrSquid
[+] A File Finder for all of your file-finding needs.""")
    def usage(self):
        self.logo()
        print("""
[+] -F, --File    - Specify the file to look for.
[+] -I, --Info    - Shows this message.
[+] -D, --Dir     - Specify the directory you will start in(optional).

[+] Examples:
[+] python3 SquidFinder.py -F file.txt -D C:/
[+] python3 SquidFinder.py -I""")
    def __init__(self):
        parse = OptionParser()
        parse.add_option("-F", "--File", dest="file")
        parse.add_option("-I","--Info", dest="info", action="store_true")
        parse.add_option("-D","--Drive", dest="drive")
        arg, op = parse.parse_args()
        if arg.info is not None or arg.file is None:
            self.usage()
            sys.exit()
        if arg.drive is None:
            if sys.platform == "win32":
                arg.drive = "C:/"
            else:
                arg.drive = "/"
        File = FileFinder(arg.file, arg.drive)
        File.get_files()
parse = OptionParse()