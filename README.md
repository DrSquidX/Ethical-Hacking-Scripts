# Ethical-Hacking-Scripts
More Advanced and Powerful Scripts made for pen-testing developped by me.
I might add dev notes to my scripts if I get bored.

# Please Don't Black Hat.
Do not use these scripts for malicious intent. I will not be responsible for any damages.

Only use these scripts if you have permission from the people whom you are attacking, and only for ethical purposes.

# What's in this Repository?
The Scripts in this repository include:
* HTTP-Flood DoS Scripts - Scripts that are aimed at taking down web servers.
* ARP-Poisoning Scripts  - Sending Poisonous Packets to the router for a Man-In-The-Middle-Attack on an IP on your network.
* Packet-Sniffers        - Get your network traffic(Use Linux for better experience).
* XSS-Payload Scripts    - Perform Cross site scripting when you are able to obtain working payloads on a vulnerable Web Server.
* Malware                - Malware that can destroy files on the computer, and can also make it unbootable.
* BotNets                - Botnets that can control and perform unauthorized actions to remote computers.
* Keyloggers             - Log the keystrokes of another person, to possibly extract their password from the keylog.
* Hash Crackers          - Brute force a Hash of a password with these scripts.
* IP Utilities           - Can get information about a specified IP address or host for future attacks.
* Vulnerability Scanners - Scan For online IP Addresses, open ports, and scan for MAC Addreses on a home network.
* Vulnerable Server Scripts - Weak servers that allow you to 'legally' test out Cross site scripting and SQL Injections(if you have nobody's permission).
* Phishing Scripts       - Scripts designed to pose as another site's login page, to extract login information from another user.

There is more to be added.

# Warnings
SquidWare and RansomSquid are very dangerous scripts. RansomSquid will encrypt all of your files, and will only decrypt them if you have the correct key. SquidWare is very dangerous as well, it deletes all of your files as well as ruining your Operating system(makes it unbootable). ONLY RUN THESE IF YOU ARE ON A VIRTUAL MACHINE OR HAVE PERMISSION FROM ANOTHER USER! Unauthorized usage of these scripts on other people is also Illegal.

# Updates
I recently reformatted my scripts into folders. The repository is a lot more organised now. I added a few more scripts as well, which include Malware and Vulnerable scripts made for pen-testing.

# Brief Overview of My Scripts(to show that these are actually mine and are not borrowed):

* SquidNet - Read my SquidNet repository(there is a lot of description there).
* SquidNetSSH - An SSH botnet made for taking control of bots in which they have port 22(SSH Protocol) open for connections. If the Bot-Master has a user and password of one of a device, they could potentially log in with those credentials where they could be able to control the device via SSH. There is also an SSH worm inside of the script, made for if someone wanted to spread the botnet automatically. However the brute forcing on this botnet is very slow, so using an external tool such as Hydra would be useful for that.
* SquidWorm - This worm first generates the payload for which it is used to infect other machines. This is so that it could configure the password file for brute forcing as well as the config for better way of SFTP when a bot has been successfully infected(Different OS's with their different directories can mess things up). It first starts out doing a host scan to get a list of all of the IP addresses in that network. It does so by doing 'arp -a' in terminal and using the information from that to build the IP list(may modify and add the ping scan instead later). I didn't really mention the way the config file worked, so what it does is you need to have the IP, operating system, as well as the username of that IP in a line(for ex. '192.168.0.230 larry windows'). Anyways, after successfully brute forcing and infecting one of the victims, it needs to clone itself in order to spread even more. The worm copies and sends the password list file, config file, as well as the script itself. Once sending it to the victim, it executes the files remotely and the process starts over. To prevent a victim from being infected multiple times, a server is binded at 0.0.0.0:42069(yes, the port is that). Before the brute forcing, the worm sends a request to that server, and if it gets the correct reply, it will not brute force that victim. If it does not send a reply it will brute force.
* HashSquid - HashSquid is a script that was made for hash cracking. (more info coming soon)






# Other Info
Do not copy these scripts and say they are yours. I am not ok with that. If you plan to modify these scripts, please credit me as I would appreciate that. 

Another thing is that My Vulnerable server scripts were intended to be horrible and very weak against attacks(so please don't bully me about the vulnerability of these web servers). 

A quick note that SquidNet is my most powerful script(It does not reflect on my socket programming skills, as DatCord does). I may make a separate repository for it as it uses client scripts for bot connections, admin connections, as well as the server itself.

SquidNet Repository: https://github.com/DrSquidX/SquidNet

# Happy (Ethical for legal purposes)Hacking, DrSquid
