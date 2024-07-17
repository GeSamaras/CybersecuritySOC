![[Pasted image 20240717154221.png]]

Immediately found the username on the page's elements, only need the password now.
The script tag sources point to different paths, but none are useful for this, an option would be to brute-force directories and files from the site and see what there might be.

# **Brute-forcing the site

GoBuster it is https://www.kali.org/tools/gobuster/

```gobuster dir -u <TARGET_URL> -x php,html,css,js,txt,pdf -w <>```

dir this option tells GoBuster we will brute-force for directories or files;
-u (URL or Domain)**: the URL or Domain of the target we want to perform the brute-force;

x (File eXtensions) the file extensions we are looking for with the provided wordlist. We are looking for the most common ones, but we could provide way more extensions to GoBuster to find hidden files;

-w (Wordlist): as the name suggests, the wordlist we will be using to brute-force. In this situation, we are using the [“directory-list-2.3-medium.txt”.](https://github.com/danielmiessler/SecLists/raw/master/Discovery/Web-Content/directory-list-2.3-medium.txt) (massive list of keywords that can possibly match with the website's pages)

![](https://miro.medium.com/v2/resize:fit:659/1*PKNl9iDnaY_NDAS67uHzLQ.png)

After a while just interrupt the run and check interesting looking pages found.
Entering portal.php in the url sends to this homepage

![](https://miro.medium.com/v2/resize:fit:700/1*C7uH_yvvkAWO5FqQflI33g.png)

And in robots.txt there seems to be the password *Wubbalubbadubdub*


# Enumeration with NMAP

First and more obvious thing, let’s do a enumeration with the IP we received from TryHackMe using NMAP. The target VM’s IP address, in my case, was 10.10.218.16.

_sudo nmap <TARGET_IP> -A -T 4 -v -oN scan_results_

![](https://miro.medium.com/v2/resize:fit:700/1*KXzhaAoIe4q7gxer9VZliQ.png)

NMAP scan command

- **-A (Agressive Scan):** enables “agressive scan mode”, which enables OS detection (-o), version detection (-sV), default script scanning (-sC) and traceroute (-traceroute);
- **• -T 4 (“Agressive” Timing Template):** NMAP has 6 timing templates (0–6, or paranoid-insane), which basically changes NMAP timings so we can avoid firewalls or IDS/IPS systems. Higher numbers are more faster but send more traffic, so they’re more likely to be detected by these technologies, but considering this is a simple CTF, the presence of firewalls or IDS/IPS systems is unlikeable;
- **-v (Verbose):** as the name suggests, it will enable the verbose mode, so we can see the NMAP results in real-time;
- **-oN scan_results (Output Normal):** this argument will send this scan results to a file called “scan_results”.

port 80 is running the http service of the website

# *Injecting le epic commands*
Started entering CLI commands in the command panel in hopes of something showing up, and with "ls" a plethora of files appeared, first one being superingridien in leet speech aha
cat + filename and it shows the first flag. Something similar to this is used on every other flag.

cat doesn't work, so there's a few other alternatives: 
- _tac Sup3rS3cretPickl3Ingred.txt_
- _less Sup3rS3cretPickl3Ingred.txt_
- _strings Sup3rS3cretPickl3Ingred.txt_
- _grep . Sup3rS3cretPickl3Ingred.txt_
- _cp Sup3rS3cretPickl3Ingred.txt /dev/stdout_
- _while read line; do echo $line; done < Sup3rS3cretPickl3Ingred.txt_

For the second flag, exploring different directories might be the right decision, and clue.txt suggests it. /home/ is a common one.
```tac "/home/rick/second\ ingredients”```

Third flag is probably hidden in some of the root directories, which will need privilege escalation, so i'll use sudo for that.
And under root there is the file named 3rd.txt, sudo tac /root/3rd.txt for the last flag.

Useful tools: 
https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
