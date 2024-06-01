
Basic syntax of commands:

```
sudo snort -A full -r mx-3.pcap -c local.rules -l . #Investigating a pcap file  
sudo snort -r ,snort.log.file> #reading dumped log file  
sudo nano local.rules #editing the local rule with a text editor, nano  
cat alert # reading the contents of the alert file  
sudo rm alert #deleting the alert file  
sudo rm <snort.log.file> #deleting the log file
```

- **/var/log/snort —** is the default location of the log file
- **/etc/snort/snort.conf —** default location of the configuration file
- **/etc/snort/rules/local.rules** — default location of the local rules

==First task==
Write rules to detect all tcp port 80  traffic packets in a pcap file

by opening /local.rules in the http task folder, and writing these lines:
```
alert tcp any 80 <> any any (msg:"inbound tcp traffic detected on port 80)

alert tcp any any <> any 80 (msg:"outbound tcp traffic detected on port 80;sid:10000000002;rev :1)
```

``` Exercise-Files/TASK-2
sudo snort -A full -r mx-3.pcap -c local.rules
```

![[Pasted image 20240531032907.png]]

164 TCP packets detected